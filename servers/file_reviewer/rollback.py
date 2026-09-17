"""回滚点。

修复任何文件之前，先把原文件备份到 <回滚目录>/<仓库名>/<回滚点名>/ 下，并写清单。
恢复必须点名（指定回滚点名称），不提供"恢复最近一次"这种可以被静默触发的入口。
回滚目录默认在被审查仓库之外。
"""
from __future__ import annotations

import json
import os
import shutil
from datetime import datetime
from pathlib import Path

from .repo_context import now_iso, sha256_of

ROLLBACK_DIR = Path(os.environ.get("MCP_SKILL_ROLLBACK_DIR", Path.home() / ".mcp-skill" / "rollback"))


def _repo_dir(repo_name: str, base: Path | str | None) -> Path:
    return Path(base or ROLLBACK_DIR) / repo_name


def create_rollback_point(repo_name: str, repo_root: str | Path, files: list[str | Path], *,
                          name: str | None = None, 说明: str = "", base: Path | str | None = None) -> dict:
    repo_root = Path(repo_root).resolve()
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    point_name = name or f"rb-{stamp}"
    point_dir = _repo_dir(repo_name, base) / point_name
    if point_dir.exists():
        raise FileExistsError(f"回滚点 {point_name} 已存在，请换一个名字")
    point_dir.mkdir(parents=True)
    manifest: list[dict] = []
    for f in files:
        src = Path(f).resolve()
        if not src.is_file():
            raise FileNotFoundError(f"要备份的文件不存在：{src}")
        try:
            rel = src.relative_to(repo_root)
        except ValueError:
            raise ValueError(f"文件不在仓库内，拒绝备份：{src}")
        dst = point_dir / "files" / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        manifest.append({"原路径": str(src), "相对路径": str(rel), "sha256": sha256_of(src),
                         "大小字节": src.stat().st_size})
    meta = {"回滚点": point_name, "仓库名": repo_name, "仓库根目录": str(repo_root),
            "创建时间": now_iso(), "说明": 说明, "文件": manifest, "已恢复": False}
    (point_dir / "manifest.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    return meta


def list_rollback_points(repo_name: str, base: Path | str | None = None) -> list[dict]:
    d = _repo_dir(repo_name, base)
    if not d.exists():
        return []
    out: list[dict] = []
    for p in sorted(d.iterdir()):
        mf = p / "manifest.json"
        if mf.exists():
            meta = json.loads(mf.read_text(encoding="utf-8"))
            out.append({"回滚点": meta["回滚点"], "创建时间": meta["创建时间"], "说明": meta.get("说明", ""),
                        "文件数": len(meta["文件"]), "已恢复": meta.get("已恢复", False)})
    return out


def restore_rollback_point(repo_name: str, name: str, *, base: Path | str | None = None) -> dict:
    """点名恢复。会覆盖仓库内对应文件，属于写操作：调用前必须已获用户明确授权。"""
    if not name:
        raise ValueError("恢复回滚必须点名：请给出回滚点名称")
    point_dir = _repo_dir(repo_name, base) / name
    mf = point_dir / "manifest.json"
    if not mf.exists():
        raise FileNotFoundError(f"没有名为 {name} 的回滚点")
    meta = json.loads(mf.read_text(encoding="utf-8"))
    restored: list[dict] = []
    for item in meta["文件"]:
        src = point_dir / "files" / item["相对路径"]
        dst = Path(item["原路径"])
        before = sha256_of(dst) if dst.exists() else None
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        restored.append({"文件": str(dst), "恢复前sha256": before, "恢复后sha256": sha256_of(dst),
                         "与备份一致": sha256_of(dst) == item["sha256"]})
    meta["已恢复"] = True
    meta["恢复时间"] = now_iso()
    mf.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"回滚点": name, "恢复时间": meta["恢复时间"], "恢复文件": restored}
