"""仓库识别、切换检测、大项目阈值、文件元数据、外部路径发现。

只读。唯一会启动的子进程是 git 的只读子命令（rev-parse / log），
并显式关闭 hooks，保证不会触发被审查仓库里的任何脚本。
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path

from .scanner import iter_source_files, detect_language, read_lines, is_probably_binary

STATE_DIR = Path(os.environ.get("MCP_SKILL_STATE_DIR", Path.home() / ".mcp-skill"))
STATE_FILE = STATE_DIR / "state.json"

LARGE_PROJECT_FILES = int(os.environ.get("MCP_SKILL_LARGE_FILES", "200"))
LARGE_PROJECT_LINES = int(os.environ.get("MCP_SKILL_LARGE_LINES", "50000"))

_GIT_SAFE = ["git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false"]


def _git(args: list[str], cwd: Path) -> str | None:
    try:
        out = subprocess.run(
            _GIT_SAFE + args, cwd=str(cwd), capture_output=True, text=True, timeout=15,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0"},
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if out.returncode != 0:
        return None
    return out.stdout.strip()


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _ts_iso(ts: float) -> str:
    return datetime.fromtimestamp(ts).astimezone().isoformat(timespec="seconds")


@dataclass
class RepoInfo:
    仓库名: str
    仓库根目录: str
    是否git仓库: bool
    当前分支: str | None
    最新提交: str | None
    最新提交日期: str | None
    远程地址: str | None


def identify_repo(path: Path | str) -> RepoInfo:
    p = Path(path).resolve()
    start = p if p.is_dir() else p.parent
    top = _git(["rev-parse", "--show-toplevel"], start)
    if top:
        root = Path(top).resolve()
        return RepoInfo(
            仓库名=root.name,
            仓库根目录=str(root),
            是否git仓库=True,
            当前分支=_git(["rev-parse", "--abbrev-ref", "HEAD"], root),
            最新提交=_git(["rev-parse", "--short", "HEAD"], root),
            最新提交日期=_git(["log", "-1", "--format=%cI"], root),
            远程地址=_git(["remote", "get-url", "origin"], root),
        )
    return RepoInfo(仓库名=start.name, 仓库根目录=str(start), 是否git仓库=False,
                    当前分支=None, 最新提交=None, 最新提交日期=None, 远程地址=None)


def sha256_of(path: Path | str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def file_metadata(path: Path | str, repo_root: Path | str | None = None) -> dict:
    p = Path(path).resolve()
    st = p.stat()
    birth = getattr(st, "st_birthtime", None)
    创建日期 = _ts_iso(birth) if birth else _ts_iso(st.st_ctime)
    创建日期说明 = "文件系统出生时间" if birth else "此系统不记录出生时间，这里是 inode 变更时间（ctime），仅作参考"
    root = Path(repo_root).resolve() if repo_root else p.parent
    rel = None
    try:
        rel = str(p.relative_to(root))
    except ValueError:
        pass
    首次提交 = _git(["log", "--diff-filter=A", "--follow", "--format=%cI", "--", rel], root) if rel else None
    最后提交 = _git(["log", "-1", "--format=%cI", "--", rel], root) if rel else None
    if 首次提交:
        首次提交 = 首次提交.splitlines()[-1]
    return {
        "文件名": p.name,
        "文件详细路径": str(p),
        "语言": detect_language(p),
        "大小字节": st.st_size,
        "文件创建日期": 创建日期,
        "创建日期说明": 创建日期说明,
        "最近修改日期": _ts_iso(st.st_mtime),
        "首次提交仓库日期": 首次提交,
        "最后提交仓库日期": 最后提交,
        "sha256": sha256_of(p),
        "元数据采集时间": now_iso(),
    }


def consistency_check(path: Path | str, recorded_sha256: str) -> dict:
    current = sha256_of(path)
    return {
        "一致性": "一致" if current == recorded_sha256 else "不一致（文件在审查后被改动过）",
        "审查时sha256": recorded_sha256,
        "当前sha256": current,
    }


def inventory(root: Path | str) -> dict:
    """只统计实际存在的文件，不读 README 之类的文字介绍。"""
    root = Path(root).resolve()
    files: list[dict] = []
    total_lines = 0
    by_lang: dict[str, int] = {}
    for p in iter_source_files(root):
        lang = detect_language(p)
        if is_probably_binary(p):
            lines = 0
            lang = "binary"
        else:
            try:
                lines = len(read_lines(p))
            except OSError:
                continue
        total_lines += lines
        by_lang[lang] = by_lang.get(lang, 0) + 1
        try:
            rel = str(p.relative_to(root))
        except ValueError:
            rel = str(p)
        files.append({"path": rel, "lang": lang, "lines": lines})
    is_large = len(files) > LARGE_PROJECT_FILES or total_lines > LARGE_PROJECT_LINES
    sensitive_names = [f["path"] for f in files if _is_sensitive_name(f["path"])]
    return {
        "仓库根目录": str(root),
        "文件数": len(files),
        "总行数": total_lines,
        "语言分布": dict(sorted(by_lang.items(), key=lambda kv: -kv[1])),
        "是否大项目": is_large,
        "大项目阈值": {"文件数": LARGE_PROJECT_FILES, "总行数": LARGE_PROJECT_LINES},
        "值得优先看的文件": sensitive_names,
        "文件清单": files,
    }


_SENSITIVE_NAME = re.compile(
    r"(^|/)(SKILL\.md|mcp\.json|\.cursor/|\.cursorrules|AGENTS?\.md|CLAUDE\.md|\.github/workflows/|"
    r"package\.json|setup\.py|pyproject\.toml|requirements[^/]*\.txt|Dockerfile|docker-compose[^/]*\.ya?ml|"
    r"\.env[^/]*|\.npmrc|\.pypirc|Makefile|install[^/]*\.(sh|py|ps1)|setup[^/]*\.(sh|ps1)|postinstall[^/]*|"
    r"\.gitmodules|\.git/hooks/|\.pre-commit-config\.yaml)$",
    re.IGNORECASE,
)


def _is_sensitive_name(rel: str) -> bool:
    return bool(_SENSITIVE_NAME.search(rel)) or rel.lower().endswith((".sh", ".ps1", ".bat", ".cmd"))


# ---------- 外部路径发现 ----------

_EXTERNAL_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("绝对路径(其他用户目录)", re.compile(r"(?<![\w:])(/home/[A-Za-z0-9_.-]+/[^\s\"'`)\]>]*|/Users/[A-Za-z0-9_.-]+/[^\s\"'`)\]>]*|/root/[^\s\"'`)\]>]*|[A-Z]:\\\\Users\\\\[^\s\"'`)\]>]+)")),
    ("环境变量路径", re.compile(r"(\$HOME|~|%USERPROFILE%|\$\{?[A-Z_]{3,}\}?)/[A-Za-z0-9_.\-/]+")),
    ("上级目录引用", re.compile(r"(?<![\w.])((\.\./){2,}[A-Za-z0-9_.\-/]*)")),
    ("git仓库地址", re.compile(r"((git\+)?(https?|ssh|git)://[^\s\"'`)\]>]+\.git|git@[A-Za-z0-9.-]+:[^\s\"'`)\]>]+|github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)")),
]


def find_external_paths(root: Path | str) -> list[dict]:
    root = Path(root).resolve()
    results: list[dict] = []
    seen: set[tuple[str, str]] = set()

    gitmodules = root / ".gitmodules"
    if gitmodules.exists():
        cur_name = None
        for n, line in enumerate(read_lines(gitmodules), 1):
            m = re.match(r'\s*\[submodule\s+"([^"]+)"\]', line)
            if m:
                cur_name = m.group(1)
            m2 = re.match(r"\s*url\s*=\s*(\S+)", line)
            if m2:
                results.append({"类型": "git子模块", "来源文件": str(gitmodules), "行号": n,
                                "引用": m2.group(1), "子模块名": cur_name, "是否指向仓库外": True})

    for p in iter_source_files(root):
        if is_probably_binary(p):
            continue
        try:
            lines = read_lines(p)
        except OSError:
            continue
        for n, line in enumerate(lines, 1):
            for kind, pat in _EXTERNAL_PATTERNS:
                for m in pat.finditer(line):
                    ref = m.group(0)
                    key = (kind, ref)
                    if key in seen:
                        continue
                    outside = _points_outside(kind, ref, p, root)
                    if outside is False:
                        continue
                    seen.add(key)
                    results.append({"类型": kind, "来源文件": str(p), "行号": n, "引用": ref,
                                    "是否指向仓库外": outside})
    return results


def _points_outside(kind: str, ref: str, file_path: Path, root: Path) -> bool | None:
    if kind == "上级目录引用":
        try:
            target = (file_path.parent / ref).resolve()
        except OSError:
            return None
        return not str(target).startswith(str(root))
    if kind == "绝对路径(其他用户目录)":
        return not ref.startswith(str(root))
    return True  # 环境变量路径与 git 地址默认视为指向仓库外，需要用户确认


# ---------- 会话状态（当前仓库 / 上次仓库 / 待审队列） ----------

def load_state() -> dict:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            pass
    return {"当前仓库": None, "历史仓库": [], "待审队列": []}


def save_state(state: dict) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")


def switch_repo(info: RepoInfo) -> dict:
    """记录当前仓库；若与上次不同，返回切换事件。"""
    state = load_state()
    prev = state.get("当前仓库")
    switched = prev is not None and prev.get("仓库根目录") != info.仓库根目录
    if prev is None or switched:
        if prev:
            state.setdefault("历史仓库", []).append({**prev, "离开时间": now_iso()})
        state["当前仓库"] = {**asdict(info), "进入时间": now_iso()}
        save_state(state)
    return {"是否切换": switched, "上一个仓库": prev, "当前仓库": state["当前仓库"]}
