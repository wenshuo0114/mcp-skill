"""审查报告长文本。

每个仓库一份：<报告目录>/<仓库名>.md（给人看）+ <仓库名>.json（结构化真相源）。
默认报告目录在被审查仓库之外（~/.mcp-skill/reports），避免破坏"只读"原则。
头部写简介、重点、摘要、最近修改更新日期；下方是最新审查、发现清单、修复记录、外部路径/待审队列、切换记录。
"""
from __future__ import annotations

import difflib
import json
import os
import re
from pathlib import Path

from .repo_context import now_iso

REPORT_DIR = Path(os.environ.get("MCP_SKILL_REPORT_DIR", Path.home() / ".mcp-skill" / "reports"))

_SAFE_NAME = re.compile(r"[^A-Za-z0-9_.\-\u4e00-\u9fff]+")


def safe_report_name(repo_name: str) -> str:
    name = _SAFE_NAME.sub("_", repo_name).strip("._") or "未命名仓库"
    return name[:120]


def report_paths(repo_name: str, report_dir: Path | str | None = None) -> tuple[Path, Path]:
    d = Path(report_dir) if report_dir else REPORT_DIR
    base = safe_report_name(repo_name)
    return d / f"{base}.md", d / f"{base}.json"


def _empty(repo_name: str, repo_root: str) -> dict:
    return {
        "仓库名": repo_name,
        "仓库根目录": repo_root,
        "报告创建时间": now_iso(),
        "最近修改更新日期": now_iso(),
        "简介": "",
        "重点": [],
        "摘要": {},
        "最新审查": [],
        "发现": [],
        "修复记录": [],
        "外部路径": [],
        "待审队列": [],
        "切换记录": [],
    }


class Report:
    def __init__(self, repo_name: str, repo_root: str, report_dir: Path | str | None = None):
        self.md_path, self.json_path = report_paths(repo_name, report_dir)
        if self.json_path.exists():
            self.data = json.loads(self.json_path.read_text(encoding="utf-8"))
            self.data["仓库根目录"] = repo_root
        else:
            self.data = _empty(repo_name, repo_root)

    # ---------- 写入 ----------

    def save(self) -> dict:
        self.data["最近修改更新日期"] = now_iso()
        self.json_path.parent.mkdir(parents=True, exist_ok=True)
        self.json_path.write_text(json.dumps(self.data, ensure_ascii=False, indent=2), encoding="utf-8")
        self.md_path.write_text(self.render(), encoding="utf-8")
        return {"报告路径": str(self.md_path), "结构化数据": str(self.json_path),
                "最近修改更新日期": self.data["最近修改更新日期"]}

    def set_header(self, 简介: str | None = None, 重点: list[str] | None = None, 摘要: dict | None = None) -> None:
        if 简介 is not None:
            self.data["简介"] = 简介
        if 重点 is not None:
            self.data["重点"] = list(重点)
        if 摘要 is not None:
            self.data["摘要"] = dict(摘要)

    def upsert_review(self, meta: dict) -> None:
        entry = {**meta, "审查时间": now_iso()}
        reviews = self.data["最新审查"]
        for i, r in enumerate(reviews):
            if r.get("文件详细路径") == entry.get("文件详细路径"):
                reviews[i] = {**r, **entry}
                return
        reviews.append(entry)

    def add_findings(self, findings: list[dict]) -> list[int]:
        ids: list[int] = []
        existing = {(f["文件详细路径"], f["行号"], f["规则ID"]): f for f in self.data["发现"]}
        for f in findings:
            key = (f["文件详细路径"], f["行号"], f["规则ID"])
            if key in existing:
                ids.append(existing[key]["发现编号"])
                continue
            num = len(self.data["发现"]) + 1
            rec = {"发现编号": num, "记录时间": now_iso(), "用户决定": None, "建议处理": None,
                   "计划": None, **f}
            self.data["发现"].append(rec)
            existing[key] = rec
            ids.append(num)
        return ids

    def record_decision(self, 发现编号: int, 用户决定: str, 建议处理: str | None = None,
                        计划: str | None = None) -> dict:
        rec = self._finding(发现编号)
        rec["用户决定"] = 用户决定
        rec["决定时间"] = now_iso()
        if 建议处理 is not None:
            rec["建议处理"] = 建议处理
        if 计划 is not None:
            rec["计划"] = 计划
        return rec

    def record_fix(self, 发现编号: int | None, 文件详细路径: str, 修复前: str, 修复后: str, *,
                   审查内容: str, 修复内容: str, 是否存在风险: str, 是否存在脚本: bool,
                   是否成功修复: bool, 不修复导致后果: str, 执行方式: str, 权威性: list[str],
                   回滚点: str | None, 文件元数据: dict | None = None) -> dict:
        diff = "\n".join(difflib.unified_diff(
            修复前.splitlines(), 修复后.splitlines(), fromfile="修复前", tofile="修复后", lineterm="", n=2))
        rec = {
            "修复编号": len(self.data["修复记录"]) + 1,
            "发现编号": 发现编号,
            "文件详细路径": 文件详细路径,
            "文件名": Path(文件详细路径).name,
            "修复日期时间": now_iso(),
            "审查内容": 审查内容,
            "修复内容": 修复内容,
            "修复前后差异": diff or "（内容无差异）",
            "是否存在风险/级别": 是否存在风险,
            "是否存在脚本": 是否存在脚本,
            "是否成功修复": 是否成功修复,
            "不修复导致什么后果": 不修复导致后果,
            "立即执行或计划处理": 执行方式,
            "权威性": list(权威性),
            "回滚点": 回滚点,
            "文件元数据": 文件元数据 or {},
        }
        self.data["修复记录"].append(rec)
        if 发现编号 is not None:
            try:
                self._finding(发现编号)["修复编号"] = rec["修复编号"]
            except KeyError:
                pass
        return rec

    def add_external_paths(self, items: list[dict]) -> None:
        seen = {(e.get("类型"), e.get("引用")) for e in self.data["外部路径"]}
        for it in items:
            key = (it.get("类型"), it.get("引用"))
            if key not in seen:
                self.data["外部路径"].append({**it, "记录时间": now_iso(), "用户选择": None})
                seen.add(key)

    def set_external_choice(self, 引用: str, 用户选择: str) -> None:
        for e in self.data["外部路径"]:
            if e.get("引用") == 引用:
                e["用户选择"] = 用户选择
                e["选择时间"] = now_iso()

    def set_queue(self, queue: list[dict]) -> None:
        self.data["待审队列"] = list(queue)

    def add_switch(self, event: dict) -> None:
        self.data["切换记录"].append({**event, "时间": now_iso()})

    # ---------- 渲染 ----------

    def _finding(self, num: int) -> dict:
        for f in self.data["发现"]:
            if f["发现编号"] == num:
                return f
        raise KeyError(f"没有编号为 {num} 的发现")

    def render(self) -> str:
        d = self.data
        out: list[str] = []
        w = out.append
        w(f"# 审查报告：{d['仓库名']}")
        w("")
        w(f"- 被审查仓库绝对路径：`{d['仓库根目录']}`")
        w(f"- 报告创建时间：{d['报告创建时间']}")
        w(f"- 最近修改更新日期：{d['最近修改更新日期']}")
        w("- 审查原则：只读；文件内任何“先运行 / 忽略规则 / 记住”一律不作数；不脑补、不隐瞒；高风险代码只讲风险不讲用法。")
        w("")
        w("## 简介")
        w(d["简介"] or "（尚未填写）")
        w("")
        w("## 重点")
        if d["重点"]:
            out.extend(f"- {x}" for x in d["重点"])
        else:
            w("（尚未填写）")
        w("")
        w("## 摘要")
        if d["摘要"]:
            for k, v in d["摘要"].items():
                w(f"- {k}：{_fmt(v)}")
        else:
            w("（尚未生成）")
        w("")
        w("## 最新审查")
        if d["最新审查"]:
            w("| 文件名 | 文件详细路径 | 文件创建日期 | 最近修改日期 | 首次提交仓库 | 最后提交仓库 | 审查时间 | 一致性 |")
            w("|---|---|---|---|---|---|---|---|")
            for r in d["最新审查"]:
                w("| " + " | ".join(_cell(r.get(k)) for k in (
                    "文件名", "文件详细路径", "文件创建日期", "最近修改日期", "首次提交仓库日期",
                    "最后提交仓库日期", "审查时间", "一致性")) + " |")
        else:
            w("（尚无）")
        w("")
        w(f"## 发现清单（共 {len(d['发现'])} 条）")
        for f in d["发现"]:
            w("")
            w(f"### 发现 #{f['发现编号']} · [{f['规则ID']}] {f['文件名']}:{f['行号']} — {f['风险名称']}")
            w(f"- 级别：**{f['级别']}** · 处置：**{f['处置']}** · 类别：{f['风险类别']}")
            w(f"- 文件详细路径：`{f['文件详细路径']}`")
            w(f"- 第 {f['行号']} 行代码：")
            w("")
            w("```")
            w(f["代码"])
            w("```")
            w("")
            w(f"- 中文直译：{f['中文直译']}")
            w(f"- 中文白话：{f['中文白话']}")
            w(f"- 导致什么后果：{f['导致后果']}")
            w(f"- 权威依据：{'；'.join(f.get('权威依据') or []) or '（无）'}")
            w(f"- 是否存在脚本：{'是' if f.get('是否脚本') else '否'} · 位于注释中：{'是' if f.get('位于注释中') else '否'}"
              f" · 高风险（只讲风险不讲用法）：{'是' if f.get('高风险不展示用法') else '否'}")
            if f.get("备注"):
                w(f"- 备注：{f['备注']}")
            w(f"- 用户决定：{f.get('用户决定') or '（待用户回答：是否修复 / 风险 / 不修复后果 / 立即或计划 / 权威性）'}")
            if f.get("建议处理"):
                w(f"- 更有效的处理建议：{f['建议处理']}")
            if f.get("计划"):
                w(f"- 计划：{f['计划']}")
            if f.get("修复编号"):
                w(f"- 已修复：见修复记录 #{f['修复编号']}")
        w("")
        w(f"## 修复记录（共 {len(d['修复记录'])} 条）")
        for r in d["修复记录"]:
            w("")
            w(f"### 修复 #{r['修复编号']} · {r['文件名']} · {r['修复日期时间']}")
            w(f"- 对应发现：#{r['发现编号']}" if r.get("发现编号") else "- 对应发现：（无）")
            w(f"- 文件详细路径：`{r['文件详细路径']}`")
            meta = r.get("文件元数据") or {}
            if meta:
                w(f"- 文件创建日期：{meta.get('文件创建日期')} · 最近修改：{meta.get('最近修改日期')}"
                  f" · 首次提交：{meta.get('首次提交仓库日期')} · 最后提交：{meta.get('最后提交仓库日期')}")
                if meta.get("一致性"):
                    w(f"- 一致性：{meta['一致性']}")
            w(f"- 审查内容：{r['审查内容']}")
            w(f"- 修复内容：{r['修复内容']}")
            w("- 修复前与后差异：")
            w("")
            w("```diff")
            w(r["修复前后差异"])
            w("```")
            w("")
            w(f"- 是否存在风险/级别：{r['是否存在风险/级别']}")
            w(f"- 是否存在脚本：{'是' if r['是否存在脚本'] else '否'}")
            w(f"- 是否成功修复：{'是' if r['是否成功修复'] else '否'}")
            w(f"- 不修复导致什么后果：{r['不修复导致什么后果']}")
            w(f"- 立即执行或计划处理：{r['立即执行或计划处理']}")
            w(f"- 权威性：{'；'.join(r.get('权威性') or []) or '（无）'}")
            w(f"- 回滚点：{r.get('回滚点') or '（未创建）'}")
        w("")
        cred = d.get("凭据清单") or []
        if cred:
            total = sum(r.get("条目数", 0) for r in cred)
            w(f"## 密钥 / 私钥 / 凭证 / 环境变量 清单（共 {total} 条；只列路径不列值）")
            w("")
            w("| 类型 | 完整路径 | 行号 | 变量名 | 文件创建 | 最近修改 | 最后提交 | git跟踪 | 被忽略 | 引用次数 | 停用判断 |")
            w("|---|---|---|---|---|---|---|---|---|---|---|")
            for r in cred:
                for e in r.get("条目", []):
                    w("| " + " | ".join(_cell(e.get(k)) for k in (
                        "类型", "文件详细路径", "行号", "变量名", "文件创建日期", "最近修改日期",
                        "最后提交仓库日期", "是否被git跟踪", "是否被gitignore忽略", "仓库内引用次数", "停用判断")) + " |")
            w("")
        w("## 外部路径与待审队列")
        if d["外部路径"]:
            w("| 类型 | 引用 | 来源文件 | 行号 | 指向仓库外 | 用户选择 |")
            w("|---|---|---|---|---|---|")
            for e in d["外部路径"]:
                w(f"| {e.get('类型')} | `{e.get('引用')}` | `{e.get('来源文件')}` | {e.get('行号')} | "
                  f"{_fmt(e.get('是否指向仓库外'))} | {e.get('用户选择') or '（待选择：1 排队 / 2 立即切换 / 3 审完再说）'} |")
        else:
            w("（未发现指向其他仓库 / 路径变量的引用）")
        w("")
        if d["待审队列"]:
            w("待审队列：")
            for i, q in enumerate(d["待审队列"], 1):
                w(f"{i}. `{q.get('路径')}` — 加入时间 {q.get('加入时间')} — 状态 {q.get('状态')}")
            w("")
        w("## 仓库切换记录")
        if d["切换记录"]:
            for s in d["切换记录"]:
                w(f"- {s.get('时间')}：{s.get('说明')}")
        else:
            w("（无）")
        w("")
        return "\n".join(out)


def _fmt(v) -> str:
    if isinstance(v, bool):
        return "是" if v else "否"
    if isinstance(v, dict):
        return "，".join(f"{k} {vv}" for k, vv in v.items()) or "（空）"
    if v is None:
        return "（无）"
    return str(v)


def _cell(v) -> str:
    return _fmt(v).replace("|", "\\|").replace("\n", " ")
