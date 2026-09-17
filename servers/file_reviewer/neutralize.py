"""无害化（"钉"）提案：只产出，不写盘。

用户定义的"钉"：
- 就地清除可利用的原文，写空值，加一条只读中文注释「已无害化，风险：X，不提供复现」；
- 不是回滚点、不为恢复、不留可利用副本；
- 不把 exploit 载入记忆（高风险原文不回显）、不留"路口"、不设陷阱。

实际写入由助手用普通编辑工具、在用户逐文件中文授权后进行。本模块只算出"写成什么样"，并给出保护性重写自检。
"""
from __future__ import annotations

import difflib
import hashlib
import re
import unicodedata
from datetime import datetime, timezone
from pathlib import Path

from . import scanner as sc

# 隐藏/双向控制字符：无害化后的文本里一个都不许有（防止"看起来干净、实际还藏东西"）
_HIDDEN_CHARS = re.compile("[\u200b-\u200f\u2028-\u202e\u2060-\u2064\u2066-\u2069\ufeff\u00ad\u180e]")

_COMMENT = {
    "python": ("# ", ""), "shell": ("# ", ""), "yaml": ("# ", ""), "toml": ("# ", ""), "txt": ("# ", ""),
    "dockerfile": ("# ", ""), "md": ("<!-- ", " -->"), "html": ("<!-- ", " -->"),
    "javascript": ("// ", ""), "typescript": ("// ", ""), "css": ("/* ", " */"),
    "json": (None, None), "unknown": ("# ", ""),
}
_ASSIGN = re.compile(r"^(?P<indent>\s*)(?P<decl>(export|const|let|var|set|setx)\s+)?(?P<name>[A-Za-z_][\w.\-\[\]\"']*)\s*(?P<op>[:=])\s*(?P<rest>.+)$")
_EMPTY_VALUE = {"python": "None", "javascript": "null", "typescript": "null", "shell": '""', "toml": '""',
                "yaml": "null", "txt": '""', "dockerfile": '""', "unknown": '""'}


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()


def hidden_chars(text: str) -> list[dict]:
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        for m in _HIDDEN_CHARS.finditer(line):
            ch = m.group(0)
            out.append({"行": i, "列": m.start() + 1, "码位": f"U+{ord(ch):04X}", "名称": unicodedata.name(ch, "未知")})
    return out


def _comment(lang: str, text: str) -> str | None:
    pre, post = _COMMENT.get(lang, ("# ", ""))
    if pre is None:
        return None
    return f"{pre}{text}{post}"


def neutralized_line(original: str, lang: str, rule: sc.Rule, when: str) -> tuple[str, list[str]]:
    """返回 (替换后的一行或多行文本, 备注)。保留缩进；有赋值就置空值，否则整行变注释。"""
    notes: list[str] = []
    marker = (f"已无害化：此处原有「{rule.name}」（{rule.id}，{rule.severity}），已于 {when} 清除原文。"
              f"风险：{rule.consequence} 不提供复现，详见审查报告。")
    m = _ASSIGN.match(original.rstrip("\n"))
    cm = _comment(lang, marker)
    if lang == "json":
        notes.append("JSON 不支持注释：建议删除该行（若它不是最后一项，注意前一行的逗号），说明只写在报告里。请人工核对语法。")
        return "", notes
    if m and lang in _EMPTY_VALUE:
        indent, decl, name, op = m.group("indent"), m.group("decl") or "", m.group("name"), m.group("op")
        empty = _EMPTY_VALUE[lang]
        if lang == "yaml" and op == ":":
            new = f"{indent}{name}: {empty}"
        elif lang in ("javascript", "typescript"):
            new = f"{indent}{decl}{name} {op} {empty};"
        elif lang == "shell":
            new = f"{indent}{decl}{name}={empty}"
        else:
            new = f"{indent}{decl}{name} {op} {empty}" if op == "=" else f"{indent}{name}{op} {empty}"
        return f"{indent}{cm}\n{new}", notes
    indent = re.match(r"^\s*", original).group(0)
    return f"{indent}{cm}", notes


def propose(file: Path, line_no: int, rule: sc.Rule, *, findings_in_file: int = 0) -> dict:
    """算出无害化后的文件长什么样。不写盘。"""
    file = Path(file)
    lang = sc.detect_language(file)
    original_text = file.read_text(encoding="utf-8", errors="replace")
    lines = original_text.splitlines(keepends=True)
    if not (1 <= line_no <= len(lines)):
        raise ValueError(f"行号 {line_no} 超出范围（文件共 {len(lines)} 行）")
    when = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    orig_line = lines[line_no - 1]
    new_block, notes = neutralized_line(orig_line, lang, rule, when)
    new_lines = lines[:line_no - 1] + ([new_block + ("\n" if orig_line.endswith("\n") else "")] if new_block else []) + lines[line_no:]
    proposed_text = "".join(new_lines)

    # 原文回显策略：高风险 / 严重级 / 必须删除 的不展示用法（不把 exploit 载入记忆、不留路口）；密钥打码；其余原样
    hide = rule.exploit_sensitive or rule.disposition == "必须删除" or rule.severity == "严重"
    if hide:
        shown = "[高风险不展示用法：原文不回显，只说明风险]"
    elif rule.category_id == "secrets":
        mm = rule.pattern.search(orig_line)
        shown = sc.redact_secret_line(orig_line, mm) if mm else "[密钥值已隐去]"
    else:
        shown = orig_line.rstrip("\n")

    diff = list(difflib.unified_diff(lines, new_lines, fromfile=f"{file.name}（修复前）", tofile=f"{file.name}（无害化后）", n=2))
    if hide or rule.category_id == "secrets":
        diff = [(f"-{shown}\n" if (d.startswith("-") and not d.startswith("---") and d[1:] == orig_line) else d) for d in diff]

    total = max(1, len(lines))
    heavy = findings_in_file >= 5 or (findings_in_file / total) > 0.3 or (total <= 10 and rule.is_script)
    if rule.disposition == "必须删除":
        fixable = "不可修复，只能清除：这类内容没有“保留功能去掉风险”的写法。"
    elif rule.disposition == "必须修复":
        fixable = "可修复：保留功能、去掉依赖性/持久性/指向性。无害化只是止血，之后还要按正确写法补回功能。"
    else:
        fixable = "建议修复：风险由你判断。无害化后功能会缺失，请确认可接受。"

    hidden = hidden_chars(proposed_text)
    return {
        "文件": str(file), "行号": line_no, "语言": lang,
        "规则": {"ID": rule.id, "名称": rule.name, "级别": rule.severity, "处置": rule.disposition, "类别": rule.category},
        "原行": shown,
        "无害化后": new_block if new_block else "（删除该行）",
        "差异预览": "".join(diff),
        "是否需要重写": heavy,
        "重写说明": ("改动大：这个文件里可疑内容占比高或本身就是一段脚本，逐行无害化会留下一个残缺的壳。建议先告知用户，"
                 "把重写方案放到单独会话/子代理里产出，再回来执行。" if heavy else "改动小：单行无害化即可。"),
        "能否修复": fixable,
        "备注": notes,
        "sha256_修复前": _sha(original_text),
        "sha256_无害化后(预期)": _sha(proposed_text),
        "隐藏字符检查": {"通过": not hidden, "发现": hidden},
        "确认词": confirm_phrase(file, line_no),
        "保护性重写自检(写入后逐项核对)": [
            "1. 用完整 diff 对照：除了这一处，文件其他任何字节不变（对比 sha256）。",
            "2. 写入后的文件里没有零宽/双向控制字符（review_verify_neutralized 会查）。",
            "3. 写入后重新扫描该文件：原规则在该行不再命中。",
            "4. review_references_of 查该符号/地址：引用归零，否则继续处置引用。",
            "5. 不留任何备份副本、不把原文写进对话或报告（报告里只有规则、行号、风险）。",
            "6. 不在文件里留下“可复原”的提示（如 base64 的原文、注释掉的原文）。",
        ],
        "红线": "本工具不写盘。写入必须由用户以确认词逐文件授权后，由助手用普通编辑工具完成；之后立即调用 review_verify_neutralized。",
    }


def confirm_phrase(file: Path, line_no: int) -> str:
    return f"✅ 授权无害化 {Path(file).name} 第{line_no}行"


def verify(file: Path, rule: sc.Rule, line_no: int, expected_sha: str | None = None, root: Path | None = None) -> dict:
    """写入后的只读核对：规则不再命中该行、无隐藏字符、注释在位、哈希对得上。"""
    file = Path(file)
    text = file.read_text(encoding="utf-8", errors="replace")
    findings = sc.scan_file(file, [rule], root or file.parent)
    still = [f.行号 for f in findings if f.规则ID == rule.id]
    hidden = hidden_chars(text)
    lines = text.splitlines()
    lang = sc.detect_language(file)
    # JSON 无注释语法：以“该行已不存在/规则不再命中”为准
    marker_ok = True if lang == "json" else any("已无害化" in l for l in lines[max(0, line_no - 2): line_no + 1])
    sha_now = _sha(text)
    leftovers = [i for i, l in enumerate(lines, 1) if re.search(r"base64|原文[:：]|#\s*(原为|原来是)\s*[:：]?\s*\S{20,}", l) and "已无害化" in l]
    ok = not still and not hidden and marker_ok and (expected_sha is None or expected_sha == sha_now) and not leftovers
    return {
        "文件": str(file), "行号": line_no, "规则ID": rule.id,
        "规则仍命中的行": still,
        "隐藏字符": hidden,
        "无害化注释在位": marker_ok,
        "sha256_现在": sha_now,
        "与预期一致": (expected_sha == sha_now) if expected_sha else None,
        "疑似留了可复原提示的行": leftovers,
        "通过": ok,
        "结论": "通过：该处已无害化，且未留可复原内容。下一步 review_references_of 查引用。" if ok else
              "未通过：按上面各项逐条修正后再核对。不要把“差不多”当通过。",
    }
