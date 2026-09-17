"""审查器自证：自身零联网、零传播、git 只读。

用户要求“严禁产生传播、禁止传播性标记”。口头承诺不算，这里用测试钉死：
一旦有人给审查器加了联网 / 推送 / 发消息 / 自复制的代码，这个测试就会红。
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "servers" / "file_reviewer"
PY_FILES = sorted(p for p in SRC.glob("*.py"))

FORBIDDEN_MODULES = {
    "socket", "http", "http.client", "http.server", "urllib", "urllib.request", "urllib3",
    "requests", "httpx", "aiohttp", "smtplib", "ftplib", "telnetlib", "xmlrpc", "websocket", "websockets",
    "paramiko", "asyncio.streams", "ssl",
}
PROPAGATION_TEXT = re.compile(
    r"git\s+(push|fetch|pull|clone|commit|remote\s+(add|set-url))|npm\s+publish|twine\s+upload|"
    r"cargo\s+publish|gh\s+(pr|repo)\s+(create|fork)|shutil\.copytree\([^)]*__file__",
)


def _imports(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


@pytest.mark.parametrize("py", PY_FILES, ids=lambda p: p.name)
def test_no_network_imports(py: Path):
    tree = ast.parse(py.read_text(encoding="utf-8"))
    bad = {m for m in _imports(tree) if m in FORBIDDEN_MODULES or m.split(".")[0] in FORBIDDEN_MODULES}
    assert not bad, f"{py.name} 引入了联网模块：{bad}"


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


FORBIDDEN_BARE = {"eval", "exec", "compile", "__import__"}
FORBIDDEN_DOTTED = re.compile(r"^(os\.(system|popen|exec\w*|spawn\w*|startfile)|pty\.spawn|importlib\.import_module|subprocess\.(Popen|call|check_output|check_call|getoutput|getstatusoutput))$")


@pytest.mark.parametrize("py", PY_FILES, ids=lambda p: p.name)
def test_no_dynamic_exec_or_shell(py: Path):
    """按语法树找真正的调用，不看字符串和注释（规则说明文字里当然会提到 eval / os.system）。"""
    tree = ast.parse(py.read_text(encoding="utf-8"))
    hits = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _dotted(node.func)
            if name in FORBIDDEN_BARE or FORBIDDEN_DOTTED.match(name):
                hits.append(f"{name}@{node.lineno}")
    assert not hits, f"{py.name} 含动态执行 / shell 调用：{hits}"


def test_subprocess_only_in_repo_context_and_git_is_readonly():
    users = [p.name for p in PY_FILES if "subprocess" in _imports(ast.parse(p.read_text(encoding="utf-8")))]
    assert users == ["repo_context.py"], f"只有 repo_context 允许用 subprocess，现在是：{users}"
    src = (SRC / "repo_context.py").read_text(encoding="utf-8")
    assert src.count("subprocess.run(") == 1, "只允许 _git 一处调用 subprocess"
    assert "core.hooksPath=/dev/null" in src, "调 git 必须禁用钩子，否则审查本身会触发被审仓库的钩子"
    from servers.file_reviewer import repo_context as rc
    for bad in (["push"], ["fetch"], ["pull"], ["commit", "-m", "x"], ["remote", "add", "x", "y"],
                ["config", "user.name", "x"], ["config", "--add", "a", "b"], ["clone", "x"]):
        with pytest.raises(PermissionError):
            rc._git(bad, Path("."))


def test_no_propagation_text_in_code():
    for py in PY_FILES:
        for i, line in enumerate(py.read_text(encoding="utf-8").splitlines(), 1):
            code = line.split("#")[0]
            # 规则说明/提示文字里可以提到“git push”这个词，但不能以子进程参数的形式出现
            if PROPAGATION_TEXT.search(code) and ("subprocess" in code or "_git(" in code or "run(" in code):
                pytest.fail(f"{py.name}:{i} 疑似传播性调用：{line.strip()}")


def test_writes_only_go_outside_reviewed_repo():
    """审查器写盘的地方只有：报告目录、状态目录、回滚目录。这三处都由环境变量指定，默认在用户 home，不在被审仓库里。"""
    for py in PY_FILES:
        src = py.read_text(encoding="utf-8")
        for m in re.finditer(r"\.write_text\(|\.write_bytes\(|open\([^)]*[\"'][wa]", src):
            line_no = src[: m.start()].count("\n") + 1
            ctx = "\n".join(src.splitlines()[max(0, line_no - 12): line_no])
            assert any(k in ctx for k in ("REPORT_DIR", "STATE_DIR", "ROLLBACK_DIR", "_repo_dir", "repo_root / ", "dest", "self.path", "self.json_path", "state_path", "meta_path", "backup", "point_dir")), \
                f"{py.name}:{line_no} 有写盘但上下文看不出写到报告/状态/回滚目录：\n{ctx}"


def test_no_tracking_markers_in_report_output(isolated_dirs, clean_repo: Path):
    """报告里不带任何外链、追踪像素、生成器水印。"""
    s = isolated_dirs["server"]
    r = s.review_open(str(clean_repo))
    s.review_scan()
    text = Path(r["报告"]["报告路径"]).read_text(encoding="utf-8")
    assert not re.search(r"https?://", text), "干净仓库的报告里不应出现任何 URL"
    assert "<img" not in text and "<script" not in text
