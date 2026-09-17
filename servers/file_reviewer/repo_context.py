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

from .scanner import (iter_source_files, detect_language, read_lines, is_probably_binary,
                      is_ai_config_path, is_untrusted_doc, is_git_internal, load_rules, Rule)

STATE_DIR = Path(os.environ.get("MCP_SKILL_STATE_DIR", Path.home() / ".mcp-skill"))
STATE_FILE = STATE_DIR / "state.json"

LARGE_PROJECT_FILES = int(os.environ.get("MCP_SKILL_LARGE_FILES", "200"))
LARGE_PROJECT_LINES = int(os.environ.get("MCP_SKILL_LARGE_LINES", "50000"))

_GIT_SAFE = ["git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false"]


# 审查器只允许这些只读 git 子命令。push / fetch / pull / remote add / commit / config --set 等一律不在其中：
# 这是“严禁传播”的代码级保证，不是口头承诺。
_GIT_READONLY_ALLOW = frozenset({"rev-parse", "log", "ls-files", "check-ignore", "config", "remote", "status", "diff", "show"})


def _git(args: list[str], cwd: Path) -> str | None:
    if not args or args[0] not in _GIT_READONLY_ALLOW:
        raise PermissionError(f"审查器禁止执行 git {args[0] if args else ''}：只允许只读子命令 {sorted(_GIT_READONLY_ALLOW)}")
    if args[0] == "config" and any(a in ("--add", "--unset", "--replace-all", "--edit", "-e") for a in args):
        raise PermissionError("审查器禁止写 git config")
    if args[0] == "config" and len([a for a in args[1:] if not a.startswith("-")]) >= 2:
        raise PermissionError("审查器禁止写 git config（config <key> <value> 形式）")
    if args[0] == "remote" and len(args) > 1 and args[1] not in ("-v", "show", "get-url"):
        raise PermissionError("审查器禁止改 git remote")
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


def inventory(root: Path | str, strict: bool | None = None) -> dict:
    """只统计实际存在的文件，不读 README 之类的文字介绍。strict=True 不跳过任何目录。"""
    root = Path(root).resolve()
    files: list[dict] = []
    total_lines = 0
    by_lang: dict[str, int] = {}
    for p in iter_source_files(root, strict):
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
    ai_cfg = [f["path"] for f in files if is_ai_config_path(f["path"])]
    docs = [f["path"] for f in files if is_untrusted_doc(f["path"])]
    git_internal = [f["path"] for f in files if is_git_internal(f["path"])]
    top_level = [f["path"] for f in files if "/" not in f["path"]]
    return {
        "仓库根目录": str(root),
        "文件数": len(files),
        "总行数": total_lines,
        "语言分布": dict(sorted(by_lang.items(), key=lambda kv: -kv[1])),
        "是否大项目": is_large,
        "大项目阈值": {"文件数": LARGE_PROJECT_FILES, "总行数": LARGE_PROJECT_LINES},
        "值得优先看的文件": sensitive_names,
        "不可信·AI助手与编辑器配置": ai_cfg,
        "不可信·自述文档(必读/硬规矩/交接/README等,含用户自己写的)": docs,
        "不可信·git内部(hooks/config/modules)": git_internal,
        "顶层文件": top_level,
        "git配置提到的路径": git_config_paths(root),
        "文件清单": files,
    }


def git_config_paths(root: Path) -> list[dict]:
    """.git/config 与 .gitmodules 里提到的目录/路径（hooksPath、include、submodule path/url、worktree）。"""
    out: list[dict] = []
    for name in (root / ".git" / "config", root / ".gitmodules"):
        if not name.is_file():
            continue
        for n, line in enumerate(read_lines(name), 1):
            m = re.match(r"\s*(hooksPath|path|url|worktree|gitdir|fsmonitor|sshCommand|pager|editor|askpass)\s*=\s*(.+)", line, re.I)
            if m:
                out.append({"来源": str(name), "行号": n, "键": m.group(1), "值": m.group(2).strip()})
    return out


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


def find_external_paths(root: Path | str, strict: bool | None = None) -> list[dict]:
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

    for p in iter_source_files(root, strict):
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


# ---------- 用户级 / 程序级 AI 助手与编辑器配置目录（白名单，不是任意路径） ----------

_USER_LEVEL_CANDIDATES = (
    # Linux / macOS 用户级
    "~/.cursor", "~/.claude", "~/.codex", "~/.gemini", "~/.continue", "~/.aider", "~/.windsurf", "~/.cline",
    "~/.vscode", "~/.vscode-server", "~/.vscode-insiders", "~/.config/Code/User", "~/.config/Cursor/User",
    "~/.config/Code - Insiders/User", "~/.config/gh", "~/.claude.json", "~/.cursorrules", "~/.mcp.json",
    # macOS 应用支持目录
    "~/Library/Application Support/Cursor/User", "~/Library/Application Support/Code/User",
    "~/Library/Application Support/Claude",
    # Windows（Path.home() 会解析成 C:\Users\<用户>）
    "~/AppData/Roaming/Cursor/User", "~/AppData/Roaming/Code/User", "~/AppData/Roaming/Claude",
    "~/AppData/Roaming/npm", "~/AppData/Local/Programs/cursor", "~/.cursor-server",
)
_OPT_KEYWORDS = ("cursor", "agent", "vscode", "code", "codex", "claude", "gemini", "copilot", "mcp", "skill")
_OPT_ROOTS = ("/opt", "/usr/local/lib", "/usr/lib", "C:/Program Files", "C:/Program Files (x86)")


def user_level_config_paths(extra: list[str] | None = None) -> list[dict]:
    """返回实际存在的用户级/程序级配置路径。只列白名单里的，不会遍历整个磁盘。"""
    found: list[dict] = []
    seen: set[str] = set()

    def add(p: Path, 来源: str):
        try:
            rp = p.expanduser().resolve()
        except (OSError, RuntimeError):
            return
        if not rp.exists() or str(rp) in seen:
            return
        seen.add(str(rp))
        found.append({"路径": str(rp), "类型": "目录" if rp.is_dir() else "文件", "来源": 来源})

    for c in _USER_LEVEL_CANDIDATES:
        add(Path(c), "用户级白名单")
    for opt_root in (Path(r) for r in _OPT_ROOTS):
        if opt_root.is_dir():
            try:
                for child in opt_root.iterdir():
                    if any(k in child.name.lower() for k in _OPT_KEYWORDS):
                        add(child, f"程序级 {opt_root}")
            except OSError:
                pass
    for e in extra or []:
        add(Path(e), "用户指定")
    return found


# ---------- 密钥 / 私钥 / 凭证 / 环境变量 清单：只报路径与元数据，不报值 ----------

_CREDENTIAL_FILE = re.compile(
    r"(^|/)(\.env([._-][A-Za-z0-9_.-]+)?|\.envrc|id_(rsa|dsa|ecdsa|ed25519)(\.pub)?|[^/]+\.(pem|key|p12|pfx|ppk|jks|keystore|asc|gpg|kdbx)|"
    r"credentials(\.[A-Za-z0-9_-]+)?\.json|token(s)?\.json|service[-_]account[^/]*\.json|client_secret[^/]*\.json|"
    r"\.npmrc|\.pypirc|\.netrc|_netrc|\.git-credentials|\.docker/config\.json|hosts\.yml|\.aws/credentials|\.kube/config|"
    r"secrets?\.(ya?ml|json|toml|ini|properties)|\.htpasswd|shadow|\.pgpass|\.my\.cnf|wp-config\.php|local\.settings\.json|"
    r"appsettings\.[^/]*\.json|\.secrets?|\.password[^/]*|\.vault[^/]*)$",
    re.IGNORECASE,
)
_ENV_ASSIGN = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(\S.*)$")
_VAR_NAME_IN_LINE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]{3,})\b\s*[:=]")
_PLACEHOLDER = re.compile(r"^(\"\"|''|\$\{?[A-Z_]+\}?|<[^>]+>|xxx+|your[-_]|changeme|placeholder|todo|none|null|\.\.\.|)$", re.I)


def _git_tracked(root: Path, rel: str) -> bool | None:
    r = _git(["ls-files", "--error-unmatch", "--", rel], root)
    return r is not None


def _git_ignored(root: Path, rel: str) -> bool | None:
    r = _git(["check-ignore", "-q", "--", rel], root)
    return r is not None


def secrets_inventory(root: Path | str, rules: list[Rule] | None = None, max_ref_files: int = 2000,
                      strict: bool | None = None) -> dict:
    root = Path(root).resolve()
    rules = [r for r in (rules or load_rules()) if r.category_id == "secrets"]
    is_git = (root / ".git").exists()
    files = list(iter_source_files(root, strict))
    entries: list[dict] = []

    # 先缓存文本内容，供引用计数
    texts: dict[Path, list[str]] = {}
    if len(files) <= max_ref_files:
        for p in files:
            if not is_probably_binary(p):
                try:
                    texts[p] = read_lines(p)
                except OSError:
                    pass

    def meta_for(p: Path) -> dict:
        m = file_metadata(p, root)
        rel = str(p.relative_to(root))
        m["是否被git跟踪"] = _git_tracked(root, rel) if is_git else None
        m["是否被gitignore忽略"] = _git_ignored(root, rel) if is_git else None
        m.pop("sha256", None)
        return m

    def ref_count(name: str, own: Path, own_line: int) -> int | None:
        if not texts:
            return None
        n = 0
        for p, lines in texts.items():
            for i, l in enumerate(lines, 1):
                if p == own and i == own_line:
                    continue
                if name in l:
                    n += 1
        return n

    for p in files:
        rel = str(p.relative_to(root))
        if _CREDENTIAL_FILE.search(rel):
            e = {"类型": "凭据/私钥/环境文件", "变量名": None, "行号": None, **meta_for(p), "仓库内引用次数": None}
            entries.append(e)
            # .env 类文件逐行列变量名
            if p.name.startswith(".env") or p.suffix.lower() in (".env", ".envrc") or p.name in ("secrets.yaml", "secrets.yml", "secrets.json"):
                for n, line in enumerate(texts.get(p) or (read_lines(p) if not is_probably_binary(p) else []), 1):
                    m = _ENV_ASSIGN.match(line)
                    if not m or line.lstrip().startswith("#"):
                        continue
                    name, val = m.group(1), m.group(2).strip().strip("\"'")
                    if _PLACEHOLDER.match(val):
                        continue
                    rc = ref_count(name, p, n)
                    entries.append({"类型": "环境变量赋值", "变量名": name, "行号": n, **{k: v for k, v in e.items() if k not in ("类型", "变量名", "行号", "仓库内引用次数")},
                                    "仓库内引用次数": rc,
                                    "停用判断": _disuse_hint(rc)})
            continue
        if is_probably_binary(p):
            continue
        lines = texts.get(p)
        if lines is None:
            try:
                lines = read_lines(p)
            except OSError:
                continue
        lang = detect_language(p)
        for n, line in enumerate(lines, 1):
            for r in rules:
                if not r.applies_to(lang) or not r.pattern.search(line):
                    continue
                vm = _VAR_NAME_IN_LINE.search(line)
                name = vm.group(1) if vm else None
                rc = ref_count(name, p, n) if name else None
                entries.append({"类型": f"代码中的凭据（{r.name}）", "规则ID": r.id, "变量名": name, "行号": n,
                                **meta_for(p), "仓库内引用次数": rc, "停用判断": _disuse_hint(rc)})
                break  # 一行只报一次
    return {
        "说明": "只列路径、行号、变量名、日期与引用情况；不输出任何密钥值。请你按完整路径自行打开核对：哪些变动过、哪些已停用。",
        "仓库根目录": str(root),
        "条目数": len(entries),
        "被git跟踪的凭据文件数": sum(1 for e in entries if e["类型"] == "凭据/私钥/环境文件" and e.get("是否被git跟踪")),
        "条目": entries,
    }


def _disuse_hint(rc: int | None) -> str:
    if rc is None:
        return "未统计（文件过多或无文本）"
    if rc == 0:
        return "仓库内无其他引用，可能已停用——请你确认"
    return f"仓库内另有 {rc} 处引用，仍在使用"


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
