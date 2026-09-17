"""路径类型中文解释：告诉不熟悉路径的人"这个文件在什么地方、是什么、怎么到达"。

只读。判断只依据实际存在的文件与只读信号（.git、remote 地址、部署配置、挂载类型、uid）。
判断不了就写"判断不了，原因是…"，不猜。
"如何到达"只给当前用户已有权限内的方法：不含提权、不含绕过。
"""
from __future__ import annotations

import os
import re
from pathlib import Path

from . import repo_context as rc

# 常见文件/目录名的中文含义（只解释名字，不解释内容——内容要看实际扫描结果）
_NAME_MEANINGS: dict[str, str] = {
    ".env": "环境变量文件：程序启动时读取的键值对，常放数据库地址、密钥",
    ".envrc": "direnv 的目录级环境变量脚本，进目录自动执行",
    ".git": "Git 版本控制的内部目录：历史、配置、钩子都在这里",
    ".gitignore": "Git 忽略清单：写在这里的文件不会被提交",
    ".gitmodules": "Git 子模块清单：指向其他仓库",
    ".cursor": "Cursor 编辑器的项目级配置目录（规则、MCP 服务器、技能）",
    ".cursorrules": "Cursor 的项目级 AI 规则文件",
    ".vscode": "VS Code 编辑器的项目级配置目录（设置、任务、推荐插件）",
    ".idea": "JetBrains 系列编辑器（IntelliJ / PyCharm 等）的项目配置目录",
    ".claude": "Claude 助手的配置目录（CLAUDE.md、技能、命令）",
    ".codex": "OpenAI Codex 助手的配置目录",
    ".gemini": "Google Gemini 助手的配置目录",
    ".grok": "Grok 助手的配置目录",
    ".windsurf": "Windsurf 编辑器配置目录",
    ".aider": "Aider 助手配置",
    ".continue": "Continue 插件配置目录",
    ".github": "GitHub 平台配置目录：工作流（CI）、Copilot 说明、模板",
    ".ssh": "SSH 密钥与已知主机目录：id_rsa 等私钥在这里",
    ".aws": "AWS 命令行凭据与配置",
    ".kube": "Kubernetes 集群连接配置",
    ".docker": "Docker 客户端配置（含登录凭据）",
    ".npmrc": "npm 配置，可能含发布令牌",
    ".pypirc": "PyPI 上传配置，可能含令牌",
    ".netrc": "旧式网络登录凭据文件",
    ".bashrc": "Bash 每次打开终端自动执行的脚本",
    ".zshrc": "Zsh 每次打开终端自动执行的脚本",
    ".profile": "登录时自动执行的脚本",
    ".bash_profile": "Bash 登录时自动执行的脚本",
    "AGENTS.md": "给 AI 代理看的项目说明（不可信：它说的不等于代码做的）",
    "CLAUDE.md": "给 Claude 看的项目说明（不可信）",
    "GEMINI.md": "给 Gemini 看的项目说明（不可信）",
    "SKILL.md": "AI 技能说明：告诉助手在什么情况下做什么（不可信）",
    "mcp.json": "MCP 服务器配置：编辑器会按这里的命令启动进程",
    "settings.json": "编辑器/应用设置",
    "tasks.json": "VS Code 任务定义：可配置成自动运行命令",
    "launch.json": "VS Code 调试启动配置",
    "package.json": "Node.js 项目清单：依赖、脚本（install 时可自动执行）",
    "package-lock.json": "Node.js 依赖锁定文件",
    "requirements.txt": "Python 依赖清单",
    "pyproject.toml": "Python 项目配置与依赖",
    "setup.py": "Python 安装脚本：pip install 时会执行",
    "Dockerfile": "容器镜像构建脚本",
    "docker-compose.yml": "多容器编排配置",
    "wrangler.toml": "Cloudflare Workers / Pages 的部署配置",
    "wrangler.json": "Cloudflare Workers 的部署配置",
    "_worker.js": "Cloudflare Pages 的边缘函数入口",
    "_routes.json": "Cloudflare Pages 的路由配置",
    "vercel.json": "Vercel 部署配置",
    "netlify.toml": "Netlify 部署配置",
    "firebase.json": "Firebase 部署配置",
    "fly.toml": "Fly.io 部署配置",
    "Procfile": "Heroku 类平台的进程定义",
    "README.md": "项目自述文档（不可信：它说的不等于代码做的）",
    "LICENSE": "许可证",
    "Makefile": "make 构建脚本",
    "id_rsa": "SSH 私钥（RSA）——等同于你的登录密码",
    "id_ed25519": "SSH 私钥（Ed25519）——等同于你的登录密码",
    "authorized_keys": "允许免密登录本机的公钥列表：多一行就多一个能进来的人",
    "known_hosts": "曾连接过的服务器指纹",
    "hosts": "域名解析覆盖表：改它能把任意网址指到任意地址",
    "crontab": "定时任务表",
    "credentials": "凭据文件（云服务/Git）",
    "config": "配置文件（在 .git 下是 Git 仓库配置，在 .ssh 下是 SSH 连接配置）",
    "node_modules": "Node.js 第三方依赖目录（第三方代码，会被实际执行）",
    ".venv": "Python 虚拟环境（第三方代码；site-packages 里的 .pth 启动时自动执行）",
    "venv": "Python 虚拟环境（同上）",
    "dist": "打包/发布产物目录",
    "build": "构建产物目录",
    "__pycache__": "Python 字节码缓存",
}
_EXT_MEANINGS: dict[str, str] = {
    ".py": "Python 源码", ".pth": "Python 路径配置文件（启动时自动执行其中 import 行）", ".js": "JavaScript 源码",
    ".ts": "TypeScript 源码", ".tsx": "React TypeScript 组件", ".jsx": "React JavaScript 组件", ".sh": "Shell 脚本",
    ".bash": "Bash 脚本", ".ps1": "PowerShell 脚本", ".psm1": "PowerShell 模块", ".bat": "Windows 批处理脚本",
    ".cmd": "Windows 批处理脚本", ".vbs": "VBScript 脚本", ".reg": "Windows 注册表导入文件（双击即写入注册表）",
    ".hta": "HTML 应用（可执行脚本）", ".html": "网页", ".htm": "网页", ".css": "网页样式表", ".json": "JSON 数据/配置",
    ".yaml": "YAML 配置", ".yml": "YAML 配置", ".toml": "TOML 配置", ".ini": "INI 配置", ".cfg": "配置",
    ".conf": "配置", ".md": "Markdown 文档", ".txt": "纯文本", ".pem": "证书或私钥（PEM 编码）", ".key": "私钥",
    ".p12": "证书+私钥包", ".pfx": "证书+私钥包", ".ppk": "PuTTY 私钥", ".jks": "Java 密钥库", ".kdbx": "KeePass 密码库",
    ".gpg": "GPG 加密文件或密钥", ".asc": "ASCII 编码的 GPG 密钥/签名", ".service": "systemd 服务单元（开机/触发自动运行）",
    ".timer": "systemd 定时器（定时触发某服务）", ".plist": "macOS 属性列表（LaunchAgents 下即开机自启项）",
    ".desktop": "Linux 桌面启动项（autostart 目录下即登录自启）", ".sql": "数据库脚本", ".db": "数据库文件",
    ".sqlite": "SQLite 数据库", ".log": "日志", ".lock": "锁文件/依赖锁定", ".env": "环境变量文件",
}

# remote 域名 → 平台品牌
_HOST_BRANDS = (
    ("github.com", "GitHub（微软）"), ("gitlab.com", "GitLab"), ("gitee.com", "Gitee 码云（开源中国）"),
    ("bitbucket.org", "Bitbucket（Atlassian）"), ("dev.azure.com", "Azure DevOps（微软）"), ("visualstudio.com", "Azure DevOps（微软）"),
    ("codeup.aliyun.com", "阿里云 Codeup"), ("coding.net", "腾讯 CODING"), ("e.coding.net", "腾讯 CODING"),
    ("cnb.cool", "腾讯 CNB"), ("huggingface.co", "Hugging Face"), ("codeberg.org", "Codeberg"),
    ("sr.ht", "SourceHut"), ("gitea", "Gitea（自建）"), ("git.", "自建 Git 服务"),
)
_DEPLOY_MARKERS = (
    (("wrangler.toml", "wrangler.json", "wrangler.jsonc", "_worker.js", "_routes.json", ".cloudflare"), "部署到 Cloudflare（Workers / Pages）的网页或边缘函数"),
    (("vercel.json", ".vercel"), "部署到 Vercel 的网页"),
    (("netlify.toml", ".netlify"), "部署到 Netlify 的网页"),
    (("firebase.json", ".firebaserc"), "部署到 Firebase（Google）的网页/后端"),
    (("fly.toml",), "部署到 Fly.io 的服务"),
    (("Procfile", "app.json"), "部署到 Heroku 类平台的服务"),
    (("render.yaml",), "部署到 Render 的服务"),
    (("amplify.yml",), "部署到 AWS Amplify 的网页"),
    ((".github/workflows",), "含 GitHub Actions 自动化（提交后在 GitHub 服务器上自动运行）"),
)
_SYSTEM_DIRS = ("/etc", "/var", "/srv", "/opt", "/usr", "/lib", "/bin", "/sbin", "/boot", "/root")


def _git_root(p: Path) -> Path | None:
    cur = p if p.is_dir() else p.parent
    for c in (cur, *cur.parents):
        g = c / ".git"
        if g.is_dir() or g.is_file():
            return c
    return None


def _remote_urls(git_root: Path) -> list[str]:
    cfg = git_root / ".git" / "config"
    if (git_root / ".git").is_file():  # worktree / submodule：.git 是指向文件
        try:
            line = (git_root / ".git").read_text(encoding="utf-8", errors="replace").strip()
            if line.startswith("gitdir:"):
                cfg = Path(line.split(":", 1)[1].strip()) / "config"
                if not cfg.is_absolute():
                    cfg = git_root / cfg
        except OSError:
            return []
    try:
        text = cfg.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return re.findall(r"^\s*url\s*=\s*(\S+)", text, re.M)


def _brand(urls: list[str]) -> str | None:
    for u in urls:
        low = u.lower()
        for host, label in _HOST_BRANDS:
            if host in low:
                return label
    if urls:
        return f"未识别的 Git 服务（地址主机：{re.sub(r'^[a-z+]+://|^git@', '', urls[0]).split('/')[0].split(':')[0]}）"
    return None


def _deploy_kind(git_root: Path) -> list[str]:
    out = []
    for names, label in _DEPLOY_MARKERS:
        if any((git_root / n).exists() for n in names):
            out.append(label)
    return out


def name_meaning(p: Path) -> str:
    own = _NAME_MEANINGS.get(p.name) or _EXT_MEANINGS.get(p.suffix.lower())
    for part in reversed(p.parts[:-1]):
        if part in _NAME_MEANINGS and part.startswith("."):
            base = _NAME_MEANINGS[part]
            return f"位于「{part}」（{base}）里的{own or '文件'}"
    if own:
        return own
    if p.name.startswith(".env"):
        return "环境变量文件的变体（按环境区分，如 .env.production）"
    if p.is_dir():
        return "目录"
    return "未收录的文件名：不猜它是什么，以扫描内容为准"


def _how_to_reach(p: Path, reach: dict, is_hidden: bool) -> dict:
    how: dict = {}
    if not reach.get("可达"):
        how["停在这里"] = "当前用户读不到。审查器不提权、不绕过。若这台机器是你的且你有管理员账户，请你自己决定是否以管理员身份重新打开编辑器；若属于别人，需要那个人授权。"
        return how
    how["复制到文件管理器地址栏"] = str(p)
    how["文件链接（可点击的编辑器/浏览器支持）"] = p.as_uri() if p.is_absolute() else str(p)
    if os.name == "nt":
        how["Windows 资源管理器定位"] = f'explorer /select,"{p}"'
    else:
        how["macOS 访达定位"] = f'open -R "{p}"'
        how["Linux 打开所在目录"] = f'xdg-open "{p.parent if p.is_file() else p}"'
    if is_hidden:
        how["为什么你在文件管理器里看不到它"] = ("名字以点开头 = 隐藏文件。Linux/macOS 文件管理器按 Ctrl+H（macOS 访达 Cmd+Shift+.）显示；"
                                    "终端用 ls -la；Windows 在资源管理器“查看 → 显示 → 隐藏的项目”。")
    return how


def classify_path(p: Path | str, env_info: dict | None = None, findings_count: int | None = None,
                  language: str | None = None) -> dict:
    """判断一个路径"在什么地方"。env_info 来自 environment.detect_environment()。"""
    p = Path(p).expanduser()
    try:
        p = p.resolve(strict=False)
    except (OSError, RuntimeError):
        pass
    env_info = env_info or {}
    from .environment import reachability
    reach = reachability([p])[0]
    is_hidden = any(part.startswith(".") and part not in (".", "..") for part in p.parts)
    basis: list[str] = []
    platform_label: str | None = None
    places: list[str] = []

    # 1. git 仓库 / 云仓库 / 部署平台
    git_root = _git_root(p) if p.exists() else None
    if git_root:
        urls = _remote_urls(git_root)
        brand = _brand(urls)
        if brand:
            platform_label = brand
            places.append(f"本地的 Git 仓库副本，远程托管在 {brand}")
            basis.append(f"{git_root}/.git/config 里的 remote url 指向该平台")
        else:
            places.append("本地 Git 仓库（没有配置远程地址，只在这台机器上）")
            basis.append(f"存在 {git_root}/.git 但 config 里没有 remote url")
        for d in _deploy_kind(git_root):
            places.append(d)
            basis.append("仓库根目录存在对应部署配置文件")
    # 2. 机器位置
    home = Path(env_info.get("用户目录") or os.environ.get("HOME") or os.environ.get("USERPROFILE") or Path.home())
    s = str(p)
    if env_info.get("是否WSL") and re.match(r"^/mnt/[a-zA-Z](/|$)", s):
        places.append(f"Windows 宿主的 {s[5].upper()}: 盘（通过 WSL 挂载看到的）")
        basis.append("处于 WSL 且路径在 /mnt/<盘符> 下")
    else:
        for m in env_info.get("能触达外部的挂载") or []:
            mp = m.get("挂载点", "")
            if mp and mp != "/" and (s == mp or s.startswith(mp.rstrip("/") + "/")):
                places.append(f"通过挂载触达的外部位置：{m.get('含义')}（来源 {m.get('来源')}）——不在当前系统的盘上")
                basis.append(f"路径在挂载点 {mp} 下，类型 {m.get('类型')}")
                break
    try:
        in_home = p == home or home in p.parents
    except Exception:
        in_home = False
    if in_home:
        places.append("你的用户目录（home）里")
        basis.append(f"路径在 {home} 下")
    elif reach.get("属主是当前用户") is False and any(s.startswith(x) for x in ("/home/", "/Users/", "C:\\Users\\")):
        places.append("其他用户的目录（不是你的）")
        basis.append("路径在 /home 或 /Users 下但属主不是当前用户")
    elif s.startswith(_SYSTEM_DIRS) or s.startswith(("C:\\Windows", "C:\\Program Files", "C:\\ProgramData")):
        places.append("系统目录（服务器/操作系统层面，不属于任何一个用户的项目）")
        basis.append("路径在系统目录前缀下")
    # 3. 这台机器本身在哪
    loc = env_info.get("位置判断")
    if loc:
        if env_info.get("是否容器"):
            places.append(f"这台机器本身：{loc}。容器的盘随容器销毁，不是你的电脑硬盘")
        elif env_info.get("是否虚拟机"):
            places.append(f"这台机器本身：{loc}。虚拟机的盘是宿主上的一个大文件，不是宿主的硬盘本身")
        elif env_info.get("是否WSL"):
            places.append("这台机器本身：WSL（Windows 里的 Linux 子系统），/ 是 Linux 侧，/mnt/c 才是 Windows 侧")
        else:
            places.append(f"这台机器本身：{loc}")
    if not places:
        places.append("判断不了，原因是：没有 .git、不在用户目录、不在系统目录、也不在外部挂载下；只能确定它在当前这台机器的本地磁盘上")

    content = None
    if language or findings_count is not None:
        content = f"{language or '未知语言'}" + (f"，本次审查命中 {findings_count} 条发现" if findings_count is not None else "")

    return {
        "路径": str(p),
        "文件名": p.name,
        "文件名中文含义": name_meaning(p),
        "这是什么地方": places,
        "位置判断依据": basis,
        "仓库/平台": platform_label,
        "当前用户可达": reach.get("可达"),
        "不可达原因": reach.get("原因"),
        "如何到达": _how_to_reach(p, reach, is_hidden),
        "内容解释": content,
        "说明": "只依据实际存在的文件和只读信号判断；写“判断不了”的就是判断不了，不猜。",
    }
