"""持久化位置清单：按当前操作系统列出"能让东西开机/登录/定时自动跑起来"的已知位置。

只读、只列文件。诚实边界：活的进程、服务、计划任务运行态，审查器不会去跑命令看；
把官方查看命令原文交给用户自己跑。
"""
from __future__ import annotations

import os
from pathlib import Path

from .environment import reachability


def _home() -> Path:
    return Path(os.environ.get("HOME") or os.environ.get("USERPROFILE") or Path.home())


def _env_path(var: str, *rest: str) -> Path | None:
    base = os.environ.get(var)
    return Path(base, *rest) if base else None


def persistence_locations() -> list[dict]:
    """返回 [{类别, 路径, 说明, 触发时机}]，只含本 OS 相关项；存在与否另查。"""
    h = _home()
    items: list[dict] = []

    def add(cat: str, path: Path | None, desc: str, when: str):
        if path is not None:
            items.append({"类别": cat, "路径": str(path), "说明": desc, "触发时机": when})

    if os.name == "nt":
        add("启动文件夹", _env_path("APPDATA", "Microsoft", "Windows", "Start Menu", "Programs", "Startup"), "当前用户登录自启", "登录")
        add("启动文件夹", _env_path("ProgramData", "Microsoft", "Windows", "Start Menu", "Programs", "Startup"), "所有用户登录自启", "登录")
        add("计划任务", Path(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "Tasks"), "计划任务定义文件（XML）", "定时/事件")
        add("hosts", Path(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "drivers", "etc", "hosts"), "域名解析覆盖表", "每次解析域名")
        add("浏览器", _env_path("LOCALAPPDATA", "Google", "Chrome", "User Data"), "Chrome 用户数据：扩展、首选项、登录库", "浏览器启动")
        add("浏览器", _env_path("LOCALAPPDATA", "Microsoft", "Edge", "User Data"), "Edge 用户数据", "浏览器启动")
        add("浏览器", _env_path("APPDATA", "Mozilla", "Firefox", "Profiles"), "Firefox 配置：user.js、扩展", "浏览器启动")
        add("PowerShell 配置", _env_path("USERPROFILE", "Documents", "WindowsPowerShell", "Microsoft.PowerShell_profile.ps1"), "每次打开 PowerShell 自动执行", "打开终端")
        add("PowerShell 配置", _env_path("USERPROFILE", "Documents", "PowerShell", "Microsoft.PowerShell_profile.ps1"), "PowerShell 7 每次启动自动执行", "打开终端")
        add("WSL", _env_path("LOCALAPPDATA", "Packages"), "WSL 发行版根文件系统所在（里面是另一套 Linux 持久化位置）", "WSL 启动")
        add("SSH", h / ".ssh" / "authorized_keys", "允许免密登录本机的公钥", "SSH 登录")
    else:
        # Linux + macOS 通用
        add("定时任务", Path("/etc/crontab"), "系统级定时任务表", "定时")
        add("定时任务", Path("/etc/cron.d"), "系统级定时任务目录", "定时")
        for n in ("hourly", "daily", "weekly", "monthly"):
            add("定时任务", Path(f"/etc/cron.{n}"), f"每{n}执行的脚本目录", "定时")
        add("定时任务", Path("/var/spool/cron"), "各用户的 crontab", "定时")
        add("定时任务", Path("/var/spool/cron/crontabs"), "各用户的 crontab（Debian 系）", "定时")
        add("systemd", Path("/etc/systemd/system"), "系统服务/定时器单元（管理员放的）", "开机/定时/触发")
        add("systemd", Path("/usr/lib/systemd/system"), "系统服务单元（软件包放的）", "开机/定时/触发")
        add("systemd", Path("/lib/systemd/system"), "系统服务单元（软件包放的）", "开机/定时/触发")
        add("systemd", Path("/run/systemd/system"), "运行时生成的单元（临时，重启消失）", "运行时")
        add("systemd", h / ".config" / "systemd" / "user", "当前用户的服务/定时器单元", "登录/定时")
        add("旧式启动", Path("/etc/init.d"), "SysV 启动脚本", "开机")
        add("旧式启动", Path("/etc/rc.local"), "开机最后执行的脚本", "开机")
        add("预加载注入", Path("/etc/ld.so.preload"), "所有程序启动前先加载的共享库列表——最隐蔽的注入点", "每个程序启动")
        add("环境变量", Path("/etc/environment"), "全局环境变量（含 LD_PRELOAD、代理）", "登录")
        add("shell 启动", Path("/etc/profile"), "所有用户登录 shell 执行", "登录")
        add("shell 启动", Path("/etc/profile.d"), "所有用户登录 shell 执行的脚本目录", "登录")
        add("shell 启动", Path("/etc/bash.bashrc"), "所有用户的 bash 启动脚本", "打开终端")
        add("shell 启动", Path("/etc/zshrc"), "所有用户的 zsh 启动脚本", "打开终端")
        for n in (".bashrc", ".bash_profile", ".profile", ".zshrc", ".zprofile", ".zshenv", ".config/fish/config.fish"):
            add("shell 启动", h / n, "当前用户每次打开终端/登录自动执行", "打开终端")
        add("桌面自启", h / ".config" / "autostart", "当前用户桌面登录自启（.desktop）", "登录")
        add("桌面自启", Path("/etc/xdg/autostart"), "所有用户桌面登录自启", "登录")
        add("SSH", h / ".ssh" / "authorized_keys", "允许免密登录本机的公钥：多一行多一个能进来的人", "SSH 登录")
        add("SSH", h / ".ssh" / "config", "SSH 客户端配置（ProxyCommand 可执行任意命令）", "每次 ssh")
        add("SSH", Path("/etc/ssh/sshd_config"), "SSH 服务端配置（AuthorizedKeysCommand、PermitRootLogin）", "SSH 服务启动")
        add("hosts", Path("/etc/hosts"), "域名解析覆盖表", "每次解析域名")
        add("Git 全局", h / ".gitconfig", "全局 git 配置（core.hooksPath、别名可执行命令）", "每次 git")
        add("Git 全局", h / ".config" / "git" / "hooks", "全局 git 钩子目录（若配置了 hooksPath）", "每次 git 操作")
        add("浏览器", h / ".config" / "google-chrome", "Chrome 用户数据：扩展、首选项、登录库", "浏览器启动")
        add("浏览器", h / ".config" / "chromium", "Chromium 用户数据", "浏览器启动")
        add("浏览器", h / ".config" / "microsoft-edge", "Edge 用户数据", "浏览器启动")
        add("浏览器", h / ".config" / "BraveSoftware", "Brave 用户数据", "浏览器启动")
        add("浏览器", h / ".mozilla" / "firefox", "Firefox 配置：user.js、扩展", "浏览器启动")
        add("浏览器策略", Path("/etc/opt/chrome/policies/managed"), "Chrome 企业策略（个人电脑不该有）", "浏览器启动")
        add("浏览器策略", Path("/etc/chromium/policies/managed"), "Chromium 企业策略", "浏览器启动")
        add("浏览器策略", Path("/etc/brave/policies/managed"), "Brave 企业策略", "浏览器启动")
        add("浏览器策略", Path("/usr/lib/firefox/distribution/policies.json"), "Firefox 企业策略", "浏览器启动")
        add("浏览器策略", Path("/etc/firefox/policies/policies.json"), "Firefox 企业策略", "浏览器启动")
        add("Python 自动执行", h / ".local" / "lib", "用户级 site-packages（里面的 .pth 启动即执行）", "每个 Python 启动")
        add("Python 自动执行", Path("/usr/lib/python3/dist-packages"), "系统级 site-packages（.pth）", "每个 Python 启动")
        add("Python 自动执行", Path("/usr/local/lib"), "本地安装的 site-packages（.pth）", "每个 Python 启动")
        add("Node 全局", h / ".npmrc", "npm 配置（可指定恶意 registry / 令牌）", "每次 npm")
        # macOS 专有
        add("macOS 启动项", h / "Library" / "LaunchAgents", "当前用户登录自启（plist）", "登录")
        add("macOS 启动项", Path("/Library/LaunchAgents"), "所有用户登录自启", "登录")
        add("macOS 启动项", Path("/Library/LaunchDaemons"), "系统级开机自启（root 权限运行）", "开机")
        add("macOS 启动项", Path("/Library/StartupItems"), "旧式启动项", "开机")
        add("macOS 浏览器", h / "Library" / "Application Support" / "Google" / "Chrome", "Chrome 用户数据", "浏览器启动")
        add("macOS 浏览器", h / "Library" / "Application Support" / "Firefox" / "Profiles", "Firefox 配置", "浏览器启动")
        add("macOS 策略", Path("/Library/Managed Preferences"), "MDM/企业策略（个人电脑不该有）", "登录")
    return items


def official_live_state_commands() -> dict:
    """活的运行态审查器不看，用户自己跑这些官方命令。"""
    return {
        "Linux": [
            "systemctl list-units --type=service --state=running   —— 正在运行的服务",
            "systemctl list-timers --all   —— 所有定时器及下次触发时间",
            "systemctl list-unit-files --state=enabled   —— 开机自启的单元",
            "crontab -l && sudo ls -la /var/spool/cron/crontabs   —— 当前用户与所有用户的定时任务",
            "ss -tulpn   —— 谁在监听哪个端口（需要 root 看进程名）",
            "ps -eo pid,ppid,user,lstart,cmd --sort=start_time   —— 进程与启动时间",
            "cat /etc/ld.so.preload; echo $LD_PRELOAD   —— 预加载注入",
            "sudo iptables -S; sudo ufw status verbose; sudo nft list ruleset   —— 防火墙规则",
            "last -a; lastlog   —— 谁登录过",
        ],
        "Windows（PowerShell）": [
            "Get-ScheduledTask | Where-Object State -ne Disabled | Select TaskName,TaskPath,State   —— 计划任务",
            "Get-CimInstance Win32_StartupCommand | Select Name,Command,Location,User   —— 启动项（注册表 Run + 启动文件夹）",
            "Get-Service | Where-Object StartType -eq Automatic | Select Name,DisplayName,Status   —— 自动启动的服务",
            "Get-CimInstance -Namespace root\\subscription -ClassName __EventFilter; Get-CimInstance -Namespace root\\subscription -ClassName CommandLineEventConsumer   —— WMI 事件订阅（隐蔽持久化）",
            "reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run; reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run   —— 注册表自启",
            "reg query HKLM\\Software\\Policies\\Google\\Chrome /s; reg query HKLM\\Software\\Policies\\Microsoft\\Edge /s   —— 浏览器策略（个人电脑应为空）",
            "netstat -abno   —— 监听端口与进程（管理员）",
            "Get-NetFirewallRule -Direction Inbound -Enabled True | Select DisplayName,Action   —— 入站防火墙规则",
            "netsh winhttp show proxy; reg query \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\" /v ProxyServer   —— 代理",
            "Get-MpPreference | Select ExclusionPath,ExclusionProcess   —— Defender 排除项（被加进去的东西不会被扫）",
        ],
        "macOS": [
            "launchctl list   —— 当前用户的 launchd 任务",
            "sudo launchctl list   —— 系统级",
            "ls -la ~/Library/LaunchAgents /Library/LaunchAgents /Library/LaunchDaemons",
            "profiles list   —— 已安装的配置描述文件（MDM/策略）",
            "sudo lsof -iTCP -sTCP:LISTEN -n -P   —— 监听端口",
            "defaults read com.google.Chrome   —— Chrome 托管策略",
        ],
        "浏览器内（任何系统）": [
            "chrome://policy   —— 生效的企业策略（个人电脑应显示“未设置策略”）",
            "chrome://extensions   —— 已装扩展；标着“由企业策略安装”的删不掉、要先删策略",
            "edge://policy、edge://extensions、about:policies、about:support   —— Edge / Firefox 对应页",
        ],
        "说明": "审查器不代跑这些命令，也不解析它们的输出。你跑完把结果里不认识的服务/任务/端口/扩展名字告诉我，我再逐个只读审对应文件。",
    }


CREDENTIAL_ROTATION_GUIDE = {
    "适用场景": "机器已售出/丢失/不再受你控制；VPS 或仓库上的文件你已读不到；或怀疑残留清不干净。",
    "原则": "你无法再控制的地方，就不要试图回去清——那是新的入侵。根治不是把东西删掉，而是让它即使还在也没用。",
    "步骤": [
        "1. 列出那台机器上曾经登录/保存过的一切：云服务商账号、Git 平台、邮箱、密码管理器、SSH 私钥、API 密钥、浏览器里保存的密码、代币/钱包。",
        "2. 逐个作废并换新：换密码、吊销 SSH 公钥（在服务器的 authorized_keys 与 Git 平台的 SSH Keys 页删掉旧公钥）、吊销 API 密钥/令牌、退出所有会话（各平台的“退出所有设备”）。",
        "3. Git 平台：Settings → SSH and GPG keys / Personal access tokens / Applications 全部检查并删掉不认识的；查看 Security log 里的登录记录。",
        "4. VPS：用服务商控制台（不是 SSH 进去）重置 root 密码、重装系统、换密钥；若你已读不到某些文件，直接重装比找它更可靠。",
        "5. 云仓库/对象存储：轮换访问密钥，开启二次验证，检查协作者列表与 Webhook。",
        "6. 浏览器：在新机器上登录账号后“清除已保存密码并重新设置”，同步的密码库要全部换。",
        "7. 记录：每一项什么时候换的、旧的什么时候作废的，写进报告。以后发现异常登录可以对时间。",
    ],
    "为什么这样就够了": "残留在别人机器上的东西，价值全在它拿到的凭据和它能连回来的地址。凭据全换、地址（你的服务器）全重装，它就成了一堆没用的字节。",
    "不要做的": "不要试图远程连回已售出的机器；不要在不属于你的机器上运行任何清理脚本；不要向对方发送任何指令。",
}
