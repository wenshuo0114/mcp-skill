"""环境真实性探测：只读地看"我站在哪台机器上"。

红线：
- 只报"我看到的信号是 X"，绝不输出"已核实真实"。
- 来宾系统里的程序原理上无法证明宿主是真的、没被动过——这一项如实停下，把官方核对命令原文交给用户自己在宿主上跑。
- 不跑任何命令（systemd-detect-virt / dmidecode / wmic 都不跑），只读文件和环境变量；Windows 用标准库 winreg 读注册表。
"""
from __future__ import annotations

import os
import platform
from pathlib import Path

# 各家虚拟机/云在 DMI 里的惯用字样（只用于"看起来像"，不用于"确认是"）
_VENDOR_HINTS = (
    ("Microsoft Corporation", "Virtual Machine", "Hyper-V（微软）"),
    ("VMware", "", "VMware"),
    ("innotek", "VirtualBox", "VirtualBox（Oracle）"),
    ("QEMU", "", "QEMU/KVM"),
    ("Red Hat", "KVM", "KVM（Red Hat）"),
    ("Xen", "", "Xen"),
    ("Parallels", "", "Parallels"),
    ("Amazon EC2", "", "AWS EC2"),
    ("Google", "Google Compute Engine", "Google Cloud"),
    ("Alibaba Cloud", "", "阿里云"),
    ("Tencent Cloud", "", "腾讯云"),
    ("Huawei", "", "华为云"),
    ("DigitalOcean", "", "DigitalOcean"),
    ("OpenStack", "", "OpenStack"),
    ("Apple", "Virtual", "Apple 虚拟化框架"),
)

# 这些文件系统类型意味着"这个挂载点能触达当前系统之外"
_OUTSIDE_FS = {
    "9p": "9p（虚拟机与宿主共享目录，常见于 WSL2 / QEMU）",
    "virtiofs": "virtiofs（虚拟机与宿主共享目录）",
    "drvfs": "drvfs（WSL 挂载的 Windows 盘）",
    "cifs": "cifs/SMB（网络共享）",
    "smb3": "SMB3（网络共享）",
    "nfs": "NFS（网络文件系统）",
    "nfs4": "NFS（网络文件系统）",
    "vboxsf": "vboxsf（VirtualBox 共享文件夹）",
    "prl_fs": "prl_fs（Parallels 共享文件夹）",
    "fuse.sshfs": "sshfs（通过 SSH 挂载的远程目录）",
    "fuse.rclone": "rclone（云存储挂载）",
    "fuse.gcsfuse": "gcsfuse（Google 云存储挂载）",
    "fuse.s3fs": "s3fs（S3 云存储挂载）",
    "vmhgfs-fuse": "vmhgfs（VMware 共享文件夹）",
    "fuse.vmhgfs-fuse": "vmhgfs（VMware 共享文件夹）",
}
_PSEUDO_FS_TYPES = {"proc", "sysfs", "cgroup", "cgroup2", "devpts", "tmpfs", "mqueue", "devtmpfs", "securityfs",
                    "debugfs", "tracefs", "pstore", "bpf", "hugetlbfs", "configfs", "fusectl", "binfmt_misc",
                    "autofs", "efivarfs", "nsfs", "rpc_pipefs", "selinuxfs", "ramfs"}

AUTHENTICITY_CONFIRM = "✅ 这台机器是我的，我有权限，继续"


def _read(p: Path) -> str | None:
    try:
        return p.read_text(encoding="utf-8", errors="replace").strip()
    except (OSError, ValueError):
        return None


def _is_admin() -> bool | None:
    if os.name == "nt":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return None
    try:
        return os.geteuid() == 0
    except AttributeError:
        return None


def _windows_registry_signals() -> dict:
    """Hyper-V 来宾专用键：只在 Hyper-V 来宾里存在，是微软官方写入的。"""
    out: dict = {"读取到": False}
    if os.name != "nt":
        return out
    try:
        import winreg  # type: ignore
    except ImportError:
        return out
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters") as k:
            out["读取到"] = True
            for name in ("HostName", "PhysicalHostName", "PhysicalHostNameFullyQualified", "VirtualMachineName"):
                try:
                    out[name] = winreg.QueryValueEx(k, name)[0]
                except OSError:
                    pass
    except OSError:
        pass
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\BIOS") as k:
            for name in ("SystemManufacturer", "SystemProductName", "BIOSVendor"):
                try:
                    out[name] = winreg.QueryValueEx(k, name)[0]
                except OSError:
                    pass
    except OSError:
        pass
    return out


def _parse_mountinfo(text: str) -> list[dict]:
    mounts: list[dict] = []
    for line in text.splitlines():
        parts = line.split(" - ")
        if len(parts) != 2:
            continue
        left, right = parts[0].split(), parts[1].split()
        if len(left) < 5 or len(right) < 2:
            continue
        mounts.append({"挂载点": left[4], "类型": right[0], "来源": right[1]})
    return mounts


def detect_environment(proc: Path | str = "/proc", sys_dmi: Path | str = "/sys/class/dmi/id",
                       env: dict | None = None) -> dict:
    """返回当前运行环境的只读信号。参数用于测试注入，正常调用不传。"""
    proc = Path(proc)
    sys_dmi = Path(sys_dmi)
    env = dict(os.environ if env is None else env)
    evidence: list[str] = []
    unknowns: list[str] = []

    # --- 基本 ---
    try:
        user = os.getlogin()
    except OSError:
        user = env.get("USER") or env.get("USERNAME") or "未知"
    uid = os.getuid() if hasattr(os, "getuid") else None
    is_admin = _is_admin()
    home = env.get("HOME") or env.get("USERPROFILE") or str(Path.home())

    # --- 虚拟机 ---
    is_vm: bool | None = None
    vendor: str | None = None
    cpuinfo = _read(proc / "cpuinfo") or ""
    if "hypervisor" in cpuinfo.split():
        is_vm = True
        evidence.append("/proc/cpuinfo 的 flags 含 hypervisor：CPU 报告自己运行在虚拟机监控器之下")
    sys_vendor = _read(sys_dmi / "sys_vendor")
    product = _read(sys_dmi / "product_name")
    if sys_vendor is None and product is None:
        unknowns.append(f"厂商查不出：{sys_dmi} 不存在或不可读（容器里通常没有；Windows 见注册表信号）")
    else:
        evidence.append(f"DMI sys_vendor={sys_vendor!r} product_name={product!r}")
        blob = f"{sys_vendor or ''} {product or ''}"
        for v, p, label in _VENDOR_HINTS:
            if v.lower() in blob.lower() and (not p or p.lower() in blob.lower()):
                vendor = label
                is_vm = True if is_vm is None else is_vm
                break
        if vendor is None and is_vm:
            unknowns.append(f"DMI 字样 {blob.strip()!r} 不在已知虚拟机厂商列表里，我不猜")
    hv_type = _read(Path("/sys/hypervisor/type"))
    if hv_type:
        evidence.append(f"/sys/hypervisor/type={hv_type}")
        is_vm = True
    reg = _windows_registry_signals()
    if reg.get("读取到"):
        is_vm = True
        vendor = vendor or "Hyper-V（微软）"
        evidence.append("注册表存在 HKLM\\SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters（只在 Hyper-V 来宾里出现）")
        if reg.get("PhysicalHostName"):
            evidence.append(f"该键记录的物理宿主名：{reg['PhysicalHostName']}")
    elif os.name == "nt":
        m = f"{reg.get('SystemManufacturer', '')} {reg.get('SystemProductName', '')}"
        if m.strip():
            evidence.append(f"注册表 BIOS 信息：{m.strip()}")
            for v, p, label in _VENDOR_HINTS:
                if v.lower() in m.lower() and (not p or p.lower() in m.lower()):
                    vendor, is_vm = label, True
                    break
    if is_vm is None:
        is_vm = False if cpuinfo else None
        if is_vm is None:
            unknowns.append("读不到 /proc/cpuinfo，虚拟机与否判断不了")

    # --- 容器 ---
    is_container = False
    if Path("/.dockerenv").exists():
        is_container = True; evidence.append("存在 /.dockerenv：Docker 容器")
    if Path("/run/.containerenv").exists():
        is_container = True; evidence.append("存在 /run/.containerenv：Podman 容器")
    cgroup = _read(proc / "1" / "cgroup") or ""
    if any(k in cgroup for k in ("docker", "containerd", "kubepods", "pod-", "libpod", "lxc")):
        is_container = True; evidence.append(f"/proc/1/cgroup 含容器字样：{cgroup.splitlines()[0][:80]}")
    if env.get("container") or env.get("KUBERNETES_SERVICE_HOST"):
        is_container = True; evidence.append("环境变量 container / KUBERNETES_SERVICE_HOST 存在")
    mountinfo = _read(proc / "self" / "mountinfo") or ""
    mounts = _parse_mountinfo(mountinfo)
    root_fs = next((m["类型"] for m in mounts if m["挂载点"] == "/"), None)
    if root_fs == "overlay":
        is_container = True; evidence.append("根文件系统是 overlay：容器镜像层")

    # --- WSL ---
    version = _read(proc / "version") or ""
    is_wsl = "microsoft" in version.lower() or bool(env.get("WSL_DISTRO_NAME"))
    if is_wsl:
        evidence.append("内核版本字串含 microsoft 或存在 WSL_DISTRO_NAME：WSL（Windows 上的 Linux 子系统）")

    # --- 能触达外部的挂载 ---
    outside = []
    for m in mounts:
        if m["类型"] in _PSEUDO_FS_TYPES:
            continue
        if m["类型"] in _OUTSIDE_FS:
            outside.append({**m, "含义": _OUTSIDE_FS[m["类型"]]})
        elif m["挂载点"] != "/" and m["类型"] not in ("ext4", "xfs", "btrfs", "overlay", "zfs", "apfs", "ntfs", "vfat", "exfat", "squashfs", "iso9660", "f2fs") \
                and not m["挂载点"].startswith(("/proc", "/sys", "/dev", "/run")):
            outside.append({**m, "含义": f"非本地磁盘类型 {m['类型']}，来源 {m['来源']}——可能触达当前系统之外"})

    # --- 宿主真实性：无法自证 ---
    unknowns.append("宿主真实性：来宾里的程序无法证明宿主是真的、没被动过（被篡改的宿主可以对来宾撒谎）。此项审查器无能为力，只能给你官方核对命令自己在宿主上跑。")

    location = (
        "容器内（套在虚拟机里）" if is_container and is_vm else
        "容器内" if is_container else
        "WSL 内（Windows 宿主的子系统）" if is_wsl else
        f"虚拟机内（{vendor or '厂商未知'}）" if is_vm else
        "物理机或未知（未见虚拟化信号）" if is_vm is False else "未知"
    )
    return {
        "操作系统": platform.system(), "内核": platform.release(), "主机名": platform.node(),
        "当前用户": user, "uid": uid, "是否root或管理员": is_admin, "用户目录": home,
        "位置判断": location,
        "是否虚拟机": is_vm, "虚拟机厂商": vendor,
        "是否容器": is_container, "是否WSL": is_wsl,
        "能触达外部的挂载": outside,
        "依据": evidence,
        "查不出的": unknowns,
        "红线": "以上只是我看到的信号，不是核实结论。",
        "官方核对命令(你自己在宿主上跑)": official_verification_commands(),
    }


def official_verification_commands() -> dict:
    return {
        "Windows 宿主（微软官方文档：Hyper-V 与 systeminfo）": [
            "systeminfo | findstr /i \"Hyper-V\"   —— 看 Hyper-V 要求那几行；宿主上会显示“已检测到虚拟机监控程序”",
            "Get-ComputerInfo | Select-Object HyperVisorPresent, CsManufacturer, CsModel   —— PowerShell，HyperVisorPresent 为 True 表示本机开着虚拟机监控器",
            "Get-VM   —— 以管理员身份在宿主 PowerShell 运行，列出本机 Hyper-V 里所有虚拟机（这才是确认“哪台是来宾”的正路）",
            "msinfo32   —— 系统信息 → 系统摘要，看“系统制造商 / 系统型号 / 已检测到虚拟机监控程序”",
            "Get-AuthenticodeSignature C:\\Windows\\System32\\vmms.exe   —— 检查 Hyper-V 管理服务的数字签名是否为 Microsoft Windows",
        ],
        "Linux 来宾（systemd / util-linux 官方工具）": [
            "systemd-detect-virt   —— 输出 microsoft / kvm / vmware / oracle / none",
            "lscpu | grep -i hypervisor",
            "sudo dmidecode -s system-manufacturer && sudo dmidecode -s system-product-name   —— 需要 root；审查器不代跑",
            "cat /proc/version   —— 含 microsoft 即 WSL",
        ],
        "macOS": [
            "sysctl -n machdep.cpu.features | grep -i vmm   —— 有 VMM 位表示在虚拟机里",
            "system_profiler SPHardwareDataType   —— 看型号标识符",
        ],
        "说明": "以上命令只读、无副作用。审查器不会替你运行它们；跑完把结果和我报出的信号对一对，不一致就以你在宿主上看到的为准。",
    }


def reachability(paths: list[str | Path]) -> list[dict]:
    """每个路径：存在？当前用户能读？能列目录？属主是谁？读不了的原因是什么。不绕过，只报。"""
    uid = os.getuid() if hasattr(os, "getuid") else None
    out: list[dict] = []
    for raw in paths:
        p = Path(raw)
        item: dict = {"路径": str(p), "存在": p.exists()}
        if not item["存在"]:
            item["可达"] = False
            item["原因"] = "路径不存在（可能已删除、挂载未就绪、或它在别的机器/容器上）"
            out.append(item)
            continue
        try:
            st = p.stat()
            owner_uid = getattr(st, "st_uid", None)
            item["属主uid"] = owner_uid
            item["属主是当前用户"] = (owner_uid == uid) if (uid is not None and owner_uid is not None) else None
        except OSError as e:
            item["属主uid"] = None
            item["stat失败"] = str(e)
        readable = os.access(p, os.R_OK)
        listable = os.access(p, os.R_OK | os.X_OK) if p.is_dir() else None
        item["可读"] = readable
        item["可列目录"] = listable
        item["可达"] = readable and (listable is not False)
        if not item["可达"]:
            if item.get("属主是当前用户") is False:
                item["原因"] = "属于其他用户，当前用户无读权限。这是别人的目录，审查器不帮绕过；要审它需要那个用户自己授权。"
            else:
                item["原因"] = "当前用户无读权限（可能需要管理员，审查器不提权；请你自己判断是否以管理员身份重新打开编辑器）。"
        out.append(item)
    return out


def authenticity_questions(env_info: dict, roots: list[str]) -> dict:
    """整盘前的反问：不先把环境甩给用户，而是请用户核对几件事并用确认词回答。"""
    reach = reachability(roots)
    return {
        "请你核对": [
            "1. 这台机器是你的吗？（不是公司的、不是借的、不是别人的服务器）",
            "2. 你是这台机器的管理员/root 吗？" + (f"（我看到当前用户 {env_info['当前用户']} " +
                                              ("是" if env_info["是否root或管理员"] else "不是" if env_info["是否root或管理员"] is False else "不确定是否") + "管理员）"),
            f"3. 你知道你现在在 {env_info['位置判断']} 吗？" +
            ("整盘扫的是这个虚拟机/容器的盘，不是宿主（你的笔记本）的盘。" if (env_info["是否虚拟机"] or env_info["是否容器"] or env_info["是否WSL"]) else ""),
            "4. 下面这些扫描根，当前用户能读到吗？读不到的我会如实跳过并计数，不会绕过。",
        ],
        "扫描根可达性": reach,
        "我看到的信号(供你核对，不是结论)": env_info["依据"],
        "我查不出的": env_info["查不出的"],
        "确认词": AUTHENTICITY_CONFIRM,
        "不确认的后果": "不扫整盘。你仍可用 review_scope 的 文件 / 文件夹 / 整仓 三种范围。",
    }
