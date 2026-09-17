"""环境真实性探测与路径类型解释：只读、只报信号、不谎称核实、判断不了就说判断不了。"""
from __future__ import annotations

import os
from pathlib import Path

from servers.file_reviewer import environment as env
from servers.file_reviewer import path_kind as pk


def _fake_proc(tmp_path: Path, *, cpuinfo="", version="Linux version 6.1", cgroup="0::/", mountinfo="") -> Path:
    proc = tmp_path / "proc"
    (proc / "1").mkdir(parents=True)
    (proc / "self").mkdir()
    (proc / "cpuinfo").write_text(cpuinfo, encoding="utf-8")
    (proc / "version").write_text(version, encoding="utf-8")
    (proc / "1" / "cgroup").write_text(cgroup, encoding="utf-8")
    (proc / "self" / "mountinfo").write_text(mountinfo, encoding="utf-8")
    return proc


def test_physical_machine_no_signals(tmp_path: Path):
    proc = _fake_proc(tmp_path, cpuinfo="flags : fpu vme sse", mountinfo="1 0 8:1 / / rw - ext4 /dev/sda1 rw\n")
    dmi = tmp_path / "dmi"; dmi.mkdir()
    (dmi / "sys_vendor").write_text("LENOVO", encoding="utf-8")
    (dmi / "product_name").write_text("20XW", encoding="utf-8")
    r = env.detect_environment(proc, dmi, env={"HOME": str(tmp_path)})
    assert r["是否虚拟机"] is False and r["是否容器"] is False and r["是否WSL"] is False
    assert r["虚拟机厂商"] is None
    assert r["位置判断"].startswith("物理机或未知")
    assert any("宿主真实性" in u for u in r["查不出的"]), "永远要说明宿主真实性无法自证"
    assert "不是核实结论" in r["红线"]
    assert "Windows 宿主" in " ".join(r["官方核对命令(你自己在宿主上跑)"].keys())


def test_hyperv_guest_by_dmi(tmp_path: Path):
    proc = _fake_proc(tmp_path, cpuinfo="flags : fpu hypervisor sse")
    dmi = tmp_path / "dmi"; dmi.mkdir()
    (dmi / "sys_vendor").write_text("Microsoft Corporation", encoding="utf-8")
    (dmi / "product_name").write_text("Virtual Machine", encoding="utf-8")
    r = env.detect_environment(proc, dmi, env={"HOME": str(tmp_path)})
    assert r["是否虚拟机"] is True and r["虚拟机厂商"] == "Hyper-V（微软）"
    assert "虚拟机内（Hyper-V（微软））" == r["位置判断"]
    assert any("hypervisor" in e for e in r["依据"])


def test_vm_with_unknown_vendor_says_unknown(tmp_path: Path):
    """像这台云机器：有 hypervisor 位、没有 DMI、套容器——厂商必须写“查不出”，不猜。"""
    proc = _fake_proc(tmp_path, cpuinfo="flags : hypervisor", cgroup="0::/system.slice/pod-abc",
                      mountinfo="1 0 0:1 / / rw - overlay overlay rw\n2 1 0:2 / /cursor/stores rw - fuse.sshfs remote:/x rw\n")
    r = env.detect_environment(proc, tmp_path / "no-dmi", env={"HOME": str(tmp_path)})
    assert r["是否虚拟机"] is True and r["虚拟机厂商"] is None
    assert r["是否容器"] is True
    assert r["位置判断"] == "容器内（套在虚拟机里）"
    assert any("厂商查不出" in u for u in r["查不出的"])
    assert r["能触达外部的挂载"] and r["能触达外部的挂载"][0]["挂载点"] == "/cursor/stores"
    assert "sshfs" in r["能触达外部的挂载"][0]["含义"]


def test_wsl_detected(tmp_path: Path):
    proc = _fake_proc(tmp_path, cpuinfo="flags : hypervisor", version="Linux version 5.15.0-microsoft-standard-WSL2",
                      mountinfo="1 0 0:1 / / rw - ext4 /dev/sdc rw\n2 1 0:2 / /mnt/c rw - 9p C:\\134 rw\n")
    r = env.detect_environment(proc, tmp_path / "no-dmi", env={"HOME": str(tmp_path), "WSL_DISTRO_NAME": "Ubuntu"})
    assert r["是否WSL"] is True
    assert r["位置判断"].startswith("WSL 内")
    assert any(m["挂载点"] == "/mnt/c" for m in r["能触达外部的挂载"])


def test_reachability_reports_reason_and_never_bypasses(tmp_path: Path):
    ok = tmp_path / "ok.txt"; ok.write_text("x", encoding="utf-8")
    missing = tmp_path / "nope"
    locked = tmp_path / "locked"; locked.mkdir(); (locked / "f").write_text("x", encoding="utf-8")
    locked.chmod(0o000)
    try:
        r = {x["路径"]: x for x in env.reachability([ok, missing, locked])}
        assert r[str(ok)]["可达"] is True
        assert r[str(missing)]["可达"] is False and "不存在" in r[str(missing)]["原因"]
        if os.geteuid() != 0:
            assert r[str(locked)]["可达"] is False and "不提权" in r[str(locked)]["原因"]
    finally:
        locked.chmod(0o755)


def test_authenticity_questions_ask_before_telling(tmp_path: Path):
    proc = _fake_proc(tmp_path, cpuinfo="flags : hypervisor")
    info = env.detect_environment(proc, tmp_path / "no-dmi", env={"HOME": str(tmp_path)})
    q = env.authenticity_questions(info, [str(tmp_path)])
    assert q["确认词"] == env.AUTHENTICITY_CONFIRM
    assert any("这台机器是你的吗" in x for x in q["请你核对"])
    assert any("不是宿主" in x for x in q["请你核对"]), "在虚拟机里要明说整盘不是宿主的盘"
    assert "不扫整盘" in q["不确认的后果"]


# ---------------- 路径类型 ----------------

def test_classify_github_repo_with_cloudflare_deploy(risky_repo: Path):
    (risky_repo / ".git" / "config").write_text(
        '[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n\turl = git@github.com:someone/demo.git\n', encoding="utf-8")
    (risky_repo / "wrangler.toml").write_text('name = "demo"\n', encoding="utf-8")
    info = {"用户目录": str(risky_repo.parent), "位置判断": "物理机或未知（未见虚拟化信号）", "是否虚拟机": False}
    r = pk.classify_path(risky_repo / "src" / "app.py", info, findings_count=5, language="python")
    assert r["仓库/平台"] == "GitHub（微软）"
    assert any("远程托管在 GitHub" in x for x in r["这是什么地方"])
    assert any("Cloudflare" in x for x in r["这是什么地方"])
    assert any("你的用户目录" in x for x in r["这是什么地方"])
    assert r["文件名中文含义"] == "Python 源码"
    assert r["当前用户可达"] is True
    assert r["内容解释"] == "python，本次审查命中 5 条发现"
    assert "复制到文件管理器地址栏" in r["如何到达"]
    assert not any("sudo" in str(v) or "chmod" in str(v) for v in r["如何到达"].values()), "如何到达里不得含提权"


def test_classify_hidden_ai_config_dir_and_unknown(tmp_path: Path):
    grok = tmp_path / "home" / "me" / ".grok" / "settings.json"
    grok.parent.mkdir(parents=True); grok.write_text("{}", encoding="utf-8")
    info = {"用户目录": str(tmp_path / "home" / "me"), "位置判断": "虚拟机内（Hyper-V（微软））", "是否虚拟机": True}
    r = pk.classify_path(grok, info)
    assert "Grok 助手的配置目录" in r["文件名中文含义"]
    assert any("虚拟机的盘是宿主上的一个大文件" in x for x in r["这是什么地方"])
    assert "为什么你在文件管理器里看不到它" in r["如何到达"]
    assert r["仓库/平台"] is None

    lonely = tmp_path / "elsewhere" / "thing.xyz"
    lonely.parent.mkdir(); lonely.write_text("x", encoding="utf-8")
    r2 = pk.classify_path(lonely, {"用户目录": str(tmp_path / "home" / "me")})
    assert any(x.startswith("判断不了") for x in r2["这是什么地方"])
    assert "不猜" in r2["文件名中文含义"]


def test_classify_unreachable_stops(tmp_path: Path):
    r = pk.classify_path(tmp_path / "ghost.py", {"用户目录": str(tmp_path)})
    assert r["当前用户可达"] is False and "不存在" in r["不可达原因"]
    assert "停在这里" in r["如何到达"] and "不提权、不绕过" in r["如何到达"]["停在这里"]


def test_explain_paths_tool_writes_report_section(isolated_dirs, risky_repo: Path):
    s = isolated_dirs["server"]
    r = s.review_open(str(risky_repo))
    assert "环境来源" in r and "仓库位置说明" in r
    s.review_scan()
    ex = s.review_explain_paths()
    assert ex["说明"] and all("这是什么地方" in n for n in ex["说明"])
    text = Path(ex["报告"]["报告路径"]).read_text(encoding="utf-8")
    assert "## 路径与位置说明" in text and "## 环境来源（只是信号，不是核实结论）" in text
    ex2 = s.review_explain_paths([str(risky_repo / ".cursor" / "mcp.json"), "/definitely/not/here"])
    kinds = {n["路径"]: n for n in ex2["说明"]}
    assert "MCP 服务器配置" in kinds[str(risky_repo / ".cursor" / "mcp.json")]["文件名中文含义"]
    assert kinds["/definitely/not/here"]["当前用户可达"] is False
