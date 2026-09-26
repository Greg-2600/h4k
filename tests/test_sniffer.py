# Tests for the network-layer lab tooling. Every external binary is faked and
# the capture output dir is redirected to tmp_path, so nothing here touches a
# real interface, the system ARP cache, or monitor mode.
import subprocess
from pathlib import Path

import pytest
from services import sniffer


@pytest.fixture(autouse=True)
def _out_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(sniffer, "OUT_DIR", tmp_path / "captures")
    return tmp_path


def _stub_run(monkeypatch, result):
    calls = []

    def run(cmd, timeout=120):
        calls.append(cmd)
        return dict(result) if callable(result) is False else result

    monkeypatch.setattr(sniffer, "_run", run)
    return calls


# --- _run wrapper -----------------------------------------------------------


def test_run_captures_output(monkeypatch):
    class P:
        returncode = 0
        stdout = "out" * 5000
        stderr = "err" * 5000

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: P())
    r = sniffer._run(["x"])
    assert r["rc"] == 0
    assert len(r["stdout"]) == 4000  # truncated tail
    assert len(r["stderr"]) == 2000


def test_run_reports_missing_binary(monkeypatch):
    def boom(*a, **k):
        raise FileNotFoundError

    monkeypatch.setattr(subprocess, "run", boom)
    r = sniffer._run(["tcpdump"])
    assert r["rc"] == -1
    assert "not installed" in r["stderr"]


def test_run_reports_timeout(monkeypatch):
    def boom(*a, **k):
        raise subprocess.TimeoutExpired(cmd="x", timeout=1)

    monkeypatch.setattr(subprocess, "run", boom)
    r = sniffer._run(["x"])
    assert r["rc"] == -1
    assert r["stderr"] == "timed out"


def test_ensure_out_dir_creates(monkeypatch):
    d = sniffer._ensure_out_dir()
    assert d.exists()
    assert d.is_dir()


# --- interfaces -------------------------------------------------------------


def test_detect_interfaces_parses_ip_output(monkeypatch):
    monkeypatch.setattr(sniffer, "_which", lambda t: "/usr/sbin/ip")
    out = (
        "1: lo: <LOOPBACK> mtu 65536 state UNKNOWN\n"
        "2: eth0: <BROADCAST> mtu 1500 state UP\n"
    )
    _stub_run(monkeypatch, {"rc": 0, "stdout": out, "stderr": ""})
    ifaces = sniffer.detect_interfaces()
    assert [i["name"] for i in ifaces] == ["lo", "eth0"]


def test_detect_interfaces_empty_without_ip(monkeypatch):
    monkeypatch.setattr(sniffer, "_which", lambda t: None)
    assert sniffer.detect_interfaces() == []


# --- sniffing ---------------------------------------------------------------


def test_sniff_requires_tcpdump(monkeypatch):
    monkeypatch.setattr(sniffer, "_which", lambda t: None)
    r = sniffer.sniff_packets("eth0")
    assert r["ok"] is False
    assert "tcpdump" in r["error"]


@pytest.mark.parametrize("rc,expected", [(0, True), (1, True), (124, True), (2, False)])
def test_sniff_ok_codes(monkeypatch, rc, expected):
    monkeypatch.setattr(sniffer, "_which", lambda t: "/usr/bin/tcpdump")
    _stub_run(monkeypatch, {"rc": rc, "stdout": "", "stderr": ""})
    assert sniffer.sniff_packets("eth0")["ok"] is expected


def test_sniff_passes_interface_and_count(monkeypatch):
    monkeypatch.setattr(sniffer, "_which", lambda t: "/usr/bin/tcpdump")
    calls = _stub_run(monkeypatch, {"rc": 0, "stdout": "", "stderr": ""})
    sniffer.sniff_packets("wlan0", count=7)
    cmd = calls[0]
    assert "wlan0" in cmd and "7" in cmd


# --- arp --------------------------------------------------------------------


def test_arp_who_uses_arp_scan(monkeypatch):
    monkeypatch.setattr(sniffer, "_which", lambda t: "/usr/bin/arp-scan")
    calls = _stub_run(monkeypatch, {"rc": 0, "stdout": "found", "stderr": ""})
    r = sniffer.arp_who("eth0", count=4)
    assert r["ok"] is True
    assert "-I" in calls[0] and "eth0" in calls[0]


def test_arp_who_falls_back_with_hint(monkeypatch):
    monkeypatch.setattr(sniffer, "_which", lambda t: None)
    r = sniffer.arp_who("eth0")
    assert r["ok"] is False
    assert "neighbors" in r["hint"]


# --- mitm -------------------------------------------------------------------


def test_mitm_requires_bettercap(monkeypatch):
    monkeypatch.setattr(sniffer, "_which", lambda t: None)
    r = sniffer.mitm_arp_poison("eth0", "10.0.0.5")
    assert r["ok"] is False


def test_mitm_requires_target(monkeypatch):
    monkeypatch.setattr(sniffer, "_which", lambda t: "/usr/bin/bettercap")
    r = sniffer.mitm_arp_poison("eth0", "")
    assert r["ok"] is False
    assert "target" in r["error"]


def test_mitm_confines_arp_spoof_to_one_target(monkeypatch):
    """Safety: the eval string must scope arp.spoof to the single given target
    and turn it back off -- never a broadcast default."""
    monkeypatch.setattr(sniffer, "_which", lambda t: "/usr/bin/bettercap")
    calls = _stub_run(monkeypatch, {"rc": 0, "stdout": "", "stderr": ""})
    sniffer.mitm_arp_poison("eth0", "10.0.0.5", seconds=3)
    cmd = calls[0]
    assert "-no-http-server" in cmd and "-no-https-server" in cmd
    eval_str = cmd[cmd.index("-eval") + 1]
    assert "set arp.spoof.targets 10.0.0.5" in eval_str
    assert "arp.spoof off" in eval_str
    # only the caller's target appears
    assert eval_str.count("targets") == 1


# --- wifi -------------------------------------------------------------------


def test_wifi_scan_requires_airmon(monkeypatch):
    monkeypatch.setattr(sniffer, "_which", lambda t: None)
    r = sniffer.wifi_scan("wlan0")
    assert r["ok"] is False
    assert "airmon-ng" in r["error"]


def test_wifi_scan_stops_monitor_mode_when_airodump_missing(monkeypatch):
    monkeypatch.setattr(
        sniffer, "_which", lambda t: "/usr/sbin/airmon-ng" if t == "airmon-ng" else None
    )
    calls = _stub_run(monkeypatch, {"rc": 0, "stdout": "", "stderr": ""})
    r = sniffer.wifi_scan("wlan0")
    assert r["ok"] is False
    # must not leave the interface stuck in monitor mode
    assert any("stop" in c for c in calls)


def test_wifi_scan_reports_json(monkeypatch):
    monkeypatch.setattr(
        sniffer,
        "_which",
        lambda t: f"/usr/bin/{t}" if t in ("airmon-ng", "airodump-ng") else None,
    )

    def run(cmd, timeout=120):
        if any("airodump-ng" in c for c in cmd) and "-j" in cmd:
            # airodump writes <base>-01.json next to the requested base
            Path(cmd[cmd.index("-j") + 1] + "-01.json").write_text(
                "{}", encoding="utf-8"
            )
        return {"rc": 0, "stdout": "", "stderr": ""}

    monkeypatch.setattr(sniffer, "_run", run)
    r = sniffer.wifi_scan("wlan0")
    assert r["files"] and r["files"][0].endswith("wifi-scan-01.json")


def test_wifi_capture_requires_airodump(monkeypatch):
    monkeypatch.setattr(sniffer, "_which", lambda t: None)
    r = sniffer.wifi_capture("wlan0")
    assert r["ok"] is False


def test_wifi_capture_lists_capture_files(monkeypatch):
    monkeypatch.setattr(sniffer, "_which", lambda t: "/usr/bin/airodump-ng")

    def run(cmd, timeout=120):
        d = sniffer.OUT_DIR
        d.mkdir(parents=True, exist_ok=True)
        (d / "capture-01.cap").write_bytes(b"\x00")
        (d / "capture.txt").write_text("x", encoding="utf-8")
        return {"rc": 0, "stdout": "", "stderr": ""}

    monkeypatch.setattr(sniffer, "_run", run)
    r = sniffer.wifi_capture("wlan0", seconds=5, channel="11")
    assert r["ok"] is True
    # only real capture artifacts are offered
    assert all(f.endswith(".cap") for f in r["files"])


def test_wifi_capture_wraps_in_timeout(monkeypatch):
    monkeypatch.setattr(sniffer, "_which", lambda t: "/usr/bin/airodump-ng")
    calls = _stub_run(monkeypatch, {"rc": 0, "stdout": "", "stderr": ""})
    sniffer.wifi_capture("wlan0", seconds=4)
    assert calls[0][0] == "timeout"
    assert "4" in calls[0]
