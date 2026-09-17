# Tests for the opt-in network-layer/sniffer service (no live NIC needed).
from services.sniffer import _run, detect_interfaces, sniff_packets


# a fake env: monkeypatch _which so tools are "not found" -> graceful return
def test_sniff_returns_graceful_when_missing(monkeypatch):
    monkeypatch.setattr("services.sniffer._which", lambda t: None)
    r = sniff_packets("eth0")
    assert r.get("ok") is False
    assert "tcpdump" in (r.get("error") or "")


def test_detect_interfaces_returns_list(monkeypatch):
    # ip missing -> empty list, no crash
    monkeypatch.setattr("services.sniffer._which", lambda t: None)
    assert detect_interfaces() == []


def test_run_missing_cmd():
    r = _run(["definitely-not-a-real-command-xyz"], timeout=2)
    assert r["rc"] == -1
    assert "not installed" in r["stderr"]
