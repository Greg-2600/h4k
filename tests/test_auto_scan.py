"""Tests for the passive auto-scan (live network map)."""

from contextlib import asynccontextmanager

import pytest


@pytest.fixture()
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("H4K_REFRESH_CVE", "0")
    monkeypatch.setenv("H4K_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("H4K_AUTO_SCAN", "0")  # do not kick off a real scan
    import app_state
    import main as main_module

    app_state.msf_client = None

    @asynccontextmanager
    async def _noop(_app):
        yield

    main_module.app.router.lifespan_context = _noop
    from fastapi.testclient import TestClient

    return TestClient(main_module.app)


def test_map_status_endpoint(client):
    r = client.get("/api/map/status")
    assert r.status_code == 200
    payload = r.json()
    assert "enabled" in payload
    assert "running" in payload


def test_map_endpoint_returns_hosts_list(client):
    r = client.get("/api/map")
    assert r.status_code == 200
    payload = r.json()
    assert isinstance(payload["hosts"], list)
    assert "status" in payload
    assert "host_count" in payload


def test_map_start_stop(client):
    r = client.post("/api/map/start")
    assert r.status_code == 200
    assert r.json()["running"] is True
    r = client.post("/api/map/stop")
    assert r.status_code == 200
    assert r.json()["running"] is False


def test_auto_scan_disabled_respects_env(monkeypatch):
    monkeypatch.setenv("H4K_AUTO_SCAN", "0")
    from services import auto_scan

    assert auto_scan.enabled() is False


def test_auto_scan_detects_a_cidr():
    from services import auto_scan

    cidr = auto_scan.detect_local_cidr()
    assert "/" in cidr
    assert len(cidr.split(".")) == 4


def test_run_one_pass_is_passive_first(monkeypatch, tmp_path):
    """_run_one_pass discovers hosts, fingerprints them, matches CVEs and
    ingests the result -- without touching credentials or exploitation."""
    import services.auto_scan as auto_scan_mod
    from services.discovery import Neighbor

    monkeypatch.setenv("H4K_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("H4K_SANDBOX", "1")

    # fake discovery
    class FakeFinder:
        def __init__(self, msf=None, interface=None):
            pass

        def discover(self, cidr):
            return [Neighbor(ip="10.10.10.5", mac="aa", hostname="web01")]

    monkeypatch.setattr("services.discovery.NeighborFinder", FakeFinder)

    # fake nmap output (open ssh + http)
    canned_xml = (
        '<?xml version="1.0"?><nmaprun><host starttime="0" endtime="1">'
        '<address addr="10.10.10.5" addrtype="ipv4"/>'
        '<ports><port protocol="tcp" portid="22"><state state="open"/>'
        '<service name="ssh" version="OpenSSH 9.2"/></port></ports></host></nmaprun>'
    )

    class FakeRunner:
        def run_tool(self, tool, argv, timeout=15):
            return {"status": "ok", "stdout": canned_xml, "stderr": "", "rc": 0}

    monkeypatch.setattr("services.toolkit.ToolkitRunner", lambda *a, **k: FakeRunner())

    # disable MSF
    import app_state

    app_state.msf_client = None

    summary = auto_scan_mod._run_one_pass("10.10.10.0/24", None)
    assert summary["hosts"] == 1
    assert summary["services"] >= 1


def test_run_one_pass_ingests_into_engagement(monkeypatch, tmp_path):
    import services.auto_scan as auto_scan_mod
    from services.discovery import Neighbor
    from services.engagement import EngagementStore

    monkeypatch.setenv("H4K_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("H4K_SANDBOX", "1")

    class FakeFinder:
        def __init__(self, msf=None, interface=None):
            pass

        def discover(self, cidr):
            return [Neighbor(ip="10.10.10.5", mac="aa", hostname="web01")]

    monkeypatch.setattr("services.discovery.NeighborFinder", FakeFinder)

    canned_xml = (
        '<?xml version="1.0"?><nmaprun><host starttime="0" endtime="1">'
        '<address addr="10.10.10.5" addrtype="ipv4"/>'
        '<ports><port protocol="tcp" portid="22"><state state="open"/>'
        '<service name="ssh" version="OpenSSH 9.2"/></port></ports></host></nmaprun>'
    )

    class FakeRunner:
        def run_tool(self, tool, argv, timeout=15):
            return {"status": "ok", "stdout": canned_xml, "stderr": "", "rc": 0}

    monkeypatch.setattr("services.toolkit.ToolkitRunner", lambda *a, **k: FakeRunner())

    import app_state

    app_state.msf_client = None

    store = EngagementStore()  # uses data_dir() -> tmp_path
    eng = store.create_engagement("auto-scan", ["10.10.10.0/24"])
    summary = auto_scan_mod._run_one_pass("10.10.10.0/24", eng["id"])
    assert summary["hosts"] == 1
    assets = store.assets(eng["id"])
    assert len(assets) == 1
    assert assets[0]["host"] == "10.10.10.5"
