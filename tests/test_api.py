# API-level tests using FastAPI TestClient with a mocked MSF backend.
# We drive the real router but stub the shared msf client so no live
# Metasploit daemon is required.
from contextlib import asynccontextmanager

import pytest


class FakeMsf:
    @property
    def client(self):
        return self

    @property
    def core(self):
        class _Core:
            @property
            def version(self):
                return {"version": "6.5.0", "ruby": "", "api": "1.0"}

        return _Core()

    def hosts(self, *a, **k):
        return []

    def services(self, *a, **k):
        return []

    def vulns(self, *a, **k):
        return []

    def jobs(self, *a, **k):
        return {}

    def sessions(self, *a, **k):
        return {}

    def current_workspace(self, *a, **k):
        return "default"

    def execute(self, *a, **k):
        return {}

    def analyze_host(self, *a, **k):
        return {"host": {"modules": []}}


class CveDbStub:
    def refresh(self, *a, **k):
        return False

    def enrich(self, hosts, vulns):
        return {"services": {}, "vulns": {}}


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setenv("H4K_REFRESH_CVE", "0")
    import app_state
    import main as main_module

    app_state.msf_client = FakeMsf()
    app_state.cve_db = CveDbStub()

    # neutralize the startup lifespan so it cannot overwrite our fake client
    @asynccontextmanager
    async def _noop(_app):
        yield

    main_module.app.router.lifespan_context = _noop

    from fastapi.testclient import TestClient

    return TestClient(main_module.app)


def test_health_reachable(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    payload = r.json()
    assert payload["msf"]["reachable"] is True


def test_scan_creates_job(client):
    r = client.post("/api/scan", json={"target": "192.168.1.248", "mode": "overt"})
    assert r.status_code == 200
    job = r.json()
    assert job["status"] == "queued"
    assert job["id"]


def test_scan_invalid_mode_400(client):
    r = client.post("/api/scan", json={"target": "x", "mode": "bogus"})
    assert r.status_code == 422


def test_job_not_found(client):
    r = client.get("/api/jobs/doesnotexist")
    assert r.status_code == 404


def test_report_not_ready(client):
    r = client.get("/api/report/doesnotexist")
    assert r.status_code == 404


def test_readme_renders(client):
    r = client.get("/readme")
    assert r.status_code == 200
    assert "PHrack" in r.text or "PHRACK" in r.text or "h4k" in r.text.lower()


# --- fuzz: iterations is wired end to end ------------------------------------


def test_fuzz_accepts_and_records_iterations(client):
    r = client.post("/api/fuzz", json={"target": "127.0.0.1", "iterations": 77})
    assert r.status_code == 200
    job = client.get(f"/api/fuzz/{r.json()['job_id']}").json()
    assert job["iterations"] == 77


def test_fuzz_defaults_iterations(client):
    r = client.post("/api/fuzz", json={"target": "127.0.0.1"})
    assert r.status_code == 200
    job = client.get(f"/api/fuzz/{r.json()['job_id']}").json()
    # A default of 1 request is not a fuzzing run; the default is a real
    # (still bounded) iteration count.
    assert job["iterations"] == 200


def test_fuzz_iterations_are_bounded(client):
    for bad in (0, -1, 200_001):
        r = client.post("/api/fuzz", json={"target": "127.0.0.1", "iterations": bad})
        assert r.status_code == 422, bad


def test_fuzz_request_bounds_at_the_schema_level():
    """Checked on the model, not the endpoint, so no requests are sent."""
    from pydantic import ValidationError
    from schemas import FuzzRequest

    assert FuzzRequest(target="h", iterations=200_000).iterations == 200_000
    assert FuzzRequest(target="h").iterations == 200
    for bad in (0, -5, 200_001, 10**9):
        with pytest.raises(ValidationError):
            FuzzRequest(target="h", iterations=bad)
    for bad_timeout in (0, -1, 61, 1000):
        with pytest.raises(ValidationError):
            FuzzRequest(target="h", timeout=bad_timeout)


# --- CTF/lab toolkit endpoints ----------------------------------------------


def test_container_escape_endpoint(client):
    r = client.post("/api/container_escape")
    assert r.status_code == 200
    d = r.json()
    assert "vectors" in d and "dangerous_caps" in d


def test_lateral_endpoint(client):
    r = client.post("/api/lateral", json={"cidr": "10.0.0.0/24"})
    assert r.status_code == 200
    assert r.json()["cidr"] == "10.0.0.0/24"


def test_db_interrogate_endpoint(client, monkeypatch):
    import services.db_interrogate as dbi

    monkeypatch.setattr(
        dbi.DBInterrogate,
        "interrogate_all",
        lambda self, target="127.0.0.1": {"target": target},
    )
    r = client.post("/api/db_interrogate", json={"target": "127.0.0.1"})
    assert r.status_code == 200
    assert r.json()["target"] == "127.0.0.1"


def test_john_endpoint(client, monkeypatch):
    import services.john as john

    monkeypatch.setattr(
        john.JohnRunner,
        "crack_ctf_hashes",
        lambda self, hashes, **k: {
            "total": 1,
            "cracked": [{"hash": "h", "password": "pw"}],
        },
    )
    r = client.post("/api/john", json={"hashes": ["h"]})
    assert r.status_code == 200
    assert r.json()["cracked"][0]["password"] == "pw"


def test_tshark_pcap_requires_file(client):
    r = client.post("/api/tshark/pcap", json={})
    assert r.status_code == 400


def test_tshark_live_requires_interface(client):
    r = client.post("/api/tshark/live", json={"duration": 1})
    assert r.status_code == 400


def test_tshark_pcap_endpoint(client, monkeypatch):
    import services.tshark as tshark

    monkeypatch.setattr(
        tshark.TsharkRunner,
        "full_pcap_analysis",
        lambda self, pcap: {"file": pcap, "stats": "S"},
    )
    r = client.post("/api/tshark/pcap", json={"pcap_file": "x.pcap"})
    assert r.status_code == 200
    assert r.json()["stats"] == "S"


def test_nmap_nse_endpoint(client, monkeypatch):
    import services.toolkit as toolkit

    monkeypatch.setattr(
        toolkit.ToolkitRunner,
        "run_tool",
        lambda self, tool, argv, timeout=300: {"tool": tool, "stdout": "22/tcp open"},
    )
    r = client.post("/api/nmap/nse", json={"target": "192.168.1.13"})
    assert r.status_code == 200
    assert r.json()["tool"]["stdout"].startswith("22")


def test_zap_endpoint(client, monkeypatch):
    import services.zap as zap

    monkeypatch.setattr(
        zap,
        "zap_scan",
        lambda target, mode="full", **k: {"target": target, "alert_count": 0},
    )
    r = client.post("/api/zap", json={"target": "http://127.0.0.1:8080"})
    assert r.status_code == 200
    assert r.json()["target"].endswith("8080")


def test_aircrack_endpoint(client, monkeypatch):
    import services.aircrack as aircrack

    monkeypatch.setattr(
        aircrack.AircrackRunner,
        "full_wpa_assessment",
        lambda self, interface, *a, **k: {"interface": interface, "networks": []},
    )
    r = client.post("/api/aircrack", json={"interface": "wlan0"})
    assert r.status_code == 200
    assert r.json()["interface"] == "wlan0"


def test_fuzz_job_reports_dedup_counts_not_raw_crash_count(client, monkeypatch):
    from services.fuzzer import LabFuzzer

    trace = (
        "==1==ERROR: AddressSanitizer: stack-buffer-overflow\n"
        "    #0 0x7f1 in parse_header /src/v.c:47:10"
    )
    calls = {"n": 0}

    def fake_send(self, host, port, vector):
        calls["n"] += 1
        return (trace, 0, 0.001) if calls["n"] > 1 else ("HTTP/1.1 200 OK", 0, 0.001)

    monkeypatch.setattr(LabFuzzer, "_probe_http", lambda self, url: True)
    monkeypatch.setattr(LabFuzzer, "_send_http", fake_send)

    job_id = client.post(
        "/api/fuzz", json={"target": "127.0.0.1", "iterations": 12}
    ).json()["job_id"]

    for _ in range(60):
        job = client.get(f"/api/fuzz/{job_id}").json()
        if job["status"] in ("done", "error"):
            break
    assert job["status"] == "done"
    # 11 crashing inputs, all the same bug -> one candidate row.
    assert job["count"] == 1
    assert job["stats"]["crashes"]["unique_crashes"] == 1
    assert job["stats"]["crashes"]["total_occurrences"] >= 10
    assert job["stats"]["coverage_guided"] is False
    assert job["candidates"][0]["confirmed"] is True
    assert job["candidates"][0]["occurrences"] >= 10
