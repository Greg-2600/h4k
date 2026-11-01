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


# ---------- job monitor: the UI must be able to enumerate running jobs ----------

JOBS_ENV = [
    "JOBS",
    "_attack_jobs",
    "_toolkit_jobs",
    "_fuzz_jobs",
    "_neighbor_jobs",
    "_fingerprint_jobs",
    "_passattack_jobs",
    "_cfuzz_jobs",
]


@pytest.fixture()
def job_stores(monkeypatch):
    """Isolated job dicts per test so counts never leak between tests."""
    from routers import scan as scan_router

    stores = {}
    for name in JOBS_ENV:
        store: dict = {}
        monkeypatch.setattr(scan_router, name, store)
        stores[name] = store
    return stores


def test_jobs_lists_every_family(client, job_stores):
    job_stores["JOBS"]["s1"] = {
        "id": "s1",
        "status": "running",
        "progress": 40.0,
        "target": "10.0.0.5",
    }
    job_stores["_attack_jobs"]["a1"] = {
        "id": "a1",
        "status": "queued",
        "target": "10.0.0.5",
    }
    job_stores["_toolkit_jobs"]["d1"] = {
        "id": "d1",
        "status": "running",
        "target": "10.0.0.5",
    }
    job_stores["_fuzz_jobs"]["f1"] = {
        "id": "f1",
        "status": "done",
        "target": "10.0.0.5",
    }
    job_stores["_neighbor_jobs"]["n1"] = {
        "id": "n1",
        "status": "done",
        "target": "10.0.0.0/24",
    }
    job_stores["_fingerprint_jobs"]["fp1"] = {
        "id": "fp1",
        "status": "done",
    }
    job_stores["_passattack_jobs"]["p1"] = {
        "id": "p1",
        "status": "running",
        "host": "10.0.0.5",
    }
    job_stores["_cfuzz_jobs"]["c1"] = {
        "id": "c1",
        "status": "done",
    }
    r = client.get("/api/jobs")
    assert r.status_code == 200
    payload = r.json()
    by_id = {j["id"]: j for j in payload["jobs"]}
    assert set(by_id) == {"s1", "a1", "d1", "f1", "n1", "fp1", "p1", "c1"}
    assert by_id["d1"]["type"] == "deepattack"
    assert by_id["f1"]["type"] == "fuzz"
    assert by_id["a1"]["type"] == "attack"
    assert by_id["n1"]["type"] == "neighbors"
    assert by_id["fp1"]["type"] == "fingerprint"
    assert by_id["p1"]["type"] == "passattack"
    assert by_id["c1"]["type"] == "container_fuzz"
    assert payload["total"] == 8
    # single-job lookup falls through to the other families too
    assert client.get("/api/jobs/n1").json()["id"] == "n1"
    assert client.get("/api/jobs/nope").status_code == 404
    assert payload["active"] == 4  # s1, a1, d1, p1 are still in flight


def test_scan_job_carries_its_target_for_the_monitor(client, job_stores, monkeypatch):
    """A scan's report is null until it finishes, so the monitor's target
    column has to come from the job itself, not the report."""
    job_stores["JOBS"]["s1"] = {
        "id": "s1",
        "status": "running",
        "progress": 10.0,
        "target": "10.0.0.5",
    }
    r = client.get("/api/jobs?active=true")
    assert r.status_code == 200
    job = next(j for j in r.json()["jobs"] if j["id"] == "s1")
    assert job["target"] == "10.0.0.5"


def test_post_scan_returns_target(client, job_stores, monkeypatch):
    """The created job must name its target even before any report exists."""
    from routers import scan as scan_router

    monkeypatch.setattr(scan_router, "_pull_cached", lambda req: None)
    monkeypatch.setattr(scan_router, "_run_scan", lambda job, req: None)
    r = client.post("/api/scan", json={"target": "10.0.0.5", "mode": "overt"})
    assert r.status_code == 200
    assert r.json()["target"] == "10.0.0.5"
    listed = client.get("/api/jobs?active=true").json()["jobs"]
    assert listed[0]["target"] == "10.0.0.5"


def test_jobs_active_filter_hides_terminal(client, job_stores):
    job_stores["JOBS"]["done1"] = {"id": "done1", "status": "done"}
    job_stores["JOBS"]["err1"] = {"id": "err1", "status": "error"}
    job_stores["JOBS"]["abort1"] = {"id": "abort1", "status": "aborted"}
    job_stores["_toolkit_jobs"]["run1"] = {"id": "run1", "status": "running"}
    job_stores["_toolkit_jobs"]["queued1"] = {"id": "queued1", "status": "queued"}
    job_stores["_attack_jobs"]["abortreq"] = {
        "id": "abortreq",
        "status": "abort_requested",
    }
    r = client.get("/api/jobs?active=true")
    assert r.status_code == 200
    assert {j["id"] for j in r.json()["jobs"]} == {"run1", "queued1", "abortreq"}
    assert r.json()["active"] == 3


def test_jobs_progress_unknown_is_none_not_zero(client, job_stores):
    """A hydra run has no meaningful percentage; 0% would read as stalled."""
    job_stores["_toolkit_jobs"]["d1"] = {"id": "d1", "status": "running"}
    r = client.get("/api/jobs")
    job = r.json()["jobs"][0]
    assert job["progress"] is None
    assert job["status"] == "running"


def test_jobs_sorted_newest_first(client, job_stores):
    job_stores["JOBS"]["old"] = {
        "id": "old",
        "status": "done",
        "created": "2024-01-01T00:00:00+00:00",
    }
    job_stores["JOBS"]["new"] = {
        "id": "new",
        "status": "done",
        "created": "2025-01-01T00:00:00+00:00",
    }
    assert [j["id"] for j in client.get("/api/jobs").json()["jobs"]] == ["new", "old"]


def test_jobs_limit(client, job_stores):
    for i in range(12):
        job_stores["JOBS"][f"j{i}"] = {
            "id": f"j{i}",
            "status": "running",
            "created": f"2025-01-{i + 1:02d}T00:00:00+00:00",
        }
    assert len(client.get("/api/jobs?limit=5").json()["jobs"]) == 5
    # total/active report the true counts, not the truncated page
    assert client.get("/api/jobs?limit=5").json()["total"] == 12


def test_job_detail_includes_log_and_created(client, job_stores):
    """The log tail was dead code because response_model filtering dropped it."""
    job_stores["JOBS"]["s1"] = {
        "id": "s1",
        "status": "running",
        "progress": 10.0,
        "log": ["recon started", "1 host"],
        "created": "2025-01-01T00:00:00+00:00",
        "updated": "2025-01-01T00:00:05+00:00",
    }
    body = client.get("/api/jobs/s1").json()
    assert body["log"] == ["recon started", "1 host"]
    assert body["created"] == "2025-01-01T00:00:00+00:00"
    assert body["updated"] == "2025-01-01T00:00:05+00:00"


def test_health_counts_active_jobs_across_families(client, job_stores):
    job_stores["_toolkit_jobs"]["d1"] = {"id": "d1", "status": "running"}
    body = client.get("/api/health").json()
    assert body["active_jobs"] == 1


def test_deepattack_marks_running_before_first_tool_finishes(job_stores, monkeypatch):
    """A hydra sweep runs for minutes; the job must not read 'queued' throughout."""
    from routers import scan as scan_router
    from schemas import DeepAttackRequest

    seen: list[str] = []
    monkeypatch.setattr(
        scan_router, "_service_for_tool", lambda tool: "ssh", raising=True
    )

    class SlowRunner:
        def __init__(self, progress=None):
            pass

        def run_tool(self, tool, argv):
            # the monitor polls mid-sweep: this is the state it must observe
            seen.append(scan_router._toolkit_jobs["d1"]["status"])
            return {"tool": tool, "rc": 0, "stdout": ""}

    import services.toolkit as toolkit_mod

    monkeypatch.setattr(toolkit_mod, "ToolkitRunner", SlowRunner)
    job = {"id": "d1", "status": "queued", "results": []}
    scan_router._toolkit_jobs["d1"] = job
    scan_router._run_deep_attack(job, DeepAttackRequest(target="10.0.0.5"), "10.0.0.5")
    assert seen, "expected at least one toolkit step"
    assert set(seen) == {"running"}
    assert job["status"] == "done"
    assert len(job["results"]) == len(seen)


def test_deepattack_failure_does_not_hang_running(job_stores, monkeypatch):
    """A crashed sweep used to stay 'running' forever in the monitor."""
    from routers import scan as scan_router
    from schemas import DeepAttackRequest

    class BoomRunner:
        def __init__(self, progress=None):
            pass

        def run_tool(self, tool, argv):
            raise RuntimeError("hydra exploded")

    import services.toolkit as toolkit_mod

    monkeypatch.setattr(toolkit_mod, "ToolkitRunner", BoomRunner)
    job = {"id": "d1", "status": "queued", "results": []}
    scan_router._toolkit_jobs["d1"] = job
    scan_router._run_deep_attack(job, DeepAttackRequest(target="10.0.0.5"), "10.0.0.5")
    assert job["status"] == "error"
    assert "hydra exploded" in job["error"]
    assert "hydra exploded" not in {
        j["id"] for j in scan_router._all_jobs(active_only=True)
    }


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


def test_nikto_endpoint(client, monkeypatch):
    import services.toolkit as toolkit

    seen = {}

    def _fake_nikto(self, tool, argv, timeout=300):
        seen["argv"] = argv
        return {"tool": tool, "stdout": "+ /admin: 200"}

    monkeypatch.setattr(toolkit.ToolkitRunner, "run_tool", _fake_nikto)
    r = client.post("/api/nikto", json={"target": "http://192.168.1.13"})
    assert r.status_code == 200
    assert r.json()["tool"]["stdout"].startswith("+ /admin")
    assert "-host" in seen["argv"] and "-maxtime" in seen["argv"]
    r = client.post("/api/nikto", json={"target": "  "})
    assert r.status_code == 400


def test_gobuster_endpoint(client, monkeypatch):
    import services.toolkit as toolkit

    seen = {}

    def _fake_gobuster(self, tool, argv, timeout=300):
        seen["argv"] = argv
        return {"tool": tool, "stdout": "/login (Status: 200)"}

    monkeypatch.setattr(toolkit.ToolkitRunner, "run_tool", _fake_gobuster)
    r = client.post(
        "/api/gobuster",
        json={"target": "http://192.168.1.13", "extensions": "php,html"},
    )
    assert r.status_code == 200
    assert r.json()["tool"]["stdout"].startswith("/login")
    assert "dir" in seen["argv"] and "-x" in seen["argv"]
    r = client.post("/api/gobuster", json={"target": "http://x", "mode": "bogus"})
    assert r.status_code == 400
    r = client.post("/api/gobuster", json={"target": "  "})
    assert r.status_code == 400
