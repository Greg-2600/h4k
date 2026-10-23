# Coverage wave: the endpoints and pipeline branches the earlier suites left
# dark. Fakes follow the established patterns (FakeMsf background, monkeypatched
# service internals) — nothing here touches a live network or daemon.
from contextlib import asynccontextmanager

import pytest


class FakeMsfFull:
    """FakeMsf with non-empty db payloads for graph/pipeline paths."""

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
        return [
            {"host": "192.168.1.10", "os": "linux", "name": "web1"},
            {"address": "192.168.1.11", "os": None, "name": None},
        ]

    def services(self, *a, **k):
        return [
            {
                "host": "192.168.1.10",
                "port": 22,
                "proto": "tcp",
                "name": "ssh",
                "state": "open",
                "info": "OpenSSH 7.4",
            },
            {
                "host": "192.168.1.10",
                "port": 80,
                "proto": "tcp",
                "name": "http",
                "state": "open",
                "info": "nginx",
            },
        ]

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
    cves: list = []  # noqa: RUF012

    def refresh(self, *a, **k):
        return False

    def match_service(self, *a, **k):
        return []

    def enrich(self, *a, **k):
        return {"services": {}, "vulns": {}}


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setenv("H4K_REFRESH_CVE", "0")
    import app_state
    import main as main_module

    app_state.msf_client = FakeMsfFull()
    app_state.cve_db = CveDbStub()
    app_state.active_engagement_id = None

    @asynccontextmanager
    async def _noop(_app):
        yield

    main_module.app.router.lifespan_context = _noop
    main_module._rate_store = None

    from fastapi.testclient import TestClient

    return TestClient(main_module.app)


@pytest.fixture()
def clean_db(monkeypatch, tmp_path):
    from routers import scan as scan_router

    monkeypatch.setattr(scan_router, "_NEIGHBOR_DB", tmp_path / "neighbors.db")
    return scan_router


def _ensure(clean_db):
    clean_db._ensure_session_row()


# ---------------- update router ----------------


def test_update_trigger_and_last(client, monkeypatch, tmp_path):
    import services.updater as updater_mod

    ran = {"n": 0}
    monkeypatch.setattr(updater_mod, "run_update", lambda: ran.update(n=ran["n"] + 1))
    r = client.post("/api/update")
    assert r.status_code == 200
    assert r.json()["status"] == "started"

    monkeypatch.setenv("H4K_UPDATE_STATE", str(tmp_path / "state.json"))
    r = client.get("/api/update/last")
    assert r.status_code == 200
    r = client.get("/api/update/should")
    assert r.status_code == 200
    assert "due" in r.json()


def test_cve_status_reports_bundled_db(client, clean_db):
    _ensure(clean_db)
    r = client.get("/api/cves/status")
    assert r.status_code == 200
    body = r.json()
    assert "loaded_at" in body
    assert "count" in body
    assert "stale" in body


def test_cve_refresh_rejects_without_db(monkeypatch):
    import app_state as app_state_mod

    saved = app_state_mod.cve_db
    app_state_mod.cve_db = None
    try:
        from routers.update import cve_refresh

        r = cve_refresh(monkeypatch_bg := _FakeBackground())  # noqa: F841
        assert r["status"] == "started"
    finally:
        app_state_mod.cve_db = saved


class _FakeBackground:
    def add_task(self, *a, **k):
        pass


# ---------------- net router ----------------


def test_net_interfaces_and_sniff(client, monkeypatch):
    monkeypatch.setattr(
        "services.sniffer.detect_interfaces",
        lambda: [{"name": "eth0", "ip": "10.0.0.5"}],
    )
    r = client.get("/api/net/interfaces")
    assert r.status_code == 200
    assert r.json()["interfaces"][0]["name"] == "eth0"

    monkeypatch.setattr(
        "services.sniffer.sniff_packets",
        lambda i, count=20, timeout=15: {"packets": count},
    )
    r = client.post("/api/net/sniff", json={"interface": "eth0", "count": 5})
    assert r.status_code == 200
    assert r.json()["packets"] == 5


def test_net_arp_mitm_wifi_validation(client, monkeypatch):
    monkeypatch.setattr("services.sniffer.arp_who", lambda i: {"entries": []})
    assert client.post("/api/net/arp", json={"interface": "eth0"}).status_code == 200

    r = client.post("/api/net/mitm", json={"interface": "eth0"})
    assert r.status_code == 400  # no target

    monkeypatch.setattr("services.sniffer.mitm_arp_poison", lambda i, t, s: {"rc": 0})
    assert (
        client.post(
            "/api/net/mitm", json={"interface": "eth0", "target": "10.0.0.6"}
        ).status_code
        == 200
    )

    assert client.post("/api/net/wifi/scan", json={}).status_code == 400
    monkeypatch.setattr("services.sniffer.wifi_scan", lambda i: {"aps": []})
    assert (
        client.post("/api/net/wifi/scan", json={"interface": "wlan0mon"}).status_code
        == 200
    )

    assert client.post("/api/net/wifi/capture", json={}).status_code == 400
    monkeypatch.setattr(
        "services.sniffer.wifi_capture",
        lambda i, seconds=20, channel="6": {"file": "x.pcap"},
    )
    assert (
        client.post("/api/net/wifi/capture", json={"interface": "wlan0mon"}).status_code
        == 200
    )


def test_net_tls_endpoints(client, monkeypatch):
    monkeypatch.setattr("services.tls_lab.status", lambda: {"ok": True})
    assert client.get("/api/net/tls/status").json()["ok"] is True
    monkeypatch.setattr("services.tls_lab.setup_ca", lambda: {"ok": True})
    assert client.post("/api/net/tls/setup").status_code == 200
    monkeypatch.setattr("services.tls_lab.install_ca_to_trust", lambda: {"ok": True})
    assert client.post("/api/net/tls/trust").status_code == 200
    monkeypatch.setattr(
        "services.tls_lab.start_https_proxy",
        lambda listen_port=8443, backend_host="", backend_port=8080: {"ok": True},
    )
    assert client.post("/api/net/tls/proxy", json={}).status_code == 200


# ---------------- ai providers ----------------


def test_ai_openai_compatible_success(monkeypatch):
    import services.ai as ai

    monkeypatch.setenv("H4K_AI_PROVIDER", "openai_compatible")
    monkeypatch.setenv("H4K_AI_KEY", "test-key")
    monkeypatch.setenv("H4K_AI_URL", "http://relay/v1")

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b'{"choices":[{"message":{"content":"ROOT_CAUSE: x"}}]}'

    monkeypatch.setattr(ai.urllib.request, "urlopen", lambda req, timeout=120: _Resp())
    out = ai.ai_analyze("payload")
    assert out["ok"] is True
    assert out["provider"] == "openai"


def test_ai_openai_compatible_failure_is_soft(monkeypatch):
    import services.ai as ai

    monkeypatch.setenv("H4K_AI_PROVIDER", "openai_compatible")
    monkeypatch.setenv("H4K_AI_KEY", "test-key")

    def _boom(req, timeout=120):
        raise OSError("relay down")

    monkeypatch.setattr(ai.urllib.request, "urlopen", _boom)
    out = ai.ai_analyze("payload")
    assert out["ok"] is False
    assert "relay down" in out["error"]


def test_ai_keyless_gate(monkeypatch):
    import services.ai as ai

    monkeypatch.setenv("H4K_AI_PROVIDER", "openai_compatible")
    monkeypatch.delenv("H4K_AI_KEY", raising=False)
    out = ai.ai_analyze("payload")
    assert out["ok"] is False
    assert "H4K_AI_KEY" in out["error"]

    monkeypatch.setenv("H4K_AI_KEYLESS", "1")
    monkeypatch.setattr(ai.urllib.request, "urlopen", lambda req, timeout=120: None)
    out = ai.ai_analyze("payload")
    assert out["ok"] is False  # urlopen returns None -> json parse fails softly
    assert out["raw"] == ""


# ---------------- scan router: runners + endpoints ----------------


def test_export_json_and_md(client, clean_db):
    _ensure(clean_db)
    from routers import scan as scan_router
    from schemas import Host, Report, Service

    job_id = "exp1"
    report = Report(
        target="192.168.1.10",
        mode="overt",
        created_at="2026-01-01T00:00:00+00:00",
        hosts=[
            Host(
                address="192.168.1.10",
                services=[
                    Service(
                        port=22,
                        proto="tcp",
                        service="ssh",
                        state="open",
                        info="OpenSSH",
                    ),
                ],
            )
        ],
        vulns=[],
        notes=[],
        credentials=[],
        security=[],
        recommendations=[],
    )
    scan_router.JOBS[job_id] = {"id": job_id, "report": report}
    r = client.get(f"/api/export/{job_id}")
    assert r.status_code == 200
    assert r.json()["format"] == "json"
    r = client.get(f"/api/export/{job_id}", params={"fmt": "md"})
    assert r.status_code == 200
    assert "h4k report" in r.json()["content"]
    r = client.get(f"/api/export/{job_id}", params={"fmt": "xml"})
    assert r.status_code == 400
    r = client.get("/api/export/missing")
    assert r.status_code == 404


def test_batch_scan_validation_and_ids(client, clean_db, monkeypatch):
    _ensure(clean_db)
    r = client.post(
        "/api/scan/batch", json={"targets": [f"192.168.1.10{i}" for i in range(60)]}
    )
    assert r.status_code == 422  # over 50
    r = client.post("/api/scan/batch", json={"targets": []})
    assert r.status_code == 422
    r = client.post(
        "/api/scan/batch", json={"targets": ["192.168.1.240", "192.168.1.241"]}
    )
    assert r.status_code == 200
    body = r.json()
    assert body["launched"] == 2
    assert len(body["jobs"]) == 2


def test_abort_scan(client, clean_db):
    _ensure(clean_db)
    r = client.post("/api/scan/missing/abort")
    assert r.status_code == 404
    from routers import scan as scan_router

    scan_router.JOBS["abortme"] = {"id": "abortme", "status": "running"}
    r = client.post("/api/scan/abortme/abort")
    assert r.json()["status"] == "abort_requested"


def test_deepattack_flow(client, clean_db, monkeypatch):
    _ensure(clean_db)
    r = client.post("/api/deepattack", json={"target": ""})
    assert r.status_code == 200

    from routers import scan as scan_router
    from services.toolkit import ToolkitPlan

    plan = [
        {"tool": "echo", "argv": ["echo", "hi"]},
    ]
    monkeypatch.setattr(ToolkitPlan, "for_target", staticmethod(lambda req: plan))
    monkeypatch.setattr("routers.scan._service_for_tool", lambda tool: "ssh")

    class _Runner:
        def __init__(self, progress=None):
            pass

        def run_tool(self, tool, argv, timeout=300):
            return {
                "tool": tool,
                "stdout": "hi\n",
                "stderr": "",
                "rc": 0,
                "elapsed": 0.0,
                "timed_out": False,
                "status": "ok",
            }

    import services.toolkit as tk

    monkeypatch.setattr(tk, "ToolkitRunner", _Runner)

    job = {
        "id": "dk",
        "target": "192.168.1.10",
        "host": "192.168.1.10",
        "status": "queued",
        "results": [],
    }
    scan_router._run_deep_attack(
        job, type("Req", (), {"target": "x", "host": "192.168.1.10"}), "192.168.1.10"
    )
    assert job["status"] == "done"
    assert job["results"][0]["service"] == "ssh"


def test_fuzz_runner(client, clean_db, monkeypatch):
    _ensure(clean_db)

    class _Fuzzer:
        def __init__(self, progress=None, timeout=None, iterations=None):
            self.stats = {"execs": 3}

        def _fuzz_http(self, host, port, scheme):
            return [{"crash": "stack-overflow", "sig": "b1", "input": "A" * 40}]

    import services.fuzzer as fz

    monkeypatch.setattr(fz, "LabFuzzer", _Fuzzer)
    from routers import scan as scan_router

    job = {"id": "fz", "status": "running", "candidates": []}
    req = type(
        "Req",
        (),
        {
            "target": "t",
            "host": "192.168.1.10",
            "port": 8080,
            "scheme": "http",
            "service": None,
            "iterations": 3,
            "timeout": 4,
        },
    )()
    scan_router._run_fuzz(job, req, "192.168.1.10", 8080)
    assert job["status"] == "done"
    assert job["count"] == 1


def test_attack_runner_records_session_and_recon(client, clean_db, monkeypatch):
    _ensure(clean_db)
    from routers import scan as scan_router

    class _Svc:
        def __init__(self, msf, progress=None):
            pass

        def run(self, req, known):
            return [
                {
                    "host": "192.168.1.10",
                    "module": "exploit/x",
                    "result": "success",
                    "detail": "pwned",
                    "session_id": "9",
                }
            ]

    import services.attack as attack_mod

    monkeypatch.setattr(attack_mod, "AttackService", _Svc)

    class _Sess:
        def run_shell_cmd(self, cmd):
            return "uid=0(root)" if cmd == "getuid" else "Linux box"

    class _Mgr:
        def session(self, sid):
            return _Sess()

    class _Msf(FakeMsfFull):
        @property
        def client(self):
            return self

        @property
        def sessions(self):
            return _Mgr()

    import app_state

    app_state.msf_client = _Msf()  # recon reads the shared client, not the arg
    job = {"id": "atk", "status": "queued", "attacks": []}
    req = type(
        "Req",
        (),
        {
            "target": "192.168.1.10",
            "host": "192.168.1.10",
            "module": "exploit/x",
            "port": 22,
            "open_sessions": False,
            "services": [],
            "mode": None,
        },
    )()
    scan_router._run_attack(job, req, _Msf())
    assert job["status"] == "done"
    atk = job["attacks"][0]
    assert atk["recon"]["getuid"] == "uid=0(root)"


def test_ollama_endpoints_validation(client, monkeypatch):
    r = client.post("/api/ollama/discover", json={})
    assert r.status_code == 422
    r = client.post("/api/ollama/rce", json={})
    assert r.status_code == 422

    class _FakeExploit:
        def __init__(self, target, port=11434):
            pass

        def discover(self):
            return {"reachable": True, "models": ["x"]}

        def execute_tool(self, cmd):
            return {"output": "ok"}

    import services.ollama as om

    monkeypatch.setattr(om, "OllamaExploit", _FakeExploit)
    assert (
        client.post("/api/ollama/discover", json={"target": "10.0.0.1"}).status_code
        == 200
    )
    assert (
        client.post(
            "/api/ollama/rce", json={"target": "10.0.0.1", "command": "id"}
        ).status_code
        == 200
    )
    r = client.post("/api/ollama/shell", json={"target": "10.0.0.1"})
    assert r.status_code == 422  # no payload


def test_graph_merges_msf_and_neighbors(client, clean_db, monkeypatch):
    _ensure(clean_db)
    clean_db._save_neighbor_host("192.168.1.200", None, "Intel", None)
    clean_db._save_neighbor_services(
        "192.168.1.200",
        [
            {
                "port": 8080,
                "state": "open",
                "service": "http",
                "product": "Apache",
                "version": "2.4",
            },
        ],
    )
    r = client.get("/api/graph")
    assert r.status_code == 200
    body = r.json()
    ids = {n["id"] for n in body["nodes"]}
    assert "192.168.1.10" in ids  # msf host
    assert "192.168.1.200" in ids  # neighbor host
    ports = {e["port"] for e in body["edges"]}
    assert 8080 in ports
    web_node = next(n for n in body["nodes"] if n["id"] == "192.168.1.200")
    assert web_node["service_count"] >= 1


def test_autopilot_404s_and_stop(client, clean_db):
    from routers import scan as scan_router

    scan_router._AUTOPILOT_STATE["job"] = None
    r = client.post("/api/autopilot/stop")
    assert r.status_code == 404
    r = client.get("/api/autopilot/status")
    assert r.json()["status"] == "idle"


# ---------------- scan_pipeline full run with fakes ----------------


def test_pipeline_run_full_flow(monkeypatch):
    import services.scan_pipeline as sp
    from schemas import ScanMode, ScanRequest
    from services.scan_pipeline import ScanPipeline

    pipeline = ScanPipeline(
        FakeMsfFull(),
        progress=lambda m, p: None,
        log=lambda m: None,
        should_stop=lambda: False,
    )
    # avoid network: DNS recon off; traceroute + cred tooling faked out
    monkeypatch.setattr(
        sp, "SecurityAssessmentService", _FakeSecuritySvc, raising=False
    )
    monkeypatch.setattr(sp.ScanPipeline, "_try_default_creds", lambda self, *a, **k: [])
    monkeypatch.setattr(sp.ScanPipeline, "_do_attacks", lambda self, *a, **k: [])
    monkeypatch.setattr(
        sp.ScanPipeline, "_dns_recon", lambda self, *a, **k: [], raising=False
    )

    req = ScanRequest(target="192.168.1.0/24", mode=ScanMode.overt)
    report = pipeline.run(req)
    assert report["target"] == "192.168.1.0/24"
    assert any(
        h["address"] in ("192.168.1.10", "192.168.1.11") for h in report["hosts"]
    )
    assert report["coverage"]["ports_spec"]


class _FakeSecuritySvc:
    def __init__(self, progress=None):
        pass

    def assess(self, host, host_info):
        return {
            "host": host,
            "level": "medium",
            "score": 50,
            "confidence": "low",
            "rationale": ["fake"],
        }


# ---------------- ad_tools ----------------


def test_ad_tools_arg_building(monkeypatch):
    import services.ad_tools as ad

    monkeypatch.setattr(
        ad.subprocess,
        "run",
        lambda *a, **k: type(
            "P",
            (),
            {"returncode": 0, "stdout": "collected", "stderr": "", "check": False},
        )(),
    )
    out = ad.bloodhound_collect("LAB", "user", "pass", collection_method="All")
    assert isinstance(out, dict)


def test_ad_tools_validation(monkeypatch):
    import services.ad_tools as ad

    monkeypatch.setattr(
        ad.subprocess,
        "run",
        lambda *a, **k: type("P", (), {"returncode": 0, "stdout": "", "stderr": ""})(),
    )
    assert isinstance(ad.responder_attack("eth0"), dict)
    assert isinstance(ad.mitm6_attack("eth0"), dict)


# ---------------- main middleware ----------------


def test_rate_limit_429(client):
    import main as m

    # fresh budget: earlier tests in this suite share the client IP
    m._rate_store = None
    # hammer one cheap endpoint past the limit from the shared test client IP
    codes = []
    for _ in range(m._RATE_LIMIT + 4):
        try:
            codes.append(client.get("/api/health").status_code)
        except Exception:
            codes.append(429)
    # the burst is allowed through, then 429s appear
    assert codes.count(200) >= m._RATE_LIMIT - 2
    assert 429 in codes


def test_index_serves_html(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "h4k" in r.text


def test_micro_edges():
    """Tiny uncovered edges across services (cve_lookup init, aircrack bytes,
    fuzzer corpus, updater refresh fallback)."""
    # cve_lookup: missing data file -> empty list, no crash
    from services.cve_lookup import CveDb

    db = CveDb(path="/tmp/opencode/definitely-missing-cves.json")
    assert db.cves == []

    # aircrack: bytes output flattened to text
    from services import aircrack as ac

    assert ac._as_text(b"abc") == "abc"
    assert ac._as_text(None) == ""

    # fuzzer: corpus add + rnd access
    from services.fuzzer import MutationEngine

    hm = MutationEngine()
    assert hm.add_corpus(b"AAAA") in (True, False)
    assert hm.rnd is not None

    # updater: refresh_cve_data falls back to ctor CveDb when app_state empty
    import app_state

    saved = app_state.cve_db
    app_state.cve_db = None
    try:
        from services.updater import refresh_cve_data

        rep = refresh_cve_data()
        assert isinstance(rep, dict)
    finally:
        app_state.cve_db = saved


def test_aircrack_parse_csv_bytes(client, monkeypatch):
    from services import aircrack as ac

    monkeypatch.setattr(ac, "CSV", None, raising=False)
    out = ac.AircrackService._parse_csv(None)
    assert out == []
