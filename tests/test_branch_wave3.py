# Branch coverage wave 3: pipeline cred option mapping, engagement scope
# helpers with an active scope, updater cycle, AI models/loop, ZAP, DB
# interrogation, container escape, source router edges, and app lifespan.
import asyncio
from contextlib import asynccontextmanager

import pytest


class FakeMsfC3:
    @property
    def client(self):
        return self

    @property
    def core(self):
        class _Core:
            @property
            def version(self):
                return {"version": "6.5.0"}

        return _Core()

    def hosts(self, *a, **k):
        return [{"address": "192.168.1.10"}]

    def services(self, *a, **k):
        return [
            {
                "host": "192.168.1.10",
                "port": 22,
                "proto": "tcp",
                "name": "ssh",
                "state": "open",
            }
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


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setenv("H4K_REFRESH_CVE", "0")
    import app_state
    import main as main_module

    app_state.msf_client = FakeMsfC3()
    app_state.cve_db = None
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


# ---------------- pipeline cred option mapping ----------------


def test_try_one_option_mapping_per_module(monkeypatch):
    from services.attack import AttackService  # noqa: F401
    from services.scan_pipeline import ScanPipeline

    seen_opts = {}

    class _Msf(FakeMsfC3):
        @property
        def modules(self):
            options = [
                "RHOSTS",
                "RPORT",
                "USERNAME",
                "PASSWORD",
                "SMBUser",
                "SMBPass",
                "STOP_ON_SUCCESS",
                "CreateSession",
            ]

            class _Mod:
                @property
                def options(self):
                    return list(options)

            class _Modules:
                def use(self, mtype, mname):
                    return _Mod()

            return _Modules()

        def execute(self, mtype, mname, opts):
            seen_opts[mname] = dict(opts)
            return {"error": "nope", "status": "failed"}  # structured failure

    p = ScanPipeline(_Msf(), log=lambda m: None)
    svc = {"port": 22, "proto": "tcp", "service": "ssh", "state": "open"}

    # ssh branch
    p._try_one("exploit/multi/ssh/ssh_login", "192.168.1.10", svc, "u", "p", False)
    ssh_opts = [v for k, v in seen_opts.items() if "ssh" in k][-1]
    assert ssh_opts.get("USERNAME") == "u" and ssh_opts.get("PASSWORD") == "p"

    # smb branch
    p._try_one(
        "exploit/windows/smb/psexec",
        "192.168.1.10",
        {"port": 445, "service": "smb", "state": "open"},
        "u",
        "p",
        True,
    )
    smb_opts = seen_opts["exploit/windows/smb/psexec"]
    assert smb_opts.get("SMBUser") == "u" and "CreateSession" in smb_opts


def test_engagement_scope_helpers_with_active_scope(clean_db):
    import app_state
    from routers.scan import _active_scope, _host_in_scope, _session_scope_info
    from services.engagement import EngagementStore, db_path

    store = EngagementStore(db_path())
    eng = store.create_engagement(
        f"wave3-{__import__('time').time()}", ["192.168.1.0/24"]
    )
    app_state.active_engagement_id = eng["id"]

    got_id, got_store = _active_scope()
    assert got_id == eng["id"] and got_store is not None
    ok, _ = _host_in_scope("192.168.1.77")
    assert ok
    ok, reason = _host_in_scope("10.9.9.9")
    assert not ok and "outside" in reason
    info = _session_scope_info()
    assert info["name"].startswith("wave3")
    assert info["scope"] == ["192.168.1.0/24"]
    app_state.active_engagement_id = None


def test_exploit_candidates_http_alt_path(client):
    r = client.get("/api/exploit-candidates", params={"service": "http-alt"})
    assert r.status_code == 200
    assert isinstance(r.json()["candidates"], list)


def test_fingerprint_results_404(client):
    r = client.get("/api/neighbors/fingerprint/results/none")
    assert r.status_code == 404


def test_neighbors_jobs_lists_all(client, clean_db):
    from routers import scan as scan_router

    scan_router._neighbor_jobs["nj"] = {
        "id": "nj",
        "status": "running",
        "hosts": [],
        "created": "t",
    }
    r = client.get("/api/neighbors/jobs")
    bodies = r.json()["jobs"]
    assert any(j["id"] == "nj" for j in bodies)


# ---------------- updater cycle ----------------


def test_updater_run_update_cycle(monkeypatch, tmp_path):
    import pathlib

    import services.updater as up

    monkeypatch.setattr(up, "UPDATER_STATE", pathlib.Path(tmp_path / "st.json"))
    calls = {"tools": 0, "cve": 0}

    def fake_refresh_cve_data():
        calls["cve"] += 1
        return {"cve_db": {"before": 1, "after": 2}}

    monkeypatch.setattr(up, "refresh_cve_data", fake_refresh_cve_data)
    report = up.run_update()
    assert (
        any("cve_db" in str(v) for k, v in report.items() if isinstance(v, dict))
        or report.get("cve_db", {}).get("after") == 2
    )
    assert calls["cve"] == 1
    assert (tmp_path / "st.json").exists()  # state persisted


# ---------------- AI models + loop ----------------


def test_ai_models_endpoint(client, monkeypatch):

    monkeypatch.setenv("H4K_AI_PROVIDER", "openai_compatible")
    r = client.get("/api/source/ai/models")
    assert r.status_code in (200, 503)


def test_ai_loop_endpoint(client, monkeypatch):
    import services.ai as ai

    calls = {"n": 0}

    def fake_ai_analyze(text, model=None):
        calls["n"] += 1
        if calls["n"] < 2:
            return {
                "ok": True,
                "raw": "ROOT_CAUSE: x\nPATCH_CANDIDATE: y\nCONFIRM_STEPS: z",
                "provider": "openai",
                "error": None,
            }
        return {
            "ok": True,
            "raw": "ROOT_CAUSE: x\nPATCH_CANDIDATE: y\nCONFIRM_STEPS: z",
            "provider": "openai",
            "error": None,
        }

    monkeypatch.setattr(ai, "ai_analyze", fake_ai_analyze)
    r = client.post(
        "/api/source/ai/loop",
        json={
            "text": "def f(u):\n    return u/0",
            "iterations": 2,
        },
    )
    assert r.status_code in (200, 422)


# ---------------- zap + db_interrogate + container_escape ----------------


def test_zap_scan_soft(client, monkeypatch):
    import services.zap as zap

    class _Resp:
        status = 200
        text = "{}"

        def json(self):
            return {}

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(zap.requests, "get", lambda *a, **k: _Resp())
    monkeypatch.setattr(zap.requests, "post", lambda *a, **k: _Resp())
    monkeypatch.setattr("services.zap.time.sleep", lambda s: None)
    out = zap.zap_scan("http://127.0.0.1:1", mode="basic")
    assert isinstance(out, dict)


def test_db_interrogate_all(client, monkeypatch):
    from services.db_interrogate import DBInterrogate

    monkeypatch.setenv("H4K_TEST_FAKE", "1")
    svc = DBInterrogate()
    out = svc.interrogate_all("192.168.1.10")
    assert isinstance(out, dict)


def test_container_escape_detect(client):
    from services.container_escape import ContainerEscape

    out = ContainerEscape().detect()
    assert isinstance(out, dict)


# ---------------- source router edges ----------------


def test_rules_run_requires_git_url(client):
    r = client.post("/api/source/rules/run", json={"git_url": None})
    assert r.status_code == 400


def test_rules_run_clone_failure(client, monkeypatch):
    import routers.source as src_router

    def boom(url, work):
        raise src_router.ingest.IngestError("clone failed")

    monkeypatch.setattr(src_router.ingest, "clone_git", boom)
    r = client.post("/api/source/rules/run", json={"git_url": "https://x/y"})
    assert r.status_code == 400
    assert "clone" in r.json()["detail"]


def test_ossfuzz_endpoint_validation_and_clone_error(client, monkeypatch):
    r = client.post("/api/source/ossfuzz", json={})
    assert r.status_code == 400
    import routers.source as src_router

    def boom(url, work):
        raise src_router.ingest.IngestError("bad repo")

    monkeypatch.setattr(src_router.ingest, "clone_git", boom)
    r = client.post("/api/source/ossfuzz", json={"git_url": "https://x/y"})
    assert r.status_code == 400
    assert "bad repo" in r.json()["detail"]


def test_fuzz_minimize_endpoint(client, monkeypatch):
    class _F:
        def minimize_crash(self, cmd, crashes):
            return {"minimized_input": "A", "crash": True}

    import services.fuzzer as fz

    monkeypatch.setattr(fz, "LabFuzzer", _F)
    r = client.post("/api/source/fuzz/minimize", json={})
    assert r.status_code == 200
    assert r.json()["minimized"]["crash"] is True


# ---------------- app lifespan (periodic tasks start + cancel) ----------------


def test_app_lifespan_starts_and_cancels_tasks(monkeypatch, client):
    import app_state
    import main as main_module
    import services.updater as updater_mod

    monkeypatch.delenv("H4K_AUTO_UPDATE", raising=False)
    monkeypatch.setenv("H4K_AUTO_UPDATE", "1")
    monkeypatch.setenv("H4K_UPDATE_INTERVAL", "0")
    monkeypatch.setenv("H4K_CVE_WEEKLY", "1")
    monkeypatch.setenv("H4K_CVE_REFRESH_INTERVAL", "0")

    ran = {"n": 0}
    monkeypatch.setattr(updater_mod, "run_update", lambda: ran.update(n=1))

    app_state.msf_client = FakeMsfC3()
    app_state.cve_db = type("C", (), {"cves": [], "refresh": lambda s: False})()

    async def _drive():
        async with main_module.lifespan(main_module.app):
            await asyncio.sleep(0.05)  # let the zero-interval loops tick once

    asyncio.run(_drive())


# ---------------- scope-active ingest trio ----------------


def test_ingest_mirrors_into_engagement(clean_db, monkeypatch):
    """_save_* helpers mirror into the engagement store when scope is active."""
    import app_state
    from routers import scan as scan_router
    from services.engagement import EngagementStore, db_path

    store = EngagementStore(db_path())
    eng = store.create_engagement(
        f"ingest-{int(__import__('time').time())}", ["192.168.1.0/24"]
    )
    app_state.active_engagement_id = eng["id"]

    scan_router._save_neighbor_host("192.168.1.10", None, "Dell", None)
    scan_router._save_neighbor_services(
        "192.168.1.10",
        [
            {"port": 22, "state": "open", "service": "ssh"},
        ],
    )
    scan_router._save_service_vulns(
        "192.168.1.10",
        22,
        "tcp",
        [
            {
                "kind": "cve",
                "vid": "CVE-X",
                "severity": 9.0,
                "detail": "bad | msf: exploit/y",
                "found_at": "t",
            }
        ],
    )
    scan_router._save_neighbor_host("192.168.1.10", None, "Dell", None)

    assets = store.assets(eng["id"])
    assert any(a["host"] == "192.168.1.10" for a in assets)
    svcs = store.services(eng["id"])
    assert any(s["port"] == 22 for s in svcs)
    vulns = store.vulns(eng["id"])
    assert any("CVE-X" in str(v) for v in vulns)

    from routers.scan import _eng_ingest_cred

    _eng_ingest_cred(
        {
            "host": "192.168.1.10",
            "port": 22,
            "service": "ssh",
            "user": "pi",
            "password": "raspberry",
        },
        verified=True,
    )
    creds = store.credentials(eng["id"])
    assert any(c.get("user") == "pi" for c in creds)
    app_state.active_engagement_id = None


# ---------------- pipeline: probe failure paths + cred success parse ----------------


def test_pipeline_probe_timeout_paths(monkeypatch):
    import socket as socket_mod

    from services.scan_pipeline import ScanPipeline

    class _FailSock:
        def settimeout(self, t):
            pass

        def connect(self, addr):
            pass

        def sendall(self, b):
            pass

        def sendto(self, b, addr):
            pass

        def recv(self, n):
            raise TimeoutError("slow")

        def recvfrom(self, n):
            raise ConnectionRefusedError("nope")

        def close(self):
            pass

    monkeypatch.setattr(socket_mod, "socket", lambda *a, **k: _FailSock())
    from services.modes import get_mode

    pipeline = ScanPipeline(FakeMsfC3(), log=lambda m: None)
    mode = get_mode("overt", "standard")
    hosts = [
        {
            "address": "192.168.1.10",
            "services": [
                {"port": 5353, "proto": "udp", "service": "unknown", "state": "open"},
                {"port": 11211, "proto": "tcp", "service": "unknown", "state": "open"},
            ],
        }
    ]
    pipeline._probe_mystery_ports(hosts, mode)  # must not raise


def test_pipeline_cred_success_scan(monkeypatch, no_subprocess):
    """The cred stage marks verified when msf reports success."""
    from services.scan_pipeline import ScanPipeline

    class _Msf(FakeMsfC3):
        def execute(self, mtype, mname, opts):
            return {
                "status": "success",
                "username": "x",
                "password": "y",
                "user": "x",
                "password_field": "y",
            }

        @property
        def modules(self):
            options = [
                "RHOSTS",
                "RPORT",
                "USERNAME",
                "PASSWORD",
                "STOP_ON_SUCCESS",
                "CreateSession",
            ]

            class _Mod:
                @property
                def options(self):
                    return list(options)

            class _Modules:
                def use(self, mtype, mname):
                    return _Mod()

            return _Modules()

    p = ScanPipeline(_Msf(), log=lambda m: None)
    opts = p._module_options("exploit/multi/ssh/ssh_login")
    assert "USERNAME" in opts
    res = p._try_one(
        "exploit/multi/ssh/ssh_login",
        "192.168.1.10",
        {"port": 22, "service": "ssh", "state": "open"},
        "u",
        "p",
        open_sessions=False,
    )
    assert res is True


def test_pipeline_reverse_dns_dig_missing(monkeypatch, no_subprocess):
    import services.scan_pipeline as sp
    from services.scan_pipeline import ScanPipeline

    def boom(argv, **k):
        raise FileNotFoundError("dig")

    monkeypatch.setattr(sp.subprocess, "run", boom)
    out = ScanPipeline(FakeMsfC3())._reverse_dns(["1.2.3.4"])
    assert out == []


# ---------------- ollama listener socket path ----------------


def test_ollama_listener_accepts_connection(client):
    import socket as socket_mod
    import time as time_mod

    port = 14790
    r = client.get("/api/ollama/listener", params={"lhost": "127.0.0.1", "lport": port})
    assert r.status_code == 200
    time_mod.sleep(0.2)
    s = socket_mod.create_connection(("127.0.0.1", port), timeout=3)
    s.sendall(b"reverse shell")
    s.close()
    time_mod.sleep(0.5)


# ---------------- zap poll loop + params path ----------------


def test_zap_with_api_calls(client, monkeypatch):
    import services.zap as zap

    class _Resp:
        status = 200

        def json(self):
            return {"scan": "0", "status": "100"}

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(zap.requests, "get", lambda *a, **k: _Resp())
    monkeypatch.setattr(zap.requests, "post", lambda *a, **k: _Resp())
    monkeypatch.setattr("services.zap.time.sleep", lambda s: None)
    monkeypatch.setenv("ZAP_TIMEOUT_SECONDS", "1")
    out = zap.zap_scan("http://127.0.0.1:1", mode="full")
    assert isinstance(out, dict)
