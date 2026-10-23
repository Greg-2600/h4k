# scan.py branch coverage: 404 endpoint paths, SSE stream, session shell
# read/write mode, aux-module CVE filtering, exploit-candidate selection,
# autopilot deep-web stage + static-map fallback, and ollama listener routes.
from contextlib import asynccontextmanager

import pytest


class FakeMsfBase:
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


class CveDbBranch:
    cves: list = [  # noqa: RUF012
        {
            "id": "CVE-AUX-1",
            "product": "openssh",
            "cvss": 5.0,
            "severity": "MEDIUM",
            "title": "enum",
            "msf_module": "auxiliary/scanner/ssh/ssh_enumusers",
        },
        {
            "id": "CVE-EXP-1",
            "product": "openssh",
            "cvss": 9.0,
            "severity": "CRITICAL",
            "title": "rce",
            "msf_module": "exploit/multi/ssh/sshexec",
        },
        {
            "id": "CVE-EXP-2",
            "product": "ftp",
            "cvss": 7.0,
            "severity": "HIGH",
            "title": "vsftpd backdoor",
            "msf_module": "exploit/unix/ftp/vsftpd_234_backdoor",
        },
    ]

    def match_service(self, svc, version=None, product=None):
        return list(self.cves)

    def refresh(self):
        return False


def _make_engagement_scope(scope=("192.168.1.0/24",)):
    from services.engagement import EngagementStore, db_path

    store = EngagementStore(db_path())
    return store.create_engagement(
        f"lab-{int(__import__('time').time())}", scope=list(scope)
    )


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setenv("H4K_REFRESH_CVE", "0")
    import app_state
    import main as main_module

    app_state.msf_client = FakeMsfBase()
    app_state.cve_db = CveDbBranch()
    app_state.active_engagement_id = None

    @asynccontextmanager
    async def _noop(_app):
        yield

    main_module.app.router.lifespan_context = _noop

    from fastapi.testclient import TestClient

    return TestClient(main_module.app)


@pytest.fixture()
def clean_db(monkeypatch, tmp_path):
    from routers import scan as scan_router

    monkeypatch.setattr(scan_router, "_NEIGHBOR_DB", tmp_path / "neighbors.db")
    return scan_router


def test_cve_aux_filter_keeps_only_exploit_modules(clean_db, monkeypatch):
    from routers.scan import _match_service_vulns

    monkeypatch.setattr("routers.scan._get_cve_db", lambda: CveDbBranch())
    hits = _match_service_vulns(
        "192.168.1.10",
        {
            "port": 22,
            "state": "open",
            "service": "ssh",
            "product": "OpenSSH",
            "version": "7.4",
        },
    )
    vids = {v["vid"] for v in hits}
    assert "CVE-EXP-1" in vids
    assert "CVE-AUX-1" not in vids  # auxiliary matches are recon leads


def test_webprobe_admin_paths_and_headers(clean_db, monkeypatch):
    import routers.scan as scan_router

    class _Resp:
        def __init__(self, status, headers, body):
            self.status = status
            self.headers = headers
            self._b = body

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, n):
            return self._b

    def fake_urlopen(req, timeout=4):
        url = req.full_url
        self_h = {"Server": "nginx/1.18 (Ubuntu)"}
        if url.endswith("http://192.168.1.10:80/"):
            body = b"<html><title>Router Admin</title></html>"
            return _Resp(200, self_h, body)
        if int(url.rsplit(":", 1)[1].split("/", 1)[0]) and "/admin" in url:
            return _Resp(200, self_h, b"ok")
        return _Resp(0, self_h, b"")

    import urllib.request

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    out = scan_router._do_web_probe("192.168.1.10", 80)
    assert out["server"].startswith("nginx")
    assert out["title"] == "Router Admin"
    assert any(p["path"].startswith("/admin") for p in out["paths"])


def test_status_404_paths(client, clean_db):
    for path in (
        "/api/neighbors/status/none",
        "/api/neighbors/fingerprint/status/none",
        "/api/neighbors/fingerprint/nope",
        "/api/passattack/none",
        "/api/attack/none",
        "/api/deepattack/none",
        "/api/fuzz/none",
        "/api/jobs/none",
        "/api/report/none",
    ):
        r = client.get(path)
        assert r.status_code in (404, 405), f"{path} -> {r.status_code}"


def test_session_cmd_shell_mode_read_write(client, clean_db, monkeypatch):
    import app_state

    frames = iter(["$ whoami\n", "root\n", ""] * 20)

    class _Sess:  # plain shell: no run_shell_cmd
        def write(self, data):
            pass

        def read(self):
            return next(frames)

    class _Mgr:
        def session(self, sid):
            return _Sess()

    class _Msf(FakeMsfBase):
        @property
        def client(self):
            return self

        @property
        def sessions(self):
            return _Mgr()

    app_state.msf_client = _Msf()
    r = client.post("/api/sessions/3/cmd", json={"command": "whoami"})
    assert r.status_code == 200
    assert "root" in r.json()["output"]


def test_session_cmd_unknown_session(client, clean_db, monkeypatch):
    r = client.post("/api/sessions/999/cmd", json={"command": "id"})
    assert r.status_code == 404


def test_sse_stream_completes(client, clean_db):
    from routers import scan as scan_router

    scan_router.JOBS["sse1"] = {
        "id": "sse1",
        "status": "done",
        "progress": 100.0,
        "log": ["[+] line1", "[+] line2"],
        "created": "2026-01-01T00:00:00+00:00",
    }
    with client.stream("GET", "/api/jobs/sse1/stream") as r:
        assert r.status_code == 200
        text = "".join(chunk for chunk in r.iter_text())
    assert "line1" in text
    assert "line2" in text
    assert "complete" in text


def test_sse_stream_unknown_job(client, clean_db):
    with client.stream("GET", "/api/jobs/none/stream") as r:
        assert r.status_code == 200
        text = "".join(chunk for chunk in r.iter_text())
    assert "error" in text


def test_exploit_candidates_from_cvedb_and_static_map(client, clean_db):
    r = client.get("/api/exploit-candidates", params={"service": "ssh", "port": 22})
    assert r.status_code == 200
    cands = r.json()["candidates"]
    assert "exploit/multi/ssh/sshexec" in cands  # CVE db + static map (deduped)

    r = client.get("/api/exploit-candidates", params={"service": "ftp", "port": 21})
    assert "exploit/unix/ftp/vsftpd_234_backdoor" in r.json()["candidates"]


def test_vulnleads_endpoint(client, clean_db):
    r = client.post("/api/vulnleads", json={"target": "192.168.1.10"})
    assert r.status_code == 200
    assert "leads" in r.json()


def test_ollama_shell_and_reverse_shell_validation(client):
    r = client.post("/api/ollama/shell", json={"target": "10.0.0.1", "payload": "id"})
    assert r.status_code in (200, 422, 404)  # real exploit path may fail offline
    r = client.post("/api/ollama/shell", json={})
    assert r.status_code == 422
    r = client.post("/api/ollama/reverse-shell", json={})
    assert r.status_code == 422


def test_ollama_listener_starts(client):
    r = client.get(
        "/api/ollama/listener", params={"lhost": "127.0.0.1", "lport": 14777}
    )
    assert r.status_code == 200
    assert r.json()["status"] == "listening"


def test_scope_branches_in_helpers(clean_db):
    from routers.scan import _host_in_scope, _session_scope_info

    ok, reason = _host_in_scope("10.9.9.9")
    assert ok and reason == ""
    info = _session_scope_info()
    assert info["engagement_id"] is None


def test_session_reset_wipes_engagements(clean_db):
    from routers import scan as scan_router

    eng = _make_engagement_scope()
    from services.engagement import EngagementStore, db_path

    store = EngagementStore(db_path())
    assert store.get_engagement(eng["id"])
    result = scan_router.reset_session(wipe_engagements=True)
    assert result["engagements_deleted"] >= 1
    assert not store.get_engagement(eng["id"])


def test_autopilot_deep_web_stage(clean_db, monkeypatch):
    from routers.scan import _AUTOPILOT_STATE, _ensure_session_row, _run_autopilot

    _ensure_session_row()
    import app_state

    eng = _make_engagement_scope()
    app_state.active_engagement_id = eng["id"]

    NMAP_XML = (
        '<host starttime="1" endtime="1"><status state="up"/>'
        '<address addr="192.168.1.10" addrtype="ipv4"/>'
        '<ports><port protocol="tcp" portid="80"><state state="open"/>'
        '<service name="http" product="Apache"/></port></ports></host>'
    )
    outputs = {
        "nmap": {
            "stdout": NMAP_XML,
            "stderr": "",
            "rc": 0,
            "elapsed": 0.1,
            "timed_out": False,
            "status": "ok",
        },
        "nikto": {
            "stdout": "+ /admin: 200\n",
            "stderr": "",
            "rc": 0,
            "elapsed": 0.1,
            "timed_out": False,
            "status": "ok",
        },
        "gobuster": {
            "stdout": "/login (Status: 200)\n",
            "stderr": "",
            "rc": 0,
            "elapsed": 0.1,
            "timed_out": False,
            "status": "ok",
        },
    }

    seen = []

    class FakeRunner:
        def __init__(self, progress=None):
            pass

        def run_tool(self, tool, argv, timeout=300):
            seen.append(tool)
            return dict(
                outputs.get(
                    tool,
                    {
                        "stdout": "",
                        "stderr": "",
                        "rc": 0,
                        "elapsed": 0,
                        "timed_out": False,
                        "status": "ok",
                    },
                )
            )

    import services.toolkit as tk

    monkeypatch.setattr(tk, "ToolkitRunner", FakeRunner)

    class FakeFinder:
        def __init__(self, msf, interface=None):
            pass

        @staticmethod
        def neighbors_to_dicts(found):
            return found

        def discover(self, cidr):
            from schemas import Neighbor

            return [Neighbor(ip="192.168.1.10", mac="01:02:03:04:05:09")]

    import services.discovery as dsc

    monkeypatch.setattr(dsc, "NeighborFinder", FakeFinder)

    job: dict = {
        "id": "apd",
        "status": "running",
        "stage": "discovery",
        "progress": 0.0,
        "message": "",
        "hosts": {},
        "log": [],
        "aborted": False,
        "deep_web": True,
    }
    _run_autopilot(job, FakeMsfBase(), ["192.168.1.0/24"], deep_web=True)
    _AUTOPILOT_STATE["job"] = None
    assert "nikto" in seen and "gobuster" in seen
    assert any("[web:" in line for line in job["log"])


def test_autopilot_static_map_fallback_for_creds(clean_db, monkeypatch):
    """Password-stage creds must seed exploit attempts via the static map."""
    from routers.scan import _AUTOPILOT_STATE, _ensure_session_row, _run_autopilot

    _ensure_session_row()
    import app_state

    eng = _make_engagement_scope()
    app_state.active_engagement_id = eng["id"]

    attempts = []

    NMAP_XML = (
        '<host starttime="1" endtime="1"><status state="up"/>'
        '<address addr="192.168.1.10" addrtype="ipv4"/>'
        '<ports><port protocol="tcp" portid="22"><state state="open"/>'
        '<service name="ssh"/></port></ports></host>'
    )
    HYDRA = "[22][ssh] host: 192.168.1.10   login: root   password: admin\n"

    class FakeRunner:
        def __init__(self, progress=None):
            pass

        def run_tool(self, tool, argv, timeout=300):
            if tool == "nmap":
                return {
                    "stdout": NMAP_XML,
                    "stderr": "",
                    "rc": 0,
                    "elapsed": 0.1,
                    "timed_out": False,
                    "status": "ok",
                }
            return {
                "stdout": HYDRA,
                "stderr": "",
                "rc": 0,
                "elapsed": 0.1,
                "timed_out": False,
                "status": "ok",
            }

    import services.toolkit as tk

    monkeypatch.setattr(tk, "ToolkitRunner", FakeRunner)

    class FakeAttackSvc:
        def __init__(self, msf_, progress=None):
            pass

        def run(self, req, known):
            attempts.append(
                {
                    "host": req.host,
                    "module": req.module,
                    "result": "failed",
                    "detail": "nope",
                    "session_id": None,
                }
            )
            return [
                {
                    "host": req.host,
                    "module": req.module,
                    "result": "failed",
                    "detail": "nope",
                    "session_id": None,
                }
            ]

    import services.attack as am

    monkeypatch.setattr(am, "AttackService", FakeAttackSvc)

    class FakeFinder:
        def __init__(self, msf, interface=None):
            pass

        @staticmethod
        def neighbors_to_dicts(found):
            return found

        def discover(self, cidr):
            from schemas import Neighbor

            return [Neighbor(ip="192.168.1.10", mac="01:02:03:04:05:09")]

    import services.discovery as dsc

    monkeypatch.setattr(dsc, "NeighborFinder", FakeFinder)

    job: dict = {
        "id": "apc",
        "status": "running",
        "stage": "discovery",
        "progress": 0.0,
        "message": "",
        "hosts": {},
        "log": [],
        "aborted": False,
    }
    _run_autopilot(job, FakeMsfBase(), ["192.168.1.0/24"])
    _AUTOPILOT_STATE["job"] = None
    # the CVE-db module hint queues the attempt; cred fallback dedupes away
    assert any(a["module"] == "exploit/multi/ssh/sshexec" for a in attempts)
    assert attempts and all(a["module"].startswith("exploit/") for a in attempts)
