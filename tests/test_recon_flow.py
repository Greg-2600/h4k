# Recon-flow surface: session lifecycle, neighbor discovery/fingerprint jobs,
# password attacks, scope enforcement, session console + report endpoints.
# Follows the test_api.py pattern: real router, faked MSF backend, no daemon.
from contextlib import asynccontextmanager
from typing import ClassVar

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
    cves: ClassVar[list] = []

    def refresh(self, *a, **k):
        return False

    def match_service(self, *a, **k):
        return []


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setenv("H4K_REFRESH_CVE", "0")
    import app_state
    import main as main_module

    app_state.msf_client = FakeMsf()
    app_state.cve_db = CveDbStub()
    app_state.active_engagement_id = None

    @asynccontextmanager
    async def _noop(_app):
        yield

    main_module.app.router.lifespan_context = _noop
    # earlier suites share this client IP and exhaust the rate-limit budget
    import main as mm

    mm._rate_store = None

    from fastapi.testclient import TestClient

    return TestClient(main_module.app)


@pytest.fixture()
def clean_db(monkeypatch, tmp_path):
    """Point the neighbor store at a throwaway sqlite file."""
    from routers import scan as scan_router

    monkeypatch.setattr(scan_router, "_NEIGHBOR_DB", tmp_path / "neighbors.db")
    return scan_router


# ---------- session lifecycle ----------


def test_session_get_creates_session(client, clean_db):
    r = client.get("/api/session")
    assert r.status_code == 200
    body = r.json()
    assert body["session_id"]
    assert body["started_at"]
    assert body["hosts"] == 0


def test_session_reset_issues_new_id(client, clean_db):
    first = client.get("/api/session").json()["session_id"]
    r = client.post("/api/session/reset", params={"wipe_engagements": False})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "reset"
    assert body["session_id"] != first
    after = client.get("/api/session").json()
    assert after["hosts"] == 0
    assert after["session_id"] == body["session_id"]


# ---------- neighbor discovery job ----------


def test_neighbor_discovery_persists_scoped_hosts(client, clean_db, monkeypatch):
    from routers.scan import _run_neighbor_discovery
    from schemas import Neighbor

    clean_db._ensure_session_row()

    class FakeFinder:
        def __init__(self, msf, interface=None):
            pass

        @staticmethod
        def neighbors_to_dicts(found):
            return [n.model_dump(exclude_none=True) for n in found]

        def discover(self, cidr):
            return [
                Neighbor(
                    ip="192.168.1.10", mac="aa:bb:cc:dd:ee:01", vendor="Raspberry Pi"
                ),
                Neighbor(ip="192.168.1.11", mac="aa:bb:cc:dd:ee:02"),
                Neighbor(ip="fe80::1", mac="00:11:22:33:44:55"),  # ipv6 skipped
                Neighbor(ip="219", mac="00:11:22:33:44:56"),  # garbage skipped
            ]

    import services.discovery as discovery_mod

    monkeypatch.setattr(discovery_mod, "NeighborFinder", FakeFinder)

    job = {"id": "t", "status": "running", "log": []}
    _run_neighbor_discovery(job, FakeMsf())
    assert job["status"] == "done"
    assert len(job["hosts"]) == 4

    hosts = clean_db._load_neighbor_hosts()
    assert set(hosts) == {"192.168.1.10", "192.168.1.11"}


# ---------- fingerprint job: parse xml + save services ----------


def test_fingerprint_parses_nmap_xml(clean_db):
    from routers.scan import _parse_nmap_xml

    xml = """
    <nmaprun><hosthint><address addr="192.168.1.2" addrtype="ipv4"/></hosthint>
    <host starttime="1" endtime="1"><status state="up"/>
    <address addr="192.168.1.2" addrtype="ipv4"/>
    <address addr="01:02:03:04:05:06" addrtype="mac" vendor="Intel"/>
    <hostnames><hostname name="box" type="PTR"/></hostnames>
    <ports>
    <port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh" method="table"/></port>
    <port protocol="tcp" portid="23"><state state="closed" reason="reset"/><service name="telnet" method="table"/></port>
    <port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/><service name="http" product="nginx" version="1.18" method="probed"/></port>
    </ports></host></nmaprun>
    """
    parsed = _parse_nmap_xml(xml)
    assert len(parsed) == 1
    entry = parsed[0]
    assert entry["ip"] == "192.168.1.2"
    assert entry["mac"] == "01:02:03:04:05:06"
    assert entry["hostname"] == "box"
    byport = {s["port"]: s for s in entry["services"]}
    assert byport[22]["state"] == "open"
    assert byport[23]["state"] == "closed"
    assert byport[80]["product"] == "nginx"
    assert byport[80]["version"] == "1.18"


def test_fingerprint_job_runs_and_saves(clean_db, monkeypatch):
    from routers.scan import _ensure_session_row, _run_fingerprint

    _ensure_session_row()
    neighbors = [{"ip": "192.168.1.10", "mac": None, "vendor": None, "hostname": None}]

    class FakeRunner:
        def __init__(self, progress=None):
            pass

        def run_tool(self, tool, argv, timeout=300):
            from routers.scan import _parse_nmap_xml  # noqa: F401

            return {
                "tool": "nmap",
                "stdout": """
                <host starttime="1" endtime="1"><status state="up"/>
                <address addr="192.168.1.10" addrtype="ipv4"/>
                <address addr="01:02:03:04:05:09" addrtype="mac" vendor="Dell"/>
                <ports><port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds" product="Windows SMB" version="6.1"/></port></ports>
                </host>
                """,
                "stderr": "",
                "rc": 0,
                "elapsed": 1.0,
                "timed_out": False,
                "status": "ok",
            }

    import services.toolkit as toolkit_mod

    monkeypatch.setattr(toolkit_mod, "ToolkitRunner", FakeRunner)

    job = {"id": "t", "status": "running", "log": []}
    _run_fingerprint(job, neighbors)
    assert job["status"] == "done"
    assert job["results"][0]["ip"] == "192.168.1.10"
    saved = clean_db._load_neighbor_services()["192.168.1.10"]
    assert any(s["port"] == 445 for s in saved)
    # host row updated with the mac observed from nmap
    assert clean_db._load_neighbor_hosts()["192.168.1.10"]["mac"] == "01:02:03:04:05:09"


# ---------- password attack ----------


def _run_passattack_job(clean_db, monkeypatch, stdout):
    from routers.scan import _ensure_session_row, _run_pass_attack

    _ensure_session_row()

    class FakeRunner:
        def __init__(self, progress=None):
            pass

        def run_tool(self, tool, argv, timeout=300):
            return {
                "tool": "hydra",
                "stdout": stdout,
                "stderr": "",
                "rc": 0,
                "elapsed": 2.0,
                "timed_out": False,
                "status": "ok",
            }

    import services.toolkit as toolkit_mod

    monkeypatch.setattr(toolkit_mod, "ToolkitRunner", FakeRunner)

    job = {"id": "pa", "status": "running", "log": []}
    _run_pass_attack(job, "192.168.1.10", "ssh", 22)
    return job


def test_passattack_parses_hydra_hits(clean_db, monkeypatch):
    from routers.scan import passattack_creds

    stdout = "[22][ssh] host: 192.168.1.10   login: pi   password: raspberry\n"
    job = _run_passattack_job(clean_db, monkeypatch, stdout)
    assert job["status"] == "done"
    assert job["found"] == [
        {
            "host": "192.168.1.10",
            "port": 22,
            "service": "ssh",
            "user": "pi",
            "password": "raspberry",
        }
    ]
    creds = passattack_creds()
    assert creds["count"] == 1


def test_passattack_no_hits_persists_nothing(clean_db, monkeypatch):
    from routers.scan import passattack_creds

    job = _run_passattack_job(clean_db, monkeypatch, "no hits")
    assert job["found"] == []
    assert passattack_creds()["count"] == 0
    assert "no match" in job["message"]


def test_passattack_endpoint_validates_service(client, clean_db):
    r = client.post(
        "/api/passattack", json={"host": "192.168.1.10", "service": "telnet"}
    )
    assert r.status_code == 200
    r = client.post(
        "/api/passattack", json={"host": "192.168.1.10", "service": "gopher"}
    )
    assert r.status_code == 422
    r = client.post("/api/passattack", json={"service": "ssh"})
    assert r.status_code == 422


def test_passattack_targets_lists_attackable_services(clean_db, monkeypatch):
    from routers.scan import _ensure_session_row

    _ensure_session_row()
    clean_db._save_neighbor_host("192.168.1.10", None, None, None)
    clean_db._save_neighbor_services(
        "192.168.1.10",
        [
            {"port": 22, "state": "open", "service": "ssh"},
            {"port": 25, "state": "open", "service": "smtp"},  # not attackable
            {"port": 23, "state": "closed", "service": "telnet"},
        ],  # closed: skip
    )
    from routers import scan as scan_router

    targets = scan_router.pass_attack_targets()
    assert targets["count"] == 1
    assert targets["targets"][0]["attack_service"] == "ssh"


# ---------- scope enforcement ----------


def _make_engagement():
    from services.engagement import EngagementStore, db_path

    store = EngagementStore(db_path())
    return store.create_engagement("lab-t", scope=["192.168.1.0/24"])


def test_scope_blocks_aggressive_action(client, clean_db, monkeypatch):
    from routers import scan as scan_router
    from routers.scan import _ensure_session_row, pass_attack

    _ensure_session_row()

    class _FakeBackground:
        def add_task(self, *a, **k):
            pass

    eng = _make_engagement()
    import app_state

    app_state.active_engagement_id = eng["id"]

    with pytest.raises(scan_router.HTTPException) as exc:
        pass_attack({"host": "10.9.9.9", "service": "ssh"}, _FakeBackground())
    assert exc.value.status_code == 403
    assert "outside" in exc.value.detail


def test_scope_allows_in_scope_and_readonly_when_cleared(clean_db, monkeypatch):
    from routers.scan import _ensure_session_row, _host_in_scope

    _ensure_session_row()
    eng = _make_engagement()
    import app_state

    app_state.active_engagement_id = eng["id"]
    ok, _ = _host_in_scope("192.168.1.55")
    assert ok
    app_state.active_engagement_id = None
    ok, _ = _host_in_scope("10.9.9.9")
    assert ok


def test_stale_scope_id_self_clears(clean_db):
    import app_state
    from routers.scan import _active_scope

    app_state.active_engagement_id = "deleted-long-ago"
    eng_id, _store = _active_scope()
    assert eng_id is None
    assert app_state.active_engagement_id is None


# ---------- session console + report ----------


def test_session_cmd_requires_open_session(client, clean_db):
    r = client.post("/api/sessions/9999/cmd", json={"command": "sysinfo"})
    assert r.status_code == 404


def test_sessions_list_merges_recorded(clean_db, client):
    from routers.scan import _ensure_session_row, _record_sessions

    _ensure_session_row()

    opened = _record_sessions(
        [
            {
                "result": "success",
                "host": "192.168.1.10",
                "port": 22,
                "module": "exploit/x",
                "session_id": "7",
            }
        ]
    )
    assert opened == 1

    tc = client
    r = tc.get("/api/sessions")
    assert r.status_code == 200
    sessions = r.json()["sessions"]
    assert any(
        s["msf_session_id"] == "7" and s["source"] == "recorded" for s in sessions
    )


def test_session_report_md_and_json(client, clean_db):
    from routers.scan import _ensure_session_row

    _ensure_session_row()
    r = client.get("/api/session/report", params={"fmt": "md"})
    assert r.status_code == 200
    md = r.json()["content"]
    assert "session report" in md
    assert "## Hosts discovered" in md

    r = client.get("/api/session/report")
    assert r.status_code == 200
    body = r.json()
    assert body["fmt"] == "json"
    for key in (
        "hosts",
        "services",
        "vulns",
        "credentials",
        "sessions",
        "exploit_attempts",
    ):
        assert key in body["report"]


def test_website_probe_validates_input(client, clean_db):
    r = client.post("/api/webprobe", json={})
    assert r.status_code == 422
    r = client.post("/api/webprobe", json={"host": "192.0.2.1", "port": 9})
    assert r.status_code == 502  # nothing listening (TEST-NET address)


def test_session_cmd_happy_path(client, clean_db, monkeypatch):
    class FakeSess:
        def run_shell_cmd(self, cmd):
            return f"ran: {cmd}"

    class FakeMgr:
        def session(self, sid):
            return FakeSess()

    class FakeMsfConsole(FakeMsf):
        @property
        def sessions(self):
            return FakeMgr()

    import app_state

    app_state.msf_client = FakeMsfConsole()
    r = client.post("/api/sessions/12/cmd", json={"command": "sysinfo"})
    assert r.status_code == 200
    assert "ran: sysinfo" in r.json()["output"]
    r = client.post("/api/sessions/12/cmd", json={})
    assert r.status_code == 422


def test_scope_endpoints_round_trip(client, clean_db):
    eng = _make_engagement()
    r = client.post("/api/session/scope", json={"engagement_id": eng["id"]})
    assert r.status_code == 200
    assert r.json()["status"] == "scoped"

    s = client.get("/api/session").json()
    assert s["scope"]["engagement_id"] == eng["id"]

    r = client.post("/api/session/scope", json={"engagement_id": None})
    assert r.json()["status"] == "unscoped"
    assert client.get("/api/session").json()["scope"]["engagement_id"] is None

    r = client.post("/api/session/scope", json={"engagement_id": "bogus"})
    assert r.status_code == 404


def test_neighbor_scan_endpoint_503_without_msf(client, clean_db, monkeypatch):
    import app_state

    app_state.msf_client = None
    r = client.post("/api/neighbors/scan")
    assert r.status_code == 503


def test_fingerpint_status_404(client):
    r = client.get("/api/neighbors/fingerprint/status/nope")
    assert r.status_code == 404


# ---------- autopilot ----------


def _run_autopilot_faked(clean_db, monkeypatch, msf):
    """Drive the full autopilot loop with canned tool output."""
    from routers.scan import (
        _AUTOPILOT_STATE,
        _ensure_session_row,
        _run_autopilot,
    )

    _ensure_session_row()

    XML = (
        '<host starttime="1" endtime="1"><status state="up"/>'
        '<address addr="192.168.1.10" addrtype="ipv4"/>'
        '<address addr="01:02:03:04:05:09" addrtype="mac" vendor="Dell"/>'
        '<ports><port protocol="tcp" portid="22"><state state="open"/>'
        '<service name="ssh" product="OpenSSH" version="7.4"/></port></ports></host>'
    )
    HYDRA = "[22][ssh] host: 192.168.1.10   login: pi   password: raspberry\n"

    class FakeRunner:
        def __init__(self, progress=None):
            pass

        def run_tool(self, tool, argv, timeout=300):
            if tool == "nmap":
                return {
                    "stdout": XML,
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

    class FakeAttackSvc:
        def __init__(self, msf_, progress=None):
            pass

        def run(self, req, known):
            return [
                {
                    "host": req.host,
                    "module": req.module,
                    "result": "success",
                    "detail": "session opened",
                    "session_id": "31",
                }
            ]

    import services.attack as attack_mod
    import services.toolkit as toolkit_mod

    monkeypatch.setattr(toolkit_mod, "ToolkitRunner", FakeRunner)
    monkeypatch.setattr(attack_mod, "AttackService", FakeAttackSvc)

    # discovery: 2 hosts, one out of scope
    class FakeFinder:
        def __init__(self, msf_, interface=None):
            pass

        @staticmethod
        def neighbors_to_dicts(found):
            return found

        def discover(self, cidr):
            from schemas import Neighbor

            return [
                Neighbor(ip="192.168.1.10", mac="01:02:03:04:05:09"),
                Neighbor(ip="10.9.9.9", mac="01:02:03:04:05:0b"),
            ]

    import services.discovery as discovery_mod

    monkeypatch.setattr(discovery_mod, "NeighborFinder", FakeFinder)

    job: dict = {
        "id": "ap",
        "status": "running",
        "stage": "discovery",
        "progress": 0.0,
        "message": "",
        "hosts": {},
        "log": [],
        "aborted": False,
    }
    scope = ["192.168.1.0/24"]
    _run_autopilot(job, msf, scope)
    return job, _AUTOPILOT_STATE


def test_autopilot_requires_scope(client, clean_db):
    r = client.post("/api/autopilot/start")
    assert r.status_code == 403
    assert "engagement" in r.json()["detail"]


def test_autopilot_status_idle(client, clean_db):
    from routers.scan import _AUTOPILOT_STATE

    _AUTOPILOT_STATE["job"] = None
    r = client.get("/api/autopilot/status")
    assert r.status_code == 200
    assert r.json()["status"] == "idle"


def test_autopilot_full_loop(clean_db, monkeypatch):
    import app_state
    from routers.scan import _AUTOPILOT_STATE

    eng = _make_engagement()  # scope 192.168.1.0/24
    app_state.active_engagement_id = eng["id"]

    class _FakeMsf(FakeMsf):
        pass

    job, _ = _run_autopilot_faked(clean_db, monkeypatch, _FakeMsf())
    _AUTOPILOT_STATE["job"] = None
    assert job["status"] == "done"
    hosts = job["hosts"]
    assert set(hosts) == {"192.168.1.10"}  # out-of-scope 10.9.9.9 skipped
    h = hosts["192.168.1.10"]
    assert h["stage"] == "pwned"
    assert h["session_id"] == "31"
    # fingerprint + password stages ran
    assert any("[passwords]" in line for line in job["log"])
    assert any(
        "[!!!] 192.168.1.10:22 login pi:raspberry" in line for line in job["log"]
    )
    assert any("[exploit]" in line for line in job["log"])
    # persisted artifacts
    assert "192.168.1.10" in clean_db._load_neighbor_hosts()
    assert clean_db.passattack_creds()["count"] == 1
    # scope enforced everywhere: out-of-scope host never recorded
    assert "10.9.9.9" not in clean_db._load_neighbor_hosts()


def test_autopilot_stop_flag_aborts_midway(clean_db, monkeypatch):
    from routers.scan import (
        _AUTOPILOT_STATE,
        _ensure_session_row,
        _run_autopilot,
    )

    _ensure_session_row()
    job: dict = {
        "id": "ap2",
        "status": "running",
        "stage": "discovery",
        "progress": 0.0,
        "message": "",
        "hosts": {},
        "log": [],
        "aborted": True,
    }
    _run_autopilot(job, FakeMsf(), ["192.168.1.0/24"])
    _AUTOPILOT_STATE["job"] = None
    assert job["status"] == "aborted"
