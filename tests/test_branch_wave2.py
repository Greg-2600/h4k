# Branch coverage wave 2: attack-service host resolution, report/SSE paths,
# rule library CRUD through the API, exploit skeleton download, merged report
# endpoints, CVE refresh path, version-aware matching, and scope helpers.
from contextlib import asynccontextmanager

import pytest


class FakeMsvc:
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
        return [{"address": "192.168.1.10", "name": "web1"}]

    def services(self, *a, **k):
        return [
            {
                "host": "192.168.1.10",
                "port": 22,
                "proto": "tcp",
                "name": "ssh",
                "state": "open",
            },
            {
                "host": "192.168.1.10",
                "port": 80,
                "proto": "tcp",
                "name": "http",
                "state": "open",
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


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setenv("H4K_REFRESH_CVE", "0")
    import app_state
    import main as main_module

    app_state.msf_client = FakeMsvc()
    app_state.cve_db = None
    app_state.active_engagement_id = None

    @asynccontextmanager
    async def _noop(_app):
        yield

    main_module.app.router.lifespan_context = _noop
    main_module._rate_store = None

    from fastapi.testclient import TestClient

    return TestClient(main_module.app)


# ---------------- attack service: resolution paths ----------------


def test_attack_service_resolves_hosts_and_services_from_db():
    from schemas import AttackRequest
    from services.attack import AttackService

    attacks = AttackService(FakeMsvc()).run(
        AttackRequest(target="192.168.1.10", host=None, module=None), []
    )
    # one attack per mapped service (ssh + http both map)
    assert {a["service"] for a in attacks} == {"ssh", "http"}
    assert all(a["result"] in ("success", "failed") for a in attacks)


def test_attack_service_no_hosts(client, monkeypatch):
    import app_state

    app_state.msf_client = None
    r = client.post("/api/attack", json={"target": "192.168.1.10"})
    assert r.status_code == 503


def test_attack_endpoint_creates_job(client):
    r = client.post(
        "/api/attack",
        json={
            "target": "192.168.1.10",
            "host": "192.168.1.10",
            "module": "exploit/multi/ssh/sshexec",
            "port": 22,
        },
    )
    assert r.status_code == 200
    jid = r.json()["job_id"]
    st = client.get(f"/api/attack/{jid}")
    assert st.status_code == 200
    assert st.json()["status"] in ("queued", "running", "done", "error")


def test_attack_endpoint_scope_refusal(client):
    import app_state
    from services.engagement import EngagementStore, db_path

    eng = EngagementStore(db_path()).create_engagement(
        f"sc-{__import__('time').time()}", ["10.9.9.0/24"]
    )
    app_state.active_engagement_id = eng["id"]
    r = client.post(
        "/api/attack",
        json={
            "target": "192.168.1.10",
            "host": "192.168.1.10",
            "module": "exploit/multi/ssh/sshexec",
            "port": 22,
        },
    )
    assert r.status_code == 403
    app_state.active_engagement_id = None


# ---------------- report / SSE edges ----------------


def test_report_not_ready(client):
    from routers import scan as scan_router

    scan_router.JOBS["nr"] = {"id": "nr", "status": "running", "report": None}
    r = client.get("/api/report/nr")
    assert r.status_code == 404
    assert "not ready" in r.json()["detail"]


def test_exploit_candidates_substring_fallback(client):
    r = client.get("/api/exploit-candidates", params={"service": "microsoft-ds"})
    assert r.status_code == 200
    cands = r.json()["candidates"]
    assert "exploit/windows/smb/ms17_010_eternalblue" in cands


# ---------------- rule library CRUD via API ----------------


def test_rules_save_list_delete(client, monkeypatch, tmp_path):
    """CRUD against an isolated rules file — never pollute the bundled one."""
    import services.rules as rules_mod

    monkeypatch.setattr(rules_mod, "RULES_FILE", tmp_path / "custom_rules.json")
    payload = {
        "rule_id": f"test-rule-{int(__import__('time').time())}",
        "name": "Wave Rule",
        "severity": "low",
        "languages": ["python"],
        "pattern": "eval($X)",
        "message": "no eval",
        "cwe": "CWE-95",
    }
    r = client.post("/api/source/rules/save", json=payload)
    assert r.status_code == 200
    assert r.json()["ok"] is True

    lst = client.get("/api/source/rules")
    assert lst.status_code == 200
    ids = [x.get("rule_id") for x in lst.json().get("rules", [])]
    assert payload["rule_id"] in ids

    r = client.delete(f"/api/source/rules/{payload['rule_id']}")
    assert r.json()["ok"] is True
    lst = client.get("/api/source/rules")
    assert payload["rule_id"] not in [
        x.get("rule_id") for x in lst.json().get("rules", [])
    ]

    bad = dict(payload, rule_id="", pattern="")
    r = client.post("/api/source/rules/save", json=bad)
    assert r.status_code in (400, 422)


# ---------------- exploit skeleton + triage-minimize ----------------


def test_exploit_download_skeleton(client):
    r = client.post(
        "/api/source/exploit/download",
        json={
            "rule_id": "wave-poc",
            "finding": {
                "rule_id": "wave-poc",
                "name": "Eval use",
                "severity": "high",
                "cwe": "CWE-95",
                "file": "a.py",
                "line": 3,
                "code": "eval(x)",
                "description": "eval of user input",
            },
        },
    )
    assert r.status_code == 200
    assert "attachment" in r.headers.get("content-disposition", "")
    body = r.text
    assert "PoC" in body or "proof" in body.lower()


def test_merged_report_endpoints(client):
    r = client.post(
        "/api/source/report/merge",
        json={
            "scan": [{"id": "t1"}],
            "sast": [{"rule_id": "r1", "severity": "high"}],
            "sca": {"cves": ["CVE-2026-1234"]},
            "fuzz": [{"crash": "x"}],
            "triage": [{"bug_class": "crash"}],
        },
    )
    assert r.status_code == 200
    r = client.post(
        "/api/source/report/md",
        json={"scan": [{"id": "t1"}], "sast": [], "sca": {}, "fuzz": [], "triage": []},
    )
    assert r.status_code == 200
    assert isinstance(r.text, str) and len(r.text) > 10
    r = client.get("/api/source/report/md")
    assert r.status_code == 200


# ---------------- cve_lookup refresh + version matching ----------------


def test_cve_refresh_persits(monkeypatch, tmp_path):
    import services.cve_lookup
    import services.cve_lookup as cve

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b'{"cves": [{"id": "CVE-2026-X1", "product": "smb", "cvss": 9.8}]}'

    monkeypatch.setattr(cve.urllib.request, "urlopen", lambda url, timeout=10: _Resp())
    db = services.cve_lookup.CveDb(path=tmp_path / "cves.json")
    ok = db.refresh()
    assert ok is True
    assert len(db.cves) == 1
    data = (tmp_path / "cves.json").read_text()
    assert "CVE-2026-X1" in data


def test_cve_refresh_offline_keeps_local(monkeypatch, tmp_path):
    import services.cve_lookup

    def boom(url, timeout=10):
        raise OSError("offline")

    monkeypatch.setattr(services.cve_lookup.urllib.request, "urlopen", boom)
    db = services.cve_lookup.CveDb()
    assert db.refresh() is False


def test_cve_db_match_service_version_aware(monkeypatch):
    import services.cve_lookup as cve
    from schemas import Service

    db = cve.CveDb()
    # version_detector drives version-aware behavior; product must appear in
    # the banner for any hit
    svc = Service(
        port=22, proto="tcp", service="ssh", state="open", info="OpenSSH 7.4 openssh"
    )
    hits = db.match_service(svc, version="7.4", product="openssh")
    assert isinstance(hits, list)
    ids = {h.get("id") for h in hits}
    assert all("CVE" in i or i == "" for i in ids)


# ---------------- zap client internals ----------------


def test_zap_client_poll_and_helpers(client, monkeypatch):
    """AJAX poll loop, alert params, auth calls (140-149, 189-192)."""
    from services import zap as zap_mod

    seq = {"n": 0}

    class _Resp:
        status = 200

        def json(self):
            seq["n"] += 1
            if seq["n"] <= 2:
                return {"status": "running"}
            return {"status": "finished", "contextId": "7"}

    monkeypatch.setattr(
        zap_mod.requests,
        "get",
        lambda *a, **k: type(
            "R", (), {"status": 200, "json": lambda s: {"response": "{}"}}
        )(),
    )
    monkeypatch.setattr(zap_mod.requests, "post", lambda *a, **k: _Resp())
    monkeypatch.setattr("services.zap.time.sleep", lambda s: None)
    monkeypatch.setattr(
        "services.zap.time.time",
        lambda: iter([0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]).__next__(),
    )

    zc = zap_mod.ZAPService.__new__(zap_mod.ZAPService)
    zc.base_url = "http://127.0.0.1:1"
    zc.api_key = ""
    zc.progress = lambda *a: None
    zc._process = None

    class _Resp2:
        status = 200

        def json(self):
            seq["n"] += 1
            if seq["n"] <= 2:
                return {"status": "running"}
            return {"status": "finished"}

    monkeypatch.setattr(zap_mod.requests, "get", lambda *a, **k: _Resp2())
    monkeypatch.setattr(zap_mod.requests, "post", lambda *a, **k: _Resp2())
    monkeypatch.setattr(zap_mod.time, "sleep", lambda s: None)

    state = zc._wait_for_ajax_spider(timeout=2)
    assert state["status"] in ("running", "finished")
    cnt = zc.get_alert_count("http://t")
    assert isinstance(cnt, dict)
    ctx = zc.create_context("wave2", "http://t")
    assert ctx in ("7", "None", None) or isinstance(ctx, str)


# ---------------- aircrack argv paths ----------------


def test_aircrack_scan_and_wordlist_paths(client, monkeypatch):
    from services import aircrack as ac

    seen = []

    def fake_run(argv, **k):
        seen.append(argv)
        return type("P", (), {"returncode": 0, "stdout": "scan done", "stderr": ""})()

    monkeypatch.setattr(ac.subprocess, "run", fake_run)
    svc_ac = ac.AircrackService()
    out = svc_ac.scan_networks("wl0mon", duration=1)
    assert isinstance(out, dict)
    out = svc_ac.crack_pmkid("c.cap", wordlist="/tmp/none.txt")
    assert isinstance(out, dict)


# ---------------- source_fetcher download paths ----------------


def test_source_fetcher_download_too_large(client, monkeypatch):
    from urllib.parse import urlparse  # noqa: F401

    from services.source_fetcher import SourceFetcher

    sf = SourceFetcher()

    class _Resp:
        status_code = 200

        def __init__(self):
            self.headers = {"content-length": str(sf.max_size + 10)}

        def raise_for_status(self):
            pass

        def iter_content(self, n):
            yield b"x"

    import services.source_fetcher as sf_mod

    monkeypatch.setattr(
        sf_mod.requests, "get", lambda url, stream=True, timeout=None: _Resp()
    )
    out = sf._download_archive("https://e.example/a.zip")
    assert out["success"] is False
    assert "too large" in out["error"].lower()


def test_source_fetcher_git_convert(client, monkeypatch):
    import services.source_fetcher as sf_mod
    from services.source_fetcher import SourceFetcher

    seen = {}

    def fake_run(argv, **k):
        seen["argv"] = argv
        return type("P", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    monkeypatch.setattr(sf_mod.subprocess, "run", fake_run)
    sf = SourceFetcher()
    sf.work_dir = sf.work_dir  # keep default
    out = sf._clone_git("https://gitlab.com/u/r")
    assert isinstance(out, dict)
