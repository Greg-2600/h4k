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
