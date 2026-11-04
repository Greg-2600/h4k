"""Lab Watch API: baseline / changes / status endpoints (offline)."""

from contextlib import asynccontextmanager

import pytest
from fastapi.testclient import TestClient


class FakeMsf:
    pass


@pytest.fixture()
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("H4K_REFRESH_CVE", "0")
    monkeypatch.setenv("H4K_DATA_DIR", str(tmp_path))
    import app_state
    import main as main_module

    app_state.msf_client = FakeMsf()

    @asynccontextmanager
    async def _noop(_app):
        yield

    main_module.app.router.lifespan_context = _noop
    return TestClient(main_module.app)


def _engagement(client, scope="10.0.0.0/24"):
    r = client.post(
        "/api/engagement", json={"name": "watch", "scope": [scope], "notes": ""}
    )
    assert r.status_code == 200, r.text
    return r.json()


def _report():
    return {
        "hosts": [
            {
                "address": "10.0.0.5",
                "services": [
                    {"port": 22, "proto": "tcp", "service": "ssh", "version": "9.2p1"}
                ],
            }
        ],
        "vulns": [
            {"host": "10.0.0.5", "name": "CVE-2021-1", "port": 22, "severity": "high"}
        ],
    }


def test_baseline_from_raw_report(client):
    eng = _engagement(client)
    r = client.post(f"/api/engagement/{eng['id']}/watch/baseline", json=_report())
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["diff"]["first_baseline"] is True
    r = client.get(f"/api/engagement/{eng['id']}/watch/status")
    assert r.json()["snapshots"] == 1


def test_baseline_from_job_id(client):
    from routers.scan import JOBS

    eng = _engagement(client)
    JOBS["watchjob1"] = {"report": _report()}
    try:
        r = client.post(
            f"/api/engagement/{eng['id']}/watch/baseline", json={"job_id": "watchjob1"}
        )
        assert r.status_code == 200, r.text
        assert r.json()["diff"]["first_baseline"] is True
    finally:
        JOBS.pop("watchjob1", None)


def test_changes_show_new_service(client):
    eng = _engagement(client)
    client.post(f"/api/engagement/{eng['id']}/watch/baseline", json=_report())
    report = _report()
    report["hosts"][0]["services"].append(
        {"port": 443, "proto": "tcp", "service": "https"}
    )
    r = client.post(f"/api/engagement/{eng['id']}/watch/baseline", json=report)
    assert r.json()["notable"] is True
    r = client.get(f"/api/engagement/{eng['id']}/watch/changes")
    assert r.status_code == 200
    changes = r.json()["changes"]
    assert len(changes) == 2
    assert changes[0]["diff"]["new_services"][0]["port"] == 443


def test_baseline_requires_report(client):
    eng = _engagement(client)
    r = client.post(
        f"/api/engagement/{eng['id']}/watch/baseline", json={"nonsense": True}
    )
    assert r.status_code == 400


def test_watch_unknown_engagement_is_404(client):
    assert (
        client.post("/api/engagement/nope/watch/baseline", json=_report()).status_code
        == 404
    )
    assert client.get("/api/engagement/nope/watch/changes").status_code == 404
    assert client.get("/api/engagement/nope/watch/status").status_code == 404


def test_config_round_trip(client):
    eng = _engagement(client)
    r = client.get(f"/api/engagement/{eng['id']}/watch/config")
    assert r.status_code == 200 and r.json()["mode"] == "notable"
    r = client.post(
        f"/api/engagement/{eng['id']}/watch/config", json={"mode": "all", "retain": 7}
    )
    assert r.status_code == 200, r.text
    assert r.json() == {"mode": "all", "retain": 7}
    r = client.post(f"/api/engagement/{eng['id']}/watch/config", json={"mode": "loud"})
    assert r.status_code == 400
    assert client.get("/api/engagement/nope/watch/config").status_code == 404


def test_trends_endpoint(client):
    eng = _engagement(client)
    client.post(f"/api/engagement/{eng['id']}/watch/baseline", json=_report())
    r = client.get(f"/api/engagement/{eng['id']}/watch/trends")
    assert r.status_code == 200, r.text
    hosts = r.json()["hosts"]
    assert hosts["10.0.0.5"]["present"] is True
    assert "22/tcp" in hosts["10.0.0.5"]["services"]


def test_verify_needs_finished_scan(client):
    eng = _engagement(client)
    r = client.post(f"/api/engagement/{eng['id']}/watch/verify", json={})
    assert r.status_code == 400


def test_verify_snapshots_latest_scan(client):
    from routers.scan import JOBS

    eng = _engagement(client)
    client.post(f"/api/engagement/{eng['id']}/watch/baseline", json=_report())
    JOBS["watchjob2"] = {
        "status": "done",
        "report": _report(),
        "created_at": "2099-01-01T00:00:00",
    }
    try:
        r = client.post(f"/api/engagement/{eng['id']}/watch/verify", json={})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["job_id"] == "watchjob2"
        assert body["diff"]["first_baseline"] is False
    finally:
        JOBS.pop("watchjob2", None)
