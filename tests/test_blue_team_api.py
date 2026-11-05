"""Blue-team handoff endpoints (offline)."""

from contextlib import asynccontextmanager

import pytest
import yaml
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
        "/api/engagement", json={"name": "handoff", "scope": [scope], "notes": ""}
    )
    assert r.status_code == 200, r.text
    return r.json()


def _seed_vuln(client, eng_id):
    r = client.post(
        f"/api/engagement/{eng_id}/ingest",
        json={
            "hosts": [
                {"address": "10.0.0.5", "services": [{"port": 22, "service": "ssh"}]}
            ],
            "vulns": [
                {
                    "host": "10.0.0.5",
                    "name": "OpenSSH outdated",
                    "port": 22,
                    "severity": "high",
                }
            ],
        },
    )
    assert r.status_code == 200, r.text


def test_navigator_layer_endpoint(client):
    eng = _engagement(client)
    _seed_vuln(client, eng["id"])
    r = client.get(f"/api/engagement/{eng['id']}/handoff/navigator")
    assert r.status_code == 200, r.text
    layer = r.json()
    assert layer["domain"] == "enterprise-attack"
    ids = [t["techniqueID"] for t in layer["techniques"]]
    assert "T1021" in ids  # ssh keyword maps to lateral movement


def test_sigma_endpoint_returns_tunable_bundle(client):
    eng = _engagement(client)
    _seed_vuln(client, eng["id"])
    r = client.get(f"/api/engagement/{eng['id']}/handoff/sigma")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["count"] >= 1
    assert all(x["status"] == "experimental" for x in body["rules"])
    docs = list(yaml.safe_load_all(body["yaml"]))
    assert len(docs) == body["count"]


def test_summary_endpoint(client):
    eng = _engagement(client)
    _seed_vuln(client, eng["id"])
    r = client.get(f"/api/engagement/{eng['id']}/handoff/summary")
    assert r.status_code == 200, r.text
    assert "T1021" in r.json()["markdown"]


def test_handoff_unknown_engagement_404s(client):
    assert client.get("/api/engagement/nope/handoff/navigator").status_code == 404
    assert client.get("/api/engagement/nope/handoff/sigma").status_code == 404
    assert client.get("/api/engagement/nope/handoff/summary").status_code == 404
