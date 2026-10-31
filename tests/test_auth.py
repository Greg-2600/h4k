"""Tests for the optional API-key authentication."""

from fastapi.testclient import TestClient


def _client(monkeypatch, key=None):
    monkeypatch.setenv("H4K_REFRESH_CVE", "0")
    if key is None:
        monkeypatch.delenv("H4K_API_KEY", raising=False)
    else:
        monkeypatch.setenv("H4K_API_KEY", key)
    # neutralise lifespan
    from contextlib import asynccontextmanager

    import main as main_module

    @asynccontextmanager
    async def _noop(_app):
        yield

    main_module.app.router.lifespan_context = _noop
    return TestClient(main_module.app)


def test_auth_disabled_by_default(monkeypatch):
    client = _client(monkeypatch, key=None)
    r = client.get("/api/health")
    assert r.status_code == 200


def test_auth_required_when_key_set(monkeypatch):
    client = _client(monkeypatch, key="secret-key")
    r = client.get("/api/health")
    # health is exempt
    assert r.status_code == 200

    r = client.get("/api/capabilities")
    assert r.status_code == 401

    r = client.get("/api/capabilities", headers={"X-API-Key": "wrong"})
    assert r.status_code == 401

    r = client.get("/api/capabilities", headers={"X-API-Key": "secret-key"})
    assert r.status_code == 200


def test_auth_exempt_paths(monkeypatch):
    client = _client(monkeypatch, key="secret-key")
    for path in ("/", "/docs", "/openapi.json", "/static/app.js"):
        r = client.get(path)
        assert r.status_code != 401, path


def test_auth_rejects_empty_key(monkeypatch):
    client = _client(monkeypatch, key="secret-key")
    r = client.post("/api/engagement", json={"name": "x", "scope": ["10.0.0.0/24"]})
    assert r.status_code == 401
    assert "api key" in r.json().get("detail", "").lower()
