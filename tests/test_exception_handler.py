"""Tests for the global exception handler."""

from contextlib import asynccontextmanager

from fastapi.testclient import TestClient


def _client(monkeypatch):
    monkeypatch.setenv("H4K_REFRESH_CVE", "0")
    import app_state
    import main as main_module

    app_state.msf_client = None

    @asynccontextmanager
    async def _noop(_app):
        yield

    main_module.app.router.lifespan_context = _noop
    return TestClient(main_module.app, raise_server_exceptions=False)


def test_unhandled_exception_returns_structured_json(monkeypatch):
    client = _client(monkeypatch)

    from fastapi import APIRouter

    router = APIRouter()

    @router.get("/__boom")
    def boom():
        raise RuntimeError("kaboom")

    client.app.include_router(router)
    r = client.get("/__boom")
    assert r.status_code == 500
    body = r.json()
    assert body["detail"] == "internal server error"
    assert "error_id" in body
    assert body["path"] == "/__boom"
    assert "kaboom" not in r.text
    assert "Traceback" not in r.text
