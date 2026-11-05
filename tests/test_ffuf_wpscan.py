"""Backlog #31: ffuf/wpscan pack — explicit dir fuzz + plugin enum."""

from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient


def _client(monkeypatch: Any, tmp_path: Any) -> TestClient:
    from contextlib import asynccontextmanager

    monkeypatch.setenv("H4K_REFRESH_CVE", "0")
    monkeypatch.setenv("H4K_SANDBOX", "1")
    import main as main_module

    @asynccontextmanager
    async def _noop(_app: Any) -> Any:
        yield

    main_module.app.router.lifespan_context = _noop
    return TestClient(main_module.app)


def test_ffuf_sandbox_and_validation(tmp_path: Any, monkeypatch: Any) -> None:
    c = _client(monkeypatch, tmp_path)
    r = c.post("/api/ffuf", json={"target": "http://10.0.0.5/"})
    assert r.status_code == 200, r.text
    assert r.json()["tool"]["status"] == "sandbox"
    assert c.post("/api/ffuf", json={"target": ""}).status_code == 400
    assert c.post(
        "/api/ffuf", json={"target": "http://x/", "threads": 0}
    ).status_code in (200, 422)


def test_wpscan_sandbox_and_validation(tmp_path: Any, monkeypatch: Any) -> None:
    c = _client(monkeypatch, tmp_path)
    r = c.post("/api/wpscan", json={"target": "http://10.0.0.5/"})
    assert r.status_code == 200, r.text
    assert r.json()["tool"]["status"] == "sandbox"
    assert c.post("/api/wpscan", json={"target": ""}).status_code == 400
    assert (
        c.post(
            "/api/wpscan", json={"target": "http://x/", "enumerate": "bogus"}
        ).status_code
        == 400
    )
