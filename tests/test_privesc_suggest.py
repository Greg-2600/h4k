"""Backlog #27: privesc suggester (read-only lin/winPEAS-style checklist)."""

from __future__ import annotations

from typing import Any

from services.privesc_suggest import sandbox_suggest, suggest


def test_suggest_shape() -> None:
    out = suggest()
    assert out["count"] == 10
    ids = [c["id"] for c in out["checks"]]
    assert ids == [
        "kernel",
        "suid",
        "caps",
        "sudo",
        "path",
        "cron",
        "nfs",
        "groups",
        "shadow",
        "modules",
    ]
    for c in out["checks"]:
        assert c["status"] in ("pass", "fail", "info")
        assert c["title"] and "detail" in c and "fix" in c


def test_suggest_needs_no_password_or_writes(tmp_path: Any, monkeypatch: Any) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("PATH", "/nonexistent-xyz")
    out = suggest()
    assert out["count"] == 10  # every check degrades, none raise


def test_sandbox_suggest() -> None:
    out = sandbox_suggest()
    assert out["count"] == 4 and out["fails"] == 2 and out["sandbox"] is True


def test_suggest_router_sandbox(tmp_path: Any, monkeypatch: Any) -> None:
    from contextlib import asynccontextmanager

    monkeypatch.setenv("H4K_REFRESH_CVE", "0")
    monkeypatch.setenv("H4K_SANDBOX", "1")
    import main as main_module

    @asynccontextmanager
    async def _noop(_app: Any) -> Any:
        yield

    main_module.app.router.lifespan_context = _noop
    from fastapi.testclient import TestClient

    c = TestClient(main_module.app)
    r = c.post("/api/privesc/suggest", json={})
    assert r.status_code == 200, r.text
    assert r.json()["count"] == 4
