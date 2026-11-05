"""Backlog #25: false-positive tuner (suppress with reason + expiry)."""

from __future__ import annotations

from typing import Any

from services.engagement import EngagementStore, ScopeError


def _eng(store: Any) -> Any:
    eng = store.create_engagement("acme", ["10.0.0.0/24"])
    store.record_vuln(eng["id"], "10.0.0.5", {"name": "Old Lead", "severity": "low"})
    return eng


def test_suppress_and_expiry(tmp_path: Any) -> None:
    store = EngagementStore(tmp_path / "sup.db")
    eng = _eng(store)
    out = store.suppress_vuln(
        eng["id"], "10.0.0.5", "Old Lead", reason="patched", days=7, actor="tester"
    )
    assert set(out) >= {"host", "name", "reason", "expires_at", "actor"}
    assert out["reason"] == "patched"
    eff = store.effective_vulns(eng["id"])
    assert eff[0]["suppressed"] is True
    # expired suppressions are inert, live ones hold
    from datetime import UTC, datetime, timedelta

    assert ("10.0.0.5", "Old Lead") not in store.suppressed_keys(
        eng["id"], now="2000-01-01T00:00:00+00:00"
    )
    assert ("10.0.0.5", "Old Lead") in store.suppressed_keys(eng["id"])
    far = (datetime.now(UTC) + timedelta(days=365)).isoformat()
    assert ("10.0.0.5", "Old Lead") not in store.suppressed_keys(eng["id"], now=far)
    assert store.unsuppress_vuln(eng["id"], "10.0.0.5", "Old Lead") is True
    assert store.unsuppress_vuln(eng["id"], "10.0.0.5", "Old Lead") is False
    assert store.effective_vulns(eng["id"])[0]["suppressed"] is False


def test_suppress_validation(tmp_path: Any) -> None:
    import pytest

    store = EngagementStore(tmp_path / "sup2.db")
    eng = _eng(store)
    with pytest.raises(ValueError):
        store.suppress_vuln(eng["id"], "10.0.0.5", "X", reason="")
    with pytest.raises(ValueError):
        store.suppress_vuln(eng["id"], "10.0.0.5", "X", reason="r", days=0)
    with pytest.raises(ScopeError):
        store.suppress_vuln(eng["id"], "8.8.8.8", "X", reason="r")
    assert store.list_suppressions(eng["id"]) == []


def test_suppress_router(tmp_path: Any, monkeypatch: Any) -> None:
    from contextlib import asynccontextmanager

    monkeypatch.setenv("H4K_REFRESH_CVE", "0")
    import main as main_module
    from routers import engagement as eng_router

    store = EngagementStore(tmp_path / "sup-router.db")
    monkeypatch.setattr(eng_router, "get_store", lambda: store)

    @asynccontextmanager
    async def _noop(_app: Any) -> Any:
        yield

    main_module.app.router.lifespan_context = _noop
    from fastapi.testclient import TestClient

    c = TestClient(main_module.app)
    eid = c.post(
        "/api/engagement", json={"name": "acme", "scope": ["10.0.0.0/24"]}
    ).json()["id"]
    store.record_vuln(eid, "10.0.0.5", {"name": "V", "severity": "medium"})
    r = c.post(
        f"/api/engagement/{eid}/vulns/suppress",
        json={"host": "10.0.0.5", "name": "V", "reason": "patched", "days": 7},
    )
    assert r.status_code == 200, r.text
    assert r.json()["expires_at"]
    r = c.get(f"/api/engagement/{eid}/vulns/effective")
    assert r.json()["vulns"][0]["suppressed"] is True
    r = c.get(f"/api/engagement/{eid}/vulns/effective?hide_suppressed=true")
    assert r.json()["count"] == 0
    r = c.get(f"/api/engagement/{eid}/vulns/suppressions")
    assert len(r.json()["suppressions"]) == 1
    assert (
        c.request(
            "DELETE",
            f"/api/engagement/{eid}/vulns/suppress",
            json={"host": "10.0.0.5", "name": "V"},
        ).status_code
        == 200
    )
    assert (
        c.request(
            "DELETE",
            f"/api/engagement/{eid}/vulns/suppress",
            json={"host": "10.0.0.5", "name": "V"},
        ).status_code
        == 404
    )
    assert (
        c.post(
            f"/api/engagement/{eid}/vulns/suppress", json={"host": "10.0.0.5"}
        ).status_code
        == 400
    )
    assert c.get("/api/engagement/nope/vulns/effective").status_code == 404
