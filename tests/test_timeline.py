"""Backlog #13: engagement timeline view."""

from __future__ import annotations

from typing import Any

from services.engagement import EngagementStore
from services.timeline import timeline


def test_timeline_empty_engagement(tmp_path: Any) -> None:
    store = EngagementStore(tmp_path / "tl.db")
    eng = store.create_engagement("acme", ["10.0.0.0/24"])
    out = timeline(store, eng["id"])
    assert out["count"] == 0 and out["events"] == []
    try:
        timeline(store, "nope")
    except ValueError:
        pass
    else:
        raise AssertionError("unknown engagement must raise")


def test_timeline_orders_credential_and_objective(tmp_path: Any) -> None:
    store = EngagementStore(tmp_path / "tl2.db")
    eng = store.create_engagement("acme", ["10.0.0.0/24"])
    store.record_credential(
        eng["id"],
        "root",
        "toor",
        "ssh",
        origin_host="10.0.0.5",
        origin_port=22,
        verified=True,
    )
    store.add_crown_jewel(eng["id"], "10.0.0.9", "db", 80)
    out = timeline(store, eng["id"])
    kinds = [e["kind"] for e in out["events"]]
    assert "credential" in kinds and "objective" in kinds
    ats = [e["at"] for e in out["events"]]
    assert ats == sorted(ats)


def test_timeline_kind_filter(tmp_path: Any) -> None:
    store = EngagementStore(tmp_path / "tl3.db")
    eng = store.create_engagement("acme", ["10.0.0.0/24"])
    store.record_credential(
        eng["id"],
        "root",
        "toor",
        "ssh",
        origin_host="10.0.0.5",
        origin_port=22,
        verified=True,
    )
    out = timeline(store, eng["id"], kinds=["objective"])
    assert all(e["kind"] == "objective" for e in out["events"])
    assert timeline(store, eng["id"], kinds=["nope", "flag"])["count"] >= 0


def test_timeline_router(tmp_path: Any, monkeypatch: Any) -> None:
    from contextlib import asynccontextmanager

    monkeypatch.setenv("H4K_REFRESH_CVE", "0")
    monkeypatch.setenv("H4K_SANDBOX", "1")
    monkeypatch.setenv("H4K_DATA_DIR", str(tmp_path))
    import main as main_module
    from routers import engagement as eng_router

    store = EngagementStore(tmp_path / "tl-router.db")
    monkeypatch.setattr(eng_router, "get_store", lambda: store)

    @asynccontextmanager
    async def _noop(_app: Any) -> Any:
        yield

    main_module.app.router.lifespan_context = _noop
    from fastapi.testclient import TestClient

    c = TestClient(main_module.app)
    eid = c.post("/api/engagement/sandbox-seed").json()["engagement"]["id"]
    r = c.get(f"/api/engagement/{eid}/timeline")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["count"] >= 1
    assert any(e["kind"] == "credential" for e in body["events"])
    r = c.get(f"/api/engagement/{eid}/timeline?kinds=objective")
    assert r.status_code == 200
    assert all(e["kind"] == "objective" for e in r.json()["events"])
    assert c.get("/api/engagement/nope/timeline").status_code == 404
