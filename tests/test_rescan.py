"""Backlog #5: per-engagement scheduled re-scans + MD digest."""

from __future__ import annotations

from typing import Any

from services.engagement import EngagementStore
from services.rescan import digest_markdown, due_engagements, run_due_rescans


def _eng(store: Any, scope: Any = None) -> Any:
    return store.create_engagement("acme", scope or ["10.0.0.0/24"])


def test_watch_interval_defaults_off_and_validates(tmp_path: Any) -> None:
    store = EngagementStore(tmp_path / "rescan.db")
    eng = _eng(store)
    assert store.get_watch_config(eng["id"])["interval"] == 0
    cfg = store.set_watch_config(eng["id"], interval=3600)
    assert cfg["interval"] == 3600
    cfg = store.set_watch_config(eng["id"], interval=999999)
    assert cfg["interval"] == 86400
    try:
        store.set_watch_config(eng["id"], interval="hourly")
    except ValueError:
        pass
    else:
        raise AssertionError("non-integer interval must raise")


def test_due_logic_respects_interval(tmp_path: Any) -> None:
    store = EngagementStore(tmp_path / "due.db")
    eng = _eng(store)
    assert due_engagements(store, now=1000.0) == []
    store.set_watch_config(eng["id"], interval=60)
    assert [d["id"] for d in due_engagements(store, now=1000.0)] == [eng["id"]]
    store.record_scheduled_pass(eng["id"], 1000.0)
    assert due_engagements(store, now=1030.0) == []
    assert [d["id"] for d in due_engagements(store, now=1061.0)] == [eng["id"]]


def test_digest_empty_state(tmp_path: Any) -> None:
    store = EngagementStore(tmp_path / "digest.db")
    eng = _eng(store)
    md = digest_markdown(store, eng["id"])
    assert md.startswith("# Lab Watch digest")
    assert "No estate changes" in md


def test_rescan_and_digest_router(tmp_path: Any, monkeypatch: Any) -> None:
    from contextlib import asynccontextmanager

    monkeypatch.setenv("H4K_REFRESH_CVE", "0")
    monkeypatch.setenv("H4K_SANDBOX", "1")
    monkeypatch.setenv("H4K_AUTO_SCAN", "0")
    import main as main_module
    from routers import engagement as eng_router

    store = EngagementStore(tmp_path / "rescan-router.db")
    monkeypatch.setattr(eng_router, "get_store", lambda: store)

    @asynccontextmanager
    async def _noop(_app: Any) -> Any:
        yield

    main_module.app.router.lifespan_context = _noop
    from fastapi.testclient import TestClient

    c = TestClient(main_module.app)
    eid = c.post("/api/engagement/sandbox-seed").json()["engagement"]["id"]
    r = c.post(f"/api/engagement/{eid}/watch/config", json={"interval": 60})
    assert r.status_code == 200 and r.json()["interval"] == 60
    r = c.post(f"/api/engagement/{eid}/rescan", json={})
    assert r.status_code == 200, r.text
    assert c.post("/api/engagement/nope/rescan", json={}).status_code == 404
    r = c.get(f"/api/engagement/{eid}/watch/digest?fmt=md")
    assert r.status_code == 200
    assert r.json()["content"].startswith("# Lab Watch digest")
    r = c.get(f"/api/engagement/{eid}/watch/digest?fmt=json")
    assert r.status_code == 200 and "changes" in r.json()
    assert c.get("/api/engagement/nope/watch/digest").status_code == 404
    due = run_due_rescans(store)
    assert due["ran"] >= 0
