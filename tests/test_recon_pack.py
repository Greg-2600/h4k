"""Backlog #11: session recon pack + loot timeline."""

from __future__ import annotations

from typing import Any

from services.engagement import EngagementStore
from services.recon_pack import loot_timeline, session_pack


def test_session_pack_unknown() -> None:
    out = session_pack("nope")
    assert out["found"] is False and out["recon"] == {}
    assert session_pack("")["found"] is False


def test_loot_timeline_orders_kinds(tmp_path: Any, monkeypatch: Any) -> None:
    monkeypatch.setenv("H4K_DATA_DIR", str(tmp_path))
    store = EngagementStore(tmp_path / "loot.db")
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
    from services.flags import FlagStore

    FlagStore().record(eng["id"], "CTF{t1}", host="10.0.0.5")
    out = loot_timeline(store, eng["id"])
    assert out["count"] >= 2
    kinds = [e["kind"] for e in out["events"]]
    assert "credential" in kinds and "flag" in kinds
    ats = [e["at"] for e in out["events"]]
    assert ats == sorted(ats)
    try:
        loot_timeline(store, "nope")
    except ValueError:
        pass
    else:
        raise AssertionError("unknown engagement must raise")


def test_loot_timeline_router(tmp_path: Any, monkeypatch: Any) -> None:
    from contextlib import asynccontextmanager

    monkeypatch.setenv("H4K_REFRESH_CVE", "0")
    monkeypatch.setenv("H4K_SANDBOX", "1")
    monkeypatch.setenv("H4K_DATA_DIR", str(tmp_path))
    import main as main_module
    from routers import engagement as eng_router

    store = EngagementStore(tmp_path / "loot-router.db")
    monkeypatch.setattr(eng_router, "get_store", lambda: store)

    @asynccontextmanager
    async def _noop(_app: Any) -> Any:
        yield

    main_module.app.router.lifespan_context = _noop
    from fastapi.testclient import TestClient

    c = TestClient(main_module.app)
    eid = c.post("/api/engagement/sandbox-seed").json()["engagement"]["id"]
    r = c.get(f"/api/engagement/{eid}/loot-timeline")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["count"] >= 1
    assert any(e["kind"] == "credential" for e in body["events"])
    assert c.get("/api/engagement/nope/loot-timeline").status_code == 404
    r = c.get("/api/sessions/999/pack")
    assert r.status_code == 200 and r.json()["found"] is False
