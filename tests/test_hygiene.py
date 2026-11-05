"""Backlog #4: credential hygiene report."""

from __future__ import annotations

from typing import Any

from services.engagement import EngagementStore
from services.hygiene import _is_weak, hygiene_report


def _store(tmp_path: Any) -> Any:
    return EngagementStore(tmp_path / "hygiene.db")


def _eng(store: Any) -> Any:
    return store.create_engagement("acme", ["10.0.0.0/24"])


def test_is_weak_flags_short_and_common() -> None:
    assert _is_weak("abc") is True
    assert _is_weak("password") is True
    assert _is_weak("s3cure!P@ssw0rd-2024") is False


def test_reuse_detected(tmp_path: Any) -> None:
    store, eng = _store(tmp_path), None
    eng = _eng(store)
    for host in ("10.0.0.5", "10.0.0.9"):
        store.record_credential(
            eng["id"],
            "root",
            "s3cure!P@ssw0rd-2024",
            "ssh",
            origin_host=host,
            origin_port=22,
            verified=True,
        )
    out = hygiene_report(store, eng["id"])
    assert out["summary"]["reuse"] == 1
    assert out["summary"]["score"] < 100
    assert any(f["kind"] == "reuse" for f in out["findings"])


def test_no_findings_for_unique_strong(tmp_path: Any) -> None:
    store = _store(tmp_path)
    eng = _eng(store)
    store.record_credential(
        eng["id"],
        "ops",
        "s3cure!P@ssw0rd-2024",
        "ssh",
        origin_host="10.0.0.5",
        origin_port=22,
        verified=True,
    )
    out = hygiene_report(store, eng["id"])
    assert out["summary"]["findings"] == 0
    assert out["summary"]["score"] == 100


def test_hygiene_router(tmp_path: Any, monkeypatch: Any) -> None:
    from contextlib import asynccontextmanager

    monkeypatch.setenv("H4K_REFRESH_CVE", "0")
    monkeypatch.setenv("H4K_SANDBOX", "1")
    import main as main_module
    from routers import engagement as eng_router

    store = EngagementStore(tmp_path / "hygiene-router.db")
    monkeypatch.setattr(eng_router, "get_store", lambda: store)

    @asynccontextmanager
    async def _noop(_app: Any) -> Any:
        yield

    main_module.app.router.lifespan_context = _noop
    from fastapi.testclient import TestClient

    c = TestClient(main_module.app)
    status = c.post("/api/engagement/sandbox-seed")
    assert status.status_code == 200
    eid = status.json()["engagement"]["id"]
    r = c.get(f"/api/engagement/{eid}/hygiene")
    assert r.status_code == 200
    body = r.json()
    assert body["summary"]["reuse"] >= 1
    assert c.get("/api/engagement/nope/hygiene").status_code == 404
