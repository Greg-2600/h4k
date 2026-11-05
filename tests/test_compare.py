"""Backlog #15: engagement compare/diff across runs."""

from __future__ import annotations

from typing import Any

from services.compare import compare_engagements
from services.engagement import EngagementStore


def _eng(store: Any, name: str, vuln: str) -> Any:
    eng = store.create_engagement(name, ["10.0.0.0/24"])
    store.ingest_scan(
        eng["id"],
        {
            "hosts": [
                {"address": "10.0.0.5", "services": [{"port": 22, "service": "ssh"}]}
            ],
            "credentials": [],
            "vulns": [{"host": "10.0.0.5", "name": vuln, "severity": "high"}],
        },
    )
    return eng


def test_compare_vulns_added_and_cleared(tmp_path: Any) -> None:
    store = EngagementStore(tmp_path / "cmp.db")
    a = _eng(store, "week1", "Old Vuln")
    b = _eng(store, "week2", "New Vuln")
    out = compare_engagements(store, a["id"], b["id"])
    assert out["vulns"]["added_count"] == 1
    assert out["vulns"]["cleared_count"] == 1
    assert out["vulns"]["added"][0]["name"] == "New Vuln"
    try:
        compare_engagements(store, "nope", b["id"])
    except ValueError:
        pass
    else:
        raise AssertionError("unknown engagement must raise")


def test_compare_identical_is_empty(tmp_path: Any) -> None:
    store = EngagementStore(tmp_path / "cmp2.db")
    a = _eng(store, "w1", "Same Vuln")
    out = compare_engagements(store, a["id"], a["id"])
    assert out["vulns"]["added_count"] == 0
    assert out["vulns"]["cleared_count"] == 0


def test_compare_router(tmp_path: Any, monkeypatch: Any) -> None:
    from contextlib import asynccontextmanager

    monkeypatch.setenv("H4K_REFRESH_CVE", "0")
    monkeypatch.setenv("H4K_SANDBOX", "1")
    import main as main_module
    from routers import engagement as eng_router

    store = EngagementStore(tmp_path / "cmp-router.db")
    monkeypatch.setattr(eng_router, "get_store", lambda: store)

    @asynccontextmanager
    async def _noop(_app: Any) -> Any:
        yield

    main_module.app.router.lifespan_context = _noop
    from fastapi.testclient import TestClient

    c = TestClient(main_module.app)
    a = c.post("/api/engagement/sandbox-seed").json()["engagement"]["id"]
    b = c.post("/api/engagement/sandbox-seed").json()["engagement"]["id"]
    assert a != b
    r = c.get(f"/api/engagement/compare?from_id={a}&to_id={b}")
    assert r.status_code == 200, r.text
    assert r.json()["from_id"] == a
    assert c.get("/api/engagement/compare").status_code == 400
    assert c.get(f"/api/engagement/compare?from_id=nope&to_id={b}").status_code == 404
    # static route wins over /{engagement_id}
    assert c.get("/api/engagement/nope").status_code == 404
