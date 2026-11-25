"""Backlog #19: mDNS/SSDP persistent map."""

from __future__ import annotations

from typing import Any

from services.engagement import EngagementStore
from services.zeroconf_map import normalize, persist


def test_normalize_mdns() -> None:
    out = normalize(
        [{"ip": "10.0.0.5", "names": ["web01"], "models": ["QEMU"]}], "mdns"
    )
    assert out[0]["vendor"] == "QEMU"
    assert "mdns:web01" in out[0]["technology"]
    assert normalize([{"names": []}], "mdns") == []


def test_normalize_ssdp() -> None:
    out = normalize(
        [
            {
                "ip": "10.0.0.42",
                "names": [],
                "models": [],
                "server": "Linux UPnP",
                "location": "http://x/desc.xml",
            }
        ],
        "ssdp",
    )
    assert "upnp" in out[0]["technology"]


def test_persist_scope_checked(tmp_path: Any) -> None:
    store = EngagementStore(tmp_path / "zc.db")
    eng = store.create_engagement("acme", ["10.0.0.0/24"])
    out = persist(
        store,
        eng["id"],
        [
            {"ip": "10.0.0.5", "names": ["a"], "models": []},
            {"ip": "8.8.8.8", "names": ["b"], "models": []},
        ],
        "mdns",
    )
    assert out["recorded"] == 1 and out["skipped_out_of_scope"] == ["8.8.8.8"]
    assert [a["host"] for a in store.assets(eng["id"])] == ["10.0.0.5"]
    try:
        persist(store, "nope", [], "mdns")
    except ValueError:
        pass
    else:
        raise AssertionError("unknown engagement must raise")


def test_sweep_router_ledger(tmp_path: Any, monkeypatch: Any) -> None:
    from contextlib import asynccontextmanager

    monkeypatch.setenv("H4K_REFRESH_CVE", "0")
    monkeypatch.setenv("H4K_SANDBOX", "1")
    import main as main_module
    from routers import engagement as eng_router

    store = EngagementStore(tmp_path / "zc-router.db")
    monkeypatch.setattr(eng_router, "get_store", lambda: store)

    @asynccontextmanager
    async def _noop(_app: Any) -> Any:
        yield

    main_module.app.router.lifespan_context = _noop
    from fastapi.testclient import TestClient

    c = TestClient(main_module.app)
    eid = c.post(
        "/api/engagement", json={"name": "acme", "scope": ["10.10.10.0/24"]}
    ).json()["id"]
    r = c.post("/api/firetv/mdns", json={"engagement_id": eid})
    assert r.status_code == 200, r.text
    assert r.json()["detail"]["ledger"]["recorded"] == 2
    assert len(store.assets(eid)) == 2
    r = c.post("/api/firetv/ssdp", json={"engagement_id": eid})
    assert r.status_code == 200 and r.json()["detail"]["ledger"]["recorded"] >= 0
    r = c.post("/api/firetv/mdns", json={"engagement_id": "nope"})
    assert r.status_code == 404
