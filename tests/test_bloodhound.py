"""Backlog #26: BloodHound ingest (SharpHound JSON → graph overlay)."""

from __future__ import annotations

from typing import Any

from services.bloodhound import parse_sharphound, sandbox_graph, shortest_paths
from services.engagement import EngagementStore


def _doc() -> dict[str, Any]:
    return {
        "users": [
            {
                "ObjectIdentifier": "S-U",
                "Properties": {"name": "alice"},
                "AllowedToDelegate": [{"ComputerSID": "S-C"}],
            },
            {"ObjectIdentifier": "S-ROOT", "Properties": {"name": "root"}},
        ],
        "computers": [
            {
                "ObjectIdentifier": "S-C",
                "Properties": {"name": "WS01"},
                "HasSession": True,
                "Sessions": [{"ComputerSID": "S-C", "UserSID": "S-U"}],
            },
        ],
        "groups": [
            {
                "ObjectIdentifier": "S-DA",
                "Properties": {"name": "Domain Admins"},
                "Members": [{"ObjectIdentifier": "S-U"}],
                "AdminTo": [{"ComputerSID": "S-C"}],
            },
        ],
    }


def test_parse_nodes_edges() -> None:
    out = parse_sharphound(_doc())
    by_id = {n["id"]: n for n in out["nodes"]}
    assert set(by_id) == {"S-U", "S-ROOT", "S-C", "S-DA"}
    assert by_id["S-DA"]["kind"] == "group"
    rels = {(e["source"], e["target"], e["rel"]) for e in out["edges"]}
    assert ("S-U", "S-DA", "MemberOf") in rels
    assert ("S-DA", "S-C", "AdminTo") in rels
    assert ("S-C", "S-U", "HasSession") in rels
    assert ("S-U", "S-C", "AllowedToDelegate") in rels


def test_parse_bare_list_and_invalid() -> None:
    out = parse_sharphound([{"ObjectIdentifier": "S-1", "Properties": {"name": "x"}}])
    assert out["node_count"] == 1 and out["edges"] == []
    try:
        parse_sharphound("nope")
    except ValueError:
        pass
    else:
        raise AssertionError("non-object input must raise")
    assert parse_sharphound({})["node_count"] == 0


def test_shortest_paths() -> None:
    g = sandbox_graph()
    paths = shortest_paths(g["nodes"], g["edges"], "Domain Admins")
    assert paths and paths[0][-1] == "S-1-5-da"
    assert shortest_paths(g["nodes"], g["edges"], "Nobody Here") == []
    assert shortest_paths(g["nodes"], g["edges"], "S-1-5-DA") == paths


def test_store_roundtrip(tmp_path: Any) -> None:
    store = EngagementStore(tmp_path / "bh.db")
    eng = store.create_engagement("acme", ["10.0.0.0/24"])
    parsed = parse_sharphound(_doc())
    stored = store.record_ad_graph(eng["id"], parsed["nodes"], parsed["edges"])
    assert stored == {"nodes": 4, "edges": 4}
    graph = store.ad_graph(eng["id"])
    assert graph["node_count"] == 4
    again = store.record_ad_graph(eng["id"], parsed["nodes"], parsed["edges"])
    assert again == {"nodes": 0, "edges": 0}  # idempotent re-ingest
    try:
        store.record_ad_graph("nope", [], [])
    except ValueError:
        pass
    else:
        raise AssertionError("unknown engagement must raise")


def test_ad_router(tmp_path: Any, monkeypatch: Any) -> None:
    from contextlib import asynccontextmanager

    monkeypatch.setenv("H4K_REFRESH_CVE", "0")
    import main as main_module
    from routers import engagement as eng_router

    store = EngagementStore(tmp_path / "bh-router.db")
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
    r = c.post(f"/api/engagement/{eid}/ad/ingest", json={"data": _doc()})
    assert r.status_code == 200, r.text
    assert r.json()["node_count"] == 4
    r = c.get(f"/api/engagement/{eid}/ad/graph")
    assert r.json()["edge_count"] == 4
    r = c.get(f"/api/engagement/{eid}/ad/paths?target=Domain Admins")
    assert r.status_code == 200 and r.json()["count"] >= 1
    assert c.get("/api/engagement/nope/ad/graph").status_code == 404
    assert (
        c.post(f"/api/engagement/{eid}/ad/ingest", json={"data": "x"}).status_code
        == 400
    )
