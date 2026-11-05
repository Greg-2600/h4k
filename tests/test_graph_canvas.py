from pathlib import Path
from typing import Any

from _pytest.monkeypatch import MonkeyPatch
from services.graph_canvas import layout_graph


def _graph() -> dict[str, Any]:
    return {
        "nodes": [
            {"id": "10.0.0.5", "label": "10.0.0.5", "type": "host"},
            {"id": "10.0.0.9", "label": "10.0.0.9", "type": "host"},
        ],
        "edges": [
            {"source": "10.0.0.5", "target": "10.0.0.5:22", "type": "service"},
            {
                "source": "10.0.0.5",
                "target": "root@ssh",
                "type": "credential",
            },
            {
                "source": "10.0.0.5",
                "target": "root@ssh",
                "type": "pivot",
                "reaches": ["10.0.0.9"],
            },
        ],
        "summary": {"assets": 2},
    }


def test_layout_is_deterministic() -> None:
    a = layout_graph(_graph())
    b = layout_graph(_graph())
    assert a == b


def test_layout_synthesizes_missing_endpoints() -> None:
    out = layout_graph(_graph())
    ids = {n["id"] for n in out["nodes"]}
    assert "10.0.0.5:22" in ids
    assert "root@ssh" in ids
    for n in out["nodes"]:
        assert isinstance(n["x"], int) and isinstance(n["y"], int)
        assert 0 <= n["x"] <= 800 and 0 <= n["y"] <= 600


def test_layout_empty_graph() -> None:
    out = layout_graph({"nodes": [], "edges": [], "summary": {}})
    assert out["nodes"] == [] and out["edges"] == []
    assert out["stage"] == {"width": 800, "height": 600}
    assert len(out["legend"]) == 4


def test_canvas_router(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    from contextlib import asynccontextmanager

    monkeypatch.setenv("H4K_REFRESH_CVE", "0")
    import main as main_module
    from routers import engagement as eng_router
    from services.engagement import EngagementStore

    store = EngagementStore(tmp_path / "canvas.db")
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
    c.post(
        f"/api/engagement/{eid}/ingest",
        json={
            "hosts": [{"address": "10.0.0.5", "services": [{"port": 22}]}],
        },
    )
    r = c.get(f"/api/engagement/{eid}/graph/canvas")
    assert r.status_code == 200
    body = r.json()
    assert body["nodes"] and body["stage"]["width"] == 800
    assert c.get("/api/engagement/nope/graph/canvas").status_code == 404
