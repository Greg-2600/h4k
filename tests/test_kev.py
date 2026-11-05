"""Backlog #23: KEV/EPSS enrichment (real snapshot, refreshable)."""

from __future__ import annotations

from typing import Any

from services import kev


def test_enrich_known_cve() -> None:
    out = kev.enrich("cve-2021-44228")
    assert out["kev"] is True
    assert out["due_date"] == "2021-12-24"
    assert float(out["epss"]["score"]) > 0.9


def test_enrich_unknown_cve() -> None:
    out = kev.enrich("CVE-9999-0001")
    assert out == {
        "cve": "CVE-9999-0001",
        "kev": False,
        "epss": None,
        "catalog_date": kev.catalog_date(),
    }


def test_enrich_many_dedups() -> None:
    out = kev.enrich_many(["CVE-2021-44228", "cve-2021-44228", "CVE-9999-1", ""])
    assert out["count"] == 2 and out["kev_count"] == 1


def test_refresh_keeps_table_on_failure(monkeypatch: Any) -> None:
    import urllib.request

    def boom(*a: Any, **k: Any) -> Any:
        raise OSError("offline")

    monkeypatch.setattr(urllib.request, "urlopen", boom)
    before = len(kev._table.get("cves", {}))
    out = kev.refresh()
    assert out["after"] == before and "error" in out


def test_kev_router() -> None:
    from contextlib import asynccontextmanager
    from typing import Any as _Any

    import main as main_module

    @asynccontextmanager
    async def _noop(_app: _Any) -> _Any:
        yield

    main_module.app.router.lifespan_context = _noop
    from fastapi.testclient import TestClient

    c = TestClient(main_module.app)
    r = c.get("/api/kev/check?cve=CVE-2017-0144")
    assert r.status_code == 200 and r.json()["kev"] is True
    assert c.get("/api/kev/check").status_code == 400
    r = c.post("/api/kev/enrich", json={"cves": ["CVE-2021-44228", "nope"]})
    assert r.status_code == 200 and r.json()["kev_count"] == 1
    assert c.post("/api/kev/enrich", json={"cves": "x"}).status_code == 400
