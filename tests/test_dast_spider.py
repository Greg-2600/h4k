"""Backlog #3: depth-bounded same-origin DAST spider + auth crawl."""

from __future__ import annotations

import io
from typing import Any
from unittest.mock import patch

from services.dast_spider import crawl, sandbox_crawl


class _FakeHeaders(dict):
    def get(self, key: str, default: str = "") -> str:
        return super().get(key, default)


class _FakeResp:
    def __init__(self, body: str, status: int = 200) -> None:
        self._buf = io.BytesIO(body.encode())
        self.status = status
        self.headers = _FakeHeaders({"Content-Type": "text/html"})

    def read(self, n: int = -1) -> bytes:
        return self._buf.read(n)

    def close(self) -> None:
        pass


def _site() -> dict[str, _FakeResp]:
    return {
        "http://own.lab/": _FakeResp(
            "<html><head><title>home</title></head><body>"
            '<a href="/login">login</a>'
            '<a href="http://evil.lab/steal">evil</a>'
            '<form action="/search" method="get">'
            '<input name="q" type="text"/></form>'
            "</body></html>"
        ),
        "http://own.lab/login": _FakeResp(
            "<html><body><form action='/login' method='post'>"
            "<input name='user'/><input name='pass' type='password'/>"
            "</form></body></html>"
        ),
    }


def _fake_urlopen_factory(seen_headers: dict[str, Any]) -> Any:
    site = _site()

    def _fake(req: Any, timeout: float = 10.0) -> _FakeResp:
        seen_headers.update(dict(req.header_items()))
        url = req.full_url
        if url not in site:
            raise AssertionError(f"off-origin or unknown fetch: {url}")
        return site[url]

    return _fake


def test_crawl_maps_links_and_forms_same_origin_only() -> None:
    seen: dict[str, Any] = {}
    with patch(
        "services.dast_spider.urlrequest.urlopen",
        side_effect=_fake_urlopen_factory(seen),
    ):
        out = crawl("http://own.lab/", max_depth=2)
    assert out["page_count"] == 2
    assert out["form_count"] == 2
    assert out["external"] == ["http://evil.lab/steal"]
    assert out["external_count"] == 1
    assert out["auth_used"] is False


def test_depth_bound_stops_at_zero() -> None:
    seen: dict[str, Any] = {}
    with patch(
        "services.dast_spider.urlrequest.urlopen",
        side_effect=_fake_urlopen_factory(seen),
    ):
        out = crawl("http://own.lab/", max_depth=0)
    assert out["page_count"] == 1
    assert out["form_count"] == 1


def test_auth_headers_are_sent() -> None:
    seen: dict[str, Any] = {}
    with patch(
        "services.dast_spider.urlrequest.urlopen",
        side_effect=_fake_urlopen_factory(seen),
    ):
        out = crawl(
            "http://own.lab/",
            max_depth=0,
            auth_header="Bearersekret",
            auth_cookie="session=abc",
        )
    assert out["auth_used"] is True
    assert seen.get("Authorization") == "Bearersekret"
    assert seen.get("Cookie") == "session=abc"


def test_sandbox_crawl_is_deterministic() -> None:
    a = sandbox_crawl("10.10.10.5")
    assert a["page_count"] == 3 and a["form_count"] == 2
    assert a["sandbox"] is True


def test_spider_router_ledger_and_scope(tmp_path: Any, monkeypatch: Any) -> None:
    from contextlib import asynccontextmanager

    monkeypatch.setenv("H4K_REFRESH_CVE", "0")
    monkeypatch.setenv("H4K_SANDBOX", "1")
    import main as main_module
    from routers import engagement as eng_router
    from services.engagement import EngagementStore

    store = EngagementStore(tmp_path / "spider.db")
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
    r = c.post(
        "/api/spider",
        json={"target": "10.0.0.5", "max_depth": 1, "engagement_id": eid},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["page_count"] == 3
    assert body["ingested_assets"] >= 1
    assert body["skipped_out_of_scope"] == []

    r2 = c.post(
        "/api/spider",
        json={"target": "8.8.8.8", "engagement_id": eid},
    )
    assert r2.status_code == 200
    assert r2.json()["skipped_out_of_scope"] == ["8.8.8.8"]
