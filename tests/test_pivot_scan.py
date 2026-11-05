"""Backlog #35: SOCKS-aware scan — fingerprint + engagement ledger."""

from __future__ import annotations

from typing import Any

from services.pivot_scan import fingerprint_scan, guess_service, ledger_scan
from services.pivot_tunnel import sandbox_scan


def test_guess_service_table() -> None:
    assert guess_service("SSH-2.0-OpenSSH_9.6", 22)["service"] == "ssh"
    assert guess_service("SSH-2.0-OpenSSH_9.6", 22)["product"] == "OpenSSH"
    assert guess_service("Apache/2.4.57", 80) == {
        "service": "http",
        "product": "Apache",
        "version": "2.4.57",
    }
    assert guess_service("whatever", 445)["service"] == "microsoft-ds"
    assert guess_service("whatever", 3389)["service"] == "ms-wbt-server"
    assert guess_service("nothing here", 9999) == {
        "service": "",
        "product": "",
        "version": "",
    }


def test_fingerprint_scan_annotates_open() -> None:
    out = fingerprint_scan(sandbox_scan("10.10.10.5"))
    by_port = {r["port"]: r for r in out["results"]}
    assert by_port[22]["service"] == "ssh"
    assert by_port[80]["service"] == "http"
    assert out["fingerprinted"] == 2
    assert out["open_count"] == 2


def _client(tmp_path: Any, monkeypatch: Any) -> Any:
    from contextlib import asynccontextmanager

    monkeypatch.setenv("H4K_REFRESH_CVE", "0")
    monkeypatch.setenv("H4K_SANDBOX", "1")
    monkeypatch.setenv("H4K_DATA_DIR", str(tmp_path))
    import main as main_module

    @asynccontextmanager
    async def _noop(_app: Any) -> Any:
        yield

    main_module.app.router.lifespan_context = _noop
    from fastapi.testclient import TestClient

    return TestClient(main_module.app)


def test_tunnel_scan_fingerprint_and_ledger(tmp_path: Any, monkeypatch: Any) -> None:
    c = _client(tmp_path, monkeypatch)
    # Fingerprint without ledger.
    r = c.post("/api/net/tunnel/scan", json={"target": "10.10.10.5"})
    assert r.status_code == 200
    body = r.json()
    assert body["fingerprinted"] == 2
    assert body["recorded"] == 0
    by_port = {row["port"]: row for row in body["results"]}
    assert by_port[22]["service"] == "ssh"

    # Ledger into a seeded engagement (scope 10.10.10.0/24) with a fresh
    # host so both service rows are new.
    eng = c.post("/api/engagement/sandbox-seed").json()["engagement"]
    eid = eng["id"]
    r = c.post(
        "/api/net/tunnel/scan",
        json={"target": "10.10.10.77", "engagement_id": eid},
    )
    assert r.status_code == 200
    assert r.json()["recorded"] == 2
    assets = c.get(f"/api/engagement/{eid}/assets").json()
    assert "10.10.10.77" in str(assets)

    # Out-of-scope target is reported, never stored.
    r = c.post(
        "/api/net/tunnel/scan",
        json={"target": "192.0.2.9", "engagement_id": eid},
    )
    assert r.status_code == 200
    assert r.json()["recorded"] == 0
    assert r.json()["skipped_out_of_scope"] == ["192.0.2.9"]

    # Unknown engagement is a 404, missing target a 400.
    assert (
        c.post(
            "/api/net/tunnel/scan",
            json={"target": "10.10.10.5", "engagement_id": "nope"},
        ).status_code
        == 404
    )
    assert c.post("/api/net/tunnel/scan", json={}).status_code == 400


def test_ledger_scan_scope_unit(tmp_path: Any, monkeypatch: Any) -> None:
    monkeypatch.setenv("H4K_DATA_DIR", str(tmp_path))
    from routers.engagement import get_store

    store = get_store()
    eng = store.create_engagement(name="pivot", scope=["10.10.10.0/24"])
    eid = eng["id"]
    out = ledger_scan(
        store, eid, "10.10.10.5", fingerprint_scan(sandbox_scan("10.10.10.5"))
    )
    assert out == {"recorded": 2, "skipped_out_of_scope": []}
    assert ledger_scan(store, eid, "192.0.2.9", {"results": []}) == {
        "recorded": 0,
        "skipped_out_of_scope": ["192.0.2.9"],
    }
