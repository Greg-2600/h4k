"""Backlog #21: Shodan/Censys BYO import (no keys in repo)."""

from __future__ import annotations

from typing import Any

from services.engagement import EngagementStore
from services.intel_import import ledger, normalize


def test_normalize_shodan() -> None:
    rows = normalize(
        "shodan",
        {
            "ip_str": "10.0.0.5",
            "port": 22,
            "product": "OpenSSH",
            "version": "7.4",
            "vulns": {"CVE-2021-41617": {}},
        },
    )
    assert rows[0]["host"] == "10.0.0.5" and rows[0]["cves"] == ["CVE-2021-41617"]


def test_normalize_shodan_envelope_and_ports() -> None:
    rows = normalize(
        "auto",
        {
            "matches": [
                {"ip_str": "10.0.0.5", "ports": [22, 80], "transport": "tcp"},
                {"nope": True},
            ]
        },
    )
    assert {(r["host"], r["port"]) for r in rows} == {
        ("10.0.0.5", 22),
        ("10.0.0.5", 80),
    }


def test_normalize_censys() -> None:
    rows = normalize(
        "censys",
        {"ip": "10.0.0.9", "services": [{"port": 443, "service_name": "https"}]},
    )
    assert rows[0]["service"] == "https"


def test_normalize_generic_and_invalid_json() -> None:
    rows = normalize(
        "generic",
        [{"host": "10.0.0.5", "port": "22", "service": "ssh", "cves": ["CVE-1"]}],
    )
    assert rows[0]["port"] == 22 and rows[0]["cves"] == ["CVE-1"]
    try:
        normalize("auto", "{bad json")
    except ValueError:
        pass
    else:
        raise AssertionError("invalid JSON must raise")
    assert normalize("auto", [{"nope": 1}]) == []
    assert normalize("auto", "[]") == []


def test_ledger_scope_checked(tmp_path: Any) -> None:
    store = EngagementStore(tmp_path / "intel.db")
    eng = store.create_engagement("acme", ["10.0.0.0/24"])
    rows = normalize(
        "generic",
        [
            {"host": "10.0.0.5", "port": 22, "service": "ssh", "cves": ["CVE-1"]},
            {"host": "8.8.8.8", "port": 53, "service": "dns"},
        ],
    )
    out = ledger(store, eng["id"], rows)
    assert out["rows"] == 2 and out["skipped_out_of_scope"] == ["8.8.8.8"]
    assert len(store.vulns(eng["id"])) == 1
    try:
        ledger(store, "nope", rows)
    except ValueError:
        pass
    else:
        raise AssertionError("unknown engagement must raise")


def test_intel_router(tmp_path: Any, monkeypatch: Any) -> None:
    from contextlib import asynccontextmanager

    monkeypatch.setenv("H4K_REFRESH_CVE", "0")
    import main as main_module
    from routers import engagement as eng_router

    store = EngagementStore(tmp_path / "intel-router.db")
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
        "/api/intel/import",
        json={
            "engagement_id": eid,
            "source": "shodan",
            "data": {
                "ip_str": "10.0.0.5",
                "port": 22,
                "product": "ssh",
                "vulns": {"CVE-1": {}},
            },
        },
    )
    assert r.status_code == 200, r.text
    assert r.json()["rows"] == 1 and r.json()["recorded"] >= 1
    assert c.post("/api/intel/import", json={}).status_code == 400
    assert (
        c.post(
            "/api/intel/import", json={"engagement_id": "nope", "data": []}
        ).status_code
        == 404
    )
    assert (
        c.post(
            "/api/intel/import", json={"engagement_id": eid, "data": "{bad"}
        ).status_code
        == 400
    )
    r = c.get("/api/intel/formats")
    assert r.status_code == 200 and "shodan" in r.json()["sources"]
