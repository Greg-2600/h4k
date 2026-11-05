"""Backlog #20: TLS cert inventory (expiry/weak/self-signed)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from services.cert_inventory import cert_leads, days_until, inventory, sandbox_inventory


def _probe(**kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "host": "10.0.0.5",
        "port": 443,
        "version": "TLSv1.2",
        "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
        "cert_sha256": "ab" * 32,
        "cert": {
            "subject": {"CN": "x"},
            "issuer": {"CN": "y"},
            "self_signed": False,
            "not_after": "",
        },
        "ok": True,
    }
    base.update(kw)
    return base


def test_days_until() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    assert days_until("Jan 11 00:00:00 2026 GMT", now) == 10
    assert days_until("Dec 22 00:00:00 2025 GMT", now) == -10
    assert days_until("garbage", now) is None


def test_cert_leads_expiry_and_weak() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    assert any(
        ld["level"] == "high"
        for ld in cert_leads(
            _probe(
                cert={
                    "subject": {"CN": "x"},
                    "issuer": {"CN": "y"},
                    "self_signed": False,
                    "not_after": "Dec 22 00:00:00 2025 GMT",
                }
            ),
            now,
        )
    )
    soon = cert_leads(
        _probe(
            cert={
                "subject": {"CN": "x"},
                "issuer": {"CN": "y"},
                "self_signed": False,
                "not_after": "Jan 11 00:00:00 2026 GMT",
            }
        ),
        now,
    )
    assert any("expires in 10" in ld["lead"] for ld in soon)
    assert any(
        "self-signed" in ld["lead"]
        for ld in cert_leads(
            _probe(
                cert={
                    "subject": {"CN": "x"},
                    "issuer": {"CN": "x"},
                    "self_signed": True,
                    "not_after": "",
                }
            ),
            now,
        )
    )
    assert cert_leads(_probe(version="TLSv1")) != []
    assert cert_leads({"ok": False}) == []


def test_inventory_parses_host_port(monkeypatch: Any) -> None:
    seen: list[tuple[str, int]] = []

    def fake_probe(host: str, port: int, timeout: float = 10.0) -> dict[str, Any]:
        seen.append((host, port))
        return _probe(host=host, port=port)

    monkeypatch.setattr("services.tls_fingerprint.probe_host", fake_probe)
    out = inventory(["a:8443", "b", "bad:port", ""])
    assert seen == [("a", 8443), ("b", 443), ("bad", 443)]
    assert out["count"] == 3


def test_sandbox_inventory() -> None:
    out = sandbox_inventory(["10.0.0.5", "10.0.0.9:8443"])
    assert out["count"] == 2 and out["sandbox"] is True


def test_inventory_router(tmp_path: Any, monkeypatch: Any) -> None:
    from contextlib import asynccontextmanager

    monkeypatch.setenv("H4K_REFRESH_CVE", "0")
    monkeypatch.setenv("H4K_SANDBOX", "1")
    import main as main_module
    from routers import engagement as eng_router
    from services.engagement import EngagementStore

    store = EngagementStore(tmp_path / "inv.db")
    monkeypatch.setattr(eng_router, "get_store", lambda: store)

    @asynccontextmanager
    async def _noop(_app: Any) -> Any:
        yield

    main_module.app.router.lifespan_context = _noop
    from fastapi.testclient import TestClient

    c = TestClient(main_module.app)
    r = c.post("/api/tls/inventory", json={"targets": ["10.0.0.5"]})
    assert r.status_code == 200, r.text
    assert r.json()["count"] == 1
    eid = c.post(
        "/api/engagement", json={"name": "acme", "scope": ["10.10.10.0/24"]}
    ).json()["id"]
    r = c.post(
        "/api/tls/inventory", json={"targets": ["10.0.0.5"], "engagement_id": eid}
    )
    assert r.status_code == 200
    # canned sandbox probes carry no leads: nothing to ledger
    assert r.json()["skipped_out_of_scope"] == []
    assert (
        c.post(
            "/api/tls/inventory", json={"targets": [], "engagement_id": "nope"}
        ).status_code
        == 404
    )


def test_inventory_ledger_scope(tmp_path: Any, monkeypatch: Any) -> None:
    from contextlib import asynccontextmanager

    monkeypatch.setenv("H4K_REFRESH_CVE", "0")
    monkeypatch.setenv("H4K_SANDBOX", "0")

    def fake_probe(host: str, port: int, timeout: float = 10.0) -> dict[str, Any]:
        return {
            "host": host,
            "port": port,
            "version": "TLSv1.2",
            "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
            "cipher_bits": 128,
            "cert_sha256": "x",
            "cert": {
                "subject": {"CN": host},
                "issuer": {"CN": host},
                "self_signed": True,
                "not_after": "",
            },
            "ok": True,
        }

    monkeypatch.setattr("services.tls_fingerprint.probe_host", fake_probe)
    import main as main_module
    from routers import engagement as eng_router
    from services.engagement import EngagementStore

    store = EngagementStore(tmp_path / "inv2.db")
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
        "/api/tls/inventory", json={"targets": ["10.0.0.5"], "engagement_id": eid}
    )
    assert r.status_code == 200, r.text
    assert r.json()["ingested"] == 1
    assert r.json()["skipped_out_of_scope"] == []
    assert len(store.vulns(eid)) == 1
    r = c.post(
        "/api/tls/inventory", json={"targets": ["8.8.8.8"], "engagement_id": eid}
    )
    assert r.json()["skipped_out_of_scope"] == ["8.8.8.8"]
