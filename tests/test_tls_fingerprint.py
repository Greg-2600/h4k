"""Backlog #16: active TLS fingerprint + C2/malware leads."""

from __future__ import annotations

from typing import Any

from services.tls_fingerprint import (
    fingerprint,
    flag_probe,
    sandbox_scan,
    scan_host,
)


def _probe(**kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "host": "10.0.0.5",
        "port": 443,
        "version": "TLSv1.2",
        "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
        "cipher_bits": 128,
        "cert_sha256": "ab" * 32,
        "cert": {"subject": {"CN": "x"}, "issuer": {"CN": "y"}, "self_signed": False},
        "ok": True,
    }
    base.update(kw)
    return base


def test_fingerprint_stable() -> None:
    assert fingerprint(_probe()) == fingerprint(_probe())
    assert fingerprint(_probe()) != fingerprint(_probe(cipher="OTHER"))


def test_flag_probe_weak_and_watchlist() -> None:
    assert flag_probe(_probe(version="TLSv1")) != []
    assert flag_probe(_probe()) == []
    fp = fingerprint(_probe())
    leads = flag_probe(_probe(), watchlist=[fp])
    assert any(ld["level"] == "high" for ld in leads)
    self_signed = _probe(
        cert={"subject": {"CN": "x"}, "issuer": {"CN": "x"}, "self_signed": True}
    )
    assert any("self-signed" in ld["lead"] for ld in flag_probe(self_signed))
    assert flag_probe({"ok": False}) == []


def test_scan_host_merges(monkeypatch: Any) -> None:
    import services.tls_fingerprint as tf

    monkeypatch.setattr(
        tf, "probe_host", lambda h, p, timeout=10.0: _probe(host=h, port=p)
    )
    out = scan_host("10.0.0.5", ports=[443, 8443])
    assert out["ports"] == [443, 8443] and out["lead_count"] == 0
    assert len(out["fingerprints"]) == 1


def test_sandbox_scan() -> None:
    out = sandbox_scan("10.0.0.5")
    assert out["ports"] == [443] and out["sandbox"] is True


def test_tls_router(tmp_path: Any, monkeypatch: Any) -> None:
    from contextlib import asynccontextmanager

    monkeypatch.setenv("H4K_REFRESH_CVE", "0")
    monkeypatch.setenv("H4K_SANDBOX", "1")
    import main as main_module

    @asynccontextmanager
    async def _noop(_app: Any) -> Any:
        yield

    main_module.app.router.lifespan_context = _noop
    from fastapi.testclient import TestClient

    c = TestClient(main_module.app)
    r = c.post("/api/tls/fingerprint", json={"target": "10.0.0.5"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ports"] == [443] and body["fingerprints"]
