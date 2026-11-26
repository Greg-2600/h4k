"""Backlog #16: active TLS fingerprint + C2/malware leads."""

from __future__ import annotations

import hashlib
from typing import Any

from services.tls_fingerprint import (
    _cert_summary,
    _rdn,
    fingerprint,
    flag_probe,
    probe_host,
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


def test_rdn_normalizes_attrs_and_skips_malformed() -> None:
    seq = [
        [("commonName", "lab")],
        [("organizationName", "ACME"), ("bad",)],
        [("countryName", "US")],
        "not-an-rdn",
    ]
    assert _rdn(seq) == {
        "commonName": "lab",
        "organizationName": "ACME",
        "countryName": "US",
    }
    assert _rdn(None) == {}


def test_cert_summary_empty_and_self_signed() -> None:
    assert _cert_summary(None) == {
        "subject": {},
        "issuer": {},
        "self_signed": False,
        "not_before": "",
        "not_after": "",
    }
    cert = {
        "subject": ((("commonName", "lab"),),),
        "issuer": ((("commonName", "lab"),),),
        "notBefore": "Jan  1 00:00:00 2026 GMT",
        "notAfter": "Dec 31 00:00:00 2026 GMT",
    }
    summary = _cert_summary(cert)
    assert summary["self_signed"] is True
    assert summary["subject"] == {"commonName": "lab"}
    assert summary["not_before"].startswith("Jan")
    assert summary["not_after"].startswith("Dec")


class _FakeTLS:
    def __init__(self, cert: dict[str, Any] | None, der: bytes | None) -> None:
        self._cert = cert
        self._der = der

    def __enter__(self) -> _FakeTLS:
        return self

    def __exit__(self, *exc: Any) -> bool:
        return False

    def version(self) -> str:
        return "TLSv1.3"

    def cipher(self) -> tuple[str, str, int]:
        return ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

    def getpeercert(self, binary_form: bool = False) -> Any:
        return self._der if binary_form else self._cert


class _FakeCtx:
    def __init__(self, tls: _FakeTLS) -> None:
        self._tls = tls

    def wrap_socket(self, sock: Any, server_hostname: str | None = None) -> _FakeTLS:
        return self._tls


class _FakeSock:
    def __enter__(self) -> _FakeSock:
        return self

    def __exit__(self, *exc: Any) -> bool:
        return False


def test_probe_host_records_negotiated_inventory(monkeypatch: Any) -> None:
    import services.tls_fingerprint as tf

    cert = {
        "subject": ((("commonName", "lab"),),),
        "issuer": ((("commonName", "lab"),),),
    }
    tls = _FakeTLS(cert, b"der-bytes")
    monkeypatch.setattr(tf.ssl, "create_default_context", lambda: _FakeCtx(tls))
    monkeypatch.setattr(
        tf.socket, "create_connection", lambda addr, timeout: _FakeSock()
    )

    out = probe_host("10.0.0.5", 443, timeout=1.0)
    assert out["ok"] is True
    assert out["version"] == "TLSv1.3"
    assert out["cipher"] == "TLS_AES_256_GCM_SHA384"
    assert out["cipher_bits"] == 256
    assert out["cert_sha256"] == hashlib.sha256(b"der-bytes").hexdigest()
    assert out["cert"]["self_signed"] is True


def test_probe_host_handles_missing_cert(monkeypatch: Any) -> None:
    import services.tls_fingerprint as tf

    tls = _FakeTLS(None, None)
    monkeypatch.setattr(tf.ssl, "create_default_context", lambda: _FakeCtx(tls))
    monkeypatch.setattr(
        tf.socket, "create_connection", lambda addr, timeout: _FakeSock()
    )

    out = probe_host("10.0.0.5", 8443)
    assert out["ok"] is True
    assert out["cert_sha256"] == ""
    assert out["cert"]["subject"] == {}
    assert out["cert"]["self_signed"] is False


def test_probe_host_records_connect_error(monkeypatch: Any) -> None:
    import services.tls_fingerprint as tf

    def _boom(addr: Any, timeout: Any) -> Any:
        raise OSError("connection refused")

    monkeypatch.setattr(tf.socket, "create_connection", _boom)
    out = probe_host("10.0.0.5", 443)
    assert out["ok"] is False
    assert out["error"] == "connection refused"
    assert out["host"] == "10.0.0.5" and out["port"] == 443
    assert "version" not in out


def test_flag_probe_weak_cipher() -> None:
    leads = flag_probe(_probe(cipher="RC4-MD5"))
    assert any("weak cipher" in ld["lead"] for ld in leads)


def test_scan_host_skips_failed_probes(monkeypatch: Any) -> None:
    import services.tls_fingerprint as tf

    def _fake_probe(host: str, port: int, timeout: float = 10.0) -> dict[str, Any]:
        if port == 8443:
            return {"host": host, "port": port, "ok": False, "error": "timeout"}
        return _probe(host=host, port=port, version="TLSv1")

    monkeypatch.setattr(tf, "probe_host", _fake_probe)
    out = scan_host("10.0.0.5", ports=[443, 8443])
    assert out["ports"] == [443]
    assert len(out["probes"]) == 2
    assert out["lead_count"] == 1
    assert all(p.get("fingerprint") for p in out["probes"] if p["ok"])
    assert "fingerprint" not in out["probes"][1]
