"""Backlog #22: CPE auto-correlate (banner → CPE → CVE)."""

from __future__ import annotations

from services.cpe import canonicalize, correlate


def test_canonicalize_known_products() -> None:
    out = canonicalize(service="ssh", product="OpenSSH", version="7.4")
    assert out["vendor"] == "openssh" and out["product"] == "openssh"
    assert out["cpe"] == "cpe:2.3:a:openssh:openssh:7.4:*:*:*:*:*:*:*"
    out = canonicalize(product="Apache httpd", version="2.4.49")
    assert out == {
        "vendor": "apache",
        "product": "httpd",
        "version": "2.4.49",
        "cpe": "cpe:2.3:a:apache:httpd:2.4.49:*:*:*:*:*:*:*",
    }
    out = canonicalize(product="MySQL")
    assert out["vendor"] == "oracle" and out["product"] == "mysql"
    assert out["cpe"].endswith(":*:*:*:*:*:*:*")


def test_canonicalize_unknown_falls_back() -> None:
    out = canonicalize(service="gopher")
    assert out["vendor"] == "gopher" and out["version"] == ""
    assert ":*:" in out["cpe"]


def test_correlate_reuses_banner_aware_matcher() -> None:
    out = correlate(service="ssh", product="OpenSSH", version="7.4")
    assert out["cpe"].startswith("cpe:2.3:a:openssh:openssh:7.4:")
    assert out["match_count"] >= 0
    # exact-vsftpd backdoor must not fire on a patched vsftpd
    out = correlate(service="ftp", product="vsftpd", version="3.0.3")
    ids = [m["id"] for m in out["matches"]]
    assert "CVE-2011-2523" not in ids


def test_correlate_router() -> None:
    from contextlib import asynccontextmanager
    from typing import Any as _Any

    import main as main_module

    @asynccontextmanager
    async def _noop(_app: _Any) -> _Any:
        yield

    main_module.app.router.lifespan_context = _noop
    from fastapi.testclient import TestClient

    c = TestClient(main_module.app)
    r = c.get("/api/cpe/correlate?product=OpenSSH&version=7.4")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["cpe"].startswith("cpe:2.3:a:openssh")
    assert "match_count" in body
