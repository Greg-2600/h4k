"""Backlog #14: one-click assessment PDF."""

from __future__ import annotations

from typing import Any


def _report() -> dict[str, Any]:
    return {
        "session_id": "test",
        "generated": "2026-01-01",
        "scope": {},
        "hosts": [
            {"ip": "10.0.0.5", "vendor": "Acme", "hostname": "web", "os": "Linux"}
        ],
        "services": [
            {
                "ip": "10.0.0.5",
                "port": 22,
                "service": "ssh",
                "product": "",
                "version": "",
            }
        ],
        "vulns": [
            {
                "vid": "CVE-2021-41617",
                "ip": "10.0.0.5",
                "port": 22,
                "severity": "high",
                "detail": "outdated",
            }
        ],
        "credentials": [
            {
                "host": "10.0.0.5",
                "port": 22,
                "service": "ssh",
                "user": "root",
                "password": "toor",
            }
        ],
        "sessions": [{"host": "10.0.0.5", "module": "m", "msf_session_id": "1"}],
        "exploit_attempts": [],
        "autopilot_runs": [],
        "watch_changes": [],
        "handoff_techniques": [],
    }


def test_build_session_pdf() -> None:
    from services.pdf_report import build_session_pdf

    pdf = build_session_pdf(_report())
    assert pdf.startswith(b"%PDF")
    assert pdf.rstrip().endswith(b"%%EOF")
    assert len(pdf) > 1000  # real multi-section document, not an empty shell
    assert b"toor" not in pdf  # passwords masked in the handoff artifact


def test_session_report_pdf_endpoint(tmp_path: Any, monkeypatch: Any) -> None:
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

    c = TestClient(main_module.app)
    r = c.get("/api/session/report?fmt=pdf")
    assert r.status_code == 200, r.text[:200]
    assert r.headers["content-type"] == "application/pdf"
    assert r.content.startswith(b"%PDF")
