"""Backlog #6: NSE service → script suggest-and-run."""

from __future__ import annotations

from typing import Any

from services.nse_suggest import services_covered, suggest


def test_suggest_ssh() -> None:
    out = suggest("ssh")
    assert out["count"] >= 3
    names = [s["script"] for s in out["scripts"]]
    assert "ssh-brute" in names
    assert "ssh-brute" in out["script_arg"]


def test_suggest_unknown_falls_back_generic() -> None:
    out = suggest("gopher")
    assert out["count"] == 2
    assert out["script_arg"] == "vuln,default"


def test_suggest_case_insensitive_and_product() -> None:
    out = suggest("SMB", product="Samba 4.1")
    assert any(s["script"] == "smb-vuln-ms17-010" for s in out["scripts"])
    assert out["scripts"][0]["product"] == "Samba 4.1"


def test_services_covered() -> None:
    covered = services_covered()
    assert "ssh" in covered and "http" in covered and len(covered) >= 10


def test_suggest_router(tmp_path: Any, monkeypatch: Any) -> None:
    from contextlib import asynccontextmanager

    monkeypatch.setenv("H4K_REFRESH_CVE", "0")
    import main as main_module

    @asynccontextmanager
    async def _noop(_app: Any) -> Any:
        yield

    main_module.app.router.lifespan_context = _noop
    from fastapi.testclient import TestClient

    c = TestClient(main_module.app)
    r = c.get("/api/nse/suggest?service=ssh")
    assert r.status_code == 200
    assert r.json()["count"] >= 3
    r = c.get("/api/nse/services")
    assert r.status_code == 200 and r.json()["count"] >= 10
