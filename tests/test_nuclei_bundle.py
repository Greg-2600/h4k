"""Backlog #2: offline nuclei bundle + engagement ledger + sandbox."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

from services.nuclei import (
    bundle_dir,
    bundle_templates,
    sandbox_result,
    to_ledger,
)


def _finding(**kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "template": "h4k-log4shell",
        "matched": "http://10.10.10.5/?x=1",
        "info": {
            "name": "Apache Log4Shell (CVE-2021-44228)",
            "severity": "critical",
            "metadata": {"cwe": "CWE-502"},
            "reference": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
        },
    }
    base.update(kw)
    return base


def test_bundle_dir_exists_with_templates() -> None:
    bdir = bundle_dir()
    assert bdir is not None
    assert set(bundle_templates()) >= {"log4shell", "struts-rce", "bluekeep"}


def test_scan_offline_uses_bundle_dir() -> None:
    from services.nuclei import NucleiService

    with patch("subprocess.run") as mock_run:
        mock_proc = MagicMock()
        mock_proc.stdout = ""
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc
        svc = NucleiService()
        out = svc.scan("http://10.0.0.5", offline=True)
        argv = mock_run.call_args[0][0]
        assert "-t" in argv
        assert str(bundle_dir()) in argv
        assert out["offline"] is True


def test_to_ledger_maps_host_severity_cwe() -> None:
    entries = to_ledger("10.10.10.5", [_finding()])
    assert len(entries) == 1
    e = entries[0]
    assert e["host"] == "10.10.10.5"
    assert e["severity"] == "critical"
    assert e["cwe"] == "CWE-502"
    assert e["module"] == "h4k-log4shell"
    assert "CVE-2021-44228" in e["reference"]


def test_to_ledger_skips_non_dicts() -> None:
    assert to_ledger("h", [{"ok": True}, "nope", _finding()]) != []


def test_sandbox_result_is_deterministic() -> None:
    a = sandbox_result("10.10.10.5")
    assert a["finding_count"] == 1
    assert a["offline"] is True
    assert a["sandbox"] is True
    assert a["findings"][0]["info"]["severity"] == "critical"


def test_nuclei_router_ledger_and_scope(tmp_path: Any, monkeypatch: Any) -> None:
    from contextlib import asynccontextmanager

    monkeypatch.setenv("H4K_REFRESH_CVE", "0")
    monkeypatch.setenv("H4K_SANDBOX", "1")
    import main as main_module
    from routers import engagement as eng_router
    from services.engagement import EngagementStore

    store = EngagementStore(tmp_path / "nuclei.db")
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
        "/api/nuclei",
        json={"target": "10.0.0.5", "offline": True, "engagement_id": eid},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["finding_count"] == 1
    assert body["ingested"] == 1
    assert body["skipped_out_of_scope"] == []
    assert len(store.vulns(eid)) == 1

    # out-of-scope target is skipped, never recorded
    r2 = c.post(
        "/api/nuclei",
        json={"target": "8.8.8.8", "offline": True, "engagement_id": eid},
    )
    assert r2.status_code == 200
    assert r2.json()["skipped_out_of_scope"] == ["8.8.8.8"]
    assert len(store.vulns(eid)) == 1


def test_nuclei_templates_endpoint(tmp_path: Any, monkeypatch: Any) -> None:
    from contextlib import asynccontextmanager

    monkeypatch.setenv("H4K_REFRESH_CVE", "0")
    import main as main_module

    @asynccontextmanager
    async def _noop(_app: Any) -> Any:
        yield

    main_module.app.router.lifespan_context = _noop
    from fastapi.testclient import TestClient

    c = TestClient(main_module.app)
    r = c.get("/api/nuclei/templates")
    assert r.status_code == 200
    body = r.json()
    assert body["offline_ready"] is True
    assert body["count"] >= 3
