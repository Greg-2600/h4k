"""Backlog #17: SNMP community sweep + MIB walk."""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

from services.snmp_sweep import parse_get, parse_walk, sandbox_sweep, sweep


def test_parse_get() -> None:
    assert parse_get("SNMPv2-MIB::sysDescr.0 = STRING: lab box") == "lab box"
    assert parse_get("") == ""
    assert parse_get("garbage") == ""


def test_parse_walk_caps_rows() -> None:
    out = parse_walk("A::b.0 = STRING: x\nNOT A LINE\nC::d.0 = INTEGER: 3", limit=1)
    assert len(out) == 1 and out[0]["oid"] == "A::b.0"


def test_sweep_uses_first_hit_for_walk() -> None:
    def fake_run(tool: str, argv: list[str], timeout: int = 60) -> dict[str, Any]:
        if tool == "snmpget":
            ok = "-c" in argv and argv[argv.index("-c") + 1] == "public"
            return {
                "status": "ok" if ok else "error",
                "stdout": "SNMPv2-MIB::sysDescr.0 = STRING: lab" if ok else "Timeout",
                "stderr": "",
                "rc": 0 if ok else 1,
                "timed_out": False,
            }
        assert tool == "snmpwalk"
        assert argv[argv.index("-c") + 1] == "public"
        return {
            "status": "ok",
            "stdout": "SNMPv2-MIB::sysName.0 = STRING: lab",
            "stderr": "",
            "rc": 0,
            "timed_out": False,
        }

    with patch("services.toolkit.ToolkitRunner.run_tool", side_effect=fake_run):
        out = sweep("10.0.0.9", communities=["private", "public"], walk=True)
    assert out["working_count"] == 1
    assert out["working"][0] == {"community": "public", "sys_descr": "lab"}
    assert out["walked_count"] == 1


def test_sweep_no_walk_without_hit() -> None:
    with patch("services.toolkit.ToolkitRunner.run_tool") as mock_run:
        mock_run.return_value = {
            "status": "error",
            "stdout": "Timeout",
            "stderr": "",
            "rc": 1,
            "timed_out": False,
        }
        out = sweep("10.0.0.9", walk=True)
    assert out["working_count"] == 0 and out["walked"] == []
    assert mock_run.call_count == 2  # one GET per community, no walk


def test_sandbox_sweep() -> None:
    out = sandbox_sweep("10.0.0.9")
    assert out["working_count"] == 1 and out["sandbox"] is True


def test_snmp_router_ledger(tmp_path: Any, monkeypatch: Any) -> None:
    from contextlib import asynccontextmanager

    monkeypatch.setenv("H4K_REFRESH_CVE", "0")
    monkeypatch.setenv("H4K_SANDBOX", "1")
    import main as main_module
    from routers import engagement as eng_router
    from services.engagement import EngagementStore

    store = EngagementStore(tmp_path / "snmp.db")
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
        "/api/snmp/sweep",
        json={"target": "10.0.0.5", "walk": True, "engagement_id": eid},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["working_count"] == 1 and body["ingested"] == 1
    assert len(store.vulns(eid)) == 1
    r = c.post("/api/snmp/sweep", json={"target": "8.8.8.8", "engagement_id": eid})
    assert r.status_code == 200 and r.json()["skipped_out_of_scope"] == ["8.8.8.8"]
    assert (
        c.post(
            "/api/snmp/sweep", json={"target": "10.0.0.5", "engagement_id": "nope"}
        ).status_code
        == 404
    )
