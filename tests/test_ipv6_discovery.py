"""Backlog #18: IPv6 discovery (NDP + nmap -6, scope-checked)."""

from __future__ import annotations

from typing import Any

from services.ipv6_discovery import discover, parse_neigh, parse_nmap6, sandbox_discover


def test_parse_neigh() -> None:
    out = parse_neigh(
        "fd00::5 dev eth0 lladdr 52:54:00:12:34:56 REACHABLE\n"
        "fe80::1 dev eth0 lladdr aa:bb:cc:dd:ee:ff STALE\n"
        "fd00::dead dev eth0 FAILED\n"
        "garbage line\n"
    )
    assert [(n["ip"], n["state"]) for n in out] == [
        ("fd00::5", "REACHABLE"),
        ("fe80::1", "STALE"),
    ]
    assert out[0]["mac"] == "52:54:00:12:34:56"


def test_parse_nmap6() -> None:
    out = parse_nmap6(
        "Nmap scan report for fd00::5\nHost is up.\n"
        "Nmap scan report for example.com (fd00::9)\nHost is up.\n"
    )
    assert [n["ip"] for n in out] == ["fd00::5", "fd00::9"]


def test_discover_merges_neigh_and_scan(monkeypatch: Any) -> None:

    def fake_run(_self: Any, tool: str, argv: list[str], **kw: Any) -> dict[str, Any]:
        if tool == "ip6neigh":
            return {
                "status": "ok",
                "stdout": "fd00::5 dev eth0 lladdr 52:54:00:12:34:56 REACHABLE\n",
                "stderr": "",
                "rc": 0,
                "timed_out": False,
            }
        assert tool == "nmap6" and "fd00::/120" in argv
        return {
            "status": "ok",
            "stdout": "Nmap scan report for fd00::9\nHost is up.\n",
            "stderr": "",
            "rc": 0,
            "timed_out": False,
        }

    monkeypatch.setattr("services.toolkit.ToolkitRunner.run_tool", fake_run)
    out = discover(cidr="fd00::/120")
    assert out["count"] == 2
    assert out["neigh_status"] == "ok" and out["scan_status"] == "ok"


def test_discover_skips_scan_without_cidr(monkeypatch: Any) -> None:

    calls: list[str] = []

    def fake_run(_self: Any, tool: str, argv: list[str], **kw: Any) -> dict[str, Any]:
        calls.append(tool)
        return {"status": "ok", "stdout": "", "stderr": "", "rc": 0, "timed_out": False}

    monkeypatch.setattr("services.toolkit.ToolkitRunner.run_tool", fake_run)
    out = discover()
    assert calls == ["ip6neigh"] and out["scan_status"] == "skipped"


def test_sandbox_discover() -> None:
    out = sandbox_discover()
    assert out["count"] == 3 and out["sandbox"] is True


def test_ipv6_router_ledger(tmp_path: Any, monkeypatch: Any) -> None:
    from contextlib import asynccontextmanager

    monkeypatch.setenv("H4K_REFRESH_CVE", "0")
    monkeypatch.setenv("H4K_SANDBOX", "1")
    import main as main_module
    from routers import engagement as eng_router
    from services.engagement import EngagementStore

    store = EngagementStore(tmp_path / "ip6.db")
    monkeypatch.setattr(eng_router, "get_store", lambda: store)

    @asynccontextmanager
    async def _noop(_app: Any) -> Any:
        yield

    main_module.app.router.lifespan_context = _noop
    from fastapi.testclient import TestClient

    c = TestClient(main_module.app)
    eid = c.post("/api/engagement", json={"name": "v6", "scope": ["fd00::/8"]}).json()[
        "id"
    ]
    r = c.post("/api/net/ipv6/discover", json={"engagement_id": eid})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["count"] == 3 and body["recorded"] == 2
    assert body["skipped_out_of_scope"] == ["fe80::42"]
    assert len(store.assets(eid)) == 2
    assert (
        c.post("/api/net/ipv6/discover", json={"engagement_id": "nope"}).status_code
        == 404
    )
