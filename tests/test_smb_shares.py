"""Backlog #7: read-only SMB share enumerator + asset-graph ledger."""

from __future__ import annotations

from typing import Any

from services.smb_shares import (
    _merge,
    enumerate_shares,
    parse_smbclient,
    parse_smbmap,
    sandbox_shares,
)
from services.toolkit import ToolkitRunner


def test_parse_smbclient_table() -> None:
    out = parse_smbclient(
        "\n".join(
            [
                "noise before the table is ignored",
                "\tSharename       Type      Comment",
                "\t---------       ----      -------",
                "\tpublic          Disk      lab drop",
                "\tIPC$            IPC       IPC Service",
                "",
                "Server               Comment",
                "---------            -------",
            ]
        )
    )
    assert [s["name"] for s in out] == ["public", "IPC$"]
    assert out[0]["comment"] == "lab drop"


def test_parse_smbmap_rows() -> None:
    out = parse_smbmap(
        "\n".join(
            [
                "READ ONLY\tpublic\tlab drop",
                "NO ACCESS\tC$\tDefault share",
                "[+] Working on it...",
                "single-column-line",
                "READ+WRITE\tbadaccess",
                "READ ONLY\tshare\tduplicate header",
                "READ ONLY\tfolder/name\tpath-like name",
            ]
        )
    )
    assert [(s["name"], s["access"]) for s in out] == [
        ("public", "READ ONLY"),
        ("C$", "NO ACCESS"),
    ]


def test_merge_prefers_first_nonempty() -> None:
    merged = _merge(
        [{"name": "public", "type": "Disk", "comment": "", "access": ""}],
        [
            {"name": "public", "type": "", "comment": "lab", "access": "READ ONLY"},
            {"name": "home", "type": "Disk", "comment": "users", "access": "READ"},
        ],
    )
    assert merged[0] == {
        "name": "home",
        "type": "Disk",
        "comment": "users",
        "access": "READ",
    }
    assert merged[1] == {
        "name": "public",
        "type": "Disk",
        "comment": "lab",
        "access": "READ ONLY",
    }


def test_enumerate_shares_null_session(monkeypatch: Any) -> None:
    calls: list[tuple[str, list[str], int]] = []

    def fake_run_tool(
        self: Any, tool: str, argv: list[str], timeout: int = 300
    ) -> dict[str, Any]:
        calls.append((tool, argv, timeout))
        if tool == "smbclient":
            return {
                "tool": tool,
                "status": "ok",
                "stdout": "\n".join(
                    [
                        "\tSharename       Type      Comment",
                        "\t---------       ----      -------",
                        "\tpublic          Disk      lab drop",
                    ]
                ),
            }
        return {
            "tool": tool,
            "status": "ok",
            "stdout": "READ ONLY\tpublic\tlab drop",
        }

    monkeypatch.setattr(ToolkitRunner, "run_tool", fake_run_tool)
    result = enumerate_shares("10.0.0.5")
    assert result["target"] == "10.0.0.5"
    assert result["success"] is True
    assert result["count"] == 1
    assert result["shares"][0]["access"] == "READ ONLY"
    assert [c[0] for c in calls] == ["smbclient", "smbmap"]
    assert calls[0][1] == ["smbclient", "-L", "//10.0.0.5", "-N", "-g"]
    assert calls[1][1] == ["smbmap", "-H", "10.0.0.5", "-u", "anonymous"]
    assert calls[0][2] == calls[1][2] == 60


def test_enumerate_shares_with_credentials(monkeypatch: Any) -> None:
    calls: list[tuple[str, list[str]]] = []

    def fake_run_tool(
        self: Any, tool: str, argv: list[str], timeout: int = 300
    ) -> dict[str, Any]:
        calls.append((tool, argv))
        return {"tool": tool, "status": "ok", "stdout": ""}

    monkeypatch.setattr(ToolkitRunner, "run_tool", fake_run_tool)
    result = enumerate_shares("fileserver", user="alice", password="s3cret")
    assert result["count"] == 0
    assert calls[0][1] == [
        "smbclient",
        "-L",
        "//fileserver",
        "-U",
        "alice%s3cret",
        "-g",
    ]
    assert calls[1][1] == [
        "smbmap",
        "-H",
        "fileserver",
        "-u",
        "alice",
        "-p",
        "s3cret",
    ]


def test_enumerate_shares_user_without_password(monkeypatch: Any) -> None:
    calls: list[tuple[str, list[str]]] = []

    def fake_run_tool(
        self: Any, tool: str, argv: list[str], timeout: int = 300
    ) -> dict[str, Any]:
        calls.append((tool, argv))
        return {"tool": tool, "status": "ok", "stdout": ""}

    monkeypatch.setattr(ToolkitRunner, "run_tool", fake_run_tool)
    enumerate_shares("fileserver", user="alice")
    assert calls[0][1] == ["smbclient", "-L", "//fileserver", "-U", "alice", "-g"]
    assert calls[1][1] == ["smbmap", "-H", "fileserver", "-u", "alice"]


def test_enumerate_shares_partial_tool_failure(monkeypatch: Any) -> None:
    def fake_run_tool(
        self: Any, tool: str, argv: list[str], timeout: int = 300
    ) -> dict[str, Any]:
        if tool == "smbclient":
            return {"tool": tool, "status": "error", "stdout": ""}
        return {
            "tool": tool,
            "status": "ok",
            "stdout": "READ ONLY\tpublic\tlab drop",
        }

    monkeypatch.setattr(ToolkitRunner, "run_tool", fake_run_tool)
    result = enumerate_shares("10.0.0.5")
    assert result["success"] is True
    assert [s["name"] for s in result["shares"]] == ["public"]
    assert [t["status"] for t in result["tools"]] == ["error", "ok"]


def test_enumerate_shares_total_failure(monkeypatch: Any) -> None:
    def fake_run_tool(
        self: Any, tool: str, argv: list[str], timeout: int = 300
    ) -> dict[str, Any]:
        return {"tool": tool, "status": "error", "stdout": ""}

    monkeypatch.setattr(ToolkitRunner, "run_tool", fake_run_tool)
    result = enumerate_shares("10.0.0.5")
    assert result["success"] is False
    assert result["shares"] == []
    assert result["count"] == 0
    assert len(result["tools"]) == 2


def test_sandbox_shares_deterministic() -> None:
    a = sandbox_shares("10.10.10.42")
    assert a["count"] == 3 and a["success"] is True
    assert a["sandbox"] is True


def test_smb_router_ledger_and_scope(tmp_path: Any, monkeypatch: Any) -> None:
    from contextlib import asynccontextmanager

    monkeypatch.setenv("H4K_REFRESH_CVE", "0")
    monkeypatch.setenv("H4K_SANDBOX", "1")
    import main as main_module
    from routers import engagement as eng_router
    from services.engagement import EngagementStore

    store = EngagementStore(tmp_path / "smb.db")
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
    r = c.post("/api/smb/shares", json={"target": "10.0.0.5", "engagement_id": eid})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["count"] == 3
    assert body["ingested"] == 3
    assert len(store.shares(eid)) == 3
    assert len(c.get(f"/api/engagement/{eid}/graph").json()["shares"]) == 3
    assert len(c.get(f"/api/engagement/{eid}/shares").json()["shares"]) == 3

    r = c.post("/api/smb/shares", json={"target": "8.8.8.8", "engagement_id": eid})
    assert r.status_code == 200
    assert r.json()["skipped_out_of_scope"] == ["8.8.8.8"]
    assert len(store.shares(eid)) == 3

    assert c.get("/api/engagement/nope/shares").status_code == 404
    assert (
        c.post(
            "/api/smb/shares", json={"target": "10.0.0.5", "engagement_id": "nope"}
        ).status_code
        == 404
    )
