"""Backlog #7: read-only SMB share enumerator + asset-graph ledger."""

from __future__ import annotations

from typing import Any

from services.smb_shares import (
    _merge,
    parse_smbclient,
    parse_smbmap,
    sandbox_shares,
)


def test_parse_smbclient_table() -> None:
    out = parse_smbclient(
        "\n".join(
            [
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
        [{"name": "public", "type": "", "comment": "lab", "access": "READ ONLY"}],
    )
    assert merged[0] == {
        "name": "public",
        "type": "Disk",
        "comment": "lab",
        "access": "READ ONLY",
    }


def test_parse_smbclient_skips_noise_and_headers() -> None:
    out = parse_smbclient(
        "\n".join(
            [
                "Connection to 10.0.0.5 failed (Error NT_STATUS_NO_LOGON_SERVERS)",
                "",
                "\tSharename       Type      Comment",
                "\t---------       ----      -------",
                "\tSharename       Type      Comment",
                "\tpublic          Disk      lab drop",
                "",
                "Server               Comment",
                "---------            -------",
                "SHOULD-NOT-APPEAR    Server  after table",
            ]
        )
    )
    assert [s["name"] for s in out] == ["public"]


def test_parse_smbmap_skips_junk_rows() -> None:
    out = parse_smbmap(
        "\n".join(
            [
                "Permissions\tShare\tComment",
                "READ ONLY\tpublic\tlab drop",
                "lonelycolumn",
                "READ+WRITE\tbadaccess\tplus is not an access word",
                "READ ONLY\tShare\tcolumn header, not a share",
                "READ ONLY\tdata.old\tdots look like paths",
                "READ ONLY\tsrv/drop\tslashes look like paths",
                "READ ONLY\tC$",
            ]
        )
    )
    assert [(s["name"], s["access"]) for s in out] == [
        ("public", "READ ONLY"),
        ("C$", "READ ONLY"),
    ]


def test_merge_adds_disjoint_names() -> None:
    merged = _merge(
        [{"name": "public", "type": "Disk", "comment": "", "access": ""}],
        [
            {"name": "public", "type": "", "comment": "lab", "access": ""},
            {"name": "extra", "type": "Disk", "comment": "", "access": "READ ONLY"},
        ],
    )
    assert [s["name"] for s in merged] == ["extra", "public"]
    assert merged[0]["access"] == "READ ONLY"


_SMBCLIENT_OK = "\n".join(
    [
        "\tSharename       Type      Comment",
        "\t---------       ----      -------",
        "\tpublic          Disk      lab drop",
        "",
    ]
)
_SMBMAP_OK = "READ ONLY\tpublic\tlab drop\n"


def _stub_runner(
    monkeypatch: Any, smb_stdout: str | None, map_stdout: str | None
) -> list[str]:
    import services.toolkit as tk

    seen: list[str] = []

    class _Runner:
        def run_tool(
            self, tool: str, argv: list[str], timeout: int = 60
        ) -> dict[str, Any]:
            seen.append(tool)
            ok = smb_stdout if tool == "smbclient" else map_stdout
            if ok is None:
                return {"tool": tool, "status": "error", "stdout": ""}
            return {"tool": tool, "status": "ok", "stdout": ok}

    monkeypatch.setattr(tk, "ToolkitRunner", lambda: _Runner())
    return seen


def test_enumerate_shares_merges_both_tools(monkeypatch: Any) -> None:
    from services.smb_shares import enumerate_shares

    seen = _stub_runner(monkeypatch, _SMBCLIENT_OK, _SMBMAP_OK)
    res = enumerate_shares("10.0.0.5")
    assert seen == ["smbclient", "smbmap"]
    assert res["success"] is True and res["count"] == 1
    assert res["shares"][0]["access"] == "READ ONLY"


def test_enumerate_shares_with_user_and_dead_smbmap(monkeypatch: Any) -> None:
    from services.smb_shares import enumerate_shares

    _stub_runner(monkeypatch, _SMBCLIENT_OK, None)
    res = enumerate_shares("10.0.0.5", user="op", password="pw")
    assert res["success"] is True and res["count"] == 1
    # smbclient-only: no access enrichment from smbmap
    assert res["shares"][0].get("access", "") == ""


def test_enumerate_shares_all_tools_fail(monkeypatch: Any) -> None:
    from services.smb_shares import enumerate_shares

    _stub_runner(monkeypatch, None, None)
    res = enumerate_shares("10.0.0.5")
    assert res["success"] is False and res["shares"] == []


def test_record_share_rejects_nameless(tmp_path: Any) -> None:
    from services.engagement import EngagementStore

    store = EngagementStore(tmp_path / "smb-empty.db")
    eng = store.create_engagement("acme", ["10.0.0.0/24"])
    assert store.record_share(eng["id"], "10.0.0.5", {}) == 0
    assert store.record_share(eng["id"], "10.0.0.5", {"name": "  "}) == 0
    assert store.shares(eng["id"]) == []


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
