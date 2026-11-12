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
