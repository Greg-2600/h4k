"""Backlog #12: loot vault with redaction + masked export."""

from __future__ import annotations

from typing import Any

from services.engagement import EngagementStore
from services.loot_vault import mask_flag, mask_secret, vault_markdown, vault_summary


def test_mask_secret() -> None:
    assert mask_secret("") == ""
    assert mask_secret("toor") == "•" * 8
    masked = mask_secret("s3cret-pw", keep=2)
    assert masked.endswith("pw") and "s3cret" not in masked


def test_mask_flag() -> None:
    assert mask_flag("CTF{abc123}") == "CTF{•••}"
    assert "abc" not in mask_flag("flag{abc}")


def test_vault_masks_by_default(tmp_path: Any, monkeypatch: Any) -> None:
    monkeypatch.setenv("H4K_DATA_DIR", str(tmp_path))
    store = EngagementStore(tmp_path / "vault.db")
    eng = store.create_engagement("acme", ["10.0.0.0/24"])
    store.record_credential(
        eng["id"],
        "root",
        "toor-secret",
        "ssh",
        origin_host="10.0.0.5",
        origin_port=22,
        verified=True,
    )
    from services.flags import FlagStore

    FlagStore().record(eng["id"], "CTF{vault}", host="10.0.0.5")
    masked = vault_summary(store, eng["id"])
    assert masked["revealed"] is False
    assert masked["counts"] == {"credentials": 1, "flags": 1, "shares": 0}
    assert "toor-secret" not in str(masked)
    assert "CTF{vault}" not in str(masked)
    open_ = vault_summary(store, eng["id"], reveal=True)
    assert "toor-secret" in str(open_) and "CTF{vault}" in str(open_)
    md = vault_markdown(store, eng["id"])
    assert md.startswith("# Loot vault") and "toor-secret" not in md
    try:
        vault_summary(store, "nope")
    except ValueError:
        pass
    else:
        raise AssertionError("unknown engagement must raise")


def test_vault_router(tmp_path: Any, monkeypatch: Any) -> None:
    from contextlib import asynccontextmanager

    monkeypatch.setenv("H4K_REFRESH_CVE", "0")
    monkeypatch.setenv("H4K_SANDBOX", "1")
    monkeypatch.setenv("H4K_DATA_DIR", str(tmp_path))
    import main as main_module
    from routers import engagement as eng_router

    store = EngagementStore(tmp_path / "vault-router.db")
    monkeypatch.setattr(eng_router, "get_store", lambda: store)

    @asynccontextmanager
    async def _noop(_app: Any) -> Any:
        yield

    main_module.app.router.lifespan_context = _noop
    from fastapi.testclient import TestClient

    c = TestClient(main_module.app)
    eid = c.post("/api/engagement/sandbox-seed").json()["engagement"]["id"]
    r = c.get(f"/api/engagement/{eid}/vault")
    assert r.status_code == 200, r.text
    assert r.json()["revealed"] is False
    assert "lab-admin" not in r.text
    r = c.get(f"/api/engagement/{eid}/vault?reveal=true")
    assert r.status_code == 200 and "lab-admin" in r.text
    r = c.get(f"/api/engagement/{eid}/vault/export?fmt=md")
    assert r.status_code == 200 and r.json()["content"].startswith("# Loot vault")
    r = c.get(f"/api/engagement/{eid}/vault/export?fmt=json")
    assert r.status_code == 200 and "items" in r.json()
    assert c.get("/api/engagement/nope/vault").status_code == 404
