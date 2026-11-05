"""Backlog #29: SQLmap tamper flow — dump → ledger, explicit only."""

from __future__ import annotations

from typing import Any

from services.sqlmap_flow import (
    TAMPERS,
    extract_creds,
    extract_flags,
    ledger,
    parse_dump_tables,
    run_tamper_scan,
    sandbox_dump,
)


def test_tamper_list_curated() -> None:
    assert "space2comment" in TAMPERS and len(TAMPERS) >= 5


def test_rejects_unknown_tamper() -> None:
    try:
        run_tamper_scan("http://x/?id=1", ["nope"])
    except ValueError as exc:
        assert "unknown tamper" in str(exc)
    else:
        raise AssertionError("unknown tamper must raise")


_DUMP = (
    "Database: labdb Table: users [2 entries]\n"
    "+----+-------+----------+\n| id | user  | password |\n+----+-------+----------+\n"
    "| 1  | admin | s3cret!  |\n| 2  | bob   | hunter2  |\n+----+-------+----------+\n"
    "Database: labdb Table: flags [1 entry]\n"
    "+----+------------+\n| id | value      |\n+----+------------+\n| 1  | CTF{sq1m4p} |\n+----+------------+\n"
)


def test_parse_dump_tables() -> None:
    tables = parse_dump_tables(_DUMP)
    assert [(t["table"], len(t["rows"])) for t in tables] == [
        ("users", 2),
        ("flags", 1),
    ]
    assert tables[0]["columns"] == ["id", "user", "password"]
    assert parse_dump_tables("nothing here") == []


def test_extract_flags_and_creds() -> None:
    tables = parse_dump_tables(_DUMP)
    flags = extract_flags(tables)
    assert [f["value"] for f in flags] == ["CTF{sq1m4p}"]
    creds = extract_creds(tables)
    assert ("admin", "s3cret!") in [(c["user"], c["password"]) for c in creds]


def test_sandbox_dump() -> None:
    out = sandbox_dump()
    assert out["success"] is True and len(out["tables"]) == 2


def test_ledger_flags_and_unverified_creds(tmp_path: Any, monkeypatch: Any) -> None:
    monkeypatch.setenv("H4K_DATA_DIR", str(tmp_path))
    from services.engagement import EngagementStore

    store = EngagementStore(tmp_path / "sq.db")
    eng = store.create_engagement("acme", ["10.0.0.0/24"])
    out = ledger(store, eng["id"], "10.0.0.5", parse_dump_tables(_DUMP))
    assert out == {
        "tables": 2,
        "flags": 1,
        "credentials": 2,
        "flag_values": ["CTF{sq1m4p}"],
    }
    from services.flags import FlagStore

    assert FlagStore().list_flags(eng["id"])[0]["value"] == "CTF{sq1m4p}"
    creds = list(store.credentials(eng["id"]))
    assert creds and all(c["verified"] is False for c in creds)
    try:
        ledger(store, "nope", "10.0.0.5", [])
    except ValueError:
        pass
    else:
        raise AssertionError("unknown engagement must raise")


def test_sqlmap_router(tmp_path: Any, monkeypatch: Any) -> None:
    from contextlib import asynccontextmanager

    monkeypatch.setenv("H4K_REFRESH_CVE", "0")
    monkeypatch.setenv("H4K_SANDBOX", "1")
    import main as main_module
    from routers import engagement as eng_router
    from services.engagement import EngagementStore

    store = EngagementStore(tmp_path / "sq-router.db")
    monkeypatch.setattr(eng_router, "get_store", lambda: store)

    @asynccontextmanager
    async def _noop(_app: Any) -> Any:
        yield

    main_module.app.router.lifespan_context = _noop
    from fastapi.testclient import TestClient

    c = TestClient(main_module.app)
    r = c.get("/api/sqlmap/tampers")
    assert r.status_code == 200 and r.json()["count"] >= 5
    r = c.post(
        "/api/sqlmap/tamper", json={"url": "http://x/?id=1", "tampers": ["nope"]}
    )
    assert r.status_code in (400, 200)
    eid = c.post(
        "/api/engagement", json={"name": "acme", "scope": ["10.0.0.0/24"]}
    ).json()["id"]
    r = c.post(
        "/api/sqlmap/dump",
        json={
            "url": "http://10.0.0.5/vuln.php?id=1",
            "engagement_id": eid,
            "host": "10.0.0.5",
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["tables"] and body["ingested"] == {"flags": 1, "credentials": 2}
    r = c.post(
        "/api/sqlmap/dump",
        json={"url": "http://x/", "engagement_id": eid, "host": "8.8.8.8"},
    )
    assert r.json()["skipped_out_of_scope"] == ["8.8.8.8"]
