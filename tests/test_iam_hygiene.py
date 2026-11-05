"""Backlog #43: IAM key hygiene — age/rotation, read-only."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from services.iam_hygiene import (
    audit_keys,
    live_report,
    mask_key_id,
    parse_credential_report,
    parse_date,
    sandbox_result,
    to_ledger,
)

NOW = datetime(2026, 6, 1, tzinfo=UTC)


def _key(
    user: str, kid: str, status: str, age: int, used: int | None = None
) -> dict[str, Any]:
    from datetime import timedelta

    row: dict[str, Any] = {
        "UserName": user,
        "AccessKeyId": kid,
        "Status": status,
        "CreateDate": (NOW - timedelta(days=age)).isoformat(),
    }
    if used is not None:
        row["LastUsedDate"] = (NOW - timedelta(days=used)).isoformat()
    return row


def test_parse_date_and_mask() -> None:
    assert parse_date("2026-01-01") is not None
    assert parse_date("not-a-date") is None
    assert parse_date("N/A") is None
    assert parse_date(None) is None
    assert mask_key_id("AKIAIOSFODNN7EXAMPLE") == "…MPLE"
    assert mask_key_id("") == "(unknown)"


def test_fresh_key_clean() -> None:
    out = audit_keys([_key("a", "AKIAAAAABBBBCCCCDDDD", "Active", 12, used=1)], now=NOW)
    assert out["clean"] is True and out["key_count"] == 1
    assert out["keys"][0]["key"] == "…DDDD"
    assert out["keys"][0]["kind"] == "long-term"


def test_stale_and_ancient() -> None:
    out = audit_keys(
        [_key("b", "AKIA1111222233334444", "Active", 120, used=100)], now=NOW
    )
    sevs = [f["severity"] for f in out["findings"]]
    assert "HIGH" in sevs  # stale + unused
    out = audit_keys([_key("c", "AKIA5555666677778888", "Active", 400)], now=NOW)
    assert any(f["severity"] == "CRITICAL" for f in out["findings"])


def test_dormant_and_temporary() -> None:
    out = audit_keys(
        [
            _key("ci", "AKIA9999000011112222", "Inactive", 400),
            _key("tmp", "ASIA3333444455556666", "Active", 1),
        ],
        now=NOW,
    )
    assert len(out["findings"]) == 1
    assert out["findings"][0]["severity"] == "LOW"


def test_entry_errors_reported() -> None:
    out = audit_keys(
        [{"UserName": "x"}, "nope", _key("a", "AKIA1", "Active", 1)], now=NOW
    )
    assert out["key_count"] == 1
    assert len(out["errors"]) == 2


def test_credential_report_parse() -> None:
    csv_text = (
        "user,access_key_1_active,access_key_1_last_rotated,"
        "access_key_1_last_used_date,access_key_2_active,"
        "access_key_2_last_rotated,access_key_2_last_used_date\n"
        "alice,true,2026-05-01T00:00:00+00:00,2026-05-20T00:00:00+00:00,"
        "false,N/A,N/A\n"
    )
    keys = parse_credential_report(csv_text)
    assert len(keys) == 2
    assert keys[0]["UserName"] == "alice" and keys[0]["Status"] == "Active"
    assert keys[1]["Status"] == "Inactive"


def test_sandbox_and_ledger_shapes() -> None:
    res = sandbox_result("lab-account")
    assert res["finding_count"] == 2 and res["clean"] is False
    assert res["keys"][0]["key"] == "…AAAA"  # masked in fixtures too
    rows = to_ledger("10.10.10.77", "lab-account", res["findings"])
    assert len(rows) == 2
    assert rows[0]["module"] == "iam-hygiene"
    assert rows[0]["cwe"] == "CWE-613"
    assert to_ledger("h", "a", []) == []


def test_live_report_no_aws(monkeypatch: Any) -> None:
    import services.iam_hygiene as mod

    monkeypatch.setattr(mod.shutil, "which", lambda _name: None)
    assert live_report()["error"] == "aws CLI not installed"


def _client(tmp_path: Any, monkeypatch: Any) -> Any:
    from contextlib import asynccontextmanager

    import services.iam_hygiene as mod

    monkeypatch.setenv("H4K_REFRESH_CVE", "0")
    monkeypatch.setenv("H4K_SANDBOX", "1")
    monkeypatch.setenv("H4K_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(mod.shutil, "which", lambda _name: None)
    import main as main_module

    @asynccontextmanager
    async def _noop(_app: Any) -> Any:
        yield

    main_module.app.router.lifespan_context = _noop
    from fastapi.testclient import TestClient

    return TestClient(main_module.app)


def test_iam_router(tmp_path: Any, monkeypatch: Any) -> None:
    c = _client(tmp_path, monkeypatch)
    r = c.post(
        "/api/iam/keys",
        json={"account": "lab", "keys": [_key("a", "AKIA1", "Active", 1)], "host": "h"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["key_count"] >= 0 and body["ingested"] == 0

    # Neither keys nor live is a 400 even in sandbox.
    assert c.post("/api/iam/keys", json={"account": "x"}).status_code == 400

    # Non-live explicit keys path in sandbox still returns canned set.
    assert (
        c.post("/api/iam/keys", json={"account": "x", "live": True}).status_code == 200
    )

    # Ledger into a seeded engagement with a fresh host.
    eng = c.post("/api/engagement/sandbox-seed").json()["engagement"]
    eid = eng["id"]
    r = c.post(
        "/api/iam/keys",
        json={
            "account": "lab",
            "keys": [_key("a", "AKIA1", "Active", 1)],
            "host": "10.10.10.77",
            "engagement_id": eid,
        },
    )
    assert r.status_code == 200
    assert r.json()["ingested"] == 2
    vulns = c.get(f"/api/engagement/{eid}/vulns/effective").json()
    assert "iam lab:" in str(vulns)

    # Unknown engagement is a 404.
    assert (
        c.post(
            "/api/iam/keys",
            json={
                "account": "x",
                "keys": [_key("a", "AKIA1", "Active", 1)],
                "host": "h",
                "engagement_id": "nope",
            },
        ).status_code
        == 404
    )

    # Out-of-scope host is reported, never stored.
    r = c.post(
        "/api/iam/keys",
        json={
            "account": "x",
            "keys": [_key("a", "AKIA1", "Active", 1)],
            "host": "192.0.2.9",
            "engagement_id": eid,
        },
    )
    assert r.status_code == 200
    assert r.json()["ingested"] == 0
    assert r.json()["skipped_out_of_scope"] == ["192.0.2.9"]
