"""Backlog #63: secret baseline + allowlist — noise reduction."""

from __future__ import annotations

from typing import Any

import pytest
from services.secret_baseline import (
    apply_allowlist,
    apply_baseline,
    audit,
    find_secrets,
    fingerprint,
    to_ledger,
)
from services.taint_pack import parse_bundle

FILES = [
    {"path": "app.py", "content": "KEY = 'AKIAIOSFODNN7EXAMPLE'\n"},
    {"path": "conf.py", "content": "password = 'known-before'\n"},
    {"path": "tests/fixtures.py", "content": "token = 'fixture-token-value'\n"},
    {"path": "clean.py", "content": "x = 1\n"},
]


def test_find_and_fingerprint() -> None:
    out = find_secrets(FILES)
    assert {f["rule_id"] for f in out} == {"secret-aws-key", "secret-assignment"}
    assert len(out) == 3
    assert fingerprint("r", "f", "  x  ") == fingerprint("r", "f", "x")
    with pytest.raises(ValueError):
        find_secrets([])


def test_baseline_diff() -> None:
    out = find_secrets(FILES)
    fps = [f["fingerprint"] for f in out]
    new, old = apply_baseline(out, fps[:2])
    assert len(new) == 1 and len(old) == 2
    new, old = apply_baseline(out, [{"fingerprint": fps[0]}, {"rule_id": "nope"}])
    assert len(new) == 2 and len(old) == 1
    new, _ = apply_baseline(out, None)
    assert len(new) == 3


def test_allowlist() -> None:
    out = find_secrets(FILES)
    kept, dropped = apply_allowlist(out, ["fixtures", r"conf\.py"])
    assert len(kept) == 1 and len(dropped) == 2
    assert {d["allowlisted_by"] for d in dropped} == {0, 1}
    with pytest.raises(ValueError):
        apply_allowlist(out, ["(["])


def test_audit_counts() -> None:
    fps = [f["fingerprint"] for f in find_secrets(FILES)][:1]
    out = audit(FILES, baseline=fps, allowlist=["fixtures"])
    assert (
        out["finding_count"],
        out["new_count"],
        out["baselined_count"],
        out["allowlisted_count"],
    ) == (3, 1, 1, 1)
    assert out["clean"] is False
    clean = audit([{"path": "a.py", "content": "x = 1\n"}])
    assert clean["clean"] is True and clean["new_count"] == 0


def test_to_ledger_and_sandbox() -> None:
    from services.secret_baseline import sandbox_result

    res = sandbox_result()
    assert res["new_count"] == 1 and res["baselined_count"] == 1
    rows = to_ledger("10.10.10.77", "secrets-baseline", res["new"])
    assert len(rows) == 1 and rows[0]["cwe"] == "CWE-798"
    assert rows[0]["severity"] == "CRITICAL"
    assert to_ledger("h", "p", []) == []


def _client(tmp_path: Any, monkeypatch: Any) -> Any:
    from contextlib import asynccontextmanager

    monkeypatch.setenv("H4K_REFRESH_CVE", "0")
    monkeypatch.setenv("H4K_SANDBOX", "1")
    monkeypatch.setenv("H4K_DATA_DIR", str(tmp_path))
    import main as main_module

    @asynccontextmanager
    async def _noop(_app: Any) -> Any:
        yield

    main_module.app.router.lifespan_context = _noop
    from fastapi.testclient import TestClient

    return TestClient(main_module.app)


BUNDLE = (
    "=== app.py ===\nKEY = 'AKIAIOSFODNN7EXAMPLE'\n"
    "=== conf.py ===\npassword = 'known-before'\n"
    "=== tests/fixtures.py ===\ntoken = 'fixture-token-value'\n"
)


def test_secrets_router(tmp_path: Any, monkeypatch: Any) -> None:
    c = _client(tmp_path, monkeypatch)
    r = c.post("/api/source/secrets/scan", json={"bundle": BUNDLE, "host": "h"})
    assert r.status_code == 200
    body = r.json()
    assert (body["finding_count"], body["new_count"]) == (3, 1)
    assert body["ingested"] == 0

    assert c.post("/api/source/secrets/scan", json={}).status_code == 400
    assert (
        c.post(
            "/api/source/secrets/scan",
            json={"bundle": BUNDLE, "allowlist": ["(["]},
        ).status_code
        == 400
    )

    fps = [f["fingerprint"] for f in find_secrets(parse_bundle(BUNDLE))][:1]
    r = c.post(
        "/api/source/secrets/scan",
        json={"bundle": BUNDLE, "baseline": fps, "allowlist": ["fixtures"]},
    )
    assert r.status_code == 200
    assert (
        r.json()["new_count"],
        r.json()["baselined_count"],
        r.json()["allowlisted_count"],
    ) == (1, 1, 1)

    eng = c.post("/api/engagement/sandbox-seed").json()["engagement"]
    eid = eng["id"]
    r = c.post(
        "/api/source/secrets/scan",
        json={"bundle": BUNDLE, "host": "10.10.10.77", "engagement_id": eid},
    )
    assert r.status_code == 200
    assert r.json()["ingested"] == 1
    vulns = c.get(f"/api/engagement/{eid}/vulns/effective").json()
    assert "secrets secrets-baseline" in str(vulns)

    assert (
        c.post(
            "/api/source/secrets/scan",
            json={"bundle": BUNDLE, "host": "h", "engagement_id": "nope"},
        ).status_code
        == 404
    )

    r = c.post(
        "/api/source/secrets/scan",
        json={"bundle": BUNDLE, "host": "192.0.2.9", "engagement_id": eid},
    )
    assert r.status_code == 200
    assert r.json()["ingested"] == 0
    assert r.json()["skipped_out_of_scope"] == ["192.0.2.9"]
