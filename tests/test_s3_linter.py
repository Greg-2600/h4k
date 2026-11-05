"""Backlog #44: S3 policy linter — public/ACL offline eval."""

from __future__ import annotations

from typing import Any

from services.s3_linter import (
    audit_acl,
    audit_policy,
    lint_bucket,
    sandbox_result,
    to_ledger,
)

PUBLIC_READ = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": "*",
            "Action": ["s3:GetObject"],
            "Resource": ["arn:aws:s3:::lab/*"],
        }
    ],
}

PUBLIC_ALL = {
    "Statement": {
        "Effect": "Allow",
        "Principal": {"AWS": "*"},
        "Action": "s3:*",
        "Resource": "*",
    }
}

CONDITIONAL = {
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": "*",
            "Condition": {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}},
        }
    ]
}

SCOPED = {
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::123:role/app"},
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::lab/*",
        }
    ]
}


def test_public_read_critical() -> None:
    out = audit_policy(PUBLIC_READ)
    assert len(out) == 1 and out[0]["severity"] == "CRITICAL"
    assert "public read" in out[0]["title"]


def test_public_all_and_conditioned() -> None:
    out = audit_policy(PUBLIC_ALL)
    assert out[0]["severity"] == "CRITICAL" and "full S3" in out[0]["title"]
    out = audit_policy(CONDITIONAL)
    assert out[0]["severity"] == "MEDIUM" and "conditioned" in out[0]["title"]


def test_scoped_clean_and_notprincipal() -> None:
    assert audit_policy(SCOPED) == []
    out = audit_policy(
        {
            "Statement": [
                {
                    "Effect": "Allow",
                    "NotPrincipal": {"AWS": "x"},
                    "Action": "s3:*",
                    "Resource": "*",
                }
            ]
        }
    )
    assert out[0]["severity"] == "HIGH"


def test_acl_variants() -> None:
    assert audit_acl("private") == []
    assert audit_acl(None) == []
    assert audit_acl("public-read-write")[0]["severity"] == "CRITICAL"
    assert audit_acl("public-read")[0]["severity"] == "HIGH"
    assert audit_acl("authenticated-read")[0]["severity"] == "MEDIUM"
    assert audit_acl("weird-name")[0]["severity"] == "MEDIUM"
    grants = [
        {
            "Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"},
            "Permission": "FULL_CONTROL",
        }
    ]
    assert audit_acl(grants)[0]["severity"] == "CRITICAL"


def test_block_neutralizes() -> None:
    full = {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": True,
    }
    out = lint_bucket("b", policy=PUBLIC_READ, acl="public-read", block_public=full)
    assert out["blocked"] is True
    assert len(out["findings"]) == 1 and out["findings"][0]["severity"] == "INFO"
    assert out["clean"] is False  # grant still on record, just neutralized


def test_lint_shapes() -> None:
    out = lint_bucket("b", policy=PUBLIC_READ, acl="public-read")
    assert out["public"] is True and out["finding_count"] == 2
    assert lint_bucket("b")["clean"] is True


def test_sandbox_and_ledger_shapes() -> None:
    res = sandbox_result("lab-bucket")
    assert res["finding_count"] == 2 and res["public"] is True
    rows = to_ledger("10.10.10.77", "lab-bucket", res["findings"])
    assert len(rows) == 2
    assert rows[0]["module"] == "s3-linter"
    assert rows[0]["cwe"] == "CWE-732"
    assert to_ledger("h", "b", []) == []


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


def test_s3_router(tmp_path: Any, monkeypatch: Any) -> None:
    c = _client(tmp_path, monkeypatch)
    r = c.post(
        "/api/s3/lint",
        json={
            "bucket": "lab",
            "policy": PUBLIC_READ,
            "acl": "public-read",
            "host": "h",
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["finding_count"] == 2 and body["ingested"] == 0
    assert body["public"] is True

    # Bad policy text is a 400 even in sandbox.
    assert (
        c.post("/api/s3/lint", json={"bucket": "x", "policy": "{bad json"}).status_code
        == 400
    )

    # Ledger into a seeded engagement with a fresh host.
    eng = c.post("/api/engagement/sandbox-seed").json()["engagement"]
    eid = eng["id"]
    r = c.post(
        "/api/s3/lint",
        json={"bucket": "lab", "host": "10.10.10.77", "engagement_id": eid},
    )
    assert r.status_code == 200
    assert r.json()["ingested"] == 2
    vulns = c.get(f"/api/engagement/{eid}/vulns/effective").json()
    assert "s3 lab" in str(vulns)

    # Unknown engagement is a 404.
    assert (
        c.post(
            "/api/s3/lint",
            json={"bucket": "x", "host": "h", "engagement_id": "nope"},
        ).status_code
        == 404
    )

    # Out-of-scope host is reported, never stored.
    r = c.post(
        "/api/s3/lint",
        json={"bucket": "x", "host": "192.0.2.9", "engagement_id": eid},
    )
    assert r.status_code == 200
    assert r.json()["ingested"] == 0
    assert r.json()["skipped_out_of_scope"] == ["192.0.2.9"]
