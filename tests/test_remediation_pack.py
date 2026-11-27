"""Backlog #71: rotation planner + patch-diff verifier + PoC capture."""

from __future__ import annotations

import json
from contextlib import asynccontextmanager
from typing import Any

import pytest
from services.remediation_pack import (
    analyze,
    capture_poc,
    plan_rotation,
    sandbox_result,
    to_ledger,
    verify_patch,
)

FAKE_AWS = "AKIAEXAMPLEEXAMPLEEX"
FAKE_VALUE = "FAKE-SECRET-DO-NOT-USE"
FAKE_DB = "FAKE-DB-PASSWORD-DO-NOT-USE"
FAKE_BEARER = "FAKE-BEARER-DO-NOT-USE"
FAKE_QUERY = "FAKE-QUERY-DO-NOT-USE"

SECRETS = [
    {
        "rule_id": "secret-aws-key",
        "label": "demo-aws-key",
        "where": "config.py",
        "exposure": "repo",
        "status": "open",
        "code": f"KEY = '{FAKE_AWS}'",
        "value": FAKE_VALUE,
    },
    {
        "kind": "db-password",
        "label": "demo-db-password",
        "where": "ci.env",
        "exposure": "log",
        "password": FAKE_DB,
    },
    {
        "kind": "github-token",
        "label": "demo-github-token",
        "where": "ci.yml",
        "status": "rotated",
        "value": FAKE_VALUE,
    },
    {
        "rule_id": "secret-assignment",
        "label": "demo-ignored",
        "status": "ignored",
        "value": FAKE_VALUE,
    },
]

BEFORE = {
    "job_id": "fuzz-before",
    "executions": 10000,
    "coverage": 0.72,
    "crashes": [{"id": "sig-a"}, {"id": "sig-b"}],
}
AFTER_FIXED = {
    "job_id": "fuzz-after",
    "executions": 12000,
    "coverage": 0.75,
    "crashes": [],
}

FLOW = [
    {"action": "navigate", "target": "http://lab.invalid/login"},
    {
        "action": "submit",
        "method": "POST",
        "target": f"http://lab.invalid/login?token={FAKE_QUERY}",
        "headers": {"Authorization": f"Bearer {FAKE_BEARER}"},
        "body": {"password": FAKE_DB},
        "value": FAKE_VALUE,
    },
    {
        "action": "assert",
        "target": "http://lab.invalid/admin",
        "expected": "admin panel reachable",
        "observed": "200 OK",
        "outcome": "confirmed",
        "note": f"secret={FAKE_VALUE}",
    },
]


def test_rotation_playbooks_and_metadata_only() -> None:
    result = plan_rotation(SECRETS)
    assert result["count"] == 4
    assert result["actionable"] == 2
    assert result["by_kind"] == {
        "aws-access-key": 1,
        "database-password": 1,
        "generic-secret": 1,
        "github-token": 1,
    }
    plans = result["plans"]
    assert plans[0]["kind"] == "aws-access-key"
    assert plans[0]["severity"] == "CRITICAL"
    assert plans[0]["priority"] == "P0"
    assert len(plans[0]["steps"]) >= 4
    assert "revoke" in plans[0]["steps"][0].lower()
    assert plans[1]["kind"] == "database-password"
    assert plans[2]["status"] == "rotated"
    assert plans[2]["step_count"] == 1
    assert plans[3]["steps"] == []
    assert plans[0]["ignored_value_keys"] == ["code", "value"]
    assert plans[1]["ignored_value_keys"] == ["password"]
    serialized = json.dumps(result)
    for sentinel in (FAKE_AWS, FAKE_VALUE, FAKE_DB):
        assert sentinel not in serialized


def test_rotation_redacts_secret_shaped_text_and_stays_stable() -> None:
    first = plan_rotation(
        [
            {
                "rule_id": "secret-aws-key",
                "label": f"aws key {FAKE_AWS}",
                "note": f"password={FAKE_VALUE}",
            }
        ]
    )
    assert (
        plan_rotation(
            [
                {
                    "rule_id": "secret-aws-key",
                    "label": f"aws key {FAKE_AWS}",
                    "note": FAKE_VALUE,
                }
            ]
        )["plans"][0]["id"]
        == first["plans"][0]["id"]
    )
    assert "<redacted>" in first["plans"][0]["label"]
    assert FAKE_AWS not in json.dumps(first)
    assert FAKE_VALUE not in json.dumps(first)


def test_rotation_string_entries_and_validation() -> None:
    plans = plan_rotation(["secret-github-token", "db-password", "random-label"])
    assert [plan["kind"] for plan in plans["plans"]] == [
        "github-token",
        "database-password",
        "generic-secret",
    ]
    with pytest.raises(ValueError, match="secrets must be a list"):
        plan_rotation("secret-aws-key")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="at most 100"):
        plan_rotation(["x"] * 101)
    with pytest.raises(ValueError, match="secrets\\[0\\]"):
        plan_rotation([42])


def test_patch_verdicts_from_supplied_results() -> None:
    fixed = verify_patch(BEFORE, AFTER_FIXED)
    assert fixed["verdict"] == "fixed"
    assert fixed["verified"] is True
    assert fixed["comparable"] is True
    assert set(fixed["cleared_signatures"]) == {"sig-a", "sig-b"}

    partial = verify_patch(BEFORE, {**AFTER_FIXED, "crashes": [{"id": "sig-a"}]})
    assert partial["verdict"] == "partial"
    assert partial["persisting_signatures"] == ["sig-a"]

    persists = verify_patch(BEFORE, {**BEFORE, "crash_count": 2})
    assert persists["verdict"] == "persists"

    regression = verify_patch(
        BEFORE, {**AFTER_FIXED, "crashes": [{"id": "sig-a"}, {"id": "sig-new"}]}
    )
    assert regression["verdict"] == "regression"
    assert regression["new_signatures"] == ["sig-new"]

    not_applicable = verify_patch({**BEFORE, "crashes": []}, AFTER_FIXED)
    assert not_applicable["verdict"] == "not_applicable"


def test_patch_inconclusive_without_comparable_runs() -> None:
    missing = verify_patch(BEFORE, {"crashes": []})
    assert missing["verdict"] == "inconclusive"
    assert any("both runs need executions" in note for note in missing["caveats"])

    fewer = verify_patch(BEFORE, {**AFTER_FIXED, "executions": 1000})
    assert fewer["verdict"] == "inconclusive"
    assert any("half the baseline" in note for note in fewer["caveats"])

    coverage_drop = verify_patch(BEFORE, {**AFTER_FIXED, "coverage": 0.4})
    assert coverage_drop["verdict"] == "inconclusive"
    assert any("coverage dropped" in note for note in coverage_drop["caveats"])

    one_sided = verify_patch(BEFORE, None)
    assert one_sided["verdict"] == "inconclusive"
    assert one_sided["baseline_crashes"] == 2
    assert one_sided["retest_crashes"] is None


def test_patch_validation() -> None:
    with pytest.raises(ValueError, match="before must be an object"):
        verify_patch("before", AFTER_FIXED)
    with pytest.raises(ValueError, match=r"before.crashes must be a list"):
        verify_patch({"crashes": "sig-a"}, AFTER_FIXED)
    with pytest.raises(ValueError, match=r"before\.crashes\[0\]"):
        verify_patch({"crashes": [42]}, AFTER_FIXED)
    with pytest.raises(ValueError, match=r"after.executions must be a number"):
        verify_patch(BEFORE, {"executions": "many"})
    with pytest.raises(ValueError, match=r"after.crash_count must be non-negative"):
        verify_patch(BEFORE, {"crash_count": -1})
    with pytest.raises(ValueError, match=r"before.coverage must be a number"):
        verify_patch({"coverage": "high"}, AFTER_FIXED)
    with pytest.raises(ValueError, match=r"after.executions must be a number"):
        verify_patch(BEFORE, {"executions": True})


def test_poc_capture_is_deterministic_and_redacts_values() -> None:
    first = capture_poc(FLOW)
    assert capture_poc(FLOW) == first
    assert first["headless"] is True
    assert first["browser"] is False
    assert first["executed"] is False
    assert first["step_count"] == 3
    assert first["actions"] == {"assert": 1, "navigate": 1, "submit": 1}
    assert first["confirmed"] is True
    assert first["confirmed_count"] == 1
    assert first["ignored_value_fields"] >= 3
    assert len(first["digest"]) == 16

    submit = first["steps"][1]
    assert submit["method"] == "POST"
    assert submit["header_names"] == ["Authorization"]
    assert submit["body_keys"] == ["password"]
    assert "?" not in submit["target"]
    assert "<redacted>" in first["steps"][2]["note"]
    serialized = json.dumps(first)
    for sentinel in (FAKE_VALUE, FAKE_DB, FAKE_BEARER, FAKE_QUERY):
        assert sentinel not in serialized
    assert [step["index"] for step in first["steps"]] == [1, 2, 3]


def test_poc_capture_userinfo_and_string_steps() -> None:
    result = capture_poc(["review the response", {"action": "note", "note": "step"}])
    assert [step["action"] for step in result["steps"]] == ["note", "note"]
    assert result["steps"][0]["note"] == "review the response"

    redacted = capture_poc(
        [{"action": "navigate", "url": f"http://user:{FAKE_VALUE}@lab.invalid/x?k=v"}]
    )
    assert FAKE_VALUE not in json.dumps(redacted)
    assert "?" not in redacted["steps"][0]["target"]
    assert "@" not in redacted["steps"][0]["target"]


def test_poc_validation() -> None:
    with pytest.raises(ValueError, match="flow must be a list"):
        capture_poc("navigate")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="at most 200"):
        capture_poc(["x"] * 201)
    with pytest.raises(ValueError, match="unsupported action"):
        capture_poc([{"action": "execute-shell"}])
    with pytest.raises(ValueError, match="headers must be an object or list"):
        capture_poc([{"action": "request", "headers": "Authorization: x"}])
    with pytest.raises(ValueError, match="flow\\[0\\]"):
        capture_poc([42])


def test_analyze_requires_input_and_ledger_rows() -> None:
    with pytest.raises(ValueError, match="secrets, before/after results or flow"):
        analyze()
    combined = analyze(SECRETS, BEFORE, AFTER_FIXED, FLOW)
    assert combined["sandbox"] is False
    assert combined["rotation"]["actionable"] == 2
    assert combined["patch_verification"]["verdict"] == "fixed"
    rows = to_ledger("10.10.10.77", combined)
    assert [row["module"] for row in rows] == [
        "secret-rotation",
        "secret-rotation",
        "poc-capture",
    ]
    assert all(row["host"] == "10.10.10.77" for row in rows)
    serialized = json.dumps(rows)
    for sentinel in (FAKE_AWS, FAKE_VALUE, FAKE_DB, FAKE_BEARER):
        assert sentinel not in serialized

    broken = analyze(
        secrets=[{"kind": "db-password", "label": "db"}],
        before=BEFORE,
        after={**AFTER_FIXED, "crashes": [{"id": "sig-new"}]},
    )
    broken_rows = to_ledger("h", broken)
    assert any(row["module"] == "patch-verifier" for row in broken_rows)


def test_sandbox_result_is_canned_and_deterministic() -> None:
    result = sandbox_result()
    assert result == sandbox_result()
    assert result["sandbox"] is True
    assert result["rotation"]["count"] == 3
    assert result["rotation"]["actionable"] == 2
    assert result["patch_verification"]["verdict"] == "fixed"
    assert result["poc_capture"]["confirmed"] is True
    assert len(to_ledger("h", result)) == 3
    serialized = json.dumps(result)
    for sentinel in (FAKE_AWS, FAKE_VALUE, FAKE_DB, FAKE_BEARER, FAKE_QUERY):
        assert sentinel not in serialized


def _client(tmp_path: Any, monkeypatch: Any, sandbox: bool) -> Any:
    monkeypatch.setenv("H4K_REFRESH_CVE", "0")
    monkeypatch.setenv("H4K_SANDBOX", "1" if sandbox else "0")
    monkeypatch.setenv("H4K_DATA_DIR", str(tmp_path))
    import main as main_module

    @asynccontextmanager
    async def _noop(_app: Any) -> Any:
        yield

    main_module.app.router.lifespan_context = _noop
    from fastapi.testclient import TestClient

    return TestClient(main_module.app)


def test_router_sandbox_and_validation(tmp_path: Any, monkeypatch: Any) -> None:
    client = _client(tmp_path, monkeypatch, sandbox=True)
    response = client.post(
        "/api/source/remediation-pack",
        json={"secrets": SECRETS, "before": BEFORE, "after": AFTER_FIXED, "flow": FLOW},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["sandbox"] is True
    assert body["rotation"]["actionable"] == 2
    assert body["patch_verification"]["verdict"] == "fixed"
    assert body["poc_capture"]["confirmed"] is True
    assert body["ingested"] == 0
    serialized = json.dumps(body)
    for sentinel in (FAKE_AWS, FAKE_VALUE, FAKE_DB, FAKE_BEARER, FAKE_QUERY):
        assert sentinel not in serialized

    assert client.post("/api/source/remediation-pack", json={}).status_code == 400
    assert (
        client.post(
            "/api/source/remediation-pack",
            json={"secrets": SECRETS, "engagement_id": "nope"},
        ).status_code
        == 404
    )

    engagement = client.post("/api/engagement/sandbox-seed").json()["engagement"]
    response = client.post(
        "/api/source/remediation-pack",
        json={
            "secrets": SECRETS,
            "before": BEFORE,
            "after": AFTER_FIXED,
            "flow": FLOW,
            "host": "10.10.10.77",
            "engagement_id": engagement["id"],
        },
    )
    assert response.status_code == 200
    assert response.json()["ingested"] == 3
    vulns = client.get(f"/api/engagement/{engagement['id']}/vulns/effective").json()
    assert "secret-rotation" in str(vulns)
    assert "poc-capture" in str(vulns)

    out_of_scope = client.post(
        "/api/source/remediation-pack",
        json={
            "secrets": SECRETS,
            "host": "203.0.113.9",
            "engagement_id": engagement["id"],
        },
    )
    assert out_of_scope.status_code == 200
    assert out_of_scope.json()["ingested"] == 0
    assert out_of_scope.json()["skipped_out_of_scope"] == ["203.0.113.9"]


def test_router_real_analysis_without_sandbox(tmp_path: Any, monkeypatch: Any) -> None:
    client = _client(tmp_path, monkeypatch, sandbox=False)
    response = client.post(
        "/api/source/remediation-pack",
        json={
            "secrets": [
                {"kind": "slack-token", "label": "demo-slack", "status": "open"}
            ],
            "before": BEFORE,
            "after": {**AFTER_FIXED, "crashes": [{"id": "sig-a"}, {"id": "sig-new"}]},
            "flow": [{"action": "note", "note": "reviewed with operator"}],
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["sandbox"] is False
    assert body["rotation"]["by_kind"] == {"slack-token": 1}
    assert body["patch_verification"]["verdict"] == "regression"
    assert body["poc_capture"]["confirmed"] is False

    bad = client.post(
        "/api/source/remediation-pack",
        json={"flow": [{"action": "execute-shell"}]},
    )
    assert bad.status_code == 400
