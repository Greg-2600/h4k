"""Backlog #74: AI-style patch ranking + test-gen + false-positive judge."""

from __future__ import annotations

import json
from contextlib import asynccontextmanager
from typing import Any

import pytest
from services.patch_review import (
    analyze,
    generate_tests,
    judge_false_positive,
    rank_patches,
    sandbox_result,
    to_ledger,
)

INJECTION = {"title": "SQL injection", "cwe": "CWE-89", "severity": "HIGH"}


def test_rank_patches_prefers_bound_query_and_flags_anti_patterns() -> None:
    patches = [
        {
            "name": "concat",
            "diff": "cursor.execute('SELECT * FROM t WHERE id=' + user_id)  # nosec",
        },
        {
            "name": "bound",
            "diff": "cursor.execute('SELECT * FROM t WHERE id=%s', (user_id,))",
        },
        {
            "name": "format",
            "diff": "cursor.execute('SELECT * FROM t WHERE id={}'.format(user_id))",
        },
    ]
    ranked = rank_patches(INJECTION, patches)
    assert [item["rank"] for item in ranked] == [1, 2, 3]
    assert ranked[0]["name"] == "bound"
    assert ranked[0]["recommended"] is True
    by_name = {item["name"]: item for item in ranked}
    assert ranked[0]["score"] > ranked[1]["score"]
    assert "uses bound placeholders" in ranked[0]["signals"]
    assert "concatenates input into a query" in by_name["concat"]["anti_patterns"]
    assert "suppresses a scanner" in by_name["concat"]["anti_patterns"]
    assert "formats input into a query" in by_name["format"]["anti_patterns"]
    assert all(item["tradeoffs"]["pros"] for item in ranked)
    assert all(item["tradeoffs"]["cons"] for item in ranked)
    assert all(item["confidence"] in {"low", "medium", "high"} for item in ranked)
    assert all(item["size"] > 0 for item in ranked)


def test_rank_patches_shell_and_memory_families() -> None:
    command = rank_patches(
        {"cwe": "78"},
        [
            {"name": "shell", "diff": "subprocess.run(cmd + arg, shell=True)"},
            {"name": "argv", "diff": "subprocess.run([cmd, arg], check=True)"},
        ],
    )
    assert command[0]["name"] == "argv"
    assert "keeps shell=True" in command[1]["anti_patterns"]

    memory = rank_patches(
        {"cwe": "CWE-120"},
        [{"name": "copy", "diff": 'snprintf(dst, sizeof(dst), "%s", src);'}],
    )
    assert "uses a bounds-checked copy" in memory[0]["signals"]
    assert "checks the buffer length" in memory[0]["signals"]


def test_templates_are_returned_when_no_patches_supplied() -> None:
    ranked = rank_patches({"title": "XSS", "cwe": "CWE-79"})
    assert len(ranked) == 3
    assert ranked[0]["recommended"] is True
    assert {item["source"] for item in ranked} == {"template"}
    assert all(item["description"] for item in ranked)
    assert all(item["tradeoffs"]["pros"] for item in ranked)
    generic = rank_patches({"title": "odd bug", "cwe": "CWE-9999"})
    assert len(generic) == 3
    assert generic[0]["source"] == "template"


def test_rank_patches_validation_and_test_flag() -> None:
    with pytest.raises(ValueError, match="patches must be a list"):
        rank_patches(INJECTION, "not-a-list")
    with pytest.raises(ValueError, match=r"patches\[0\] must be an object"):
        rank_patches(INJECTION, ["nope"])
    with pytest.raises(ValueError, match="must include diff/code/patch text"):
        rank_patches(INJECTION, [{"name": "empty"}])
    with pytest.raises(ValueError, match="too large"):
        rank_patches(INJECTION, [{"diff": "A" * 50000}])
    with pytest.raises(ValueError, match="at most"):
        rank_patches(INJECTION, [{"diff": "x"}] * 26)
    with_test = rank_patches(
        INJECTION,
        [{"diff": "cursor.execute('SELECT 1')", "tests": True}],
    )
    assert with_test[0]["has_tests"] is True
    assert "includes a regression test" in with_test[0]["signals"]


def test_generate_tests_python_javascript_go_and_generic() -> None:
    python = generate_tests(INJECTION)
    assert python["language"] == "python"
    assert python["framework"] == "pytest"
    assert python["filename"] == "test_cwe_89_regression.py"
    assert "def test_cwe_89_regression" in python["code"]
    assert "assert" in python["code"]
    assert python["negative_cases"]
    assert python["steps"] and python["assertions"]

    js = generate_tests(INJECTION, language="javascript")
    assert js["framework"] == "jest"
    assert js["filename"].endswith(".test.js")
    assert "expect(" in js["code"]

    go = generate_tests(INJECTION, language="go")
    assert go["framework"] == "testing"
    assert go["filename"].endswith("_test.go")
    assert "func TestCwe89" in go["code"]

    generic = generate_tests(INJECTION, language="ruby")
    assert generic["framework"] == "generic"
    assert generic["filename"].endswith(".txt")
    assert "Regression test skeleton" in generic["code"]


def test_false_positive_judge_is_conservative() -> None:
    unknown = judge_false_positive(INJECTION, {})
    assert unknown["verdict"] == "needs_review"
    assert unknown["why_not_exploitable"] == []
    assert unknown["missing_evidence"]
    assert "no evidence supplied" in unknown["reasons"][0]

    cleared = judge_false_positive(
        INJECTION,
        {
            "reachable": False,
            "user_input_reaches_sink": False,
            "version_affected": False,
            "sanitizer_present": True,
        },
    )
    assert cleared["verdict"] == "false_positive"
    assert cleared["why_not_exploitable"]
    assert cleared["confidence"] >= 60

    partial = judge_false_positive(INJECTION, {"user_input_reaches_sink": False})
    assert partial["verdict"] == "likely_false_positive"
    assert partial["why_not_exploitable"]

    confirmed = judge_false_positive(
        INJECTION,
        {
            "runtime_confirmed": True,
            "user_input_reaches_sink": False,
            "version_affected": False,
        },
    )
    assert confirmed["verdict"] == "confirmed"
    assert confirmed["why_not_exploitable"] == []
    assert confirmed["confidence"] == 95

    sanitized_but_reachable = judge_false_positive(
        INJECTION,
        {
            "reachable": True,
            "user_input_reaches_sink": True,
            "sanitizer_present": True,
        },
    )
    assert sanitized_but_reachable["verdict"] == "needs_review"

    true_positive = judge_false_positive(
        INJECTION,
        {
            "reachable": True,
            "user_input_reaches_sink": True,
            "version_affected": True,
        },
    )
    assert true_positive["verdict"] == "likely_true_positive"

    with pytest.raises(ValueError, match="evidence must be an object"):
        judge_false_positive(INJECTION, "yes")


def test_false_positive_judge_accepts_string_aliases() -> None:
    result = judge_false_positive(
        INJECTION,
        {
            "attacker_reachable": "yes",
            "untrusted_input": "true",
            "affected_version": "in_range",
            "reproduced": "no",
            "mitigated": "absent",
        },
    )
    assert result["evidence"]["reachable"] is True
    assert result["evidence"]["user_input_reaches_sink"] is True
    assert result["evidence"]["version_affected"] is True
    assert result["evidence"]["runtime_confirmed"] is False
    assert result["evidence"]["compensating_control"] is False


def test_analyze_validates_and_combines_sections() -> None:
    with pytest.raises(ValueError, match="required"):
        analyze()
    with pytest.raises(ValueError, match="finding must be an object"):
        analyze(finding="CWE-89")
    with pytest.raises(ValueError, match="patches must be a list"):
        analyze(patches="nope")
    with pytest.raises(ValueError, match="evidence must be an object"):
        analyze(evidence="nope")

    result = analyze(
        finding=INJECTION,
        patches=[
            {"name": "bound", "diff": "cursor.execute('SELECT 1 WHERE id=%s', (x,))"}
        ],
        evidence={"reachable": True, "user_input_reaches_sink": True},
    )
    assert result["sandbox"] is False
    assert result["summary"]["patch_count"] == 1
    assert result["summary"]["recommended_patch"] == "bound"
    assert result["summary"]["verdict"] == "likely_true_positive"
    assert result["tests"]["language"] == "python"
    assert "Offline" in result["limitations"]

    evidence_only = analyze(evidence={"version_affected": False})
    assert evidence_only["patches"] == []
    assert evidence_only["tests"] is None
    assert evidence_only["false_positive"]["verdict"] == "likely_false_positive"


def test_to_ledger_only_records_true_positives() -> None:
    true_positive = analyze(
        finding=INJECTION,
        evidence={"reachable": True, "user_input_reaches_sink": True},
    )
    rows = to_ledger("10.10.10.77", true_positive)
    assert len(rows) == 1
    assert rows[0]["module"] == "patch-review"
    assert rows[0]["cwe"] == "CWE-89"
    assert rows[0]["host"] == "10.10.10.77"
    assert rows[0]["severity"] == "HIGH"

    cleared = analyze(
        finding=INJECTION,
        evidence={"user_input_reaches_sink": False, "version_affected": False},
    )
    assert to_ledger("10.10.10.77", cleared) == []


def test_sandbox_result_is_canned_and_deterministic() -> None:
    result = sandbox_result()
    assert result == sandbox_result()
    assert result["sandbox"] is True
    assert result["summary"]["patch_count"] == 3
    assert result["summary"]["verdict"] in {"confirmed", "likely_true_positive"}
    assert len(to_ledger("h", result)) == 1
    json.dumps(result)


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


def test_router_sandbox_validation_and_ledger(tmp_path: Any, monkeypatch: Any) -> None:
    client = _client(tmp_path, monkeypatch, sandbox=True)
    response = client.post(
        "/api/source/patch-review",
        json={"finding": {"title": "ignored", "cwe": "CWE-89"}},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["sandbox"] is True
    assert body["summary"]["patch_count"] == 3
    assert client.post("/api/source/patch-review", json={}).status_code == 400
    assert (
        client.post(
            "/api/source/patch-review",
            json={"finding": INJECTION, "engagement_id": "nope"},
        ).status_code
        == 404
    )

    engagement = client.post("/api/engagement/sandbox-seed").json()["engagement"]
    response = client.post(
        "/api/source/patch-review",
        json={
            "finding": INJECTION,
            "host": "10.10.10.77",
            "engagement_id": engagement["id"],
        },
    )
    assert response.status_code == 200
    assert response.json()["ingested"] == 1
    vulns = client.get(f"/api/engagement/{engagement['id']}/vulns/effective").json()
    assert "patch-review" in str(vulns)

    out_of_scope = client.post(
        "/api/source/patch-review",
        json={
            "finding": INJECTION,
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
        "/api/source/patch-review",
        json={
            "finding": INJECTION,
            "patches": [
                {
                    "name": "bound",
                    "diff": "cursor.execute('SELECT * FROM t WHERE id=%s', (x,))",
                },
                {
                    "name": "concat",
                    "diff": "cursor.execute('SELECT * FROM t WHERE id=' + x)",
                },
            ],
            "evidence": {"reachable": True, "user_input_reaches_sink": True},
            "test_language": "javascript",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["sandbox"] is False
    assert body["recommended"]["name"] == "bound"
    assert body["summary"]["verdict"] == "likely_true_positive"
    assert body["tests"]["framework"] == "jest"

    assert (
        client.post(
            "/api/source/patch-review",
            json={"patches": [{"name": "empty"}]},
        ).status_code
        == 400
    )
    assert (
        client.post(
            "/api/source/patch-review",
            json={"evidence": "nope"},
        ).status_code
        == 422
    )
