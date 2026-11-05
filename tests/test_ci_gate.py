"""Backlog #65: rule CI gate — fail on high-severity SAST."""

from __future__ import annotations

from typing import Any

import pytest
from services.ci_gate import evaluate, normalize_severity, sandbox_result

FINDINGS = [
    {"rule_id": "a", "name": "A", "severity": "critical", "file": "x.py", "line": 1},
    {"rule_id": "b", "name": "B", "severity": "high", "file": "x.py", "line": 2},
    {"rule_id": "c", "name": "C", "severity": "medium", "file": "y.py", "line": 3},
    {"rule_id": "d", "name": "D", "severity": "low", "file": "y.py", "line": 4},
    {"rule_id": "e", "name": "E", "severity": "info", "file": "z.py", "line": 5},
    {"rule_id": "f", "name": "F", "severity": "bogus", "file": "z.py", "line": 6},
]


def test_normalize_severity() -> None:
    assert normalize_severity("CRITICAL") == "critical"
    assert normalize_severity("bogus") == "medium"
    assert normalize_severity(None) == "medium"


def test_thresholds() -> None:
    out = evaluate(FINDINGS, fail_on="critical")
    assert out["passed"] is False and out["blocking_count"] == 1
    assert out["blocking"][0]["rule_id"] == "a"
    out = evaluate(FINDINGS, fail_on="high")
    assert [b["rule_id"] for b in out["blocking"]] == ["a", "b"]
    out = evaluate(FINDINGS, fail_on="medium")
    # "bogus" normalizes to medium, so it blocks too.
    assert [b["rule_id"] for b in out["blocking"]] == ["a", "b", "c", "f"]
    out = evaluate(FINDINGS, fail_on="low")
    assert out["blocking_count"] == 5  # everything but info
    assert out["counts"] == {"info": 1, "low": 1, "medium": 2, "high": 1, "critical": 1}


def test_ignore_list_is_audited() -> None:
    out = evaluate(FINDINGS, fail_on="critical", ignore_rule_ids=["a", "nope"])
    assert out["passed"] is True
    assert [i["rule_id"] for i in out["ignored"]] == ["a"]
    assert out["ignored"][0]["waived"] is True


def test_clean_and_empty() -> None:
    out = evaluate([{"rule_id": "x", "severity": "low"}], fail_on="high")
    assert out["passed"] is True
    out = evaluate([], fail_on="high")
    assert out == {
        "passed": True,
        "threshold": "high",
        "counts": {"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0},
        "evaluated": 0,
        "blocking": [],
        "blocking_count": 0,
        "ignored": [],
        "ignored_count": 0,
    }


def test_validation() -> None:
    with pytest.raises(ValueError):
        evaluate(FINDINGS, fail_on="severe")
    with pytest.raises(ValueError):
        evaluate("nope")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        evaluate([{"rule_id": "ok"}, "junk"])  # type: ignore[list-item]


def test_sandbox_shape() -> None:
    res = sandbox_result()
    assert res["passed"] is False and res["threshold"] == "high"
    assert res["blocking_count"] == 1
    assert res["blocking"][0]["severity"] == "critical"
    assert res["sandbox"] is True


def _client(tmp_path: Any, monkeypatch: Any, sandbox: str = "1") -> Any:
    from contextlib import asynccontextmanager

    monkeypatch.setenv("H4K_REFRESH_CVE", "0")
    monkeypatch.setenv("H4K_SANDBOX", sandbox)
    monkeypatch.setenv("H4K_DATA_DIR", str(tmp_path))
    import main as main_module

    @asynccontextmanager
    async def _noop(_app: Any) -> Any:
        yield

    main_module.app.router.lifespan_context = _noop
    from fastapi.testclient import TestClient

    return TestClient(main_module.app)


def test_ci_gate_router(tmp_path: Any, monkeypatch: Any) -> None:
    c = _client(tmp_path, monkeypatch)
    r = c.post("/api/source/ci/gate", json={"findings": FINDINGS})
    assert r.status_code == 200
    body = r.json()
    assert body["passed"] is False and body["blocking_count"] == 1

    assert (
        c.post(
            "/api/source/ci/gate", json={"findings": FINDINGS, "fail_on": "severe"}
        ).status_code
        == 400
    )
    assert c.post("/api/source/ci/gate", json={"findings": "nope"}).status_code in (
        400,
        422,
    )


def test_ci_gate_router_live(tmp_path: Any, monkeypatch: Any) -> None:
    c = _client(tmp_path, monkeypatch, sandbox="0")
    r = c.post("/api/source/ci/gate", json={"findings": FINDINGS})
    assert r.status_code == 200
    body = r.json()
    assert body["passed"] is False
    assert [b["rule_id"] for b in body["blocking"]] == ["a", "b"]
    assert body["sandbox"] is False

    r = c.post(
        "/api/source/ci/gate",
        json={"findings": FINDINGS, "ignore_rule_ids": ["a", "b"]},
    )
    assert r.status_code == 200 and r.json()["passed"] is True

    assert (
        c.post(
            "/api/source/ci/gate", json={"findings": FINDINGS, "fail_on": "severe"}
        ).status_code
        == 400
    )
    assert (
        c.post(
            "/api/source/ci/gate", json={"findings": [{"rule_id": "ok"}, 42]}
        ).status_code
        == 400
    )
