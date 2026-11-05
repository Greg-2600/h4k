"""Backlog #66: delta SAST — diff-only findings per PR."""

from __future__ import annotations

from typing import Any

import pytest
from services.sast_delta import DEFAULT_TOLERANCE, diff_findings, sandbox_result

BASE = [
    {"rule_id": "a", "name": "A", "severity": "high", "file": "x.py", "line": 10},
    {"rule_id": "b", "name": "B", "severity": "medium", "file": "x.py", "line": 20},
    {"rule_id": "c", "name": "C", "severity": "low", "file": "y.py", "line": 5},
]


def test_identical_is_all_unchanged() -> None:
    out = diff_findings(BASE, [dict(f) for f in BASE])
    assert out["new_count"] == 0 and out["fixed_count"] == 0
    assert out["moved_count"] == 0 and out["unchanged_count"] == 3
    assert out["baseline_count"] == 3 and out["current_count"] == 3


def test_new_fixed_moved() -> None:
    current = [
        {"rule_id": "a", "severity": "high", "file": "x.py", "line": 10},  # unchanged
        {"rule_id": "b", "severity": "medium", "file": "x.py", "line": 22},  # moved +2
        {"rule_id": "d", "severity": "critical", "file": "z.py", "line": 1},  # new
    ]
    out = diff_findings(BASE, current)
    assert [f["rule_id"] for f in out["new"]] == ["d"]
    assert [f["rule_id"] for f in out["fixed"]] == ["c"]
    assert len(out["moved"]) == 1 and out["moved"][0]["was_line"] == 20
    assert out["moved"][0]["line"] == 22 and out["unchanged_count"] == 1


def test_beyond_tolerance_is_new() -> None:
    current = [{"rule_id": "b", "severity": "medium", "file": "x.py", "line": 50}]
    out = diff_findings(BASE, current, move_tolerance=3)
    assert [f["rule_id"] for f in out["new"]] == ["b"]
    assert out["moved_count"] == 0
    out = diff_findings(BASE, current, move_tolerance=100)
    assert out["new_count"] == 0 and out["moved_count"] == 1


def test_empty_sides() -> None:
    out = diff_findings([], BASE)
    assert out["new_count"] == 3 and out["fixed_count"] == 0
    out = diff_findings(BASE, [])
    assert out["new_count"] == 0 and out["fixed_count"] == 3


def test_validation() -> None:
    with pytest.raises(ValueError):
        diff_findings("nope", [])  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        diff_findings([], "nope")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        diff_findings([{"rule_id": "ok"}], [{"rule_id": "ok"}, 42])
    with pytest.raises(ValueError):
        diff_findings([], [{"rule_id": "x", "line": "ten"}])
    with pytest.raises(ValueError):
        diff_findings([], [], move_tolerance=-1)
    with pytest.raises(ValueError):
        diff_findings([], [], move_tolerance="far")  # type: ignore[arg-type]


def test_sandbox_shape() -> None:
    res = sandbox_result()
    assert res["new_count"] == 1 and res["fixed_count"] == 1
    assert res["moved_count"] == 1 and res["sandbox"] is True
    assert res["move_tolerance"] == DEFAULT_TOLERANCE


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


def test_delta_router_sandbox(tmp_path: Any, monkeypatch: Any) -> None:
    c = _client(tmp_path, monkeypatch)
    r = c.post("/api/source/sast/delta", json={"baseline": BASE, "current": BASE})
    assert r.status_code == 200
    body = r.json()
    assert body["new_count"] == 1 and body["sandbox"] is True


def test_delta_router_live(tmp_path: Any, monkeypatch: Any) -> None:
    c = _client(tmp_path, monkeypatch, sandbox="0")
    current = [dict(f) for f in BASE] + [
        {"rule_id": "d", "severity": "high", "file": "z.py", "line": 1}
    ]
    r = c.post("/api/source/sast/delta", json={"baseline": BASE, "current": current})
    assert r.status_code == 200
    body = r.json()
    assert body["new_count"] == 1 and body["sandbox"] is False
    assert body["new"][0]["rule_id"] == "d"
    assert (
        c.post(
            "/api/source/sast/delta",
            json={"baseline": BASE, "current": [{"rule_id": "ok"}, 7]},
        ).status_code
        == 400
    )
