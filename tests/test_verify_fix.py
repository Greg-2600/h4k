"""Backlog #64: verify-fix retest + flaky detector + dedup."""

from __future__ import annotations

from typing import Any

import pytest
from services.verify_fix import sandbox_result, verify

BASE = [
    {"rule_id": "a", "name": "A", "severity": "high", "file": "x.py", "line": 10},
    {"rule_id": "b", "name": "B", "severity": "medium", "file": "x.py", "line": 20},
    {"rule_id": "c", "name": "C", "severity": "low", "file": "y.py", "line": 5},
]


def test_fix_holds() -> None:
    out = verify(BASE, [dict(f) for f in BASE])
    assert out["persists_count"] == 3 and out["fixed_count"] == 0
    assert out["new_count"] == 0 and out["flaky_count"] == 0
    assert out["duplicates_dropped"] == 0


def test_fixed_and_new() -> None:
    current = [
        {"rule_id": "a", "severity": "high", "file": "x.py", "line": 10},
        {"rule_id": "d", "severity": "critical", "file": "z.py", "line": 1},
    ]
    out = verify(BASE, current)
    assert [f["rule_id"] for f in out["persists"]] == ["a"]
    assert [f["rule_id"] for f in out["fixed"]] == ["b", "c"]
    assert [f["rule_id"] for f in out["new"]] == ["d"]


def test_reappeared_is_flaky() -> None:
    history = [[{"rule_id": "d", "severity": "high", "file": "z.py", "line": 1}]]
    out = verify(
        BASE,
        [{"rule_id": "d", "severity": "high", "file": "z.py", "line": 1}],
        history=history,
    )
    assert out["new_count"] == 0 and out["flaky_count"] == 1
    assert out["flaky"][0]["flake"] == "reappeared after absence"


def test_dedup_and_suppressed() -> None:
    base = [*BASE, dict(BASE[0])]  # duplicate of a
    base[0]["suppressed_by"] = {"line": 9, "rules": [], "owner": "ops"}
    out = verify(base, [dict(BASE[1])])
    assert out["duplicates_dropped"] == 1
    assert out["suppressed_count"] == 1
    assert out["baseline_count"] == 3


def test_validation() -> None:
    with pytest.raises(ValueError):
        verify("nope", [])  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        verify([], "nope")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        verify([], [], history="nope")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        verify([], [], history=["nope"])
    with pytest.raises(ValueError):
        verify([{"rule_id": "ok"}, 7], [])
    with pytest.raises(ValueError):
        verify([{"rule_id": "x", "line": "ten"}], [])


def test_sandbox_shape() -> None:
    res = sandbox_result()
    assert res["persists_count"] == 1 and res["fixed_count"] == 1
    assert res["flaky_count"] == 1 and res["sandbox"] is True


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


def test_verify_router_sandbox(tmp_path: Any, monkeypatch: Any) -> None:
    c = _client(tmp_path, monkeypatch)
    r = c.post("/api/source/verify/fix", json={"baseline": BASE, "current": BASE})
    assert r.status_code == 200 and r.json()["sandbox"] is True


def test_verify_router_live(tmp_path: Any, monkeypatch: Any) -> None:
    c = _client(tmp_path, monkeypatch, sandbox="0")
    r = c.post("/api/source/verify/fix", json={"baseline": BASE, "current": []})
    assert r.status_code == 200
    body = r.json()
    assert body["fixed_count"] == 3 and body["sandbox"] is False
    assert (
        c.post(
            "/api/source/verify/fix",
            json={"baseline": BASE, "current": [{"rule_id": "ok"}, 3]},
        ).status_code
        == 400
    )


def test_quarantine_loader(tmp_path: Any) -> None:
    from conftest import load_quarantine

    assert load_quarantine(tmp_path / "missing.txt") == set()
    qf = tmp_path / "quarantine.txt"
    qf.write_text(
        "# known flake (2026-11-07)\n"
        "tests/e2e/test_x.py::test_y\n"
        "\n"
        "   \n"
        "tests/e2e/test_z.py::test_w  \n"
    )
    assert load_quarantine(qf) == {
        "tests/e2e/test_x.py::test_y",
        "tests/e2e/test_z.py::test_w",
    }


def test_quarantine_file_parses() -> None:
    from pathlib import Path

    from conftest import load_quarantine

    live = load_quarantine(Path("tests/e2e/quarantine.txt"))
    assert isinstance(live, set)
    assert all("::" in node for node in live)
