"""Backlog #67: inline suppress — NOSAST with expiry + owner."""

from __future__ import annotations

from typing import Any

import pytest
from services.suppress import (
    match_suppressions,
    parse_bundle,
    parse_directives,
    sandbox_result,
)

SRC = """import os
# NOSAST: sast-exec-shell owner=ops expires=2099-01-01 reason=lab runner
os.system(x)  # line 3
# NOSAST owner=sec
eval(y)  # line 5
# NOSAST: other-rule owner=ops
exec(z)  # line 7
# NOSAST: sast-old owner=ops expires=2020-01-01
old()  # line 9
"""

FINDINGS = [
    {"rule_id": "sast-exec-shell", "severity": "high", "file": "app.py", "line": 3},
    {"rule_id": "sast-eval", "severity": "high", "file": "app.py", "line": 5},
    {"rule_id": "sast-exec", "severity": "high", "file": "app.py", "line": 7},
    {"rule_id": "sast-old", "severity": "low", "file": "app.py", "line": 9},
    {"rule_id": "sast-new", "severity": "high", "file": "app.py", "line": 20},
]


def test_parse_directives() -> None:
    got = parse_directives("app.py", SRC)
    assert len(got) == 4
    assert got[0]["rules"] == ["sast-exec-shell"] and got[0]["owner"] == "ops"
    assert got[0]["expires"] == "2099-01-01" and not got[0]["expired"]
    assert got[0]["reason"] == "lab runner"
    assert got[1]["rules"] == []  # bare NOSAST covers any rule
    assert got[3]["expired"] is True
    dup = parse_directives("a.py", "# NOSAST owner=a owner=b expires=2099-01-01\n")
    assert dup[0]["owner"] == "a"  # first key wins


def test_match_split() -> None:
    out = match_suppressions([{"path": "app.py", "content": SRC}], FINDINGS)
    assert [f["rule_id"] for f in out["suppressed"]] == ["sast-exec-shell", "sast-eval"]
    assert out["suppressed"][0]["suppressed_by"]["owner"] == "ops"
    assert [f["rule_id"] for f in out["active"]] == [
        "sast-exec",
        "sast-old",
        "sast-new",
    ]
    assert out["expired_count"] == 1 and out["directives"] == 4


def test_same_line_also_matches() -> None:
    src = "x = 1  # NOSAST: sast-x owner=ops\n"
    out = match_suppressions(
        [{"path": "a.py", "content": src}],
        [{"rule_id": "sast-x", "file": "a.py", "line": 1}],
    )
    assert out["suppressed_count"] == 1


def test_validation() -> None:
    with pytest.raises(ValueError):
        match_suppressions("nope", [])  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        match_suppressions([], "nope")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        match_suppressions([{"path": "a"}], [])
    with pytest.raises(ValueError):
        match_suppressions(["nope"], [])  # type: ignore[list-item]
    with pytest.raises(ValueError):
        match_suppressions([{"path": "a", "content": 42}], [])  # type: ignore[dict-item]
    with pytest.raises(ValueError):
        match_suppressions(
            [{"path": "a", "content": "# NOSAST expires=soon"}],
            [],
        )
    with pytest.raises(ValueError):
        match_suppressions(
            [{"path": "a", "content": "x = 1"}],
            [{"rule_id": "x", "line": "ten"}],
        )
    with pytest.raises(ValueError):
        match_suppressions([{"path": "a", "content": "x=1"}], [{"rule_id": "ok"}, 7])


def test_parse_bundle() -> None:
    files = parse_bundle("=== a.py ===\nx = 1\n=== b.py ===\n# NOSAST\n")
    assert [f["path"] for f in files] == ["a.py", "b.py"]
    assert files[1]["content"] == "# NOSAST"
    assert parse_bundle("no blocks here") == []


def test_sandbox_shape() -> None:
    res = sandbox_result()
    assert res["suppressed_count"] == 1 and res["active_count"] == 1
    assert res["expired_count"] == 1 and res["sandbox"] is True


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


BUNDLE = "=== app.py ===\n" + SRC


def test_suppress_router_sandbox(tmp_path: Any, monkeypatch: Any) -> None:
    c = _client(tmp_path, monkeypatch)
    r = c.post(
        "/api/source/suppress/match", json={"bundle": BUNDLE, "findings": FINDINGS}
    )
    assert r.status_code == 200
    assert r.json()["sandbox"] is True


def test_suppress_router_live(tmp_path: Any, monkeypatch: Any) -> None:
    c = _client(tmp_path, monkeypatch, sandbox="0")
    r = c.post(
        "/api/source/suppress/match", json={"bundle": BUNDLE, "findings": FINDINGS}
    )
    assert r.status_code == 200
    body = r.json()
    assert body["suppressed_count"] == 2 and body["sandbox"] is False
    assert body["active_count"] == 3 and body["expired_count"] == 1
    assert (
        c.post("/api/source/suppress/match", json={"findings": []}).status_code == 400
    )
    assert (
        c.post(
            "/api/source/suppress/match",
            json={"bundle": BUNDLE, "findings": [{"rule_id": "ok"}, 9]},
        ).status_code
        == 400
    )
