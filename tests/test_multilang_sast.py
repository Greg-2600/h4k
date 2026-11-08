"""Backlog #66: multi-lang SAST — Go + Rust source→sink rules."""

from __future__ import annotations

from typing import Any

from services.multilang_sast import RULES, sandbox_result, scan_files, to_ledger

GO_VULN = """package main
import (
  "database/sql"
  "net/http"
  "os/exec"
)
func h(w http.ResponseWriter, r *http.Request) {
  q := r.FormValue("q")
  out, _ := exec.Command("sh", "-c", q).Output()
  w.Write(out)
  db.Query("SELECT * FROM u WHERE n='" + q + "'")
}
"""

GO_CLEAN = """package main
import "database/sql"
func h(id string) {
  db.Query("SELECT * FROM u WHERE n=$1", id)
}
"""

RUST_VULN = """use std::process::Command;
fn h(q: &str) {
    let n = format!("SELECT * FROM u WHERE n='{}'", q);
    let _ = sqlx::query(&n);
    let _ = Command::new("sh").arg("-c").arg(q).output();
}
"""

RUST_SANITIZED = """fn h() {
    let q = std::env::args().nth(1).unwrap();
    let safe = shlex::quote(&q);
    let _ = Command::new("ls").arg(&*safe).output();
}
"""


def _ids(out: dict[str, Any]) -> list[str]:
    return sorted(f["rule_id"] for f in out["findings"])


def test_go_rules_fire() -> None:
    out = scan_files([{"path": "main.go", "content": GO_VULN}])
    assert out["parsed"] == 1 and not out["clean"]
    assert _ids(out) == ["ml-go-cmd-injection", "ml-go-sqli"]


def test_go_placeholder_query_is_clean() -> None:
    out = scan_files([{"path": "main.go", "content": GO_CLEAN}])
    assert out["clean"] is True and out["finding_count"] == 0


def test_rust_rules_fire() -> None:
    out = scan_files([{"path": "db.rs", "content": RUST_VULN}])
    assert _ids(out) == ["ml-rust-cmd-injection", "ml-rust-sqli"]


def test_rust_quoted_args_sanitized() -> None:
    out = scan_files([{"path": "run.rs", "content": RUST_SANITIZED}])
    assert "ml-rust-cmd-injection" not in _ids(out)


def test_window_edge_and_one_hit() -> None:
    far = 'x := r.FormValue("q")\n\n\n\n\n\n\nexec.Command(x)'
    src = 'package main\nimport "os/exec"\n' + far
    out = scan_files([{"path": "a.go", "content": src}])
    # source 7 lines above the sink: outside the 6-line window → no hit
    assert out["clean"] is True
    out = scan_files(
        [
            {"path": "a.go", "content": src + "\nexec.Command(x)"},
            {"path": "b.py", "content": "print(1)"},
        ]
    )
    assert out["skipped"] == ["b.py"] and out["finding_count"] <= len(RULES)


def test_validation() -> None:
    import pytest

    with pytest.raises(ValueError):
        scan_files([])


def test_empty_content_skipped_and_no_source_no_hit() -> None:
    from services.multilang_sast import _finder

    assert _finder("([") is None
    out = scan_files(
        [
            {"path": "a.go", "content": "   \n  "},
            {"path": "b.go", "content": 'exec.Command("ls", "-l")'},
        ]
    )
    assert out["clean"] is True and out["parsed"] == 1


def test_ledger_shape() -> None:
    rows = to_ledger(
        "h",
        "multilang-sast",
        [
            {
                "rule_id": "ml-go-sqli",
                "name": "t",
                "severity": "high",
                "cwe": "CWE-89",
                "file": "a.go",
                "line": 3,
                "code": "db.Query(x)",
            }
        ],
    )
    assert rows[0]["module"] == "multilang-sast"
    assert rows[0]["severity"] == "HIGH" and rows[0]["host"] == "h"


def test_sandbox_shape() -> None:
    res = sandbox_result()
    assert res["finding_count"] == 2 and res["sandbox"] is True
    assert {f["file"] for f in res["findings"]} == {"main.go", "db.rs"}


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


BUNDLE = "=== main.go ===\n" + GO_VULN + "\n=== db.rs ===\n" + RUST_VULN


def test_multilang_router_sandbox(tmp_path: Any, monkeypatch: Any) -> None:
    c = _client(tmp_path, monkeypatch)
    r = c.post("/api/source/sast/multilang", json={"bundle": BUNDLE})
    assert r.status_code == 200 and r.json()["sandbox"] is True


def test_multilang_router_live(tmp_path: Any, monkeypatch: Any) -> None:
    c = _client(tmp_path, monkeypatch, sandbox="0")
    r = c.post("/api/source/sast/multilang", json={"bundle": BUNDLE})
    assert r.status_code == 200
    body = r.json()
    assert body["finding_count"] >= 4 and body["sandbox"] is False
    assert body["parsed"] == 2
    assert c.post("/api/source/sast/multilang", json={}).status_code == 400
    assert (
        c.post(
            "/api/source/sast/multilang",
            json={"bundle": BUNDLE, "engagement_id": "nope"},
        ).status_code
        == 404
    )
