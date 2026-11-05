"""Backlog #52: AFL++ persistent runner — harness + stats."""

from __future__ import annotations

import importlib.util
import os
import stat
from typing import Any

import pytest
from services.afl_runner import (
    create_run,
    harness_c,
    import_crashes,
    launch,
    list_crashes,
    read_stats,
    sandbox_run,
    stop_run,
    to_ledger,
)

FAKE_AFL = """#!/bin/sh
OUT=""
IN=""
while [ $# -gt 0 ]; do
  case "$1" in
    -i) IN="$2"; shift 2;;
    -o) OUT="$2"; shift 2;;
    --) shift; break;;
    *) shift;;
  esac
done
mkdir -p "$OUT/crashes"
printf 'start_time        : 1700000000\\nrun_time          : 42\\nexecs_done        : 1234\\nedges_found       : 56\\ncorpus_count       : 3\\nhangs_saved       : 0\\nlast_crash        : 12 seconds ago\\n' > "$OUT/fuzzer_stats"
printf 'CRASH-BYTES' > "$OUT/crashes/id:000000,sig:11,src:000000,op:havoc"
sleep 30
"""


def _fake_afl_bin(tmp_path: Any, monkeypatch: Any) -> None:
    bindir = tmp_path / "bin"
    bindir.mkdir()
    exe = bindir / "afl-fuzz"
    exe.write_text(FAKE_AFL)
    exe.chmod(exe.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")


def test_harness_template() -> None:
    src = harness_c("my_target")
    assert "__AFL_LOOP(1000)" in src and "my_target" in src
    assert harness_c("evil;name") and "evil_name" in harness_c("evil;name")


def test_create_and_stats_lifecycle(tmp_path: Any, monkeypatch: Any) -> None:
    monkeypatch.setenv("H4K_DATA_DIR", str(tmp_path))
    meta = create_run("/lab/harness", args=["@@@"], seeds=[b"A", b"", b"B"])
    assert meta["seeds"] == 2  # empty seeds skipped
    assert (tmp_path / "afl" / meta["id"] / "harness.c").exists()
    stats = read_stats(meta["id"])
    assert stats["running"] is False and "not started" in stats["note"]
    assert list_crashes(meta["id"]) == []


def test_validation(tmp_path: Any, monkeypatch: Any) -> None:
    import pytest

    monkeypatch.setenv("H4K_DATA_DIR", str(tmp_path))
    with pytest.raises(ValueError):
        create_run("  ")
    with pytest.raises(ValueError):
        read_stats("nope")["running"]  # unknown run dir, no stats file
    with pytest.raises(ValueError):
        stop_run("nope", {})


def test_launch_with_fake_afl(tmp_path: Any, monkeypatch: Any) -> None:
    import time

    monkeypatch.setenv("H4K_DATA_DIR", str(tmp_path))
    _fake_afl_bin(tmp_path, monkeypatch)
    meta = create_run("/lab/harness", seeds=[b"seed"])
    jobs: dict[str, Any] = {}
    out = launch(meta["id"], "/lab/harness")
    assert out["started"] is True and out["pid"] > 0
    jobs[meta["id"]] = {"pid": out["pid"]}
    try:
        deadline = time.time() + 10
        stats: dict[str, Any] = {}
        while time.time() < deadline:
            stats = read_stats(meta["id"])
            if stats.get("running") and stats.get("execs") == 1234:
                break
            time.sleep(0.2)
        assert stats["execs"] == 1234
        assert stats["crashes"] == 1
        crashes = list_crashes(meta["id"])
        assert crashes[0]["file"].startswith("id:000000")
        rows = to_ledger("10.10.10.77", meta["id"], crashes)
        assert len(rows) == 1 and rows[0]["cwe"] == "CWE-119"
        assert to_ledger("h", "r", []) == []
    finally:
        stopped = stop_run(meta["id"], jobs)
        assert stopped["stopped"] is True


def test_launch_without_binary(tmp_path: Any, monkeypatch: Any) -> None:
    monkeypatch.setenv("H4K_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("PATH", "/nonexistent-bin-dir")
    meta = create_run("/lab/harness")
    out = launch(meta["id"], "/lab/harness")
    assert out["started"] is False and "afl-fuzz not found" in out["error"]


def test_import_crashes_needs_corpus(tmp_path: Any, monkeypatch: Any) -> None:
    monkeypatch.setenv("H4K_DATA_DIR", str(tmp_path))
    _fake_afl_bin(tmp_path, monkeypatch)
    meta = create_run("/lab/harness")
    out = launch(meta["id"], "/lab/harness")
    jobs = {meta["id"]: {"pid": out.get("pid")}}
    try:
        import time

        deadline = time.time() + 10
        while time.time() < deadline:
            if list_crashes(meta["id"]):
                break
            time.sleep(0.2)
        if importlib.util.find_spec("services.corpus") is None:
            with pytest.raises(ValueError, match="corpus-sync"):
                import_crashes(meta["id"])
        else:
            res = import_crashes(meta["id"])
            assert res["added"] == 1
            again = import_crashes(meta["id"])
            assert again["deduped"] == 1
    finally:
        stop_run(meta["id"], jobs)


def test_sandbox_shapes() -> None:
    res = sandbox_run("/lab/harness")
    assert res["status"] == "running" and res["crash_count"] == 1
    assert res["clean"] is False


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


def test_afl_router(tmp_path: Any, monkeypatch: Any) -> None:
    c = _client(tmp_path, monkeypatch)
    assert c.post("/api/afl/run", json={"target": ""}).status_code == 400
    r = c.post("/api/afl/run", json={"target": "/lab/harness"})
    assert r.status_code == 200
    body = r.json()
    assert body["run_id"] == "sandbox01abcd" and body["status"] == "running"

    r = c.get("/api/afl")
    assert r.status_code == 200 and isinstance(r.json()["runs"], list)
    r = c.get("/api/afl/sandbox01abcd")
    assert r.status_code == 200 and r.json()["crash_count"] == 1

    eng = c.post("/api/engagement/sandbox-seed").json()["engagement"]
    eid = eng["id"]
    r = c.post(
        "/api/afl/sandbox01abcd/ledger",
        json={"engagement_id": eid, "host": "10.10.10.77"},
    )
    assert r.status_code == 200 and r.json()["ingested"] == 1
    vulns = c.get(f"/api/engagement/{eid}/vulns/effective").json()
    assert "afl-run sandbox01abcd" in str(vulns)

    # Sandbox answers canned crashes regardless of run identity.
    assert c.post("/api/afl/nope/abort").json() == {"stopped": True, "run_id": "nope"}
    r = c.post(
        "/api/afl/nope/ledger", json={"engagement_id": eid, "host": "10.10.10.77"}
    )
    assert r.status_code == 200 and r.json()["ingested"] == 1
    assert c.post("/api/afl/x/ledger", json={}).status_code == 400
    assert (
        c.post(
            "/api/afl/sandbox01abcd/ledger",
            json={"engagement_id": "nope", "host": "h"},
        ).status_code
        == 404
    )
    r = c.post(
        "/api/afl/sandbox01abcd/ledger",
        json={"engagement_id": eid, "host": "192.0.2.9"},
    )
    assert r.json()["ingested"] == 0
    assert r.json()["skipped_out_of_scope"] == ["192.0.2.9"]
