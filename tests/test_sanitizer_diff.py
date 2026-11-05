"""Backlog #53: sanitizer diff — ASan vs UBSan vs MSan compare."""

from __future__ import annotations

from typing import Any

import pytest
from services.sanitizer_diff import (
    detect_sanitizer,
    diff_report,
    extract_frames,
    sandbox_result,
)

ASAN = """ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1234
    #0 0xaaaa in vuln_parse vuln.c:42
    #1 0xbbbb in main main.c:9
SUMMARY: AddressSanitizer: heap-buffer-overflow"""

UBSAN = """vuln.c:10:5: runtime error: signed integer overflow: 2147483647 + 1 cannot be represented in type 'int'
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior"""

MSAN = """WARNING: MemorySanitizer: use-of-uninitialized-value
    #0 0xcccc in handle req.c:77
    #1 0xdddd in main main.c:3
SUMMARY: MemorySanitizer: use-of-uninitialized-value"""


def test_detect() -> None:
    assert detect_sanitizer(ASAN) == "ASan"
    assert detect_sanitizer(UBSAN) == "UBSan"
    assert detect_sanitizer(MSAN) == "MSan"
    assert detect_sanitizer("leak here LeakSanitizer: detected") == "LSan"
    assert detect_sanitizer("plain log") == "unknown"


def test_frames() -> None:
    frames = extract_frames(ASAN)
    assert frames[0].startswith("vuln_parse")
    assert len(frames) == 2
    assert extract_frames("no frames") == []


def test_asan_heap_overflow() -> None:
    out = diff_report(ASAN)
    assert out["detected"] == "ASan"
    assert out["class"] == "heap-buffer-overflow"
    assert out["cwe"] == "CWE-122"
    by_fam = {m["sanitizer"]: m["would_detect"] for m in out["matrix"]}
    assert by_fam == {"ASan": "yes", "UBSan": "no", "MSan": "no"}
    assert set(out["blind_spots"]) == {"UBSan", "MSan"}
    assert "ASan" in out["recommendation"]["build"]
    assert out["frames"][0].startswith("vuln_parse")


def test_ubsan_overflow() -> None:
    out = diff_report(UBSAN)
    assert out["class"] == "signed-integer-overflow"
    by_fam = {m["sanitizer"]: m["would_detect"] for m in out["matrix"]}
    assert by_fam["UBSan"] == "yes" and by_fam["ASan"] == "no"
    assert "UBSan" in out["recommendation"]["build"]


def test_msan_uninit() -> None:
    out = diff_report(MSAN)
    assert out["class"] == "use-of-uninitialized-value"
    assert out["cwe"] == "CWE-457"
    by_fam = {m["sanitizer"]: m["would_detect"] for m in out["matrix"]}
    assert by_fam == {"ASan": "no", "UBSan": "no", "MSan": "yes"}
    assert "MSan" in out["recommendation"]["build"]


def test_unknown_report() -> None:
    out = diff_report("something odd happened")
    assert out["class"] == "unknown"
    assert all(m["would_detect"] == "maybe" for m in out["matrix"])
    with pytest.raises(ValueError):
        diff_report("   ")


def test_sandbox_shapes() -> None:
    res = sandbox_result()
    assert res["class"] == "heap-buffer-overflow"
    assert len(res["matrix"]) == 3
    assert res["recommendation"]["build"].startswith("ASan")


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


def test_sanitizer_router(tmp_path: Any, monkeypatch: Any) -> None:
    c = _client(tmp_path, monkeypatch)
    r = c.post("/api/source/sanitizer/diff", json={"report": ASAN})
    assert r.status_code == 200
    body = r.json()
    assert body["bug_class"] == "heap-buffer-overflow"
    assert len(body["matrix"]) == 3
    assert body["recommendation"]["build"].startswith("ASan")
    assert (
        c.post("/api/source/sanitizer/diff", json={"report": "  "}).status_code == 400
    )
