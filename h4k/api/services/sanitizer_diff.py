"""Sanitizer diff — ASan vs UBSan vs MSan compare (Backlog #53).

Offline analysis of one pasted sanitizer report. The report is
classified with the existing `sanitizer.classify_trace`, then each of
the three sanitizer families is asked — from a stated coverage table,
not from running anything — whether it would have caught the same
bug, and the blind spots are named:

- ASan family (AddressSanitizer + built-in LSan): spatial safety
  (stack/heap/global overflows, OOB reads), temporal safety
  (use-after-free/scope, double-free), runaway stack, leaks.
- UBSan: integer overflow/wraparound, shifts, division by zero, null
  dereference, misaligned access.
- MSan: use of uninitialized memory (its flagship; the other two are
  blind to it by construction).

The verdict names the single best confirming build (exact flags +
replay recipe included) and lists what each family would miss, so the
operator rebuilds once instead of three times. Sandbox returns a
canned heap-overflow diff without parsing anything.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from services import sanitizer

logger = logging.getLogger("h4k.sanitizer_diff")

_ASAN_CLASSES = {
    "stack-buffer-overflow",
    "heap-buffer-overflow",
    "global-buffer-overflow",
    "use-after-free",
    "double-free",
    "use-after-scope",
    "stack-overflow",
    "out-of-bounds",
    "format-string",
    "leak",
}
_UBSAN_CLASSES = {
    "signed-integer-overflow",
    "unsigned-integer-overflow",
    "null-pointer",
    "misaligned-access",
    "division-by-zero",
    "shift-out-of-bounds",
}
_MSAN_CLASSES = {"use-of-uninitialized-value"}

_FAMILY_BLURB = {
    "ASan": "spatial + temporal memory safety, leaks",
    "UBSan": "undefined behaviour (integers, null, alignment, div-by-zero)",
    "MSan": "uninitialized-memory reads",
}

_DETECT_RE = {
    "ASan": re.compile(r"AddressSanitizer", re.IGNORECASE),
    "LSan": re.compile(r"LeakSanitizer", re.IGNORECASE),
    "UBSan": re.compile(r"UndefinedBehaviorSanitizer|runtime error:", re.IGNORECASE),
    "MSan": re.compile(r"MemorySanitizer", re.IGNORECASE),
}

_UNINIT_RE = re.compile(r"uninitiali[sz]ed", re.IGNORECASE)

_FRAME_RE = re.compile(r"#\d+\s+0x[0-9a-f]+\s+in\s+(\S+)(?:\s+(\S+:\d+))?")


def detect_sanitizer(report: str) -> str:
    """Name the sanitizer that produced the report (or 'unknown')."""
    text = report or ""
    for name in ("ASan", "LSan", "UBSan", "MSan"):
        if _DETECT_RE[name].search(text):
            return name
    return "unknown"


def extract_frames(report: str, limit: int = 8) -> list[str]:
    """Top stack frames (`#0 … in func file:line`), deepest first."""
    frames: list[str] = []
    for line in (report or "").splitlines():
        match = _FRAME_RE.search(line)
        if match:
            frame = match.group(1)
            if match.group(2):
                frame += f" ({match.group(2)})"
            frames.append(frame)
        if len(frames) >= limit:
            break
    return frames


def _classify(report: str) -> dict[str, Any]:
    """classify_trace plus the MSan flagship class the table lacks."""
    if _DETECT_RE["MSan"].search(report or "") and _UNINIT_RE.search(report or ""):
        info = {
            "class": "use-of-uninitialized-value",
            "summary": "MemorySanitizer: use-of-uninitialized-value",
            "sanitizer": "MemorySanitizer (MSan)",
            "expect": "WARNING: MemorySanitizer: use-of-uninitialized-value",
            "cwe": "CWE-457",
            "cwe_name": "Use of Uninitialized Variable",
        }
        return dict(info)
    return dict(sanitizer.classify_trace(report))


def _family_verdict(family: str, klass: str, detected: str) -> dict[str, str]:
    table = {"ASan": _ASAN_CLASSES, "UBSan": _UBSAN_CLASSES, "MSan": _MSAN_CLASSES}
    if klass == "unknown":
        return {
            "sanitizer": family,
            "would_detect": "maybe",
            "why": "report unclassified — re-run under each; start with ASan+UBSan",
        }
    if klass in table[family]:
        return {
            "sanitizer": family,
            "would_detect": "yes",
            "why": f"{klass} is in the {family} coverage ({_FAMILY_BLURB[family]})",
        }
    return {
        "sanitizer": family,
        "would_detect": "no",
        "why": f"{klass} is outside {family} coverage ({_FAMILY_BLURB[family]})",
    }


def diff_report(report: str) -> dict[str, Any]:
    """Classify one report and compare the three families against it."""
    if not (report or "").strip():
        raise ValueError("report required (paste sanitizer output)")
    detected = detect_sanitizer(report)
    classified = _classify(report)
    klass = str(classified.get("class") or "unknown")
    matrix = [_family_verdict(f, klass, detected) for f in ("ASan", "UBSan", "MSan")]
    blind = [m["sanitizer"] for m in matrix if m["would_detect"] == "no"]
    primary = next(
        (m["sanitizer"] for m in matrix if m["would_detect"] == "yes"), "ASan+UBSan"
    )
    if klass == "use-of-uninitialized-value":
        build, profile = "MSan (-fsanitize=memory)", "c"
    elif primary == "UBSan":
        build, profile = "UBSan (-fsanitize=undefined)", "c"
    else:
        build, profile = "ASan+UBSan (-fsanitize=address,undefined)", "c"
    return {
        "detected": detected,
        "class": klass,
        "summary": classified.get("summary", ""),
        "cwe": classified.get("cwe", ""),
        "cwe_name": classified.get("cwe_name", ""),
        "frames": extract_frames(report),
        "matrix": matrix,
        "blind_spots": blind,
        "recommendation": {
            "build": build,
            "build_flags": sanitizer.flags(profile),
            "env": sanitizer.trace_env(),
            "replay": sanitizer.replay_command(profile=profile),
        },
    }


def sandbox_result() -> dict[str, Any]:
    """Canned ASan heap-overflow diff (nothing parsed)."""
    return {
        "detected": "ASan",
        "class": "heap-buffer-overflow",
        "summary": "AddressSanitizer: heap-buffer-overflow (sandbox)",
        "cwe": "CWE-122",
        "cwe_name": "Heap-based Buffer Overflow",
        "frames": ["vuln_parse (vuln.c:42)", "main (main.c:9)"],
        "matrix": [
            {
                "sanitizer": "ASan",
                "would_detect": "yes",
                "why": "in the ASan coverage (sandbox)",
            },
            {
                "sanitizer": "UBSan",
                "would_detect": "no",
                "why": "outside UBSan coverage (sandbox)",
            },
            {
                "sanitizer": "MSan",
                "would_detect": "no",
                "why": "outside MSan coverage (sandbox)",
            },
        ],
        "blind_spots": ["UBSan", "MSan"],
        "recommendation": {
            "build": "ASan+UBSan (-fsanitize=address,undefined)",
            "build_flags": "-fsanitize=address,undefined -fno-omit-frame-pointer -g",
            "env": {"ASAN_OPTIONS": "abort_on_error=1"},
            "replay": "clang <flags> -o repro repro.c && ./repro (sandbox)",
        },
        "sandbox": True,
    }
