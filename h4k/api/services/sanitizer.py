# Sanitizer-first: one shared source of truth for "how do I confirm this bug
# under a sanitizer?".
#
# Every finding h4k produces — SAST hits, black-box fuzz candidates, OSS-Fuzz
# crashes — carries a sanitizer block built here: the exact build flags, the
# runtime env for a clean abort-on-first-error trace, and the error string a
# sanitizer is expected to print.
#
# This is deliberately honest. A sanitizer can only *confirm or refute*
# memory-safety / undefined-behaviour classes. For everything else (SQL
# injection, command injection, path traversal, ...) we say so instead of
# implying a sanitizer verdict we cannot produce. A black-box HTTP anomaly
# carries a *replay* recipe, not a bug class — the sanitizer names the class
# when you actually get a trace.
import re
from typing import Any

# ---------------------------------------------------------------------------
# Build flags
# ---------------------------------------------------------------------------
# `-fno-omit-frame-pointer` + `-g` keep the trace readable; `-O1` keeps the
# build fast without inlining the frame away. `address,undefined` is the
# combination that catches the widest set of real bugs.
FLAGS_ASAN_UBSAN = "-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1"
FLAGS_LIBFUZZER = (
    "-fsanitize=address,undefined,fuzzer-no-link -fno-omit-frame-pointer -g -O1"
)
FLAGS_AFL = "AFL_USE_ASAN=1 AFL_USE_UBSAN=1 CC=clang CXX=clang++"

BUILD_PROFILES: dict[str, str] = {
    "c": FLAGS_ASAN_UBSAN,
    "c++": FLAGS_ASAN_UBSAN,
    "libfuzzer": FLAGS_LIBFUZZER,
    "afl": FLAGS_AFL,
}

# Runtime env for a *clean* trace: abort on the first error (so one repro =
# one bug), full stacktrace, symbolize inline. detect_leaks=0 because libFuzzer
# processes exit non-zero and LSan noise buries the real report (enable it
# explicitly for a dedicated leak hunt).
TRACE_ENV: dict[str, str] = {
    "ASAN_OPTIONS": "detect_leaks=0:abort_on_error=1:print_stacktrace=1:symbolize=1",
    "UBSAN_OPTIONS": "print_stacktrace=1:halt_on_error=1",
    "LSAN_OPTIONS": "detect_leaks=1:print_suppressions=0",
}

# ---------------------------------------------------------------------------
# Bug classes a sanitizer can actually name, with the trace line it prints.
# ---------------------------------------------------------------------------
BUG_CLASSES: dict[str, dict[str, str]] = {
    "stack-buffer-overflow": {
        "sanitizer": "AddressSanitizer (ASan)",
        "expect": "AddressSanitizer: stack-buffer-overflow",
        "cwe": "CWE-120",
        "cwe_name": "Copy of Buffer without Checking Size of Input",
    },
    "heap-buffer-overflow": {
        "sanitizer": "AddressSanitizer (ASan)",
        "expect": "AddressSanitizer: heap-buffer-overflow",
        "cwe": "CWE-122",
        "cwe_name": "Heap-based Buffer Overflow",
    },
    "global-buffer-overflow": {
        "sanitizer": "AddressSanitizer (ASan)",
        "expect": "AddressSanitizer: global-buffer-overflow",
        "cwe": "CWE-120",
        "cwe_name": "Copy of Buffer without Checking Size of Input",
    },
    "use-after-free": {
        "sanitizer": "AddressSanitizer (ASan)",
        "expect": "AddressSanitizer: heap-use-after-free",
        "cwe": "CWE-416",
        "cwe_name": "Use After Free",
    },
    "double-free": {
        "sanitizer": "AddressSanitizer (ASan)",
        "expect": "AddressSanitizer: attempting double-free",
        "cwe": "CWE-415",
        "cwe_name": "Double Free",
    },
    "use-after-scope": {
        "sanitizer": "AddressSanitizer (ASan)",
        "expect": "AddressSanitizer: stack-use-after-scope",
        "cwe": "CWE-416",
        "cwe_name": "Use After Free",
    },
    "stack-overflow": {
        "sanitizer": "AddressSanitizer (ASan)",
        "expect": "AddressSanitizer: stack-overflow",
        "cwe": "CWE-674",
        "cwe_name": "Uncontrolled Recursion",
    },
    "out-of-bounds": {
        "sanitizer": "AddressSanitizer (ASan)",
        "expect": "AddressSanitizer: heap-buffer-overflow",
        "cwe": "CWE-125",
        "cwe_name": "Out-of-bounds Read",
    },
    "format-string": {
        "sanitizer": "AddressSanitizer (ASan) / -Wformat",
        "expect": "AddressSanitizer: format-param / -Wformat-security",
        "cwe": "CWE-134",
        "cwe_name": "Use of Externally-Controlled Format String",
    },
    "signed-integer-overflow": {
        "sanitizer": "UndefinedBehaviorSanitizer (UBSan)",
        "expect": "runtime error: signed integer overflow",
        "cwe": "CWE-190",
        "cwe_name": "Integer Overflow or Wraparound",
    },
    "unsigned-integer-overflow": {
        "sanitizer": (
            "UndefinedBehaviorSanitizer (UBSan, "
            "-fsanitize=unsigned-integer-overflow)"
        ),
        "expect": "runtime error: unsigned integer overflow",
        "cwe": "CWE-190",
        "cwe_name": "Integer Overflow or Wraparound",
    },
    "null-pointer": {
        "sanitizer": "UndefinedBehaviorSanitizer (UBSan)",
        "expect": "runtime error: load of null pointer",
        "cwe": "CWE-476",
        "cwe_name": "NULL Pointer Dereference",
    },
    "misaligned-access": {
        "sanitizer": "UndefinedBehaviorSanitizer (UBSan)",
        "expect": "runtime error: misaligned address",
        "cwe": "CWE-704",
        "cwe_name": "Incorrect Type Conversion or Cast",
    },
    "division-by-zero": {
        "sanitizer": "UndefinedBehaviorSanitizer (UBSan)",
        "expect": "runtime error: division by zero",
        "cwe": "CWE-369",
        "cwe_name": "Divide By Zero",
    },
    "shift-out-of-bounds": {
        "sanitizer": "UndefinedBehaviorSanitizer (UBSan)",
        "expect": "runtime error: shift exponent",
        "cwe": "CWE-190",
        "cwe_name": "Integer Overflow or Wraparound",
    },
    "leak": {
        "sanitizer": "LeakSanitizer (LSan, built into ASan)",
        "expect": "ERROR: LeakSanitizer: detected memory leaks",
        "cwe": "CWE-401",
        "cwe_name": "Missing Release of Memory after Effective Lifetime",
    },
    "unknown": {
        "sanitizer": "ASan + UBSan",
        "expect": "(no trace parsed)",
        "cwe": "CWE-710",
        "cwe_name": "Improper Adherence to Coding Standards",
    },
}

# Reverse index used to classify a raw trace line into a bug class.
_CLASS_PATTERNS: list[tuple[str, str]] = [
    ("stack-buffer-overflow", r"stack-buffer-overflow"),
    ("use-after-scope", r"use-after-scope"),
    ("use-after-free", r"use-after-free"),
    ("double-free", r"double-free"),
    ("double-free", r"attempting free"),
    ("heap-buffer-overflow", r"heap-buffer-overflow"),
    ("global-buffer-overflow", r"global-buffer-overflow"),
    ("stack-overflow", r"stack-overflow"),
    ("format-string", r"format-param"),
    ("format-string", r"format-string"),
    ("signed-integer-overflow", r"signed integer overflow"),
    ("unsigned-integer-overflow", r"unsigned integer overflow"),
    ("null-pointer", r"load of null pointer"),
    ("null-pointer", r"member access within null pointer"),
    ("misaligned-access", r"misaligned address"),
    ("division-by-zero", r"division by zero"),
    ("shift-out-of-bounds", r"shift exponent"),
    ("leak", r"detected memory leaks"),
    ("out-of-bounds", r"out-of-bounds"),
]

# CWE -> the bug class a sanitizer would report for it. Lets a *static* finding
# (which only knows a CWE) state what a sanitizer would print if the bug is real.
CWE_TO_CLASS: dict[str, str] = {
    "CWE-120": "stack-buffer-overflow",
    "CWE-121": "stack-buffer-overflow",
    "CWE-122": "heap-buffer-overflow",
    "CWE-124": "heap-buffer-overflow",
    "CWE-125": "out-of-bounds",
    "CWE-126": "out-of-bounds",
    "CWE-127": "out-of-bounds",
    "CWE-134": "format-string",
    "CWE-190": "signed-integer-overflow",
    "CWE-191": "signed-integer-overflow",
    "CWE-401": "leak",
    "CWE-415": "double-free",
    "CWE-416": "use-after-free",
    "CWE-476": "null-pointer",
    "CWE-704": "misaligned-access",
    "CWE-369": "division-by-zero",
    "CWE-787": "out-of-bounds",
}

# Black-box HTTP fuzz signals -> which sanitizer bug classes plausibly explain
# the anomaly. This is a *candidate set*, not a verdict: a sanitizer names the
# real class on the replay trace.
SIGNAL_CANDIDATES: dict[str, list[str]] = {
    "teardown": [
        "use-after-free",
        "heap-buffer-overflow",
        "stack-buffer-overflow",
        "null-pointer",
    ],
    "resource": ["use-after-free", "heap-buffer-overflow"],
    "hang": ["heap-buffer-overflow", "leak"],
    "anomaly": ["heap-buffer-overflow", "stack-buffer-overflow"],
    "server_error": [],
}


def flags(profile: str = "c") -> str:
    """Build flags for a profile: c | c++ | libfuzzer | afl."""
    return BUILD_PROFILES.get(profile, FLAGS_ASAN_UBSAN)


def trace_env() -> dict[str, str]:
    """Runtime env for a clean abort-on-first-error sanitizer trace."""
    return dict(TRACE_ENV)


def replay_command(
    source: str = "repro.c",
    binary: str = "repro",
    profile: str = "c",
    stdin: str | None = None,
) -> str:
    """A copy-pasteable rebuild+replay recipe with sanitizers on."""
    fl = flags(profile)
    env = " ".join(f"{k}={v}" for k, v in TRACE_ENV.items() if k != "LSAN_OPTIONS")
    cmd = f"clang {fl} -o {binary} {source}"
    run = f"{env} ./{binary}"
    if stdin:
        run += f" < {stdin}"
    return f"{cmd} && {run}"


def classify_trace(text: str) -> dict[str, str]:
    """Classify a raw sanitizer/ASan/UBSan report into a known bug class.

    Returns {class, sanitizer, expect, cwe, cwe_name, summary}. Unrecognized
    text yields the "unknown" bucket rather than a guess.
    """
    low = (text or "").lower()

    # Prefer the authoritative AddressSanitizer ERROR: line if present.
    summary = ""
    for line in (text or "").splitlines():
        if "error:" in line.lower() and (
            "sanitizer" in line.lower() or "runtime error" in line.lower()
        ):
            summary = line.split("error:", 1)[-1].strip()
            break
    if not summary:
        m = re.search(r"(?:ERROR|SUMMARY):\s*(.+)", text or "")
        if m:
            summary = m.group(1).strip()

    hay = f"{summary} {low}"
    klass = "unknown"
    for name, pat in _CLASS_PATTERNS:
        if re.search(pat, hay):
            klass = name
            break

    info = BUG_CLASSES.get(klass, BUG_CLASSES["unknown"])
    return {
        "class": klass,
        "summary": summary[:300],
        "sanitizer": info["sanitizer"],
        "expect": info["expect"],
        "cwe": info["cwe"],
        "cwe_name": info["cwe_name"],
    }


def verify_plan(
    cwe: str | None = None,
    *,
    rule_id: str = "",
    file: str = "",
    profile: str = "c",
) -> dict[str, Any]:
    """Build the sanitizer block for a *static* finding that knows only a CWE.

    `relevant` is False for bug classes no sanitizer can adjudicate (injection,
    traversal, secrets, ...) — we say so rather than implying coverage.
    """
    cls = CWE_TO_CLASS.get((cwe or "").upper())
    if cls is None:
        return {
            "relevant": False,
            "class": None,
            "cwe": cwe or "",
            "sanitizer": None,
            "expect": None,
            "build_flags": flags(profile),
            "env": trace_env(),
            "replay": replay_command(profile=profile),
            "note": (
                "not a memory-safety or undefined-behaviour class — a sanitizer "
                "cannot confirm or refute this. Confirm with a tainted-input "
                "repro (see the PoC button)."
            ),
        }
    info = BUG_CLASSES[cls]
    return {
        "relevant": True,
        "class": cls,
        "cwe": info["cwe"],
        "cwe_name": info["cwe_name"],
        "sanitizer": info["sanitizer"],
        "expect": info["expect"],
        "build_flags": flags(profile),
        "env": trace_env(),
        "replay": replay_command(profile=profile),
        "file": file,
        "rule_id": rule_id,
        "note": (
            f"hypothesis, not a verdict: rebuild with these flags and replay; a "
            f"clean abort printing '{info['expect']}' confirms it. False positives "
            f"are expected until you run it."
        ),
    }


def confirm_plan(
    signal: str,
    *,
    host: str = "",
    port: int | None = None,
    vector: str = "",
) -> dict[str, Any]:
    """Build the sanitizer block for a black-box fuzz candidate.

    A connection teardown or a dropped service is *not* proof of memory
    corruption, so we attach a replay recipe and the plausible classes instead
    of a verdict. The sanitizer names the real class on the trace.
    """
    candidates = SIGNAL_CANDIDATES.get(signal, [])
    if not candidates:
        return {
            "relevant": False,
            "class": None,
            "signal": signal,
            "cwe_candidates": [],
            "build_flags": flags("c"),
            "env": trace_env(),
            "replay": None,
            "note": (
                f"'{signal}' is not sanitizer-adjudicable on its own — it may be "
                "an unhandled exception, a resource limit, or a config issue. "
                "Reproduce on a lab build with ASan/UBSan to see whether any "
                "memory error is hiding behind it."
            ),
        }
    expect_lines = [BUG_CLASSES[c]["expect"] for c in candidates]
    where = f"{host}:{port}" if host else "the lab service"
    return {
        "relevant": True,
        "class": None,  # unknown until a trace names it
        "signal": signal,
        "cwe_candidates": sorted({BUG_CLASSES[c]["cwe"] for c in candidates}),
        "class_candidates": candidates,
        "build_flags": flags("c"),
        "env": trace_env(),
        "replay": (
            f"rebuild the service under sanitizers "
            f"(clang {flags('c')} -o server ...), then replay vector "
            f"'{vector or 'this one'}' against {where}"
        ),
        "note": (
            "black-box signal, not a verdict. Rebuild the service with ASan+UBSan "
            f"and replay; expect one of: {' | '.join(expect_lines)}"
        ),
    }
