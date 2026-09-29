"""Crash dedup: collapse many crashing inputs into distinct bugs.

A fuzzer reports *events*, not bugs. One stack-buffer-overflow in a length
field can produce tens of thousands of distinct crashing inputs, and every
one of them is the same single bug with one root cause. "Found 40000
crashes" is a useless headline; "found 3 distinct bugs" is the number an
operator can act on. That number does not exist for free -- it only exists
if crashes are fingerprinted and grouped.

Fingerprinting uses the *sanitizer report*, never the input bytes. Two
crashes are the same bug when the faulting code path is the same, so the
fingerprint is built from the sanitizer's own error class plus the
normalized top stack frames.

Normalization matters, because ASLR guarantees the raw text differs run to
run. Everything volatile is stripped before hashing:
  - load addresses  ``0x7f3c9a2b1000``  (ASLR)
  - source line     ``vulnlab.c:47``     (edits shift it, bug does not)
  - module offsets  ``(vulnlab+0x4a12)`` (rebuilt, not recompiled)
  - frame indices   ``#7``               (truncated stacks shift numbering)

What survives is the faulting function and module -- e.g. ``parse_header``
in ``vulnlab.c`` -- which is precisely the thing that defines the bug.

There is an honesty constraint here on purpose. When no sanitizer trace is
available (a black-box HTTP fuzz signal such as a connection teardown), we
CANNOT claim a fingerprint identifies a distinct root cause. Those records
are keyed on the observable signal plus the request shape and are marked
``basis="signal"`` so the caller can report them as *unconfirmed leads*
rather than bugs. Only sanitizer-backed fingerprints (``basis="sanitizer"``)
are counted as unique bugs.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

# Frames look like:  "#0 0x55d3a2 in parse_header /src/vulnlab.c:47:10"
_FRAME = re.compile(r"^\s*#\d+\s+(?:0x[0-9a-fA-F]+\s+)?in\s+(.+?)\s*$")
# ASan/UBSan/MSan error class: "==1==ERROR: AddressSanitizer: stack-buffer-overflow"
_ERROR_CLASS = re.compile(
    r"(?:ERROR|SUMMARY):\s*(?:[A-Za-z]+Sanitizer|libFuzzer):\s*([^\s]+)"
)
_UNFLAVOR = re.compile(r"\s*\((?:BuildID|size|offset)[^)]*\)")
_ADDR = re.compile(r"0x[0-9a-fA-F]+")
_LINE_NO = re.compile(r"(\.[A-Za-z]{1,4}):\d+(?::\d+)?")
_MODULE_OFF = re.compile(r"\s*\([^)]*\+0x[0-9a-fA-F]+\)")

_UNIQUE_FRAMES = 6
MAX_TRACKED_FRAMES = 40

# Signals we can observe without a sanitizer trace. These are leads, not bugs.
SIGNAL_BASIS = "signal"
SANITIZER_BASIS = "sanitizer"


def _normalize_frame(raw: str) -> str:
    """Strip every volatile part of a frame, keeping function + module."""
    frame = _MODULE_OFF.sub("", raw)
    frame = _LINE_NO.sub(r"\1", frame)
    frame = _ADDR.sub("", frame)
    frame = _UNFLAVOR.sub("", frame)
    return " ".join(frame.split()).strip()


def extract_frames(trace: str) -> list[str]:
    """Normalized, de-duplicated, order-preserving top stack frames."""
    frames: list[str] = []
    for line in trace.splitlines():
        match = _FRAME.match(line)
        if not match:
            continue
        norm = _normalize_frame(match.group(1))
        if norm and norm not in frames:
            frames.append(norm)
        if len(frames) >= _UNIQUE_FRAMES:
            break
    return frames


def error_class(trace: str) -> str:
    """The sanitizer's own verdict, e.g. 'stack-buffer-overflow'."""
    match = _ERROR_CLASS.search(trace or "")
    return match.group(1) if match else "unknown"


def fingerprint(trace: str) -> str:
    """Stable 16-hex id for a sanitizer crash.

    Two different inputs that fault through the same code path produce the
    same fingerprint. That equivalence is the whole point: it is what turns
    a crash log into a bug count.
    """
    frames = extract_frames(trace)
    basis = SANITIZER_BASIS if (frames or error_class(trace) != "unknown") else None
    if basis is None:
        return ""
    key = error_class(trace) + "|" + "|".join(frames)
    return hashlib.sha256(key.encode("utf-8", "replace")).hexdigest()[:16]


def signal_fingerprint(signal: str, context: str = "") -> str:
    """Fingerprint for a black-box signal with no sanitizer trace.

    Deliberately NOT a bug claim. A teardown on header A and a teardown on
    header B may be the same parser bug or two different ones, and a
    connection reset tells us neither. This groups leads so the operator
    sees "1 distinct signal" instead of "300 identical-looking rows", and
    the caller is expected to label the result unconfirmed.

    `context` identifies the TARGET (host:port), never the mutation operator.
    Keying on the operator was a bug: `resource` reached via `bitflip` and via
    `splice` are the same observed condition on the same service, and keying
    on the operator reported one dead service as 8 unrelated "crashes".
    """
    key = f"{signal}|{context}"
    return hashlib.sha256(key.encode("utf-8", "replace")).hexdigest()[:16]


@dataclass
class CrashRecord:
    """One distinct crash, with every input that triggered it counted."""

    crash_id: str
    basis: str
    bug_class: str
    host: str
    service: str
    port: int | None
    vector: str
    signal: str
    repro: str
    evidence: str = ""
    frames: list[str] = field(default_factory=list)
    occurrences: int = 1
    first_seen: str = ""
    last_seen: str = ""
    minimized: str = ""
    minimized_bytes: int | None = None
    original_bytes: int | None = None

    @property
    def confirmed(self) -> bool:
        """True only when a sanitizer trace actually fingerprinted this."""
        return self.basis == SANITIZER_BASIS

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "crash_id": self.crash_id,
            "basis": self.basis,
            "confirmed": self.confirmed,
            "bug_class": self.bug_class,
            "host": self.host,
            "service": self.service,
            "port": self.port,
            "vector": self.vector,
            "signal": self.signal,
            "repro": self.repro,
            "evidence": self.evidence,
            "occurrences": self.occurrences,
            "frames": self.frames,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }
        if self.minimized:
            payload["minimized"] = self.minimized
        if self.minimized_bytes is not None:
            payload["minimized_bytes"] = self.minimized_bytes
        if self.original_bytes is not None:
            payload["original_bytes"] = self.original_bytes
        if self.minimized_bytes is not None and self.original_bytes:
            payload["reduction_pct"] = round(
                100.0 * (1 - self.minimized_bytes / self.original_bytes), 1
            )
        return payload


class CrashRegistry:
    """In-memory accumulator that dedups crashes by fingerprint.

    Kept deliberately dependency-free and in-process: a fuzz job owns its
    registry for the life of the job, and the result is serialized with the
    job. That keeps the dedup accounting honest (it counts what this run
    actually saw) instead of merging in a global history that nobody can
    audit.
    """

    def __init__(self) -> None:
        self._records: dict[str, CrashRecord] = {}

    def __len__(self) -> int:
        return len(self._records)

    def __contains__(self, crash_id: object) -> bool:
        return crash_id in self._records

    def __iter__(self) -> Iterator[CrashRecord]:
        return iter(self._records.values())

    def get(self, crash_id: str) -> CrashRecord | None:
        return self._records.get(crash_id)

    @property
    def records(self) -> list[CrashRecord]:
        return list(self._records.values())

    def record(
        self,
        *,
        host: str,
        service: str,
        port: int | None,
        vector: str,
        signal: str,
        repro: str,
        evidence: str = "",
        trace: str = "",
        seen_at: str = "",
        bug_class: str = "",
    ) -> tuple[CrashRecord, bool]:
        """Register a crash. Returns (record, is_new).

        `is_new` is the signal the fuzzer corpus uses to decide whether an
        input earned its place: a duplicate fingerprint means the input
        rediscovered a bug we already have, so it teaches us nothing new.
        """
        fp = fingerprint(trace) if trace else ""
        basis = SANITIZER_BASIS if fp else SIGNAL_BASIS
        crash_id = fp or signal_fingerprint(signal, f"{host}:{port}")

        existing = self._records.get(crash_id)
        if existing is not None:
            existing.occurrences += 1
            if seen_at:
                existing.last_seen = seen_at
            return existing, False

        if basis == SANITIZER_BASIS:
            cls = bug_class or error_class(trace)
            frames = extract_frames(trace)
        else:
            cls = bug_class or signal
            frames = []

        record = CrashRecord(
            crash_id=crash_id,
            basis=basis,
            bug_class=cls,
            host=host,
            service=service,
            port=port,
            vector=vector,
            signal=signal,
            repro=repro,
            evidence=evidence,
            frames=frames,
            first_seen=seen_at,
            last_seen=seen_at,
        )
        self._records[crash_id] = record
        return record, True

    def attach_minimized(
        self, crash_id: str, minimized: str, original: bytes | None = None
    ) -> bool:
        """Record a real reduction result against a crash, if it actually shrank."""
        record = self._records.get(crash_id)
        if record is None or not minimized:
            return False
        original_size = len(original) if original is not None else record.original_bytes
        if original_size is None:
            return False
        if len(minimized) >= original_size:
            return False
        record.minimized = minimized
        record.original_bytes = original_size
        record.minimized_bytes = len(minimized)
        return True

    def summary(self) -> dict[str, Any]:
        """Counts an operator can act on.

        `unique_crashes` is the number that matters. `total_occurrences`
        is kept alongside it precisely so the two cannot be confused -- a
        big occurrence count with a small unique count is a fuzzer rediscovering
        one bug, and reporting only the former would be the misleading
        version of this feature.
        """
        confirmed = [r for r in self._records.values() if r.confirmed]
        leads = [r for r in self._records.values() if not r.confirmed]
        return {
            "unique_crashes": len(self._records),
            "confirmed_bugs": len(confirmed),
            "unconfirmed_leads": len(leads),
            "total_occurrences": sum(r.occurrences for r in self._records.values()),
            "minimized": sum(1 for r in self._records.values() if r.minimized),
        }
