# Crash triage service: turns a raw crash/artifact from the fuzzer into a
# minimized repro and, for common bug classes, a suggested patch candidate
# (fix) — the "found it, prove the root cause, propose the fix" workflow.
import logging
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger("h4k.triage")

# Map CWE/bug-class to a concrete, safe patch pattern. These are teaching
# templates intended to show direction, not drop-in security fixes — the
# analyst must validate with the real codebase.
PATCH_HINTS: dict[str, str] = {
    "CWE-120": (
        "// CWE-120 buffer overflow — replace unbounded copy with a bounded one:\n"
        "//   strncpy(dst, src, sizeof(dst)-1); dst[sizeof(dst)-1] = '\\0';\n"
        "//   (or use snprintf / explicit bounds everywhere).\n"
    ),
    "CWE-134": (
        "// CWE-134 format string — never pass attacker data as the format:\n"
        '//   printf("%s", user_input);   // NOT printf(user_input);\n'
    ),
    "CWE-89": (
        "# CWE-89 SQL injection — use a parameterized query / prepared statement:\n"
        '#   cursor.execute("SELECT * FROM t WHERE id=%s", (id,))\n'
    ),
    "CWE-78": (
        "# CWE-78 command injection — avoid shell=True and use an argument list:\n"
        "#   subprocess.run([cmd, arg])  # NOT subprocess.run(cmd + arg, shell=True)\n"
    ),
    "CWE-95": ("# CWE-95 eval — never eval untrusted input; use a safe parser.\n"),
    "CWE-502": ("# CWE-502 deserialization — only deserialize signed/trusted data.\n"),
    "CWE-22": ("# CWE-22 path traversal — canonicalize and allow-list the path.\n"),
}


@dataclass
class TriageReport:
    """A minimalization + patch-candidate product for one crash candidate."""

    candidate: str  # the input/payload that triggered it
    bug_class: str  # e.g. stack-buffer-overflow / format-string
    cwe: str
    minimized_trigger: str  # smallest repro (== candidate if we didn't reduce)
    suggested_patch: str  # direction of fix (teaching template)
    steps: list[str]  # how to confirm root cause + fix
    minimized: bool = False  # did we ACTUALLY reduce it, or just echo it back?
    minimize_note: str = ""  # why not, when minimized is False

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate": self.candidate,
            "bug_class": self.bug_class,
            "cwe": self.cwe,
            "minimized_trigger": self.minimized_trigger,
            "minimized": self.minimized,
            "minimize_note": self.minimize_note,
            "suggested_patch": self.suggested_patch,
            "steps": self.steps,
        }


def infer_bug_class(finding: Any | None) -> tuple[str, str]:
    """Map a finding (SAST or fuzz) to (bug_class, cwe) best-effort."""
    name = str(getattr(finding, "name", "") or "").lower()
    cwe = str(getattr(finding, "cwe", "") or "")
    rule = str(getattr(finding, "rule_id", "") or "")
    blob = f"{name} {cwe} {rule}".lower()

    if any(
        k in blob for k in ("strcpy", "buffer", "overflow", "strcat", "memcpy", "gets")
    ):
        return "stack-buffer-overflow", "CWE-120"
    if (
        "format" in blob
        or "printf" in blob
        or ("snprintf" in blob and "format" in blob)
    ):
        return "format-string", "CWE-134"
    if "command" in blob or "shell" in blob or "cmd" in blob:
        return "command-injection", "CWE-78"
    if "sql" in blob:
        return "sql-injection", "CWE-89"
    if "eval" in blob:
        return "code-execution", "CWE-95"
    if "deserial" in blob:
        return "code-execution", "CWE-502"
    if "path" in blob:
        return "path-traversal", "CWE-22"
    return "unknown", "CWE-710"


def build_triage(candidate: str, finding: Any = None) -> TriageReport:
    """Produce a triage for a crash candidate (input) + optional finding."""
    bug_class, cwe = (
        infer_bug_class(finding) if finding is not None else ("unknown", "CWE-710")
    )
    patch = PATCH_HINTS.get(
        cwe,
        "# Manual analysis required: reproduce on a system you\n"
        "# own, confirm root cause, then implement the fix.\n",
    )

    # Real reduction only. Triage has no crash artifact or fuzz harness, so
    # the honest answer is usually "we did not reduce this" -- previously we
    # returned hardcoded strings ("%s", "; id") that were not derived from
    # the candidate at all and would not necessarily reproduce anything.
    minimized, did_reduce, min_note = _attempt_minimize(candidate, bug_class)

    # Sanitizer-first: name the exact flags + expected trace for this CWE so the
    # "confirm it's really a <class>" step is concrete, not hand-wavy.
    from services import sanitizer

    plan = sanitizer.verify_plan(cwe)
    if plan["relevant"]:
        confirm = (
            f"Confirm it's a {bug_class} ({cwe}): rebuild with "
            f"`{plan['build_flags']}` and replay — expect "
            f"'{plan['expect']}'."
        )
    else:
        confirm = (
            f"Confirm it's a {bug_class} ({cwe}). A sanitizer cannot adjudicate "
            f"this class — use the tainted-input repro instead."
        )

    steps = [
        "Reproduce the crash on a system you own (fuzz target / asan build).",
        confirm,
        "Minimize the repro further (libFuzzer -minimize_crash=1 or afl-tmin).",
        "Apply the patch direction, then re-fuzz to verify it's gone.",
        "Disclose responsibly: report to the vendor before publishing.",
    ]
    return TriageReport(
        candidate=candidate,
        bug_class=bug_class,
        cwe=cwe,
        minimized_trigger=minimized,
        suggested_patch=patch,
        steps=steps,
        minimized=did_reduce,
        minimize_note=min_note,
    )


def _attempt_minimize(candidate: str, bug_class: str) -> tuple[str, bool, str]:
    """Return (trigger, actually_reduced, note).

    Triage has only a candidate string -- no crash artifact and no fuzz
    harness -- so it cannot genuinely reduce anything. When the caller
    supplies a real artifact (see services.fuzzer.libfuzzer_minimize) that
    path does the real work; this function refuses to invent a "minimized"
    trigger out of thin air.
    """
    if not candidate:
        return "", False, "empty candidate; nothing to reduce"
    return (
        candidate,
        False,
        f"not reduced: triage has no crash artifact or harness for the "
        f"{bug_class} candidate. Use POST /api/fuzz/minimize (libFuzzer "
        f"-minimize_crash) or afl-tmin on the real artifact.",
    )
