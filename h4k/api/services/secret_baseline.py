"""Secret baseline + allowlist — noise reduction (Backlog #63).

Committed-secret scanning is only useful when the second run is
quieter than the first. This service scans pasted sources (bundle or
explicit files) for hardcoded-secret shapes, then applies two
noise-reduction passes:

1. Baseline: findings whose fingerprint (rule + path + matched line)
   already appears in a previously saved baseline are reported as
   `baseline` instead of `new` — only genuinely new secrets shout.
2. Allowlist: operator-supplied regexes (test fixtures, example
   keys, docs) suppress matching findings with the matching pattern
   recorded, so the suppression is auditable instead of silent.

Only `new` (neither baselined nor allowlisted) findings ledger as
engagement vulns when `engagement_id` is given (scope-enforced).
Sandbox returns a canned mix without parsing anything.
"""

from __future__ import annotations

import hashlib
import logging
import re
from typing import Any

logger = logging.getLogger("h4k.secret_baseline")

# (rule_id, severity, title, pattern)
PATTERNS: list[tuple[str, str, str, str]] = [
    (
        "secret-aws-key",
        "critical",
        "possible AWS access key",
        r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
    ),
    (
        "secret-private-key",
        "critical",
        "private key block",
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    ),
    (
        "secret-github-token",
        "critical",
        "possible GitHub token",
        r"\bgh[pousr]_[A-Za-z0-9]{20,}\b",
    ),
    (
        "secret-slack-token",
        "high",
        "possible Slack token",
        r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b",
    ),
    (
        "secret-stripe-key",
        "high",
        "possible Stripe secret key",
        r"\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b",
    ),
    (
        "secret-bearer",
        "medium",
        "hardcoded bearer token",
        r"\bBearer\s+[A-Za-z0-9\-._~+/]{20,}={0,2}\b",
    ),
    (
        "secret-assignment",
        "medium",
        "assigned secret-looking value",
        r"(?:password|passwd|pwd|secret|api[_-]?key|apikey|token)\s*=\s*"
        r"(?:\"|')?(?:\$\{)?[A-Za-z0-9_\-]{12,}",
    ),
]

_SKIP_DIRS = {"node_modules", ".venv", "vendor", "dist", "build", "__pycache__"}


def fingerprint(rule_id: str, path: str, code: str) -> str:
    """Stable identity for a finding (rule + path + matched line)."""
    return hashlib.sha256(f"{rule_id}|{path}|{code.strip()}".encode()).hexdigest()


def find_secrets(files: list[dict[str, str]]) -> list[dict[str, Any]]:
    """Scan bundle/file contents for hardcoded-secret shapes."""
    if not files:
        raise ValueError("bundle or files required (paste sources)")
    compiled = [(rid, sev, title, re.compile(pat)) for rid, sev, title, pat in PATTERNS]
    out: list[dict[str, Any]] = []
    for entry in files:
        path = str(entry.get("path") or "file")
        if any(part in _SKIP_DIRS for part in path.split("/")):
            continue
        content = str(entry.get("content") or "")
        if not content.strip():
            continue
        for lineno, line in enumerate(content.splitlines(), 1):
            for rule_id, severity, title, rx in compiled:
                try:
                    if not rx.search(line):
                        continue
                except re.error:
                    continue
                code = line.strip()[:200]
                out.append(
                    {
                        "rule_id": rule_id,
                        "name": title,
                        "severity": severity,
                        "cwe": "CWE-798",
                        "file": path,
                        "line": lineno,
                        "code": code,
                        "fingerprint": fingerprint(rule_id, path, code),
                    }
                )
                break  # one hit per rule per line is plenty
    return out


def _baseline_set(baseline: list[Any] | None) -> set[str]:
    known: set[str] = set()
    for item in baseline or []:
        if isinstance(item, str) and item.strip():
            known.add(item.strip().lower())
        elif isinstance(item, dict):
            fp = str(item.get("fingerprint") or "")
            if fp:
                known.add(fp.strip().lower())
            else:
                for key in ("rule_id", "rule", "id", "name"):
                    if item.get(key):
                        known.add(f"{item.get(key)}|{item.get('file', '')}".lower())
                        break
    return known


def apply_baseline(
    findings: list[dict[str, Any]], baseline: list[Any] | None
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Split findings into (new, already-baselined)."""
    known = _baseline_set(baseline)
    new = [f for f in findings if f.get("fingerprint", "").lower() not in known]
    old = [f for f in findings if f.get("fingerprint", "").lower() in known]
    return new, old


def validate_allowlist(patterns: list[str] | None) -> None:
    """Compile-check allowlist regexes (400-worthy on the first bad one)."""
    for idx, pat in enumerate(patterns or []):
        if not str(pat or "").strip():
            continue
        try:
            re.compile(str(pat))
        except re.error as exc:
            raise ValueError(f"allowlist[{idx}] is not a regex: {exc}") from exc


def apply_allowlist(
    findings: list[dict[str, Any]], patterns: list[str] | None
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Split findings into (kept, suppressed); bad regexes raise."""
    validate_allowlist(patterns)
    compiled: list[tuple[int, Any]] = []
    for idx, pat in enumerate(patterns or []):
        if not str(pat or "").strip():
            continue
        compiled.append((idx, re.compile(str(pat))))
    kept: list[dict[str, Any]] = []
    suppressed: list[dict[str, Any]] = []
    for finding in findings:
        hay = f"{finding.get('file', '')}\n{finding.get('code', '')}"
        hit = next(
            (idx for idx, rx in compiled if rx.search(hay)),
            None,
        )
        if hit is None:
            kept.append(finding)
        else:
            suppressed.append({**finding, "allowlisted_by": hit})
    return kept, suppressed


def audit(
    files: list[dict[str, str]],
    baseline: list[Any] | None = None,
    allowlist: list[str] | None = None,
) -> dict[str, Any]:
    """Scan, then baseline-diff, then allowlist — counts at every stage."""
    findings = find_secrets(files)
    new, baselined = apply_baseline(findings, baseline)
    kept, suppressed = apply_allowlist(new, allowlist)
    return {
        "findings": findings,
        "finding_count": len(findings),
        "new": kept,
        "new_count": len(kept),
        "baselined": baselined,
        "baselined_count": len(baselined),
        "allowlisted": suppressed,
        "allowlisted_count": len(suppressed),
        "clean": not kept,
    }


def to_ledger(
    host: str, pack: str, findings: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Map NEW findings to engagement vuln rows for the labeled host."""
    rows: list[dict[str, Any]] = []
    for finding in findings:
        title = str(finding.get("name") or "secret").strip() or "secret"
        rows.append(
            {
                "host": host,
                "name": f"secrets {pack}: {title}"[:220],
                "severity": str(finding.get("severity") or "UNKNOWN").upper(),
                "module": "secrets-baseline",
                "reference": "",
                "cwe": "CWE-798",
                "detail": f"rule={finding.get('rule_id', '')} "
                f"file={finding.get('file', '')}:{finding.get('line', '')}".strip()[
                    :400
                ],
            }
        )
    return rows


def sandbox_result() -> dict[str, Any]:
    """Canned audit: one new, one baselined, one allowlisted finding."""
    return {
        "findings": [
            {
                "rule_id": "secret-aws-key",
                "name": "possible AWS access key",
                "severity": "critical",
                "cwe": "CWE-798",
                "file": "app.py",
                "line": 4,
                "code": "KEY = 'AKIAIOSFODNN7EXAMPLE'",
                "fingerprint": "new-1",
            },
            {
                "rule_id": "secret-assignment",
                "name": "assigned secret-looking value",
                "severity": "medium",
                "cwe": "CWE-798",
                "file": "conf.py",
                "line": 2,
                "code": "password = 'known-before'",
                "fingerprint": "base-1",
            },
            {
                "rule_id": "secret-assignment",
                "name": "assigned secret-looking value",
                "severity": "medium",
                "cwe": "CWE-798",
                "file": "tests/fixtures.py",
                "line": 1,
                "code": "token = 'fixture-token-value'",
                "fingerprint": "allow-1",
            },
        ],
        "finding_count": 3,
        "new": [
            {
                "rule_id": "secret-aws-key",
                "name": "possible AWS access key",
                "severity": "critical",
                "cwe": "CWE-798",
                "file": "app.py",
                "line": 4,
                "code": "KEY = 'AKIAIOSFODNN7EXAMPLE'",
                "fingerprint": "new-1",
            }
        ],
        "new_count": 1,
        "baselined": [
            {
                "rule_id": "secret-assignment",
                "name": "assigned secret-looking value",
                "severity": "medium",
                "cwe": "CWE-798",
                "file": "conf.py",
                "line": 2,
                "code": "password = 'known-before'",
                "fingerprint": "base-1",
            }
        ],
        "baselined_count": 1,
        "allowlisted": [
            {
                "rule_id": "secret-assignment",
                "name": "assigned secret-looking value",
                "severity": "medium",
                "cwe": "CWE-798",
                "file": "tests/fixtures.py",
                "line": 1,
                "code": "token = 'fixture-token-value'",
                "fingerprint": "allow-1",
                "allowlisted_by": 0,
            }
        ],
        "allowlisted_count": 1,
        "clean": False,
        "sandbox": True,
    }
