"""IAM key hygiene — age/rotation, read-only (Backlog #43).

Read-only audit of AWS-style access keys from data the operator pastes
(`keys`: tolerant JSON list with user/id/status/dates) or, with
`live: true`, from one `aws iam get-credential-report` call (fixed
argv, no shell — fails cleanly when the CLI or credentials are
absent). Nothing is created, rotated, or deleted; every finding ships
a rotation/deletion policy.

Per-key checklist (default 90-day rotation window):

- active long-term key older than the window → HIGH (stale — rotate),
  twice the window → CRITICAL
- temporary `ASIA` session credential → noted, never flagged
- inactive key → LOW (dormant — delete it)
- last-used older than the window → HIGH (unused — delete it)

Key IDs are masked to their last 4 characters everywhere. Findings
ledger as engagement vulns on the labeled host when `engagement_id`
is given (scope-enforced). Sandbox returns canned findings without
parsing anything.
"""

from __future__ import annotations

import base64
import csv
import json
import logging
import shutil
import subprocess  # nosec B404 - fixed-argv aws credential report
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger("h4k.iam_hygiene")


def _now() -> datetime:
    return datetime.now(UTC)


def parse_date(value: Any) -> datetime | None:
    """Parse ISO-8601 / credential-report dates; None when absent/garbage."""
    if value is None:
        return None
    text = str(value).strip()
    if not text or text.upper() in ("N/A", "NO_INFORMATION", "NEVER"):
        return None
    for candidate in (text, text.replace("Z", "+00:00")):
        try:
            parsed = datetime.fromisoformat(candidate)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
        except ValueError:
            continue
    return None


def mask_key_id(key_id: str) -> str:
    """Show only the last 4 characters of a key ID."""
    tail = (key_id or "").strip()[-4:]
    return f"…{tail}" if tail else "(unknown)"


def _key_kind(key_id: str) -> str:
    upper = (key_id or "").upper()
    if upper.startswith("ASIA"):
        return "temporary"
    if upper.startswith("AKIA"):
        return "long-term"
    return "unknown"


def audit_keys(
    keys: list[dict[str, Any]],
    max_age_days: int = 90,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Audit normalized key rows; entry problems are reported, not fatal."""
    moment = now or _now()
    window = max(int(max_age_days or 90), 1)
    audited: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    errors: list[str] = []
    for idx, entry in enumerate(keys):
        if not isinstance(entry, dict):
            errors.append(f"key[{idx}]: not an object (ignored)")
            continue
        key_id = str(entry.get("AccessKeyId") or entry.get("key_id") or "").strip()
        user = str(entry.get("UserName") or entry.get("user") or "unknown")
        if not key_id:
            errors.append(f"key[{idx}]: no AccessKeyId (ignored)")
            continue
        status = str(entry.get("Status") or entry.get("status") or "Active")
        created = parse_date(entry.get("CreateDate", entry.get("create_date")))
        last_used = parse_date(
            entry.get(
                "LastUsedDate", entry.get("last_used", entry.get("last_used_date"))
            )
        )
        age_days = (moment - created).days if created else None
        last_used_days: int | None = (moment - last_used).days if last_used else None
        kind = _key_kind(key_id)
        record: dict[str, Any] = {
            "user": user,
            "key": mask_key_id(key_id),
            "kind": kind,
            "status": status,
            "age_days": age_days,
            "last_used_days": last_used_days,
        }
        audited.append(record)
        label = f"{user}/{mask_key_id(key_id)}"
        if kind == "temporary":
            continue  # short-lived session credentials are the goal, not a finding
        if status.lower() != "active":
            findings.append(
                _finding(
                    label,
                    "LOW",
                    f"dormant {status.lower()} key — delete it",
                    f"status={status} (cannot be used, but clutters the account)",
                )
            )
            continue
        if age_days is not None and age_days > 2 * window:
            findings.append(
                _finding(
                    label,
                    "CRITICAL",
                    f"active key is {age_days}d old (limit {window}d) — rotate now",
                    f"age_days={age_days} max_age_days={window}",
                )
            )
        elif age_days is not None and age_days > window:
            findings.append(
                _finding(
                    label,
                    "HIGH",
                    f"active key is {age_days}d old (limit {window}d) — rotate",
                    f"age_days={age_days} max_age_days={window}",
                )
            )
        last_used_days = record["last_used_days"]
        if last_used_days is not None and last_used_days > window:
            findings.append(
                _finding(
                    label,
                    "HIGH",
                    f"key unused for {last_used_days}d — delete it",
                    f"last_used_days={last_used_days} max_age_days={window}",
                )
            )
    return {
        "keys": audited,
        "key_count": len(audited),
        "errors": errors,
        "findings": findings,
        "finding_count": len(findings),
        "clean": not findings,
    }


def _finding(label: str, severity: str, title: str, evidence: str) -> dict[str, Any]:
    return {
        "key": label,
        "severity": severity,
        "title": title,
        "evidence": evidence[:200],
        "policy": "Rotate active keys inside the window (disable → verify → delete the old one); delete dormant and unused keys.",
    }


def parse_credential_report(csv_text: str) -> list[dict[str, Any]]:
    """Flatten a get-credential-report CSV into key rows (both slots)."""
    keys: list[dict[str, Any]] = []
    reader = csv.DictReader((csv_text or "").splitlines())
    for row in reader:
        user = (row.get("user") or "").strip() or "unknown"
        for slot in ("1", "2"):
            active = (row.get(f"access_key_{slot}_active") or "").strip().lower()
            if active not in ("true", "false"):
                continue
            keys.append(
                {
                    "UserName": user,
                    "AccessKeyId": f"slot-{slot}",
                    "Status": "Active" if active == "true" else "Inactive",
                    "CreateDate": row.get(f"access_key_{slot}_last_rotated"),
                    "LastUsedDate": row.get(f"access_key_{slot}_last_used_date"),
                }
            )
    return keys


def live_report(timeout: int = 60) -> dict[str, Any]:
    """One `aws iam get-credential-report` call; error dict when unavailable."""
    aws = shutil.which("aws")
    if not aws:
        return {"keys": [], "error": "aws CLI not installed"}
    try:
        proc = subprocess.run(  # nosec B603 - fixed argv, no shell
            [aws, "iam", "get-credential-report", "--output", "json"],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {"keys": [], "error": "aws CLI timed out"}
    except Exception as exc:
        return {"keys": [], "error": str(exc)[:160]}
    if proc.returncode != 0:
        return {"keys": [], "error": (proc.stderr or "aws CLI failed")[-200:]}
    try:
        content = json.loads(proc.stdout or "{}").get("Content", "")
        csv_text = base64.b64decode(content).decode("utf-8", errors="replace")
    except (ValueError, KeyError) as exc:
        return {"keys": [], "error": f"bad credential report: {exc}"[:160]}
    return {"keys": parse_credential_report(csv_text)}


def to_ledger(
    host: str, account: str, findings: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Map hygiene findings to engagement vuln rows for the labeled host."""
    rows: list[dict[str, Any]] = []
    for finding in findings:
        title = str(finding.get("title") or "iam-hygiene").strip() or "iam-hygiene"
        rows.append(
            {
                "host": host,
                "name": f"iam {account}: {title}"[:220],
                "severity": str(finding.get("severity") or "UNKNOWN").upper(),
                "module": "iam-hygiene",
                "reference": "",
                "cwe": "CWE-613",
                "detail": (
                    f"key={finding.get('key', '')} "
                    f"evidence={finding.get('evidence', '')} "
                    f"policy={finding.get('policy', '')}"
                ).strip(),
            }
        )
    return rows


def sandbox_result(account: str = "lab-account") -> dict[str, Any]:
    """Canned hygiene audit (nothing parsed, no CLI run)."""
    keys = [
        {
            "user": "alice",
            "key": "…AAAA",
            "kind": "long-term",
            "status": "Active",
            "age_days": 12,
            "last_used_days": 1,
        },
        {
            "user": "bob",
            "key": "…BBBB",
            "kind": "long-term",
            "status": "Active",
            "age_days": 120,
            "last_used_days": 100,
        },
        {
            "user": "ci",
            "key": "…CCCC",
            "kind": "long-term",
            "status": "Inactive",
            "age_days": 400,
            "last_used_days": 300,
        },
    ]
    findings = [
        {
            "key": "bob/…BBBB",
            "severity": "HIGH",
            "title": "active key is 120d old (limit 90d) — rotate",
            "evidence": "age_days=120 max_age_days=90 (sandbox)",
            "policy": "Rotate active keys inside the window (sandbox).",
        },
        {
            "key": "ci/…CCCC",
            "severity": "LOW",
            "title": "dormant inactive key — delete it",
            "evidence": "status=Inactive (sandbox)",
            "policy": "Rotate active keys inside the window (sandbox).",
        },
    ]
    return {
        "account": account or "lab-account",
        "keys": keys,
        "key_count": len(keys),
        "errors": [],
        "findings": findings,
        "finding_count": len(findings),
        "clean": False,
        "sandbox": True,
    }
