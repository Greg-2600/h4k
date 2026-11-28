"""Rotation planner + patch-diff verifier + PoC capture (Backlog #71).

Three offline, operator-driven helpers for the proof-and-remediation half of
an assessment:

* **Rotation planner** turns pasted secret-scan metadata into ordered,
  service-specific rotation steps. It accepts metadata only (rule id, label,
  location, exposure, status); secret values, code snippets, header values and
  bodies are ignored and never echoed, hashed into an identifier or ledgered.
* **Patch-diff verifier** compares before/after fuzz results the operator
  supplies. It classifies crash signatures as cleared, persisting or new and
  only calls a patch *verified* when both runs are comparable and the retest
  has zero crashes. Missing counts or non-comparable runs are inconclusive.
* **PoC capture** records an exploit flow as a deterministic, headless step
  list. It normalizes and redacts the descriptors supplied by the operator;
  it never starts a browser, makes a request or executes a step.

Nothing here contacts the network, runs a tool, writes a file or touches a
real secret. Sandbox mode returns canned data without parsing the request.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from typing import Any
from urllib.parse import urlsplit

logger = logging.getLogger("h4k.remediation_pack")

LIMITATIONS = (
    "Offline, operator-supplied data only. Rotation steps are advice and are "
    "never executed; secret values, code, headers and bodies are ignored, "
    "redacted and never echoed or ledgered. Patch proof compares the supplied "
    "before/after fuzz results only: it is inconclusive without comparable "
    "runs and does not re-run a fuzzer. PoC capture records a deterministic "
    "headless step list from supplied descriptors; no browser, network, "
    "script or exploit step is executed."
)

MAX_SECRETS = 100
MAX_STEPS = 200

_FAKE_DB_PASSWORD = "FAKE-DB-PASSWORD-DO-NOT-USE"  # nosec B105 - fake fixture
_FAKE_BODY_PASSWORD = "FAKE-BODY-DO-NOT-USE"  # nosec B105 - fake fixture

ALLOWED_ACTIONS: frozenset[str] = frozenset(
    {
        "navigate",
        "request",
        "set_header",
        "submit",
        "click",
        "wait",
        "screenshot",
        "assert",
        "note",
    }
)
ALLOWED_METHODS: frozenset[str] = frozenset(
    {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
)
ALLOWED_EXPOSURES: frozenset[str] = frozenset(
    {"repo", "log", "public", "client", "unknown"}
)
ALLOWED_SECRET_STATUS: frozenset[str] = frozenset(
    {"open", "rotated", "revoked", "ignored"}
)
ALLOWED_OUTCOMES: frozenset[str] = frozenset({"confirmed", "failed", "unknown"})

IGNORED_VALUE_KEYS: frozenset[str] = frozenset(
    {
        "value",
        "secret",
        "password",
        "passwd",
        "token",
        "code",
        "key",
        "credential",
        "credentials",
        "authorization",
        "cookie",
        "body",
        "data",
        "raw",
        "headers",
    }
)

REDACTION_PATTERNS = (
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
    re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b"),
    re.compile(r"\bBearer\s+[A-Za-z0-9\-._~+/]{12,}={0,2}\b", re.I),
    re.compile(
        r"(?i)(password|passwd|pwd|secret|token|api[_-]?key|apikey|"
        r"authorization|cookie)\s*[:=]\s*['\"]?[^\s'\"&,;]+"
    ),
)

ROTATION_PLAYBOOKS: dict[str, dict[str, Any]] = {
    "aws-access-key": {
        "label": "cloud access key",
        "severity": "CRITICAL",
        "priority": "P0",
        "steps": (
            "Disable or revoke the exposed key at the provider; keep the audit "
            "trail for the incident record.",
            "Issue a least-privilege replacement and store it in the approved "
            "secret manager, never in source or chat.",
            "Repoint CI/CD and application configuration at the new reference; "
            "do not paste the value into tickets.",
            "Invalidate sessions and temporary credentials minted with the old "
            "key and review provider logs for use.",
            "Confirm no workload still references the old key, then delete it.",
        ),
    },
    "github-token": {
        "label": "source-control token",
        "severity": "CRITICAL",
        "priority": "P0",
        "steps": (
            "Revoke the token in the source-control provider and record the "
            "time and actor.",
            "Issue a scoped, short-lived replacement with only the permissions "
            "the workflow needs.",
            "Update workflow secrets and rotated deploy keys, then rerun the "
            "affected pipeline.",
            "Review audit logs for repositories and packages touched by the "
            "old token.",
            "Confirm the old token is rejected and remove it from all mirrors.",
        ),
    },
    "slack-token": {
        "label": "chat workspace token",
        "severity": "HIGH",
        "priority": "P1",
        "steps": (
            "Revoke the workspace token or app installation that owns it.",
            "Issue a replacement with the minimum scopes and move it into the "
            "approved secret store.",
            "Update integrations and bots, then verify they reconnect.",
            "Review workspace audit logs for messages or files read with the "
            "old token.",
        ),
    },
    "stripe-key": {
        "label": "payment API key",
        "severity": "CRITICAL",
        "priority": "P0",
        "steps": (
            "Roll the exposed restricted/live key in the payment dashboard.",
            "Issue a restricted replacement with only the required permissions.",
            "Update the service configuration through the secret manager and "
            "restart dependents.",
            "Review payment API logs for unexpected charges or data access.",
            "Confirm the old key returns an authentication error.",
        ),
    },
    "private-key": {
        "label": "private key",
        "severity": "CRITICAL",
        "priority": "P0",
        "steps": (
            "Remove the key from the repository/history view and revoke its "
            "corresponding public key or certificate.",
            "Generate a new keypair with a passphrase, preferably hardware- or "
            "secret-manager-backed.",
            "Distribute the new public key and retire the old authorization.",
            "Review host and service authentication logs for use of the old key.",
            "Purge the old key from history with a documented, coordinated "
            "rewrite if exposure was public.",
        ),
    },
    "database-password": {
        "label": "database credential",
        "severity": "CRITICAL",
        "priority": "P0",
        "steps": (
            "Rotate the database password/role credential with the DBA or "
            "managed-service console.",
            "Update connection strings through the secret manager and roll "
            "application instances.",
            "Terminate stale sessions and verify no process still authenticates "
            "with the old credential.",
            "Review query and authentication logs for access outside the "
            "expected hosts.",
        ),
    },
    "bearer-token": {
        "label": "bearer/API token",
        "severity": "HIGH",
        "priority": "P1",
        "steps": (
            "Revoke the token at the issuing service and note the owner.",
            "Issue a scoped replacement with an expiry and store it in the "
            "approved secret manager.",
            "Update callers and confirm the old token is rejected.",
            "Review service logs for use from unexpected clients.",
        ),
    },
    "generic-secret": {
        "label": "unclassified secret",
        "severity": "MEDIUM",
        "priority": "P2",
        "steps": (
            "Identify the owning system and confirm whether the exposed value "
            "is still active.",
            "Rotate or revoke it with the owning team; use a secret manager "
            "reference instead of a literal.",
            "Update all configuration that references the old value and "
            "restart dependents.",
            "Review logs for use outside the expected workload and record the "
            "outcome.",
        ),
    },
}

KIND_ALIASES: tuple[tuple[str, str], ...] = (
    ("aws", "aws-access-key"),
    ("akia", "aws-access-key"),
    ("github", "github-token"),
    ("gitlab", "github-token"),
    ("slack", "slack-token"),
    ("stripe", "stripe-key"),
    ("private-key", "private-key"),
    ("private_key", "private-key"),
    ("rsa-key", "private-key"),
    ("database", "database-password"),
    ("db-password", "database-password"),
    ("db_password", "database-password"),
    ("bearer", "bearer-token"),
    ("jwt", "bearer-token"),
)


def _text(value: Any, limit: int = 160) -> str:
    """Return a bounded operator-safe string with secret-shaped text redacted."""
    if value is None:
        return ""
    text = str(value).strip()
    for pattern in REDACTION_PATTERNS:
        text = pattern.sub("<redacted>", text)
    return text[:limit]


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def _kind_from_hints(*hints: Any) -> str:
    text = " ".join(_text(hint, 120).lower() for hint in hints if hint)
    for needle, kind in KIND_ALIASES:
        if needle in text:
            return kind
    if "secret" in text or "password" in text or "api-key" in text:
        return "generic-secret"
    if text.startswith("db-") or text.startswith("db_"):
        return "database-password"
    return "generic-secret"


def _exposure(value: Any) -> str:
    text = _text(value, 60).lower().replace(" ", "-").replace("_", "-")
    for candidate in ALLOWED_EXPOSURES:
        if candidate in text:
            return candidate
    return "unknown"


def _secret_status(value: Any) -> str:
    text = _text(value, 40).lower()
    for candidate in ALLOWED_SECRET_STATUS:
        if candidate in text:
            return candidate
    return "open"


def _normalize_secret(entry: Any, index: int) -> dict[str, Any]:
    ignored_keys: list[str] = []
    if isinstance(entry, str):
        hints = {
            "kind": None,
            "rule_id": entry,
            "name": None,
            "label": None,
            "where": None,
            "exposure": None,
            "status": None,
            "owner": None,
        }
    elif isinstance(entry, dict):
        ignored_keys = [
            str(key)
            for key in entry
            if key in IGNORED_VALUE_KEYS and entry[key] not in (None, "", {}, [])
        ]
        hints = {
            "kind": entry.get("kind"),
            "rule_id": entry.get("rule_id"),
            "name": entry.get("name"),
            "label": entry.get("label"),
            "where": entry.get("where") or entry.get("file") or entry.get("path"),
            "exposure": entry.get("exposure"),
            "status": entry.get("status"),
            "owner": entry.get("owner"),
        }
    else:
        raise ValueError(f"secrets[{index}]: must be an object or string")

    kind = _kind_from_hints(hints.get("kind"), hints.get("rule_id"))
    playbook = ROTATION_PLAYBOOKS[kind]
    rule = _text(hints["rule_id"], 80)
    label = _text(hints["label"] or hints["name"] or rule, 120) or f"secret-{index + 1}"
    where = _text(hints["where"], 160)
    exposure = _exposure(hints["exposure"])
    status = _secret_status(hints["status"])
    owner = _text(hints["owner"], 80)
    fingerprint = _digest(f"{kind}|{label}|{where}|{exposure}")

    if status == "ignored":
        steps: list[str] = []
    elif status in {"rotated", "revoked"}:
        steps = [
            "Confirm the replacement is in use and the old value is rejected; "
            "close the finding only after that check."
        ]
    else:
        steps = list(playbook["steps"])

    return {
        "id": fingerprint,
        "kind": kind,
        "label": label,
        "where": where,
        "exposure": exposure,
        "owner": owner,
        "status": status,
        "severity": playbook["severity"],
        "priority": playbook["priority"],
        "needs_action": status == "open",
        "steps": steps,
        "step_count": len(steps),
        "ignored_value_keys": sorted(ignored_keys),
    }


def plan_rotation(secrets: list[Any] | None = None) -> dict[str, Any]:
    """Build ordered, advice-only rotation plans from secret metadata."""
    if secrets is None:
        secrets = []
    if not isinstance(secrets, list):
        raise ValueError("secrets must be a list")
    if len(secrets) > MAX_SECRETS:
        raise ValueError(f"secrets must be at most {MAX_SECRETS} entries")
    plans = [_normalize_secret(entry, i) for i, entry in enumerate(secrets)]
    by_kind: dict[str, int] = {}
    for plan in plans:
        by_kind[plan["kind"]] = by_kind.get(plan["kind"], 0) + 1
    return {
        "count": len(plans),
        "actionable": sum(1 for plan in plans if plan["needs_action"]),
        "by_kind": dict(sorted(by_kind.items())),
        "plans": plans,
    }


def _signature(entry: Any, label: str, index: int) -> str:
    if isinstance(entry, str):
        return _text(entry, 120) or f"unnamed-{index + 1}"
    if isinstance(entry, dict):
        for key in ("id", "signature", "fingerprint", "crash_id", "hash", "name"):
            if entry.get(key) not in (None, ""):
                return _text(entry[key], 120)
        return f"unnamed-{index + 1}"
    raise ValueError(f"{label}[{index}]: crash must be an object or string")


def _run(value: Any, label: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    crashes = value.get("crashes")
    signatures: list[str] = []
    if crashes is not None:
        if not isinstance(crashes, list):
            raise ValueError(f"{label}.crashes must be a list")
        signatures = [
            _signature(item, f"{label}.crashes", i) for i, item in enumerate(crashes)
        ]

    def _count(key: str) -> int | None:
        raw = value.get(key)
        if raw is None:
            return None
        if isinstance(raw, bool):
            raise ValueError(f"{label}.{key} must be a number")
        try:
            number = int(raw)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{label}.{key} must be a number") from exc
        if number < 0:
            raise ValueError(f"{label}.{key} must be non-negative")
        return number

    executions = _count("executions")
    before_coverage = value.get("coverage")
    coverage: float | None = None
    if before_coverage is not None:
        if isinstance(before_coverage, bool):
            raise ValueError(f"{label}.coverage must be a number")
        try:
            coverage = float(before_coverage)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{label}.coverage must be a number") from exc
        if coverage < 0:
            raise ValueError(f"{label}.coverage must be non-negative")

    explicit_crashes = _count("crash_count")
    explicit_distinct = _count("distinct_crashes")
    crash_count = (
        explicit_crashes
        if explicit_crashes is not None
        else (len(signatures) if crashes is not None else None)
    )
    distinct_count = (
        explicit_distinct
        if explicit_distinct is not None
        else (len(set(signatures)) if crashes is not None else None)
    )
    return {
        "job_id": _text(value.get("job_id"), 80),
        "executions": executions,
        "coverage": coverage,
        "crash_count": crash_count,
        "distinct_crashes": distinct_count,
        "signatures_supplied": crashes is not None,
        "signatures": signatures,
    }


def _comparability(
    before: dict[str, Any], after: dict[str, Any]
) -> tuple[bool, list[str]]:
    caveats: list[str] = []
    base_exec = before.get("executions")
    new_exec = after.get("executions")
    if not base_exec or not new_exec:
        caveats.append("both runs need executions > 0")
    elif new_exec < base_exec * 0.5:
        caveats.append("retest executed less than half the baseline iterations")
    base_cov = before.get("coverage")
    new_cov = after.get("coverage")
    if base_cov is None or new_cov is None:
        caveats.append("coverage was not supplied for both runs")
    elif new_cov < base_cov - 0.05:
        caveats.append("retest coverage dropped by more than 5%")
    return (not caveats), caveats


def verify_patch(before: Any = None, after: Any = None) -> dict[str, Any]:
    """Compare supplied before/after fuzz results; never re-run a fuzzer."""
    baseline = _run(before, "before")
    retest = _run(after, "after")
    comparable, caveats = _comparability(baseline, retest)

    base_sigs = set(baseline.get("signatures") or [])
    new_sigs = set(retest.get("signatures") or [])
    both_supplied = bool(before is not None and after is not None)
    have_signatures = bool(
        baseline.get("signatures_supplied") and retest.get("signatures_supplied")
    )
    cleared = sorted(base_sigs - new_sigs) if have_signatures else []
    persisting = sorted(base_sigs & new_sigs) if have_signatures else []
    new = sorted(new_sigs - base_sigs) if have_signatures and both_supplied else []

    base_crashes = baseline.get("crash_count")
    after_crashes = retest.get("crash_count")

    if (
        not both_supplied
        or not comparable
        or base_crashes is None
        or after_crashes is None
    ):
        verdict = "inconclusive"
    elif base_crashes == 0:
        verdict = "not_applicable"
    elif after_crashes == 0:
        verdict = "fixed"
    elif new:
        verdict = "regression"
    elif after_crashes < base_crashes:
        verdict = "partial"
    else:
        verdict = "persists"

    evidence: list[str] = []
    if base_crashes is None:
        evidence.append("baseline crash count not supplied")
    else:
        evidence.append(f"baseline crashes={base_crashes}")
    if after_crashes is None:
        evidence.append("retest crash count not supplied")
    else:
        evidence.append(f"retest crashes={after_crashes}")
    if have_signatures:
        evidence.append(
            f"signatures cleared={len(cleared)} persisting={len(persisting)} new={len(new)}"
        )
    else:
        evidence.append("crash signatures were not supplied for both runs")
    evidence.extend(caveats)

    return {
        "verdict": verdict,
        "verified": verdict == "fixed",
        "comparable": comparable,
        "caveats": caveats,
        "before": {
            key: value
            for key, value in baseline.items()
            if key not in {"signatures", "signatures_supplied"}
        },
        "after": {
            key: value
            for key, value in retest.items()
            if key not in {"signatures", "signatures_supplied"}
        },
        "baseline_crashes": base_crashes,
        "retest_crashes": after_crashes,
        "cleared_signatures": cleared,
        "persisting_signatures": persisting,
        "new_signatures": new,
        "evidence": evidence,
    }


def _safe_target(value: Any) -> str:
    raw = _text(value, 240)
    if not raw:
        return ""
    parts = urlsplit(raw)
    if parts.scheme and parts.netloc:
        host = parts.hostname or parts.netloc.split("@")[-1]
        port = f":{parts.port}" if parts.port else ""
        target = f"{parts.scheme}://{_text(host, 120)}{port}{parts.path}"
    else:
        target = raw.split("?", 1)[0].split("#", 1)[0]
    return _text(target, 200)


def _normalize_step(entry: Any, index: int) -> tuple[dict[str, Any], int]:
    if isinstance(entry, str):
        data: dict[str, Any] = {"action": "note", "note": entry}
    elif isinstance(entry, dict):
        data = entry
    else:
        raise ValueError(f"flow[{index}]: step must be an object or string")
    action = _text(data.get("action") or "note", 40).lower()
    if action not in ALLOWED_ACTIONS:
        raise ValueError(f"flow[{index}]: unsupported action {action!r}")

    raw_method = _text(data.get("method"), 16).upper()
    method = raw_method if raw_method in ALLOWED_METHODS else ""
    raw_headers = data.get("headers") or {}
    if isinstance(raw_headers, dict):
        header_names = sorted(_text(name, 60) for name in raw_headers if name)
    elif isinstance(raw_headers, list):
        header_names = sorted(
            (
                _text(name if isinstance(name, str) else name.get("name"), 60)
                if isinstance(name, (str, dict))
                else ""
            )
            for name in raw_headers
        )
    else:
        raise ValueError(f"flow[{index}]: headers must be an object or list")
    header_names = [name for name in header_names if name]

    raw_body = data.get("body")
    body_keys: list[str] = []
    if isinstance(raw_body, dict):
        body_keys = sorted(_text(key, 60) for key in raw_body)
    elif raw_body not in (None, ""):
        body_keys = ["<redacted>"]

    outcome = ""
    if action == "assert":
        raw_outcome = _text(
            data.get("outcome") or data.get("result") or data.get("status"), 40
        ).lower()
        outcome = raw_outcome if raw_outcome in ALLOWED_OUTCOMES else "unknown"

    ignored = sorted(
        key
        for key in IGNORED_VALUE_KEYS
        if key in data and data[key] not in (None, "", {}, [])
    )
    step = {
        "index": index + 1,
        "action": action,
        "target": _safe_target(
            data.get("target") or data.get("url") or data.get("path")
        ),
        "method": method,
        "header_names": header_names,
        "body_keys": body_keys,
        "expected": _text(data.get("expected"), 160),
        "observed": _text(data.get("observed"), 160),
        "outcome": outcome,
        "note": _text(data.get("note"), 200),
        "sensitive_redacted": bool(
            ignored
            or header_names
            or body_keys
            or "?"
            in _text(data.get("target") or data.get("url") or data.get("path"), 240)
        ),
    }
    canonical = json.dumps(step, sort_keys=True, separators=(",", ":"))
    step["id"] = _digest(canonical)
    return step, len(ignored)


def capture_poc(flow: list[Any] | None = None) -> dict[str, Any]:
    """Record supplied step descriptors as a deterministic headless step list."""
    if flow is None:
        flow = []
    if not isinstance(flow, list):
        raise ValueError("flow must be a list")
    if len(flow) > MAX_STEPS:
        raise ValueError(f"flow must be at most {MAX_STEPS} steps")
    steps: list[dict[str, Any]] = []
    dropped: int = 0
    for index, entry in enumerate(flow):
        step, ignored_count = _normalize_step(entry, index)
        dropped += ignored_count
        steps.append(step)

    actions: dict[str, int] = {}
    for step in steps:
        actions[step["action"]] = actions.get(step["action"], 0) + 1
    digest_source = json.dumps(steps, sort_keys=True, separators=(",", ":"))
    return {
        "steps": steps,
        "step_count": len(steps),
        "actions": dict(sorted(actions.items())),
        "confirmed": any(step["outcome"] == "confirmed" for step in steps),
        "confirmed_count": sum(1 for step in steps if step["outcome"] == "confirmed"),
        "ignored_value_fields": dropped,
        "digest": hashlib.sha256(digest_source.encode("utf-8")).hexdigest()[:16],
        "headless": True,
        "browser": False,
        "executed": False,
    }


def analyze(
    secrets: list[Any] | None = None,
    before: dict[str, Any] | None = None,
    after: dict[str, Any] | None = None,
    flow: list[Any] | None = None,
) -> dict[str, Any]:
    """Run the rotation planner, patch verifier and headless PoC capture."""
    if not secrets and before is None and after is None and not flow:
        raise ValueError("secrets, before/after results or flow required")
    return {
        "rotation": plan_rotation(secrets),
        "patch_verification": verify_patch(before, after),
        "poc_capture": capture_poc(flow),
        "limitations": LIMITATIONS,
        "sandbox": False,
    }


def to_ledger(host: str, result: dict[str, Any]) -> list[dict[str, Any]]:
    """Map actionable rotation plans, failed patch proof and confirmed PoCs."""
    rows: list[dict[str, Any]] = []
    rotation = result.get("rotation") or {}
    for plan in rotation.get("plans") or []:
        if not plan.get("needs_action"):
            continue
        rows.append(
            {
                "host": host,
                "name": (
                    f"rotate {plan.get('kind', 'secret')}: {plan.get('label', '?')} "
                    f"at {plan.get('where') or 'unknown'}"
                )[:220].strip(),
                "severity": str(plan.get("severity") or "MEDIUM").upper(),
                "module": "secret-rotation",
                "reference": str(plan.get("id") or ""),
                "cwe": "CWE-798",
                "detail": (
                    f"priority={plan.get('priority', '')} "
                    f"exposure={plan.get('exposure', '')} "
                    f"steps={plan.get('step_count', 0)}"
                ).strip()[:400],
            }
        )

    patch = result.get("patch_verification") or {}
    verdict = str(patch.get("verdict") or "")
    if verdict in {"regression", "persists", "partial"}:
        rows.append(
            {
                "host": host,
                "name": f"patch not verified: {verdict} after retest"[:220],
                "severity": "HIGH" if verdict == "regression" else "MEDIUM",
                "module": "patch-verifier",
                "reference": str((patch.get("after") or {}).get("job_id") or ""),
                "cwe": "CWE-693",
                "detail": (
                    f"baseline_crashes={patch.get('baseline_crashes', '')} "
                    f"retest_crashes={patch.get('retest_crashes', '')} "
                    f"new={len(patch.get('new_signatures') or [])}"
                ).strip()[:400],
            }
        )

    capture = result.get("poc_capture") or {}
    if capture.get("confirmed"):
        rows.append(
            {
                "host": host,
                "name": (
                    f"recorded PoC: {capture.get('confirmed_count', 0)} "
                    "confirmed headless step(s)"
                )[:220],
                "severity": "HIGH",
                "module": "poc-capture",
                "reference": str(capture.get("digest") or ""),
                "cwe": "CWE-693",
                "detail": (
                    f"steps={capture.get('step_count', 0)} "
                    "headless recording only, no browser or network execution"
                ).strip()[:400],
            }
        )
    return rows


def sandbox_result() -> dict[str, Any]:
    """Canned rotation/patch/PoC result with deliberately fake values."""
    result = analyze(
        secrets=[
            {
                "rule_id": "secret-aws-key",
                "label": "demo-aws-key",
                "where": "config.py",
                "exposure": "repo",
                "status": "open",
                "code": "AKIAEXAMPLEEXAMPLEEX",
                "value": "FAKE-SECRET-DO-NOT-USE",
            },
            {
                "kind": "db-password",
                "label": "demo-db-password",
                "where": "ci.env",
                "exposure": "log",
                "status": "open",
                "password": _FAKE_DB_PASSWORD,
            },
            {
                "kind": "github-token",
                "label": "demo-github-token",
                "where": "ci.yml",
                "status": "rotated",
                "value": "FAKE-GITHUB-TOKEN-DO-NOT-USE",
            },
        ],
        before={
            "job_id": "fuzz-before",
            "executions": 10000,
            "coverage": 0.72,
            "crashes": [{"id": "sig-a"}, {"id": "sig-b"}],
        },
        after={
            "job_id": "fuzz-after",
            "executions": 12000,
            "coverage": 0.75,
            "crashes": [],
        },
        flow=[
            {"action": "navigate", "target": "http://lab.invalid/login"},
            {
                "action": "submit",
                "method": "POST",
                "target": ("http://lab.invalid/login?token=FAKE-QUERY-DO-NOT-USE"),
                "headers": {"Authorization": "Bearer FAKE-BEARER-DO-NOT-USE"},
                "body": {"password": _FAKE_BODY_PASSWORD},
                "value": "FAKE-VALUE-DO-NOT-USE",
            },
            {
                "action": "assert",
                "target": "http://lab.invalid/admin",
                "expected": "admin panel reachable",
                "observed": "200 OK",
                "outcome": "confirmed",
                "note": "secret=FakePasswordValueDoNotUse",
            },
        ],
    )
    result["sandbox"] = True
    return result
