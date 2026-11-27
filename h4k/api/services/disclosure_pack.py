"""Disclosure tracker + CVSS builder + CWE browser (Backlog #72).

Offline helpers for the disclosure half of an assessment:

* **Disclosure tracker** turns a report date into a deterministic 90-day
  coordinated-disclosure timeline with reminder dates and a status. Dates are
  pure calendar arithmetic from the supplied report/as-of dates; nothing is
  scheduled, emailed or persisted.
* **CVSS builder** assembles a CVSS v3.1 base vector from picked metrics and
  reuses :mod:`services.cvss` for the exact FIRST score. A supplied vector may
  be v3.1 or v4.0; v4.0 scores are still asserted by the operator, never
  guessed.
* **CWE browser** searches a small curated CWE dictionary by id, name,
  description or keyword and can look entries up by id.

Everything is offline and honest: the CWE list is a demonstration corpus, not
the full MITRE dictionary, and CVSS temporal/environmental metrics are out of
scope. Sandbox mode returns canned data without parsing the request.
"""

from __future__ import annotations

import re
from datetime import date, datetime, timedelta
from typing import Any

from services.cvss import score_vector, severity_for

LIMITATIONS = (
    "Offline only: the disclosure timeline is calendar arithmetic over the "
    "dates you supply (no scheduling, email or persistence), CVSS v3.1 base "
    "scores are computed exactly but v4.0 scores are operator-asserted and "
    "temporal/environmental metrics are not modelled, and the CWE dictionary "
    "is a small curated subset of MITRE CWE rather than the full catalogue. "
    "No network, NVD, vendor portal or MITRE feed is contacted."
)

DISCLOSURE_DAYS = 90

CVSS_METRICS: tuple[dict[str, Any], ...] = (
    {
        "key": "AV",
        "name": "Attack Vector",
        "options": [
            {"value": "N", "label": "Network"},
            {"value": "A", "label": "Adjacent"},
            {"value": "L", "label": "Local"},
            {"value": "P", "label": "Physical"},
        ],
    },
    {
        "key": "AC",
        "name": "Attack Complexity",
        "options": [
            {"value": "L", "label": "Low"},
            {"value": "H", "label": "High"},
        ],
    },
    {
        "key": "PR",
        "name": "Privileges Required",
        "options": [
            {"value": "N", "label": "None"},
            {"value": "L", "label": "Low"},
            {"value": "H", "label": "High"},
        ],
    },
    {
        "key": "UI",
        "name": "User Interaction",
        "options": [
            {"value": "N", "label": "None"},
            {"value": "R", "label": "Required"},
        ],
    },
    {
        "key": "S",
        "name": "Scope",
        "options": [
            {"value": "U", "label": "Unchanged"},
            {"value": "C", "label": "Changed"},
        ],
    },
    {
        "key": "C",
        "name": "Confidentiality Impact",
        "options": [
            {"value": "H", "label": "High"},
            {"value": "L", "label": "Low"},
            {"value": "N", "label": "None"},
        ],
    },
    {
        "key": "I",
        "name": "Integrity Impact",
        "options": [
            {"value": "H", "label": "High"},
            {"value": "L", "label": "Low"},
            {"value": "N", "label": "None"},
        ],
    },
    {
        "key": "A",
        "name": "Availability Impact",
        "options": [
            {"value": "H", "label": "High"},
            {"value": "L", "label": "Low"},
            {"value": "N", "label": "None"},
        ],
    },
)

_V31_BUILDER_KEYS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
_V31_LABELS = {
    metric["key"]: {option["value"]: option["label"] for option in metric["options"]}
    for metric in CVSS_METRICS
}

CWE_ENTRIES: tuple[dict[str, Any], ...] = (
    {
        "id": "CWE-20",
        "name": "Improper Input Validation",
        "category": "Input Validation",
        "description": "The product receives input without validating that it "
        "has the required properties, allowing malformed data to reach "
        "security-sensitive logic.",
        "mitigation": "Validate input against a strict allowlist at every trust "
        "boundary and reject anything unexpected.",
        "keywords": ("input", "validation", "validate", "malformed", "allowlist"),
    },
    {
        "id": "CWE-22",
        "name": "Path Traversal",
        "category": "Path Handling",
        "description": "The product uses a user-controlled path without limiting "
        "it to a restricted directory, so an attacker can read or write files "
        "outside the intended location.",
        "mitigation": "Resolve the path and confirm it stays inside a fixed base "
        "directory; avoid user-supplied path fragments.",
        "keywords": ("path", "traversal", "directory", "dotdot", "../", "file"),
    },
    {
        "id": "CWE-77",
        "name": "Command Injection",
        "category": "Injection",
        "description": "The product builds a command from untrusted input without "
        "neutralizing special elements, letting an attacker add commands.",
        "mitigation": "Use a fixed argv-style API and validate each argument; "
        "never concatenate input into a command string.",
        "keywords": ("command", "injection", "shell", "exec", "rce"),
    },
    {
        "id": "CWE-78",
        "name": "OS Command Injection",
        "category": "Injection",
        "description": "The product passes untrusted input to an operating-system "
        "shell, allowing an attacker to execute arbitrary commands.",
        "mitigation": "Avoid the shell, use fixed argv arrays, and validate or "
        "allowlist any user-controlled argument.",
        "keywords": ("os", "command", "injection", "shell", "exec", "rce"),
    },
    {
        "id": "CWE-79",
        "name": "Cross-site Scripting",
        "category": "Web",
        "description": "The product inserts untrusted input into a web page "
        "without correct encoding or sanitization, so attacker script runs in a "
        "victim's browser.",
        "mitigation": "Encode output for its HTML context and use a vetted "
        "sanitizer where markup is required.",
        "keywords": ("xss", "cross-site", "scripting", "html", "javascript"),
    },
    {
        "id": "CWE-89",
        "name": "SQL Injection",
        "category": "Injection",
        "description": "The product builds a SQL statement from untrusted input "
        "without neutralization, allowing an attacker to change the query.",
        "mitigation": "Use parameterized queries or prepared statements and never "
        "concatenate input into SQL.",
        "keywords": ("sql", "injection", "sqli", "database", "query", "orm"),
    },
    {
        "id": "CWE-94",
        "name": "Code Injection",
        "category": "Injection",
        "description": "The product generates code from untrusted input, letting "
        "an attacker control what the application executes.",
        "mitigation": "Never evaluate user input as code; use data-only formats "
        "and explicit allowlists.",
        "keywords": ("code", "injection", "eval", "execute", "rce"),
    },
    {
        "id": "CWE-119",
        "name": "Buffer Bounds",
        "category": "Memory Safety",
        "description": "The product performs operations on a memory buffer "
        "without restricting them to the buffer's bounds, risking corruption.",
        "mitigation": "Use memory-safe abstractions and bounds-checked APIs; "
        "audit length arithmetic.",
        "keywords": ("buffer", "overflow", "bounds", "memory", "write"),
    },
    {
        "id": "CWE-125",
        "name": "Out-of-bounds Read",
        "category": "Memory Safety",
        "description": "The product reads memory beyond the end of an allocated "
        "buffer, potentially leaking data or crashing.",
        "mitigation": "Validate indexes and lengths before access and use "
        "bounds-checked containers.",
        "keywords": ("out-of-bounds", "oob", "read", "buffer", "memory"),
    },
    {
        "id": "CWE-190",
        "name": "Integer Overflow or Wraparound",
        "category": "Memory Safety",
        "description": "An arithmetic operation wraps past the range of an "
        "integer type, producing an unexpected value that can drive unsafe "
        "memory or logic.",
        "mitigation": "Check arithmetic for overflow and use sized or checked "
        "integer types.",
        "keywords": ("integer", "overflow", "wraparound", "arithmetic"),
    },
    {
        "id": "CWE-200",
        "name": "Sensitive Information Exposure",
        "category": "Information Disclosure",
        "description": "The product exposes sensitive information to an actor "
        "who should not have it, such as secrets, internal paths or private data.",
        "mitigation": "Minimize returned data, redact secrets and enforce "
        "authorization on every sensitive response.",
        "keywords": ("information", "disclosure", "leak", "exposure", "secret"),
    },
    {
        "id": "CWE-269",
        "name": "Improper Privilege Management",
        "category": "Access Control",
        "description": "The product does not correctly assign, check or drop "
        "privileges, letting an actor gain capabilities they should not have.",
        "mitigation": "Apply least privilege, separate privileged operations and "
        "re-check authorization server-side.",
        "keywords": ("privilege", "escalation", "management", "permissions"),
    },
    {
        "id": "CWE-287",
        "name": "Improper Authentication",
        "category": "Authentication",
        "description": "The product does not adequately prove an actor's identity "
        "before granting access.",
        "mitigation": "Use a vetted authentication library, enforce strong "
        "credentials and fail closed on errors.",
        "keywords": ("authentication", "auth", "login", "identity", "bypass"),
    },
    {
        "id": "CWE-306",
        "name": "Missing Authentication for Critical Function",
        "category": "Authentication",
        "description": "A critical function can be reached without any "
        "authentication, exposing it to unauthenticated actors.",
        "mitigation": "Require authentication on every critical endpoint and "
        "test it explicitly.",
        "keywords": ("missing", "authentication", "unauthenticated", "critical"),
    },
    {
        "id": "CWE-319",
        "name": "Cleartext Transmission of Sensitive Information",
        "category": "Cryptography",
        "description": "Sensitive data is sent over a channel that does not "
        "protect it from interception.",
        "mitigation": "Use TLS for all sensitive traffic and reject cleartext "
        "fallbacks.",
        "keywords": ("cleartext", "plaintext", "tls", "http", "transmission"),
    },
    {
        "id": "CWE-326",
        "name": "Inadequate Encryption Strength",
        "category": "Cryptography",
        "description": "The product uses a weak key size or algorithm that can be "
        "broken with feasible effort.",
        "mitigation": "Use current algorithms and key sizes from a vetted "
        "cryptographic library.",
        "keywords": ("encryption", "weak", "crypto", "cipher", "key"),
    },
    {
        "id": "CWE-352",
        "name": "Cross-Site Request Forgery",
        "category": "Web",
        "description": "The product accepts a state-changing request without "
        "proving it came from the user's own page, letting another site trigger "
        "it.",
        "mitigation": "Require CSRF tokens or a same-site cookie policy for "
        "state-changing requests.",
        "keywords": ("csrf", "cross-site", "request", "forgery", "state"),
    },
    {
        "id": "CWE-384",
        "name": "Session Fixation",
        "category": "Authentication",
        "description": "The product keeps a session identifier across a privilege "
        "change, allowing an attacker who fixed it to reuse the session.",
        "mitigation": "Rotate the session identifier on login and privilege "
        "changes.",
        "keywords": ("session", "fixation", "cookie", "login", "rotate"),
    },
    {
        "id": "CWE-416",
        "name": "Use After Free",
        "category": "Memory Safety",
        "description": "The product uses memory after it has been freed, "
        "potentially allowing corruption or code execution.",
        "mitigation": "Clear pointers after free, use ownership-aware abstractions "
        "and run memory sanitizers.",
        "keywords": ("use-after-free", "uaf", "free", "memory", "dangling"),
    },
    {
        "id": "CWE-434",
        "name": "Unrestricted File Upload",
        "category": "File Handling",
        "description": "The product accepts an uploaded file of a dangerous type "
        "without restricting where or how it can be used.",
        "mitigation": "Allowlist file types, store uploads outside the web root "
        "and never execute them.",
        "keywords": ("upload", "file", "unrestricted", "dangerous", "webshell"),
    },
    {
        "id": "CWE-476",
        "name": "NULL Pointer Dereference",
        "category": "Memory Safety",
        "description": "The product dereferences a pointer that may be NULL, "
        "causing a crash or denial of service.",
        "mitigation": "Check pointers before use and fail safely on missing " "values.",
        "keywords": ("null", "pointer", "dereference", "crash", "memory"),
    },
    {
        "id": "CWE-502",
        "name": "Deserialization of Untrusted Data",
        "category": "Injection",
        "description": "The product deserializes data from an untrusted source, "
        "allowing an attacker to control object state or execute code.",
        "mitigation": "Avoid native deserialization of untrusted data and use "
        "schema-validated data formats.",
        "keywords": ("deserialization", "untrusted", "pickle", "yaml", "object"),
    },
    {
        "id": "CWE-601",
        "name": "Open Redirect",
        "category": "Web",
        "description": "The product redirects to a user-controlled URL without "
        "restriction, helping phishing and token leakage.",
        "mitigation": "Allowlist redirect targets or use relative paths only.",
        "keywords": ("redirect", "open", "url", "phishing", "untrusted"),
    },
    {
        "id": "CWE-611",
        "name": "XML External Entity Reference",
        "category": "Injection",
        "description": "The product parses XML with external entity resolution "
        "enabled, allowing file disclosure or server-side requests.",
        "mitigation": "Disable external entities and DTDs in the XML parser.",
        "keywords": ("xml", "xxe", "external", "entity", "parser"),
    },
    {
        "id": "CWE-639",
        "name": "Authorization Bypass Through User-Controlled Key",
        "category": "Access Control",
        "description": "The product uses a user-supplied identifier to select a "
        "record without checking that the user is allowed to access it (IDOR).",
        "mitigation": "Authorize every object access against the authenticated "
        "principal, not just the supplied id.",
        "keywords": ("idor", "authorization", "object", "reference", "bypass"),
    },
    {
        "id": "CWE-732",
        "name": "Incorrect Permission Assignment",
        "category": "Access Control",
        "description": "A critical resource is created with permissions that are "
        "too broad, exposing it to unintended actors.",
        "mitigation": "Apply least-privilege file and resource permissions and "
        "verify them after creation.",
        "keywords": ("permissions", "chmod", "world-writable", "access", "file"),
    },
    {
        "id": "CWE-798",
        "name": "Use of Hard-coded Credentials",
        "category": "Credentials",
        "description": "The product embeds a password, key or token in source or "
        "configuration, making it reusable by anyone who can read the code.",
        "mitigation": "Remove hard-coded secrets, rotate them and load credentials "
        "from a secret store.",
        "keywords": ("hardcoded", "hard-coded", "credentials", "password", "secret"),
    },
    {
        "id": "CWE-862",
        "name": "Missing Authorization",
        "category": "Access Control",
        "description": "The product does not check whether an actor is allowed to "
        "perform an action, so authenticated users can exceed their rights.",
        "mitigation": "Enforce authorization server-side on every sensitive "
        "action and test it with low-privilege accounts.",
        "keywords": ("missing", "authorization", "access", "control", "forbidden"),
    },
    {
        "id": "CWE-918",
        "name": "Server-Side Request Forgery",
        "category": "Web",
        "description": "The product fetches a user-controlled URL without "
        "restriction, allowing an attacker to reach internal services.",
        "mitigation": "Allowlist destinations, block link-local/metadata ranges "
        "and re-check after DNS resolution.",
        "keywords": ("ssrf", "server-side", "request", "forgery", "metadata"),
    },
    {
        "id": "CWE-1021",
        "name": "Improper Restriction of Rendered UI Layers",
        "category": "Web",
        "description": "The product can be framed by another site, enabling "
        "clickjacking and UI redress attacks.",
        "mitigation": "Send frame-ancestors CSP or X-Frame-Options and avoid "
        "framing sensitive pages.",
        "keywords": ("clickjacking", "frame", "iframe", "ui", "redress"),
    },
    {
        "id": "CWE-1104",
        "name": "Use of Unmaintained Third Party Components",
        "category": "Supply Chain",
        "description": "The product depends on a component that is no longer "
        "maintained, so known defects and vulnerabilities may never be fixed.",
        "mitigation": "Track component lifecycle and replace or pin maintained "
        "alternatives.",
        "keywords": ("unmaintained", "eol", "dependency", "component", "supply-chain"),
    },
    {
        "id": "CWE-1321",
        "name": "Prototype Pollution",
        "category": "Injection",
        "description": "The product merges attacker-controlled keys into an "
        "object, modifying its prototype and changing application behaviour.",
        "mitigation": "Reject __proto__/constructor keys, use null-prototype "
        "objects and vetted merge libraries.",
        "keywords": ("prototype", "pollution", "javascript", "object", "merge"),
    },
    {
        "id": "CWE-1336",
        "name": "Server-Side Template Injection",
        "category": "Injection",
        "description": "The product renders untrusted input as a template, "
        "allowing an attacker to execute template expressions or code.",
        "mitigation": "Keep templates trusted, pass user data as values and use "
        "sandboxed rendering.",
        "keywords": ("ssti", "template", "injection", "jinja", "twig"),
    },
    {
        "id": "CWE-1333",
        "name": "Inefficient Regular Expression Complexity",
        "category": "Denial of Service",
        "description": "A regular expression with pathological backtracking can "
        "consume excessive CPU on crafted input (ReDoS).",
        "mitigation": "Use linear-time regex engines or bound input length and "
        "pattern complexity.",
        "keywords": ("redos", "regex", "regular", "expression", "backtracking"),
    },
)

_CWE_BY_ID = {entry["id"]: entry for entry in CWE_ENTRIES}
_WORD_RE = re.compile(r"[a-z0-9]+")
_CWE_ID_RE = re.compile(r"^(?:cwe[-_ ]?)?(\d+)$", re.IGNORECASE)


def cvss_catalog() -> list[dict[str, Any]]:
    """Return the pickable CVSS v3.1 base metrics and their values."""
    return [
        {
            "key": metric["key"],
            "name": metric["name"],
            "options": [dict(option) for option in metric["options"]],
        }
        for metric in CVSS_METRICS
    ]


def _metric_labels(metrics: dict[str, str]) -> dict[str, str]:
    labels: dict[str, str] = {}
    for key, value in metrics.items():
        labels[key] = _V31_LABELS.get(key, {}).get(value, value)
    return labels


def build_vector(metrics: dict[str, Any]) -> str:
    """Assemble a CVSS:3.1 base vector from a complete metric mapping."""
    if not isinstance(metrics, dict):
        raise ValueError("cvss metrics must be an object")
    normalized: dict[str, str] = {}
    missing: list[str] = []
    for key in _V31_BUILDER_KEYS:
        raw = metrics.get(key, metrics.get(key.lower()))
        if raw is None or not str(raw).strip():
            missing.append(key)
            continue
        normalized[key] = str(raw).strip().upper()
    if missing:
        raise ValueError(f"missing CVSS metrics: {', '.join(missing)}")
    return "CVSS:3.1/" + "/".join(
        f"{key}:{normalized[key]}" for key in _V31_BUILDER_KEYS
    )


def build_cvss(
    metrics: dict[str, Any] | None = None,
    vector: str | None = None,
    asserted_score: float | None = None,
) -> dict[str, Any]:
    """Score a supplied vector or build one from picked v3.1 metrics."""
    if vector is not None and str(vector).strip():
        chosen = str(vector).strip()
    elif metrics is not None:
        chosen = build_vector(metrics)
    else:
        raise ValueError("cvss vector or metrics required")
    scored = score_vector(chosen, asserted=asserted_score)
    result = dict(scored)
    result["vector"] = chosen
    result["severity"] = severity_for(float(scored["score"]))
    result["metric_labels"] = _metric_labels(scored["metrics"])
    return result


def _parse_date(value: Any, field: str) -> date:
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{field} must be an ISO date")
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).date()
    except ValueError as exc:
        raise ValueError(f"{field} must be an ISO date") from exc


def _reminder_offsets(total_days: int) -> list[tuple[int, str]]:
    candidates = [
        (0, "Report sent"),
        (30, "30-day check-in"),
        (60, "60-day check-in"),
        (total_days - 7, "7-day deadline warning"),
        (total_days, "Disclosure deadline"),
    ]
    return sorted(
        (offset, label) for offset, label in candidates if 0 <= offset <= total_days
    )


def build_timeline(
    reported_at: Any,
    as_of: Any = None,
    disclosure_days: int = DISCLOSURE_DAYS,
    extension_days: int = 0,
    vendor: str = "",
    title: str = "",
) -> dict[str, Any]:
    """Compute a deterministic disclosure timeline from supplied dates.

    ``as_of`` defaults to ``reported_at`` so the result never depends on the
    wall clock; callers that want a later view must pass it explicitly.
    """
    reported = _parse_date(reported_at, "reported_at")
    as_of_date = reported if as_of in (None, "") else _parse_date(as_of, "as_of")
    if not 1 <= int(disclosure_days) <= 3650:
        raise ValueError("disclosure_days must be between 1 and 3650")
    if not 0 <= int(extension_days) <= 3650:
        raise ValueError("extension_days must be between 0 and 3650")
    total_days = int(disclosure_days) + int(extension_days)
    deadline = reported + timedelta(days=total_days)
    days_remaining = (deadline - as_of_date).days
    elapsed_days = (as_of_date - reported).days

    reminders: list[dict[str, Any]] = []
    for offset, label in _reminder_offsets(total_days):
        reminder_date = reported + timedelta(days=offset)
        until = (reminder_date - as_of_date).days
        if until < 0:
            state = "past"
        elif until == 0:
            state = "due"
        else:
            state = "upcoming"
        reminders.append(
            {
                "label": label,
                "offset_days": offset,
                "date": reminder_date.isoformat(),
                "days_until": until,
                "state": state,
            }
        )

    if as_of_date < reported:
        status = "scheduled"
    elif days_remaining < 0:
        status = "overdue"
    elif days_remaining == 0:
        status = "due"
    elif days_remaining <= 14:
        status = "due_soon"
    else:
        status = "open"

    if as_of_date < reported:
        phase = "scheduled"
    elif elapsed_days < 7:
        phase = "reported"
    elif elapsed_days < 30:
        phase = "triage"
    elif elapsed_days < total_days - 7:
        phase = "vendor-fix"
    elif elapsed_days <= total_days:
        phase = "disclosure-window"
    else:
        phase = "expired"

    next_reminder = next((item for item in reminders if item["days_until"] >= 0), None)

    return {
        "title": title,
        "vendor": vendor,
        "reported_at": reported.isoformat(),
        "as_of": as_of_date.isoformat(),
        "disclosure_days": total_days,
        "base_days": int(disclosure_days),
        "extension_days": int(extension_days),
        "deadline": deadline.isoformat(),
        "days_remaining": days_remaining,
        "elapsed_days": elapsed_days,
        "status": status,
        "phase": phase,
        "reminders": reminders,
        "next_reminder": next_reminder,
        "policy": (
            "Coordinated disclosure: report, allow 90 days for a fix, then "
            "disclose unless a documented extension is agreed with the vendor."
        ),
    }


def _normalize_cwe_id(value: Any) -> str:
    match = _CWE_ID_RE.match(str(value or "").strip())
    if not match:
        return ""
    return f"CWE-{int(match.group(1))}"


def _cwe_public(
    entry: dict[str, Any], score: int = 0, matched: list[str] | None = None
) -> dict[str, Any]:
    public = {
        key: (list(value) if isinstance(value, tuple) else value)
        for key, value in entry.items()
    }
    public["score"] = score
    public["matched_on"] = matched or []
    return public


def cwe_lookup(cwe_id: Any) -> dict[str, Any] | None:
    """Return one CWE entry by id (``79`` or ``CWE-79``), or None."""
    entry = _CWE_BY_ID.get(_normalize_cwe_id(cwe_id))
    return _cwe_public(entry) if entry else None


def cwe_suggest(query: str = "", limit: int = 10) -> list[dict[str, Any]]:
    """Search the curated CWE dictionary; an empty query browses all entries."""
    try:
        limit_value = int(limit)
    except (TypeError, ValueError):
        limit_value = 10
    limit_value = max(1, min(limit_value, 50))
    text = str(query or "").strip().lower()
    ordered = sorted(CWE_ENTRIES, key=lambda entry: int(entry["id"].split("-")[1]))
    if not text:
        return [_cwe_public(entry) for entry in ordered[:limit_value]]

    normalized = _normalize_cwe_id(text)
    digits = re.sub(r"\D", "", text)
    tokens = set(_WORD_RE.findall(text))
    scored: list[tuple[int, int, dict[str, Any]]] = []
    for entry in ordered:
        score = 0
        matched: list[str] = []
        entry_id = entry["id"]
        entry_number = entry_id.split("-")[1]
        name = entry["name"].lower()
        if normalized and entry_id == normalized:
            score += 100
            matched.append("id")
        elif digits and not normalized and entry_number.startswith(digits):
            score += 30
            matched.append("id-prefix")
        if text in name:
            score += 40
            matched.append("name")
        if text in entry["description"].lower():
            score += 12
            matched.append("description")
        if text in entry["category"].lower():
            score += 15
            matched.append("category")
        keywords = {keyword.lower() for keyword in entry["keywords"]}
        name_tokens = set(_WORD_RE.findall(name))
        for token in tokens:
            if token in keywords:
                score += 20
                matched.append(f"keyword:{token}")
            elif token in name_tokens:
                score += 10
                matched.append(f"name-token:{token}")
        if score:
            scored.append(
                (
                    score,
                    int(entry_number),
                    _cwe_public(entry, score, sorted(set(matched))),
                )
            )
    scored.sort(key=lambda item: (-item[0], item[1]))
    return [item[2] for item in scored[:limit_value]]


def analyze(
    reported_at: str | None = None,
    as_of: str | None = None,
    disclosure_days: int = DISCLOSURE_DAYS,
    extension_days: int = 0,
    vendor: str = "",
    title: str = "",
    cvss: dict[str, Any] | None = None,
    cwe_query: str = "",
    cwe_ids: list[str] | None = None,
    cwe_browse: bool = False,
    cwe_limit: int = 10,
) -> dict[str, Any]:
    """Build whichever disclosure/CVSS/CWE outputs the request asked for."""
    if cvss is not None and not isinstance(cvss, dict):
        raise ValueError("cvss must be an object")
    if isinstance(cwe_ids, str):
        raise ValueError("cwe_ids must be a list")
    has_input = bool(
        reported_at
        or cvss is not None
        or str(cwe_query or "").strip()
        or cwe_ids
        or cwe_browse
    )
    if not has_input:
        raise ValueError("reported_at, cvss, cwe_query, cwe_ids or cwe_browse required")

    timeline = None
    if reported_at:
        timeline = build_timeline(
            reported_at,
            as_of=as_of,
            disclosure_days=disclosure_days,
            extension_days=extension_days,
            vendor=vendor,
            title=title,
        )

    cvss_result = None
    if cvss is not None:
        cvss_result = build_cvss(
            metrics=cvss.get("metrics"),
            vector=cvss.get("vector"),
            asserted_score=cvss.get("asserted_score", cvss.get("score")),
        )

    cwe: dict[str, Any] = {"matches": [], "selected": [], "unknown": []}
    query = str(cwe_query or "").strip()
    if cwe_browse or query:
        cwe["matches"] = cwe_suggest(query, limit=cwe_limit)
    for raw in cwe_ids or []:
        entry = cwe_lookup(raw)
        if entry is None:
            label = str(raw or "").strip()
            if label:
                cwe["unknown"].append(label)
        else:
            cwe["selected"].append(entry)

    return {
        "timeline": timeline,
        "cvss": cvss_result,
        "cvss_catalog": cvss_catalog(),
        "cwe": cwe,
        "limitations": LIMITATIONS,
        "sandbox": False,
    }


def sandbox_result() -> dict[str, Any]:
    """Deterministic canned result for sandbox mode and CI."""
    result = analyze(
        reported_at="2026-01-01",
        as_of="2026-02-15",
        vendor="Example Vendor",
        title="Demo finding",
        cvss={"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
        cwe_query="sql injection",
    )
    result["sandbox"] = True
    return result
