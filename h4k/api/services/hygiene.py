"""Credential hygiene report (Backlog #4).

One verified credential reused across the estate is worth more to an
operator than a dozen isolated findings. This module summarizes the
hygiene of the credentials already recorded in an engagement:

- **reuse**: the same user:password verified on more than one host
- **weak**: short or common-password heuristic (labeled as such)
- **default**: the pair ships in the default-credential archive

Read-only and deterministic: it only reads what the engagement store
already verified. Nothing is sprayed, guessed, or fetched.
"""

from __future__ import annotations

from typing import Any

WEAK_PASSWORDS = frozenset(
    {
        "password",
        "123456",
        "12345678",
        "qwerty",
        "admin",
        "letmein",
        "welcome",
        "monkey",
        "dragon",
        "master",
        "changeme",
        "default",
    }
)


def _is_weak(password: str) -> bool:
    pw = (password or "").strip()
    return len(pw) < 8 or pw.lower() in WEAK_PASSWORDS


def _default_pairs() -> set[tuple[str, str]]:
    try:
        from services.creds import CredArchive

        archive = CredArchive()
        pairs = {
            (str(c.get("user", "")), str(c.get("password", "")))
            for c in archive.universal
        }
        for vendor in archive.vendors:
            for c in vendor.get("creds", []) or []:
                pairs.add((str(c.get("user", "")), str(c.get("password", ""))))
        return {(u, p) for u, p in pairs if u or p}
    except Exception:
        return set()


def hygiene_report(store: Any, engagement_id: str) -> dict[str, Any]:
    """Summarize credential hygiene for one engagement."""
    creds = [c for c in store.credentials(engagement_id) if c.get("verified")]
    defaults = _default_pairs()
    findings: list[dict[str, Any]] = []
    for cred in creds:
        hosts = [h.get("host") for h in cred.get("hosts", []) if h.get("host")]
        user = str(cred.get("user", ""))
        password = str(cred.get("password", ""))
        if len(set(hosts)) > 1:
            findings.append(
                {
                    "kind": "reuse",
                    "user": user,
                    "detail": f"{user} reused on {len(set(hosts))} hosts",
                    "hosts": sorted(set(hosts)),
                    "severity": "high",
                }
            )
        if _is_weak(password):
            findings.append(
                {
                    "kind": "weak",
                    "user": user,
                    "detail": f"{user} uses a weak password (heuristic: short/common)",
                    "hosts": sorted(set(hosts)) or ["?"],
                    "severity": "medium",
                }
            )
        if (user, password) in defaults:
            findings.append(
                {
                    "kind": "default",
                    "user": user,
                    "detail": f"{user} matches the default-credential archive",
                    "hosts": sorted(set(hosts)) or ["?"],
                    "severity": "high",
                }
            )
    reuse = sum(1 for f in findings if f["kind"] == "reuse")
    weak = sum(1 for f in findings if f["kind"] == "weak")
    default = sum(1 for f in findings if f["kind"] == "default")
    score = max(0, 100 - 10 * reuse - 5 * weak - 5 * default)
    order = {"reuse": 0, "default": 1, "weak": 2}
    findings.sort(key=lambda f: (order.get(f["kind"], 9), f["user"]))
    return {
        "engagement_id": engagement_id,
        "summary": {
            "verified_credentials": len(creds),
            "findings": len(findings),
            "reuse": reuse,
            "weak": weak,
            "default": default,
            "score": score,
        },
        "findings": findings,
    }
