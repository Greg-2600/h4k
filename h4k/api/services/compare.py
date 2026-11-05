"""Engagement compare/diff (Backlog #15).

One engagement is a snapshot in time; two runs are a story. This module
diffs two engagements — vulns added/cleared, credentials banked/lost,
crown jewels declared/retired, and the best attack-path score on each
side — so the operator can answer "are we better or worse than last
week?" Read-only on both engagements.
"""

from __future__ import annotations

from typing import Any


def _vuln_key(v: dict[str, Any]) -> tuple[str, str]:
    return (str(v.get("host") or ""), str(v.get("name") or ""))


def _cred_key(c: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(c.get("user") or ""),
        str(c.get("password") or ""),
        str(c.get("service") or ""),
    )


def compare_engagements(store: Any, from_id: str, to_id: str) -> dict[str, Any]:
    """Diff `to` against `from` (added/cleared per category)."""
    if not store.get_engagement(from_id):
        raise ValueError(f"unknown engagement: {from_id}")
    if not store.get_engagement(to_id):
        raise ValueError(f"unknown engagement: {to_id}")
    from_vulns = {_vuln_key(v): v for v in store.vulns(from_id)}
    to_vulns = {_vuln_key(v): v for v in store.vulns(to_id)}
    added_v = [to_vulns[k] for k in to_vulns if k not in from_vulns]
    cleared_v = [from_vulns[k] for k in from_vulns if k not in to_vulns]

    from_creds = {_cred_key(c) for c in store.credentials(from_id) if c.get("verified")}
    to_creds = {_cred_key(c) for c in store.credentials(to_id) if c.get("verified")}

    from_jewels = {j["host"]: j for j in store.list_crown_jewels(from_id)}
    to_jewels = {j["host"]: j for j in store.list_crown_jewels(to_id)}

    from_paths: dict[str, Any] = {"summary": {"best_score": 0, "paths": 0}}
    to_paths: dict[str, Any] = {"summary": {"best_score": 0, "paths": 0}}
    try:
        from services.attack_paths import compute_attack_paths

        from_paths = compute_attack_paths(store, from_id, limit=10)
        to_paths = compute_attack_paths(store, to_id, limit=10)
    except Exception:
        pass
    return {
        "from_id": from_id,
        "to_id": to_id,
        "vulns": {
            "added": added_v,
            "cleared": cleared_v,
            "added_count": len(added_v),
            "cleared_count": len(cleared_v),
        },
        "credentials": {
            "added": sorted(to_creds - from_creds),
            "removed": sorted(from_creds - to_creds),
        },
        "crown_jewels": {
            "added": [to_jewels[h] for h in to_jewels if h not in from_jewels],
            "removed": [from_jewels[h] for h in from_jewels if h not in to_jewels],
        },
        "paths": {
            "from_best": from_paths.get("summary", {}).get("best_score", 0),
            "to_best": to_paths.get("summary", {}).get("best_score", 0),
            "from_paths": from_paths.get("summary", {}).get("paths", 0),
            "to_paths": to_paths.get("summary", {}).get("paths", 0),
        },
    }
