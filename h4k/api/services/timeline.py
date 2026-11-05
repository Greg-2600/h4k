"""Engagement timeline view (Backlog #13).

Scans, credentials, sessions and objectives accumulate in different
stores. This module merges them into one chronological feed per
engagement — scan → creds → sessions → paths — so the operator (and the
report) can tell the story of the engagement in order:

- scans/fingerprints from the neighbors store (in-scope hosts only),
- verified credential logins from the attempt ledger,
- sessions opened,
- crown jewels declared (objectives for the attack paths),
- flags captured,
- Lab Watch snapshot passes.

Read-only. Attack-path computations themselves are on-demand and are
not history; their objectives (crown jewels) are.
"""

from __future__ import annotations

import sqlite3
from typing import Any

from paths import data_dir

_KINDS = ("scan", "credential", "session", "objective", "flag", "watch")


def _neighbors() -> sqlite3.Connection:
    conn = sqlite3.connect(data_dir() / "neighbors.db", timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def timeline(
    store: Any, engagement_id: str, kinds: list[str] | None = None
) -> dict[str, Any]:
    """Chronological events for one engagement (scope-filtered)."""
    eng = store.get_engagement(engagement_id)
    if not eng:
        raise ValueError("unknown engagement")
    want = {k for k in (kinds or []) if k in _KINDS} or set(_KINDS)
    events: list[dict[str, Any]] = []

    def in_scope(host: str) -> bool:
        try:
            return bool(host) and store.in_scope(engagement_id, host)
        except Exception:
            return False

    if "scan" in want:
        try:
            conn = _neighbors()
            try:
                for r in conn.execute(
                    "SELECT ip, discovered_at FROM discovered_hosts"
                ).fetchall():
                    if in_scope(r["ip"]):
                        events.append(
                            {
                                "at": r["discovered_at"] or "",
                                "kind": "scan",
                                "detail": f"host discovered: {r['ip']}",
                            }
                        )
                for r in conn.execute(
                    "SELECT ip, port, service, scanned_at FROM discovered_services"
                ).fetchall():
                    if in_scope(r["ip"]):
                        events.append(
                            {
                                "at": r["scanned_at"] or "",
                                "kind": "scan",
                                "detail": f"service fingerprinted: {r['ip']}:{r['port']} ({r['service'] or '?'})",
                            }
                        )
            finally:
                conn.close()
        except Exception:
            pass
    if "credential" in want:
        for a in store.access(engagement_id):
            if not a.get("verified"):
                continue
            events.append(
                {
                    "at": a.get("last_verified") or a.get("first_seen") or "",
                    "kind": "credential",
                    "detail": f"{a.get('user')} verified on {a.get('host')}",
                }
            )
    if "session" in want:
        try:
            conn = _neighbors()
            try:
                rows = conn.execute(
                    "SELECT msf_session_id, host, opened_at FROM exploit_sessions"
                    " ORDER BY opened_at"
                ).fetchall()
            finally:
                conn.close()
            for r in rows:
                if in_scope(r["host"]):
                    events.append(
                        {
                            "at": r["opened_at"] or "",
                            "kind": "session",
                            "detail": f"session {r['msf_session_id']} opened on {r['host']}",
                        }
                    )
        except Exception:
            pass
    if "objective" in want:
        for jewel in store.list_crown_jewels(engagement_id):
            events.append(
                {
                    "at": jewel.get("created_at") or "",
                    "kind": "objective",
                    "detail": f"objective declared: {jewel.get('label') or jewel.get('host')}",
                }
            )
    if "flag" in want:
        try:
            from services.flags import FlagStore

            for flag in FlagStore().list_flags(engagement_id):
                events.append(
                    {
                        "at": flag.get("created_at") or "",
                        "kind": "flag",
                        "detail": f"flag captured on {flag.get('host') or 'unknown host'}",
                    }
                )
        except Exception:
            pass
    if "watch" in want:
        for ch in store.watch_changes(engagement_id, limit=100):
            events.append(
                {
                    "at": ch.get("created_at") or "",
                    "kind": "watch",
                    "detail": f"estate pass [{ch.get('source')}]: {ch.get('summary')}",
                }
            )
    events.sort(key=lambda e: (e["at"] or "", e["kind"]))
    counts: dict[str, int] = {}
    for e in events:
        counts[e["kind"]] = counts.get(e["kind"], 0) + 1
    return {
        "engagement_id": engagement_id,
        "events": events,
        "count": len(events),
        "kinds": counts,
    }
