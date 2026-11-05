"""Session post-exploit recon pack + loot timeline (Backlog #11).

Opening a shell is the middle of the story, not the end. This module
bundles what a session yielded — the standard recon set
(sysinfo/getuid/hashdump, already stored in `session_recon` when the
session opened) — with the loot timeline for the engagement: sessions
opened, credentials verified and flags captured, in chronological order.
Read-only: it only reads stores, never touches a session.
"""

from __future__ import annotations

import sqlite3
from typing import Any

from paths import data_dir


def _neighbors_db() -> sqlite3.Connection:
    conn = sqlite3.connect(data_dir() / "neighbors.db", timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def session_pack(session_id: str) -> dict[str, Any]:
    """Recon outputs stored for one Meterpreter/shell session id."""
    sid = (session_id or "").strip()
    if not sid:
        return {"session_id": "", "session": None, "recon": {}, "found": False}
    conn = _neighbors_db()
    try:
        sess = conn.execute(
            "SELECT * FROM exploit_sessions WHERE msf_session_id=?", (sid,)
        ).fetchone()
        rows = conn.execute(
            "SELECT command, output, at FROM session_recon WHERE msf_session_id=?"
            " ORDER BY command",
            (sid,),
        ).fetchall()
    except Exception:
        return {"session_id": sid, "session": None, "recon": {}, "found": False}
    finally:
        conn.close()
    if sess is None and not rows:
        return {"session_id": sid, "session": None, "recon": {}, "found": False}
    return {
        "session_id": sid,
        "session": dict(sess) if sess else None,
        "recon": {r["command"]: r["output"] for r in rows},
        "found": True,
    }


def loot_timeline(store: Any, engagement_id: str) -> dict[str, Any]:
    """Chronological loot: sessions opened, creds verified, flags captured."""
    if not store.get_engagement(engagement_id):
        raise ValueError("unknown engagement")
    events: list[dict[str, Any]] = []

    for cred in store.credentials(engagement_id):
        if not cred.get("verified"):
            continue
        for h in cred.get("hosts") or []:
            events.append(
                {
                    "at": h.get("last_verified") or cred.get("last_verified") or "",
                    "kind": "credential",
                    "detail": f"{cred.get('user')} verified on {h.get('host')}",
                }
            )
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
    try:
        conn = _neighbors_db()
        try:
            rows = conn.execute(
                "SELECT msf_session_id, host, port, module, opened_at"
                " FROM exploit_sessions ORDER BY opened_at"
            ).fetchall()
        except Exception:
            rows = []
        finally:
            conn.close()
        for row in rows:
            d = dict(row)
            host = str(d.get("host") or "")
            if host and store.in_scope(engagement_id, host):
                events.append(
                    {
                        "at": d.get("opened_at") or "",
                        "kind": "session",
                        "detail": f"session {d.get('msf_session_id')} opened on {host}",
                    }
                )
    except Exception:
        pass
    events.sort(key=lambda e: (e["at"] or "", e["kind"]))
    kinds: dict[str, int] = {}
    for e in events:
        kinds[e["kind"]] = kinds.get(e["kind"], 0) + 1
    return {
        "engagement_id": engagement_id,
        "events": events,
        "count": len(events),
        "kinds": kinds,
    }
