"""Scheduled re-scans + diff-alert digest (Backlog #5).

The global auto-scan keeps one default engagement fresh. This module adds
the per-engagement half: each engagement declares its own rescan cadence
(`watch_interval` seconds, 0 = off) and the scheduler runs a recon-only
pass when it is due, folding the result into the engagement and its Lab
Watch history. Recon only — never credentials, never exploitation.

`digest_markdown` renders recent Lab Watch changes as a markdown alert
digest for the handoff/report flow.
"""

from __future__ import annotations

import logging
import time
from typing import Any

logger = logging.getLogger("h4k.rescan")


def _scope_cidrs(store: Any, engagement_id: str) -> list[str]:
    eng = store.get_engagement(engagement_id)
    return list((eng or {}).get("scope") or [])


def due_engagements(store: Any, now: float | None = None) -> list[dict[str, Any]]:
    """Engagements whose rescan cadence has elapsed."""
    now = float(now if now is not None else time.time())
    due = []
    for eng in store.list_engagements():
        try:
            cfg = store.get_watch_config(eng["id"])
        except ValueError:
            continue
        interval = int(cfg.get("interval") or 0)
        if interval <= 0:
            continue
        last = cfg.get("last_scheduled")
        if last is None or now - float(last) >= interval:
            due.append(
                {
                    "id": eng["id"],
                    "name": eng.get("name", ""),
                    "interval": interval,
                    "last_scheduled": last,
                }
            )
    return due


def run_due_rescans(store: Any, now: float | None = None) -> dict[str, Any]:
    """Run one recon-only pass per due engagement. Returns a summary."""
    from services.auto_scan import _run_one_pass

    now = float(now if now is not None else time.time())
    ran: list[dict[str, Any]] = []
    for cand in due_engagements(store, now):
        eid = cand["id"]
        cidrs = _scope_cidrs(store, eid)
        totals = {"hosts": 0, "services": 0, "vulns": 0}
        try:
            for cidr in cidrs:
                if not cidr or ":" in cidr:
                    continue
                summary = _run_one_pass(cidr, eid)
                for key in totals:
                    totals[key] += int(summary.get(key, 0))
            store.record_scheduled_pass(eid, now)
            ran.append({"id": eid, "name": cand["name"], **totals})
        except Exception as exc:
            logger.debug("scheduled rescan failed for %s: %s", eid, exc)
            ran.append({"id": eid, "name": cand["name"], "error": str(exc)[:200]})
    return {"ran": len(ran), "results": ran}


def digest_markdown(store: Any, engagement_id: str, limit: int = 10) -> str:
    """Render recent Lab Watch changes as a markdown alert digest."""
    eng = store.get_engagement(engagement_id)
    if not eng:
        raise ValueError("unknown engagement")
    changes = store.watch_changes(engagement_id, limit=max(1, min(int(limit), 100)))
    lines = [f"# Lab Watch digest — {eng.get('name') or engagement_id}", ""]
    if not changes:
        lines.append("_No estate changes recorded yet._")
        return "\n".join(lines) + "\n"
    alerts = 0
    for ch in changes:
        diff = ch.get("diff") or {}
        hot = bool(
            diff.get("appeared_hosts")
            or diff.get("new_vulns")
            or diff.get("new_services")
        )
        if hot:
            alerts += 1
        marker = "🔴" if hot else "⚪"
        lines.append(f"## {marker} {ch.get('created_at')} ({ch.get('source')})")
        lines.append("")
        lines.append(f"- {ch.get('summary')}")
        for key in (
            "appeared_hosts",
            "vanished_hosts",
            "new_services",
            "closed_services",
            "changed_services",
            "new_vulns",
            "cleared_vulns",
        ):
            items = diff.get(key) or []
            if items:
                lines.append(f"- {key}: {len(items)}")
                for item in items[:10]:
                    lines.append(f"  - {item}")
        lines.append("")
    lines.insert(2, f"_{len(changes)} snapshot(s), {alerts} with new attack surface._")
    lines.insert(3, "")
    return "\n".join(lines) + "\n"
