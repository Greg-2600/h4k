"""SNMP community sweep + MIB walk (Backlog #17).

Tries a small operator-supplied community list (default public/private)
with a single sysDescr GET each — no brute-force wordlists — then
optionally walks the system MIB with the first working community.
Read-only: no SETs, ever. With `engagement_id`, each accepted community
is ledgered as a vuln lead (scope-enforced).
"""

from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger("h4k.snmp")

SYS_DESCR_OID = "1.3.6.1.2.1.1.1.0"
SYSTEM_MIB = "1.3.6.1.2.1.1"
DEFAULT_COMMUNITIES = ["public", "private"]

_MIB_LINE_RE = re.compile(r"^(\S+)\s*=\s*(\w+):\s*(.*)$")


def parse_get(stdout: str) -> str:
    """Pull the value out of one `snmpget` response line."""
    lines = (stdout or "").strip().splitlines()
    if not lines:
        return ""
    m = _MIB_LINE_RE.match(lines[0])
    return m.group(3).strip() if m else ""


def parse_walk(stdout: str, limit: int = 100) -> list[dict[str, str]]:
    """Parse `snmpwalk` lines into {oid, type, value} rows."""
    rows: list[dict[str, str]] = []
    for line in (stdout or "").splitlines():
        m = _MIB_LINE_RE.match(line.strip())
        if not m:
            continue
        rows.append(
            {"oid": m.group(1), "type": m.group(2), "value": m.group(3).strip()}
        )
        if len(rows) >= limit:
            break
    return rows


def sweep(
    target: str,
    communities: list[str] | None = None,
    walk: bool = False,
    timeout: int = 10,
) -> dict[str, Any]:
    """Try each community once; walk the system MIB with the first hit."""
    from services.toolkit import ToolkitRunner

    runner = ToolkitRunner()
    tried = [c for c in (communities or DEFAULT_COMMUNITIES) if c.strip()][:20]
    working: list[dict[str, Any]] = []
    attempts: list[dict[str, Any]] = []
    for community in tried:
        out = runner.run_tool(
            "snmpget",
            [
                "snmpget",
                "-v2c",
                "-c",
                community,
                "-t",
                str(timeout),
                "-r",
                "0",
                target,
                SYS_DESCR_OID,
            ],
            timeout=timeout + 10,
        )
        ok = out.get("status") == "ok" and bool(parse_get(out.get("stdout", "")))
        attempts.append(
            {"community": community, "accepted": ok, "status": out.get("status")}
        )
        if ok:
            working.append(
                {"community": community, "sys_descr": parse_get(out.get("stdout", ""))}
            )
    walked: list[dict[str, str]] = []
    if walk and working:
        out = runner.run_tool(
            "snmpwalk",
            [
                "snmpwalk",
                "-v2c",
                "-c",
                working[0]["community"],
                "-t",
                str(timeout),
                "-r",
                "0",
                target,
                SYSTEM_MIB,
            ],
            timeout=timeout + 30,
        )
        if out.get("status") == "ok":
            walked = parse_walk(out.get("stdout", ""))
    return {
        "target": target,
        "tried": len(tried),
        "working": working,
        "working_count": len(working),
        "walked": walked,
        "walked_count": len(walked),
        "attempts": attempts,
        "tools_ok": any(a["status"] == "ok" for a in attempts),
    }


def sandbox_sweep(target: str) -> dict[str, Any]:
    """Deterministic offline stand-in (sandbox/e2e only)."""
    return {
        "target": target,
        "tried": 2,
        "working": [{"community": "public", "sys_descr": "sandbox lab device"}],
        "working_count": 1,
        "walked": [
            {
                "oid": "SNMPv2-MIB::sysDescr.0",
                "type": "STRING",
                "value": "sandbox lab device",
            },
            {"oid": "SNMPv2-MIB::sysName.0", "type": "STRING", "value": "sandbox"},
        ],
        "walked_count": 2,
        "attempts": [
            {"community": "public", "accepted": True, "status": "ok"},
            {"community": "private", "accepted": False, "status": "ok"},
        ],
        "tools_ok": True,
        "sandbox": True,
    }
