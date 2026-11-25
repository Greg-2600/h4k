"""SMB share enumerator (Backlog #7).

Read-only share/ACL inventory for a host you own: null-session
`smbclient -L` plus `smbmap` when available, parsed into structured
shares. With `engagement_id` the shares are recorded per host
(scope-enforced) and surfaced in the asset-graph payload.
"""

from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger("h4k.smb_shares")


def parse_smbclient(stdout: str) -> list[dict[str, str]]:
    """Parse `smbclient -L` share-table rows."""
    shares: list[dict[str, str]] = []
    in_table = False
    for line in (stdout or "").splitlines():
        if re.match(r"^\s*Sharename\s+Type\s+Comment", line):
            in_table = True
            continue
        if not in_table:
            continue
        if re.match(r"^\s*[-_ ]{3,}", line) or not line.strip():
            continue
        if re.match(
            r"^(Server|Workgroup|SMB|session|Anonymous|Enter|Connection|Reconnecting|protocol|OS=|Domain=|\s*$)",
            line,
        ):
            break
        parts = re.split(r"\s{2,}|\t+", line.strip(), maxsplit=2)
        if len(parts) >= 2 and parts[0] not in ("Sharename",):
            shares.append(
                {
                    "name": parts[0],
                    "type": parts[1] if len(parts) > 1 else "",
                    "comment": parts[2] if len(parts) > 2 else "",
                }
            )
    return shares


def parse_smbmap(stdout: str) -> list[dict[str, str]]:
    """Parse `smbmap -H` share rows (permission + name columns)."""
    shares: list[dict[str, str]] = []
    for line in (stdout or "").splitlines():
        if not line.strip() or line.lstrip().startswith(("[", "+", "-", "=")):
            continue
        parts = re.split(r"\t+|\s{2,}", line.strip(), maxsplit=2)
        if len(parts) < 2:
            continue
        access, name = parts[0].strip(), parts[1].strip()
        if not re.fullmatch(r"[A-Za-z\-? ]+", access):
            continue
        if name.lower() in (
            "share",
            "name",
            "permissions",
            "comment",
            "disk",
            "working",
            "----",
            "-----------",
        ):
            continue
        if "/" in name or "\\" in name or "." in name:
            continue
        shares.append(
            {
                "name": name,
                "type": "Disk",
                "comment": parts[2].strip() if len(parts) > 2 else "",
                "access": access,
            }
        )
    return shares


def _merge(
    base: list[dict[str, str]], extra: list[dict[str, str]]
) -> list[dict[str, str]]:
    by_name = {s["name"]: dict(s) for s in base}
    for s in extra:
        if s["name"] in by_name:
            for key, val in s.items():
                if val and not by_name[s["name"]].get(key):
                    by_name[s["name"]][key] = val
        else:
            by_name[s["name"]] = dict(s)
    return sorted(by_name.values(), key=lambda s: s["name"])


def enumerate_shares(  # nosec B107 - user/password are optional operator args, never baked-in secrets
    target: str, user: str = "", password: str = ""
) -> dict[str, Any]:
    """Enumerate SMB shares on one host (read-only, null session default)."""
    from services.toolkit import ToolkitRunner

    runner = ToolkitRunner()
    tools: list[dict[str, Any]] = []
    all_shares: list[dict[str, str]] = []

    smb_argv = ["smbclient", "-L", f"//{target}", "-N", "-g"]
    if user:
        smb_argv = [
            "smbclient",
            "-L",
            f"//{target}",
            "-U",
            f"{user}%{password}" if password else user,
            "-g",
        ]
    out = runner.run_tool("smbclient", smb_argv, timeout=60)
    tools.append(out)
    if out.get("status") == "ok":
        all_shares = _merge(all_shares, parse_smbclient(out.get("stdout", "")))

    map_argv = ["smbmap", "-H", target]
    if user:
        map_argv += ["-u", user] + (["-p", password] if password else [])
    else:
        map_argv += ["-u", "anonymous"]
    out = runner.run_tool("smbmap", map_argv, timeout=60)
    tools.append(out)
    if out.get("status") == "ok":
        all_shares = _merge(all_shares, parse_smbmap(out.get("stdout", "")))

    ok = any(t.get("status") == "ok" for t in tools)
    return {
        "target": target,
        "shares": all_shares,
        "count": len(all_shares),
        "tools": tools,
        "success": ok,
    }


def sandbox_shares(target: str) -> dict[str, Any]:
    """Deterministic offline stand-in (sandbox/e2e only)."""
    shares = [
        {
            "name": "ADMIN$",
            "type": "Disk",
            "comment": "Remote Admin",
            "access": "NO ACCESS",
        },
        {
            "name": "C$",
            "type": "Disk",
            "comment": "Default share",
            "access": "NO ACCESS",
        },
        {
            "name": "public",
            "type": "Disk",
            "comment": "lab drop",
            "access": "READ ONLY",
        },
    ]
    return {
        "target": target,
        "shares": shares,
        "count": len(shares),
        "tools": [{"tool": "smbclient", "status": "sandbox"}],
        "success": True,
        "sandbox": True,
    }
