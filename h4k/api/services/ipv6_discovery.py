"""IPv6 discovery (Backlog #18).

ARP only sees IPv4. This module reads the kernel IPv6 neighbour table
(`ip -6 neigh`, the NDP equivalent of the ARP cache) and, only when the
operator passes an explicit CIDR, runs a bounded `nmap -6 -sn` sweep of
it. With `engagement_id`, in-scope hosts are recorded as assets —
out-of-scope addresses are reported and never stored.
"""

from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger("h4k.ipv6")

_NEIGH_RE = re.compile(
    r"^(?P<ip>[0-9a-fA-F:]+)\s+dev\s+(?P<dev>\S+)"
    r"(?:\s+lladdr\s+(?P<mac>[0-9a-fA-F:]{17}))?"
    r"(?:\s+(?P<state>\S+))?"
)


def parse_neigh(stdout: str) -> list[dict[str, str]]:
    """Parse `ip -6 neigh show` rows (skips FAILED/INCOMPLETE entries)."""
    out: list[dict[str, str]] = []
    for line in (stdout or "").splitlines():
        m = _NEIGH_RE.match(line.strip())
        if not m:
            continue
        if (m.group("state") or "").upper() in ("FAILED", "INCOMPLETE"):
            continue
        out.append(
            {
                "ip": m.group("ip"),
                "dev": m.group("dev"),
                "mac": (m.group("mac") or "").lower(),
                "state": (m.group("state") or "").upper(),
            }
        )
    return out


def parse_nmap6(stdout: str) -> list[dict[str, str]]:
    """Pull up-host IPv6 addresses from `nmap -6 -sn` output."""
    found: list[dict[str, str]] = []
    current = ""
    for line in (stdout or "").splitlines():
        m = re.match(r"Nmap scan report for (\S+)(?: \(([^)]+)\))?", line)
        if m:
            current = (m.group(2) or m.group(1)).strip()
            continue
        if "Host is up" in line and current and ":" in current:
            if not any(f["ip"] == current for f in found):
                found.append({"ip": current, "dev": "", "mac": "", "state": "UP"})
            current = ""
    return found


def discover(
    interface: str | None = None,
    cidr: str | None = None,
    timeout: int = 60,
) -> dict[str, Any]:
    """NDP neighbour table + optional explicit-CIDR nmap -6 sweep."""
    from services.toolkit import ToolkitRunner

    runner = ToolkitRunner()
    neigh_argv = ["ip", "-6", "neigh", "show"]
    if interface:
        neigh_argv += ["dev", interface]
    neigh = runner.run_tool("ip6neigh", neigh_argv, timeout=timeout)
    neighbors = (
        parse_neigh(neigh.get("stdout", "")) if neigh.get("status") == "ok" else []
    )
    scanned: list[dict[str, str]] = []
    scan_status = "skipped"
    if cidr and cidr.strip():
        out = runner.run_tool(
            "nmap6",
            ["nmap", "-6", "-sn", "-T4", "--max-retries", "1", cidr.strip()],
            timeout=timeout + 60,
        )
        scan_status = out.get("status", "error")
        if out.get("status") == "ok":
            scanned = parse_nmap6(out.get("stdout", ""))
    merged: dict[str, dict[str, str]] = {n["ip"]: dict(n) for n in neighbors}
    for s in scanned:
        merged.setdefault(s["ip"], dict(s))
    return {
        "neighbors": sorted(merged.values(), key=lambda n: n["ip"]),
        "count": len(merged),
        "neigh_status": neigh.get("status"),
        "scan_status": scan_status,
    }


def sandbox_discover() -> dict[str, Any]:
    """Deterministic offline stand-in (sandbox/e2e only)."""
    neighbors = [
        {
            "ip": "fd00::5",
            "dev": "eth0",
            "mac": "52:54:00:12:34:56",
            "state": "REACHABLE",
        },
        {"ip": "fd00::9", "dev": "eth0", "mac": "52:54:00:12:34:57", "state": "STALE"},
        {
            "ip": "fe80::42",
            "dev": "eth0",
            "mac": "52:54:00:12:34:58",
            "state": "REACHABLE",
        },
    ]
    return {
        "neighbors": neighbors,
        "count": len(neighbors),
        "neigh_status": "sandbox",
        "scan_status": "skipped",
        "sandbox": True,
    }
