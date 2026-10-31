# Flag-anchored attack paths: from foothold to captured flag.
#
# Crown jewels are declared objectives. Captured flags are *achieved*
# objectives -- each one sits on a host (or it is unplaced), and the
# operator wants the evidence chain that reaches it: foothold -> pivot* ->
# flag host, with the ATT&CK techniques along the way. This reuses the
# attack-paths engine with one synthetic jewel per flag host, and attaches
# the flags captured on each path's final host.
from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("h4k.flag_paths")


def compute_flag_paths(
    store: Any,
    engagement_id: str,
    flag_store: Any = None,
    max_depth: int = 6,
    limit: int = 25,
) -> dict[str, Any]:
    """Paths from plausible footholds to the hosts where flags were found."""
    from services.attack_paths import (
        _build_graph,
        _footholds,
        _paths_for_jewel,
    )
    from services.flags import FlagStore

    max_depth = max(1, min(int(max_depth or 6), 12))
    limit = max(1, min(int(limit or 25), 100))

    fs = flag_store or FlagStore()
    flags = fs.list_flags(engagement_id)

    by_host: dict[str, list[dict[str, Any]]] = {}
    unplaced: list[dict[str, Any]] = []
    for flag in flags:
        host = (flag.get("host") or "").strip()
        if host:
            by_host.setdefault(host, []).append(flag)
        else:
            unplaced.append(flag)

    if not by_host:
        return {
            "engagement_id": engagement_id,
            "flags": flags,
            "flag_hosts": [],
            "unplaced": unplaced,
            "objectives": [],
            "paths": [],
            "summary": {
                "flags": len(flags),
                "flag_hosts": 0,
                "paths": 0,
                "best_score": 0,
                "footholds": 0,
            },
        }

    nodes, adjacency, vulns_by_host = _build_graph(store, engagement_id)

    objectives = [
        {
            "id": f"flag:{host}",
            "host": host,
            "label": f"flag on {host} ({len(rows)} captured)",
            "value": 100,
        }
        for host, rows in sorted(by_host.items())
    ]
    all_paths: list[dict[str, Any]] = []
    for jewel in objectives:
        for path in _paths_for_jewel(
            jewel, nodes, adjacency, vulns_by_host, max_depth, limit
        ):
            path["flags"] = [
                {
                    "value": f.get("value"),
                    "path": f.get("path"),
                    "method": f.get("method"),
                    "auto": bool(f.get("auto")),
                }
                for f in by_host.get(path.get("crown_jewel_host", ""), [])
            ]
            all_paths.append(path)

    all_paths.sort(key=lambda p: (-p["score"], p["hops"]))
    all_paths = all_paths[:limit]
    best_score = all_paths[0]["score"] if all_paths else 0
    return {
        "engagement_id": engagement_id,
        "flags": flags,
        "flag_hosts": sorted(by_host),
        "unplaced": unplaced,
        "objectives": objectives,
        "crown_jewels": objectives,
        "paths": all_paths,
        "summary": {
            "flags": len(flags),
            "flag_hosts": len(by_host),
            "paths": len(all_paths),
            "best_score": best_score,
            "footholds": len(_footholds(nodes, vulns_by_host)),
        },
    }


def flag_paths_to_markdown(result: dict[str, Any]) -> str:
    """Report-like writeup: captured flags, then the ranked evidence chains."""
    from services.attack_paths import paths_to_markdown

    lines = ["# Flag paths", ""]
    flags = result.get("flags") or []
    if flags:
        lines.append("## Captured flags")
        lines.append("")
        for flag in flags:
            where = flag.get("host") or "unplaced"
            lines.append(f"- `{flag.get('value')}` ({where})")
        lines.append("")
    unplaced = result.get("unplaced") or []
    if unplaced:
        lines.append(
            f"_Note: {len(unplaced)} flag(s) have no host recorded, "
            "so no path can be computed for them._"
        )
        lines.append("")
    lines.append(paths_to_markdown(result))
    return "\n".join(lines)
