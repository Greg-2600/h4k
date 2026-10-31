"""Attack-path analysis: crown jewels and paths to them.

An engagement's raw graph (hosts, services, credentials, vulns) is a lot of
data. What an operator actually wants to know is: *given what I've found, how
do I reach the thing that matters?* A CVSS 9.8 on an isolated box is noise
next to a CVSS 2.0 info-leak that pivots through three credential hops into
the domain controller.

This module turns the engagement store into a reachability graph and computes
simple paths from any plausible foothold to each declared crown jewel. It only
uses edges we have *verified* (credential logins that actually succeeded) plus
the vulnerability inventory, so a path is an evidence chain, not a guess.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any

logger = logging.getLogger("h4k.attack_paths")

_SEV_WEIGHT = {
    "critical": 40,
    "high": 30,
    "medium": 20,
    "low": 10,
    "info": 5,
    "informational": 5,
    "unknown": 5,
}

_TECHNIQUE_FOR_EDGE = {
    "vuln": "T1190",
    "credential": "T1078",
    "pivot": "T1021",
}


def _sev_weight(sev: Any) -> int:
    return _SEV_WEIGHT.get(str(sev or "unknown").strip().lower(), 5)


def _build_graph(store: Any, engagement_id: str) -> tuple[
    set[str],
    dict[str, list[tuple[str, dict[str, Any]]]],
    dict[str, list[dict[str, Any]]],
]:
    assets = store.assets(engagement_id)
    nodes: set[str] = {a["host"] for a in assets}
    for cj in store.list_crown_jewels(engagement_id):
        nodes.add(cj["host"])

    vulns_by_host: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for v in store.vulns(engagement_id):
        vulns_by_host[v["host"]].append(v)
        nodes.add(v["host"])

    adjacency: dict[str, list[tuple[str, dict[str, Any]]]] = {n: [] for n in nodes}

    for cred in store.credentials(engagement_id):
        if not cred.get("verified"):
            continue
        hosts = [h["host"] for h in (cred.get("hosts") or [])]
        if len(hosts) < 2:
            continue
        for u in hosts:
            for v in hosts:
                if u == v:
                    continue
                nodes.add(u)
                nodes.add(v)
                adjacency.setdefault(u, [])
                adjacency.setdefault(v, [])
                adjacency[u].append(
                    (
                        v,
                        {
                            "type": "pivot",
                            "user": cred.get("user"),
                            "service": cred.get("service"),
                            "credential": f"{cred.get('user')}:{cred.get('password')}",
                            "technique": _TECHNIQUE_FOR_EDGE["pivot"],
                        },
                    )
                )

    for n in nodes:
        adjacency.setdefault(n, [])
    return nodes, adjacency, {k: list(v) for k, v in vulns_by_host.items()}


def _footholds(
    nodes: set[str], vulns_by_host: dict[str, list[dict[str, Any]]]
) -> list[str]:
    holds = [n for n in nodes if vulns_by_host.get(n)]
    if holds:
        return holds
    return sorted(nodes)


def _paths_for_jewel(
    jewel: dict[str, Any],
    nodes: set[str],
    adjacency: dict[str, list[tuple[str, dict[str, Any]]]],
    vulns_by_host: dict[str, list[dict[str, Any]]],
    max_depth: int,
    limit: int,
) -> list[dict[str, Any]]:
    target = jewel["host"]
    jewel_nodes = set(nodes) | {target}
    adjacency.setdefault(target, adjacency.get(target, []))

    found: list[dict[str, Any]] = []

    def dfs(
        current: str,
        visited: set[str],
        node_seq: list[str],
        edge_seq: list[dict[str, Any]],
    ) -> None:
        if len(node_seq) > max_depth:
            return
        if current == target and len(node_seq) > 1:
            vulns_on_path: list[dict[str, Any]] = []
            for n in node_seq:
                for v in vulns_by_host.get(n, []):
                    vulns_on_path.append(
                        {
                            "host": n,
                            "name": v.get("name"),
                            "severity": v.get("severity"),
                            "cwe": v.get("cwe"),
                            "module": v.get("module"),
                        }
                    )
            score = int(jewel.get("value") or 50)
            score += sum(_sev_weight(v.get("severity")) for v in vulns_on_path)
            score += 25 * len(edge_seq)
            score -= 12 * (len(node_seq) - 1)
            if vulns_by_host.get(node_seq[0]):
                score += 10
            techniques = sorted(
                {str(e.get("technique")) for e in edge_seq if e.get("technique")}
            )
            found.append(
                {
                    "crown_jewel_id": jewel["id"],
                    "crown_jewel_host": target,
                    "crown_jewel_label": jewel.get("label") or target,
                    "entry": node_seq[0],
                    "nodes": list(node_seq),
                    "edges": list(edge_seq),
                    "hops": len(node_seq) - 1,
                    "vulns": vulns_on_path,
                    "techniques": techniques,
                    "score": score,
                }
            )
            return
        for nxt, meta in adjacency.get(current, []):
            if nxt in visited:
                continue
            if nxt not in jewel_nodes and nxt not in nodes:
                continue
            visited.add(nxt)
            edge_seq.append(dict(meta))
            node_seq.append(nxt)
            dfs(nxt, visited, node_seq, edge_seq)
            node_seq.pop()
            edge_seq.pop()
            visited.discard(nxt)

    starts = _footholds(nodes, vulns_by_host)
    for start in starts:
        if start == target or start not in nodes:
            continue
        dfs(start, {start}, [start], [])

    seen: set[tuple[str, ...]] = set()
    deduped: list[dict[str, Any]] = []
    for p in found:
        key = tuple(p["nodes"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(p)
    deduped.sort(key=lambda p: (-p["score"], p["hops"], p["entry"]))
    return deduped[:limit]


def compute_attack_paths(
    store: Any,
    engagement_id: str,
    crown_jewel_id: str | None = None,
    max_depth: int = 6,
    limit: int = 25,
) -> dict[str, Any]:
    max_depth = max(1, min(int(max_depth or 6), 12))
    limit = max(1, min(int(limit or 25), 100))

    jewels = []
    if crown_jewel_id:
        j = store.get_crown_jewel(engagement_id, crown_jewel_id)
        if j:
            jewels.append(j)
    else:
        jewels = store.list_crown_jewels(engagement_id)

    if not jewels:
        return {
            "engagement_id": engagement_id,
            "crown_jewels": [],
            "paths": [],
            "summary": {
                "crown_jewels": 0,
                "paths": 0,
                "best_score": 0,
            },
        }

    nodes, adjacency, vulns_by_host = _build_graph(store, engagement_id)

    all_paths: list[dict[str, Any]] = []
    for jewel in jewels:
        all_paths.extend(
            _paths_for_jewel(jewel, nodes, adjacency, vulns_by_host, max_depth, limit)
        )

    all_paths.sort(key=lambda p: (-p["score"], p["hops"]))
    all_paths = all_paths[:limit]

    best_score = all_paths[0]["score"] if all_paths else 0
    return {
        "engagement_id": engagement_id,
        "crown_jewels": jewels,
        "paths": all_paths,
        "summary": {
            "crown_jewels": len(jewels),
            "paths": len(all_paths),
            "best_score": best_score,
            "footholds": len(_footholds(nodes, vulns_by_host)),
        },
    }


def paths_to_markdown(result: dict[str, Any]) -> str:
    """Render computed attack paths as a markdown writeup.

    The shape is deliberately report-like: an objective, the ranked paths
    with their evidence, and the ATT&CK techniques involved -- so it can go
    straight into a delivery note.
    """
    lines: list[str] = ["# Attack paths", ""]
    jewels = result.get("crown_jewels") or []
    if jewels:
        lines.append("## Objectives")
        lines.append("")
        for jewel in jewels:
            lines.append(
                f"- **{jewel.get('label') or jewel.get('host')}** "
                f"(`{jewel.get('host')}`, business value {jewel.get('value')})"
            )
        lines.append("")

    paths = result.get("paths") or []
    if not paths:
        lines.append("_No evidence-backed path to any objective was found._")
        lines.append("")
        return "\n".join(lines)

    summary = result.get("summary") or {}
    lines.append(
        f"_{len(paths)} path(s); best score {summary.get('best_score', 0)}; "
        f"{summary.get('footholds', 0)} foothold(s) considered._"
    )
    lines.append("")
    for index, path in enumerate(paths, start=1):
        lines.append(
            f"## {index}. {path.get('entry')} → {path.get('crown_jewel_host')}"
        )
        lines.append("")
        lines.append(f"- **Objective**: {path.get('crown_jewel_label')}")
        lines.append(f"- **Hops**: {path.get('hops')}")
        lines.append(f"- **Score**: {path.get('score')}")
        lines.append(f"- **Chain**: {' → '.join(path.get('nodes') or [])}")
        edges = path.get("edges") or []
        if edges:
            creds = []
            for edge in edges:
                if edge.get("user"):
                    creds.append(f"{edge.get('user')} via {edge.get('service') or '?'}")
            if creds:
                lines.append(f"- **Credentials reused**: {', '.join(creds)}")
        vulns = path.get("vulns") or []
        if vulns:
            lines.append(
                "- **Findings on the path**: "
                + ", ".join(
                    f"{v.get('name')} ({v.get('severity') or '?'}) on {v.get('host')}"
                    for v in vulns
                )
            )
        techniques = path.get("techniques") or []
        if techniques:
            lines.append(f"- **ATT&CK**: {', '.join(techniques)}")
        lines.append("")
    return "\n".join(lines)
