"""BloodHound ingest — SharpHound JSON → graph overlay (Backlog #26).

Running the collector (`POST /api/ad/bloodhound`) is only half the
story; the JSON it produces usually dies in a zip file. This module
ingests SharpHound output (users, computers, groups, OUs, GPOs,
domains) into per-engagement tables and serves the overlay back:
nodes, edges for the attack-graph canvas, and shortest paths to a
high-value target (Domain Admins by default).

The parser only reads a documented subset of relations (MemberOf,
AdminTo, HasSession, AllowedToDelegate, AllowedToAct); anything else
stays in the raw node props instead of being guessed at.
"""

from __future__ import annotations

from collections import deque
from typing import Any

NODE_LISTS = ("users", "computers", "groups", "ous", "gpos", "domains")

# object key -> (edge relation, direction). Direction "out" means an edge
# from the object to each listed SID; lists of objects use their "SID",
# "ObjectIdentifier", "ComputerSID" or "UserSID" fields.
_EDGE_KEYS: dict[str, tuple[str, str]] = {
    "Members": ("MemberOf", "in"),
    "MemberOf": ("MemberOf", "out"),
    "AdminTo": ("AdminTo", "out"),
    "HasSession": ("HasSession", "out"),
    "Sessions": ("HasSession", "out"),
    "AllowedToDelegate": ("AllowedToDelegate", "out"),
    "AllowedToAct": ("AllowedToAct", "out"),
}


def _sid(value: Any) -> str:
    if isinstance(value, dict):
        for key in ("ObjectIdentifier", "SID", "ComputerSID", "UserSID", "MemberId"):
            if value.get(key):
                return str(value[key])
        return ""
    return str(value or "").strip()


def _props(obj: dict[str, Any]) -> dict[str, Any]:
    props = obj.get("Properties") or {}
    if not isinstance(props, dict):
        return {}
    keep = {}
    for key in (
        "name",
        "distinguishedname",
        "samaccountname",
        "enabled",
        "owned",
        "highvalue",
        "description",
    ):
        if props.get(key) is not None:
            keep[key] = props[key]
    return keep


def parse_sharphound(data: Any) -> dict[str, Any]:
    """Normalize SharpHound JSON (dict of lists, or bare list) to nodes+edges."""
    if isinstance(data, list):
        flat: list[dict[str, Any]] = [o for o in data if isinstance(o, dict)]
        buckets: dict[str, list[dict[str, Any]]] = {"objects": flat}
    elif isinstance(data, dict):
        buckets = {k: v for k, v in data.items() if isinstance(v, list)}
    else:
        raise ValueError("expected a JSON object or array of objects")
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    for bucket, objs in buckets.items():
        kind = bucket.rstrip("s") if bucket in NODE_LISTS else "object"
        for obj in objs:
            if not isinstance(obj, dict):
                continue
            sid = str(obj.get("ObjectIdentifier") or "").strip()
            if not sid:
                continue
            props = _props(obj)
            label = str(props.get("name") or sid)
            nodes[sid] = {"id": sid, "label": label, "kind": kind, "props": props}
            for key, (rel, direction) in _EDGE_KEYS.items():
                if key == "Sessions":
                    # sessions name both ends: ComputerSID -> UserSID
                    items = obj.get(key)
                    if not isinstance(items, list):
                        continue
                    for item in items:
                        if not isinstance(item, dict):
                            continue
                        host = str(item.get("ComputerSID") or "").strip()
                        user = str(item.get("UserSID") or "").strip()
                        if host and user:
                            edges.append(
                                {"source": host or sid, "target": user, "rel": rel}
                            )
                    continue
                targets = obj.get(key)
                if isinstance(targets, bool):
                    continue
                if not isinstance(targets, list):
                    targets = [targets] if targets else []
                for target in targets:
                    other = _sid(target)
                    if not other:
                        continue
                    if direction == "out":
                        edges.append({"source": sid, "target": other, "rel": rel})
                    else:
                        edges.append({"source": other, "target": sid, "rel": rel})
    # dedupe, keep insertion order
    seen: set[tuple[str, str, str]] = set()
    unique = []
    for e in edges:
        triple = (e["source"], e["target"], e["rel"])
        if triple not in seen and e["source"] != e["target"]:
            seen.add(triple)
            unique.append(e)
    return {
        "nodes": list(nodes.values()),
        "edges": unique,
        "node_count": len(nodes),
        "edge_count": len(unique),
    }


def shortest_paths(
    nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
    target: str,
    limit: int = 5,
) -> list[list[str]]:
    """BFS shortest paths (by node label, case-insensitive) to `target`."""
    ids = {n["id"] for n in nodes}
    labels = {n["id"]: str(n.get("label", "") or "").lower() for n in nodes}
    want = target.strip().lower()
    goals = {i for i in ids if i.lower() == want or labels.get(i) == want}
    if not goals:
        # substring fallback on the label (e.g. "domain admins")
        goals = {i for i in ids if want in labels.get(i, "")}
    if not goals:
        return []
    adj: dict[str, list[str]] = {i: [] for i in ids}
    for e in edges:
        if e["source"] in adj and e["target"] in ids:
            adj[e["source"]].append(e["target"])
    found: list[list[str]] = []
    queue: deque[list[str]] = deque([[i] for i in sorted(ids - goals)])
    seen: dict[str, int] = {}
    while queue and len(found) < max(1, limit):
        path = queue.popleft()
        node = path[-1]
        if len(path) > 1 and len(path) - 1 > seen.get(node, 99):
            continue
        seen[node] = len(path) - 1
        if node in goals:
            found.append(path)
            continue
        if len(path) > 8:
            continue
        for nxt in sorted(set(adj.get(node, []))):
            if nxt not in path:
                queue.append([*path, nxt])
    return found


def sandbox_graph() -> dict[str, Any]:
    """Deterministic mini-AD (sandbox/e2e only)."""
    return {
        "nodes": [
            {
                "id": "S-1-5-alice",
                "label": "alice",
                "kind": "user",
                "props": {"name": "alice"},
            },
            {
                "id": "S-1-5-ws01",
                "label": "WS01",
                "kind": "computer",
                "props": {"name": "WS01"},
            },
            {
                "id": "S-1-5-da",
                "label": "Domain Admins",
                "kind": "group",
                "props": {"name": "Domain Admins"},
            },
        ],
        "edges": [
            {"source": "S-1-5-alice", "target": "S-1-5-ws01", "rel": "HasSession"},
            {"source": "S-1-5-alice", "target": "S-1-5-da", "rel": "MemberOf"},
        ],
        "node_count": 3,
        "edge_count": 2,
        "sandbox": True,
    }
