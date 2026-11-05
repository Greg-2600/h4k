"""Canvas-ready layout for the engagement asset graph.

Feature 1 of the 200-item backlog: an interactive attack-graph canvas
(clickable pan/zoom nodes, PNG export). The store's raw ``graph()`` is
topology only (hosts + edges, no coordinates). This module adds a
deterministic layout so the UI can render without a client-side physics
engine: same input graph always yields identical x/y, so a finding is
replayable and e2e-stable.

Layout (all integer coords on an 800x600 stage):
- host nodes on a circle (radius 220, centre 400,300)
- service targets (``host:port`` edge endpoints with no host node) placed
  on a small ring around their parent host
- credential/pivot label nodes placed on a top row (y=40, spread on x)
"""

from __future__ import annotations

import math
from typing import Any

STAGE_W = 800
STAGE_H = 600
LEGEND = [
    {"type": "host", "label": "host", "color": "#4da3ff"},
    {"type": "service", "label": "service (host:port)", "color": "#9fe870"},
    {"type": "credential", "label": "verified credential", "color": "#ffd166"},
    {"type": "pivot", "label": "pivot (verified reuse)", "color": "#ef476f"},
]


def layout_graph(graph: dict[str, Any]) -> dict[str, Any]:
    """Add deterministic x/y to every node, synthesizing missing endpoints.

    Missing edge targets (service ``host:port`` strings, credential
    labels) become explicit nodes so the canvas has something to draw
    and click. Pure function: no I/O, no network.
    """
    raw_nodes = list((graph or {}).get("nodes") or [])
    raw_edges = list((graph or {}).get("edges") or [])
    summary = (graph or {}).get("summary") or {}

    host_ids = sorted(
        {str(n.get("id")) for n in raw_nodes if n.get("id")}
        or {str(e.get("source")) for e in raw_edges if e.get("source")}
    )
    # host positions on a circle; single host goes to centre
    positioned: dict[str, dict[str, Any]] = {}
    existing = {str(n.get("id")): dict(n) for n in raw_nodes if n.get("id")}
    n_hosts = len(host_ids)
    for i, hid in enumerate(host_ids):
        if n_hosts == 1:
            x, y = STAGE_W // 2, STAGE_H // 2
        else:
            ang = 2 * math.pi * i / max(n_hosts, 1) - math.pi / 2
            x = int(STAGE_W // 2 + 220 * math.cos(ang))
            y = int(STAGE_H // 2 + 200 * math.sin(ang))
        base = existing.get(hid, {"id": hid, "label": hid, "type": "host"})
        base["x"] = x
        base["y"] = y
        base.setdefault("type", "host")
        base.setdefault("label", hid)
        positioned[hid] = base

    # service endpoints missing from nodes: ring around parent host
    orphans: dict[str, list[str]] = {}
    for e in raw_edges:
        for key in ("source", "target"):
            tid = str(e.get(key) or "")
            if tid and tid not in positioned:
                orphans.setdefault(tid, []).append(str(e.get("type") or ""))
    # credential-ish labels go on the top row instead of a ring
    top_row: list[str] = []
    ring: list[str] = []
    for tid in sorted(orphans):
        kinds = orphans[tid]
        if any(k in ("credential", "pivot") for k in kinds):
            top_row.append(tid)
        else:
            ring.append(tid)

    for j, tid in enumerate(top_row):
        x = int(80 + (STAGE_W - 160) * (j + 1) / (len(top_row) + 1))
        positioned[tid] = {
            "id": tid,
            "label": tid,
            "type": "credential" if "credential" in orphans[tid] else "pivot",
            "x": x,
            "y": 40,
        }

    # group ring orphans by parent host prefix before ':'
    by_parent: dict[str, list[str]] = {}
    for tid in ring:
        parent = tid.split(":")[0] if ":" in tid else ""
        by_parent.setdefault(parent, []).append(tid)
    for parent, tids in by_parent.items():
        anchor = positioned.get(parent, {"x": STAGE_W // 2, "y": STAGE_H // 2})
        for k, tid in enumerate(sorted(tids)):
            ang = 2 * math.pi * k / max(len(tids), 1)
            positioned[tid] = {
                "id": tid,
                "label": tid,
                "type": "service",
                "x": int(anchor["x"] + 70 * math.cos(ang)),
                "y": int(anchor["y"] + 60 * math.sin(ang)),
                "parent": parent,
            }

    nodes = [positioned[k] for k in sorted(positioned)]
    return {
        "nodes": nodes,
        "edges": raw_edges,
        "legend": LEGEND,
        "stage": {"width": STAGE_W, "height": STAGE_H},
        "summary": summary,
    }
