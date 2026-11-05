"""mDNS/SSDP persistent map (Backlog #19).

The sweeps themselves (`mdns_discover`, `ssdp_discover`) already exist;
their results died with the response. This module normalizes both shapes
into assets and records the in-scope ones in the engagement — so the
next scan, the graph and the timeline all see the TV/printer/speaker
fleet. Out-of-scope addresses are reported and never stored.
"""

from __future__ import annotations

from typing import Any


def normalize(devices: list[dict[str, Any]], source: str) -> list[dict[str, Any]]:
    """One asset row per discovered device: ip + vendor + technology."""
    out: list[dict[str, Any]] = []
    for d in devices or []:
        ip = str(d.get("ip") or "").strip()
        if not ip:
            continue
        names = [str(n) for n in (d.get("names") or []) if str(n).strip()]
        models = [str(m) for m in (d.get("models") or []) if str(m).strip()]
        tech = [f"{source}:{n}" for n in names[:4]] + [f"model:{m}" for m in models[:2]]
        if d.get("server"):
            tech.append(f"server:{d['server']}")
        if d.get("location"):
            tech.append("upnp")
        out.append(
            {
                "ip": ip,
                "vendor": models[0] if models else "",
                "technology": sorted(set(tech)),
            }
        )
    return out


def persist(
    store: Any, engagement_id: str, devices: list[dict[str, Any]], source: str
) -> dict[str, Any]:
    """Record in-scope sweep results as engagement assets."""
    if not store.get_engagement(engagement_id):
        raise ValueError("unknown engagement")
    recorded = 0
    skipped: list[str] = []
    for asset in normalize(devices, source):
        try:
            recorded += store.upsert_asset(
                engagement_id,
                asset["ip"],
                vendor=asset["vendor"] or None,
                technology=asset["technology"],
            )
        except Exception:
            skipped.append(asset["ip"])
    return {"recorded": recorded, "skipped_out_of_scope": sorted(set(skipped))}


def sandbox_devices(source: str) -> list[dict[str, Any]]:
    """Deterministic offline stand-ins (sandbox/e2e only)."""
    if source == "mdns":
        return [
            {"ip": "10.10.10.5", "names": ["web01"], "models": ["QEMU"]},
            {"ip": "10.10.10.9", "names": ["db01"], "models": ["QEMU"]},
        ]
    return [
        {
            "ip": "10.10.10.42",
            "names": [],
            "models": [],
            "server": "Linux UPnP",
            "location": "http://10.10.10.42/desc.xml",
        },
    ]
