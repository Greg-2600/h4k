"""Shodan/Censys BYO import (Backlog #21).

No API keys live in this repo, so there is no live Shodan/Censys client.
Instead the operator pastes (or uploads) JSON they already exported from
their own Shodan/Censys account, and this module normalizes the three
shapes we accept into engagement leads:

- Shodan host objects (`ip_str`, `port`, `transport`, `product`,
  `version`, `vulns: {CVE: {...}}`),
- Censys-style objects (`ip`, `services: [{port, service_name, ...}]`),
- a minimal generic row (`host`, `port`, `service`, `product`,
  `version`, `cves: [...]`).

Everything lands in the engagement scope-checked: out-of-scope hosts
are reported, never recorded. Findings become vuln leads (clearly
labeled `intel-import`), never asserted exploits.
"""

from __future__ import annotations

import json
from typing import Any


def _as_list(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, dict)]
    return []


def normalize_shodan(obj: dict[str, Any]) -> list[dict[str, Any]]:
    """One Shodan host object may carry many ports — split per service."""
    host = str(obj.get("ip_str") or obj.get("ip") or "").strip()
    if not host:
        return []
    rows = []
    ports = obj.get("ports") or ([obj.get("port")] if obj.get("port") else [])
    for port in ports:
        try:
            port_n = int(port)
        except (TypeError, ValueError):
            continue
        rows.append(
            {
                "host": host,
                "port": port_n,
                "service": str(obj.get("product") or obj.get("transport") or ""),
                "product": str(obj.get("product") or ""),
                "version": str(obj.get("version") or ""),
                "cves": sorted((obj.get("vulns") or {}).keys()),
                "source": "shodan",
            }
        )
    return rows


def normalize_censys(obj: dict[str, Any]) -> list[dict[str, Any]]:
    """Censys host object with a services list."""
    host = str(obj.get("ip") or obj.get("ip_str") or "").strip()
    if not host:
        return []
    rows = []
    for svc in _as_list(obj.get("services")):
        try:
            port_n = int(svc.get("port") or 0)
        except (TypeError, ValueError):
            continue
        if not port_n:
            continue
        rows.append(
            {
                "host": host,
                "port": port_n,
                "service": str(svc.get("service_name") or svc.get("service") or ""),
                "product": str(
                    svc.get("software", [{}])[0].get("uniform_resource_identifier", "")
                    if isinstance(svc.get("software"), list) and svc.get("software")
                    else ""
                ),
                "version": "",
                "cves": [],
                "source": "censys",
            }
        )
    return rows


def normalize_generic(obj: dict[str, Any]) -> list[dict[str, Any]] | None:
    """Minimal row shape; None when the object is not generic-shaped."""
    if "host" not in obj:
        return None
    try:
        port_n = int(obj.get("port", 0) or 0)
    except (TypeError, ValueError):
        port_n = 0
    cves = obj.get("cves") or []
    return [
        {
            "host": str(obj.get("host") or "").strip(),
            "port": port_n,
            "service": str(obj.get("service") or ""),
            "product": str(obj.get("product") or ""),
            "version": str(obj.get("version") or ""),
            "cves": [str(c) for c in cves if str(c).strip()],
            "source": "generic",
        }
    ]


def normalize(source: str, data: Any) -> list[dict[str, Any]]:
    """Normalize pasted/uploaded JSON into lead rows."""
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSON: {exc}") from exc
    if (
        isinstance(data, dict)
        and "matches" in data
        and isinstance(data["matches"], list)
    ):
        data = data["matches"]  # Shodan search envelope
    if isinstance(data, dict) and "result" in data and isinstance(data["result"], dict):
        hits = data["result"].get("hits")
        if isinstance(hits, list):
            data = hits  # Censys search envelope
    rows: list[dict[str, Any]] = []
    src = (source or "auto").strip().lower()
    for obj in _as_list(data):
        if src == "shodan":
            rows.extend(normalize_shodan(obj))
        elif src == "censys":
            rows.extend(normalize_censys(obj))
        elif src == "generic":
            gen = normalize_generic(obj)
            if gen:
                rows.extend(gen)
        else:  # auto: try each shape in turn
            gen = normalize_generic(obj) if "host" in obj else None
            if gen:
                rows.extend(gen)
            elif "services" in obj:
                rows.extend(normalize_censys(obj))
            else:
                rows.extend(normalize_shodan(obj))
    return [r for r in rows if r["host"]]


def ledger(
    store: Any, engagement_id: str, rows: list[dict[str, Any]]
) -> dict[str, Any]:
    """Record normalized rows: assets + services + CVE leads (scope-checked)."""
    if not store.get_engagement(engagement_id):
        raise ValueError("unknown engagement")
    recorded = 0
    skipped: list[str] = []
    for row in rows:
        try:
            recorded += store.upsert_asset(
                engagement_id,
                row["host"],
                technology=[row["service"]] if row["service"] else [],
            )
            if row.get("port"):
                store.upsert_service(
                    engagement_id,
                    row["host"],
                    {
                        "port": row["port"],
                        "service": row["service"] or "unknown",
                    },
                )
            for cve in row.get("cves", []):
                recorded += store.record_vuln(
                    engagement_id,
                    row["host"],
                    {
                        "name": cve,
                        "severity": "unknown",
                        "module": f"intel-import:{row['source']}",
                    },
                )
        except Exception:
            if row["host"] not in skipped:
                skipped.append(row["host"])
    return {
        "recorded": recorded,
        "skipped_out_of_scope": sorted(skipped),
        "rows": len(rows),
    }
