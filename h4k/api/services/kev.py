"""KEV/EPSS enrichment (Backlog #23).

Every CVE in a report gets two questions: is it on CISA's Known
Exploited Vulnerabilities list (someone is exploiting it *right now*),
and what does EPSS say about near-term exploitation probability?
Answers come from a bundled snapshot (`h4k/data/kev.json`, stamped with
its fetch date and sources — real catalog + EPSS API output, never
hand-written scores) and can be refreshed live via `refresh()`, which
swaps the in-memory table only when the fetch succeeds.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import urllib.request
from pathlib import Path
from typing import Any

logger = logging.getLogger("h4k.kev")

BUNDLE = Path(__file__).resolve().parent.parent.parent / "data" / "kev.json"
KEV_CSV_URL = (
    "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"
)
EPSS_API_URL = "https://api.first.org/data/v1/epss"


def _load_bundle() -> dict[str, Any]:
    try:
        with open(BUNDLE, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as exc:
        logger.warning("KEV bundle not found at %s: %s", BUNDLE, exc)
        return {"catalog_date": "", "cves": {}, "source": ""}


_table: dict[str, Any] = _load_bundle()


def catalog_date() -> str:
    return str(_table.get("catalog_date") or "")


def enrich(cve_id: str) -> dict[str, Any]:
    """KEV flag + EPSS for one CVE id (case-insensitive, exact match only)."""
    key = (cve_id or "").strip().upper()
    entry = (_table.get("cves") or {}).get(key)
    if entry is None:
        return {"cve": key, "kev": False, "epss": None, "catalog_date": catalog_date()}
    epss = entry.get("epss") or {}
    return {
        "cve": key,
        "kev": bool(entry.get("kev")),
        "vendor": entry.get("vendor", ""),
        "product": entry.get("product", ""),
        "due_date": entry.get("due_date", ""),
        "ransomware_use": entry.get("ransomware_use", ""),
        "epss": {
            "score": epss.get("score"),
            "percentile": epss.get("percentile"),
            "date": epss.get("date", ""),
        },
        "catalog_date": catalog_date(),
    }


def enrich_many(cve_ids: list[str]) -> dict[str, Any]:
    """Batch enrichment; unknown CVEs report kev=false, epss=null."""
    seen: list[str] = []
    results = []
    for raw in cve_ids or []:
        key = str(raw or "").strip().upper()
        if not key or key in seen:
            continue
        seen.append(key)
        results.append(enrich(key))
    kev_count = sum(1 for r in results if r["kev"])
    return {
        "results": results,
        "count": len(results),
        "kev_count": kev_count,
        "catalog_date": catalog_date(),
    }


def refresh(timeout: int = 60) -> dict[str, Any]:
    """Re-fetch the KEV catalog + EPSS and swap the live table.

    Best-effort: any failure keeps the previous table and reports why.
    """
    global _table
    before = len(_table.get("cves", {}))
    try:
        req = urllib.request.Request(KEV_CSV_URL, headers={"User-Agent": "h4k-lab/1.0"})
        with urllib.request.urlopen(
            req, timeout=timeout
        ) as r:  # nosec B310 - fixed HTTPS catalog URL
            rows = list(csv.DictReader(io.TextIOWrapper(r, encoding="utf-8")))
        from datetime import UTC, datetime

        today = datetime.now(UTC).date().isoformat()
        cves: dict[str, Any] = {}
        for row in rows:
            cve = (row.get("cveID") or "").upper()
            if not cve.startswith("CVE-"):
                continue
            cves[cve] = {
                "kev": True,
                "vendor": row.get("vendorProject", ""),
                "product": row.get("product", ""),
                "due_date": row.get("dueDate", ""),
                "ransomware_use": row.get("knownRansomwareCampaignUse", ""),
                "notes": (row.get("shortDescription", "") or "")[:200],
            }
        ids = sorted(cves)
        for i in range(0, len(ids), 100):
            chunk = ids[i : i + 100]
            url = EPSS_API_URL + "?cve=" + ",".join(chunk)
            req = urllib.request.Request(url, headers={"User-Agent": "h4k-lab/1.0"})
            with urllib.request.urlopen(
                req, timeout=timeout
            ) as r:  # nosec B310 - fixed HTTPS EPSS URL
                payload = json.load(r)
            for row in payload.get("data", []):
                cve = str(row.get("cve", "")).upper()
                if cve in cves:
                    cves[cve]["epss"] = {
                        "score": row.get("epss"),
                        "percentile": row.get("percentile"),
                        "date": today,
                    }
        _table = {
            "catalog_date": today,
            "cves": cves,
            "source": KEV_CSV_URL + " + " + EPSS_API_URL,
        }
        return {"before": before, "after": len(cves), "catalog_date": today}
    except Exception as exc:
        logger.warning("KEV refresh failed, keeping bundled table: %s", exc)
        return {"before": before, "after": before, "error": str(exc)[:200]}
