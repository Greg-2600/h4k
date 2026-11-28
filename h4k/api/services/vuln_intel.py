"""Vulnerability intel: Exploit-DB mirror search + MSF delta + tech->CVE (Backlog #73).

Three offline helpers for the intelligence half of an assessment:

* **Exploit-DB mirror search** queries a small bundled snapshot of real
  Exploit-DB entries (``h4k/data/exploitdb.json``, generated from CVE queries
  and date/source stamped) by keyword, CVE, platform or exploit type.
* **MSF module delta** compares an operator-supplied current module list with
  a baseline list to name what is new since the last update and links any new
  module that the curated CVE table already maps.
* **Technology -> CVE auto-link** takes WhatWeb/Wappalyzer-style fingerprints
  (name + optional version) and reuses the offline CVE matcher and version
  ranges, so a version outside every known range is *not* reported.

Everything is deliberately offline and honest. Nothing runs Metasploit, scans
a host or fetches Exploit-DB; the bundled snapshot is a small subset, not the
authoritative mirror. Sandbox mode returns canned data without reading input.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from schemas import Service
from services.cve_lookup import CveDb

logger = logging.getLogger("h4k.vuln_intel")

LIMITATIONS = (
    "Offline intel only: Exploit-DB results come from a small date-stamped "
    "snapshot bundled with h4k (not the live mirror), Metasploit is never "
    "run and the module delta is computed only from the lists you paste, and "
    "technology->CVE links reuse the curated CVE table plus simplified version "
    "ranges. Treat every hit as a review lead: absence of a result is not "
    "proof that no exploit or CVE exists."
)

BUNDLE = Path(__file__).resolve().parent.parent.parent / "data" / "exploitdb.json"
_WORD_RE = re.compile(r"[a-z0-9]+")
_CVE_RE = re.compile(r"^(?:CVE[-_ ]?)?(\d{4})[-_ ]?(\d{4,7})$", re.IGNORECASE)


def _load_bundle() -> dict[str, Any]:
    try:
        with open(BUNDLE, encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict) or not isinstance(data.get("entries"), list):
            raise ValueError("bad exploitdb bundle shape")
        return data
    except Exception as exc:  # pragma: no cover - only on a broken install
        logger.warning("Exploit-DB snapshot not found at %s: %s", BUNDLE, exc)
        return {"entries": [], "generated": "", "source": "", "note": ""}


_TABLE = _load_bundle()
_CVE_DB: CveDb | None = None


def _cve_db() -> CveDb:
    global _CVE_DB
    if _CVE_DB is None:
        _CVE_DB = CveDb()
    return _CVE_DB


def catalog_info() -> dict[str, Any]:
    """Metadata for the bundled Exploit-DB snapshot."""
    return {
        "count": len(_TABLE.get("entries") or []),
        "generated": str(_TABLE.get("generated") or ""),
        "source": str(_TABLE.get("source") or ""),
        "note": str(_TABLE.get("note") or ""),
    }


def _normalize_cve(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    match = _CVE_RE.match(text)
    if match:
        return f"CVE-{match.group(1)}-{match.group(2)}"
    return text.upper()


def _platform(value: Any) -> str:
    return str(value or "").strip().lower()


def _entry_public(
    entry: dict[str, Any], score: int = 0, matched: list[str] | None = None
) -> dict[str, Any]:
    public = {
        "id": entry.get("id", ""),
        "edb_id": entry.get("edb_id", 0),
        "title": entry.get("title", ""),
        "platform": entry.get("platform", ""),
        "type": entry.get("type", ""),
        "date": entry.get("date", ""),
        "verified": bool(entry.get("verified")),
        "author": entry.get("author", ""),
        "cves": list(entry.get("cves") or []),
    }
    public["score"] = score
    public["matched_on"] = sorted(set(matched or []))
    return public


def _limit(value: Any, default: int = 10) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("limit must be an integer") from exc
    if not 1 <= number <= 50:
        raise ValueError("limit must be between 1 and 50")
    return number


def search_exploits(
    query: str = "",
    cve: str = "",
    platform: str = "",
    etype: str = "",
    limit: int = 10,
    verified_only: bool = False,
) -> dict[str, Any]:
    """Search the bundled Exploit-DB snapshot; an empty query browses it."""
    text = str(query or "").strip().lower()
    cve_key = _normalize_cve(cve)
    platform_key = _platform(platform)
    type_key = str(etype or "").strip().lower()
    limit_value = _limit(limit)
    tokens = set(_WORD_RE.findall(text))

    scored: list[tuple[int, dict[str, Any]]] = []
    for entry in _TABLE.get("entries") or []:
        cves = [str(item).upper() for item in entry.get("cves") or []]
        if cve_key and cve_key not in cves:
            continue
        if platform_key and platform_key != _platform(entry.get("platform")):
            continue
        if type_key and type_key != str(entry.get("type") or "").lower():
            continue
        if verified_only and not entry.get("verified"):
            continue

        score = 0
        matched: list[str] = []
        title = str(entry.get("title") or "").lower()
        edb_id = str(entry.get("id") or "").lower()
        if cve_key and cve_key in cves:
            score += 100
            matched.append("cve")
        if text:
            if text == edb_id or text == str(entry.get("edb_id") or ""):
                score += 120
                matched.append("id")
            if text in title:
                score += 40
                matched.append("title")
            for token in tokens:
                if token in title:
                    score += 8
                    matched.append("title-token")
                elif token in _platform(entry.get("platform")):
                    score += 3
                    matched.append("platform-token")
                elif token in str(entry.get("type") or "").lower():
                    score += 2
                    matched.append("type-token")
            if not score:
                continue
        scored.append((score, _entry_public(entry, score, matched)))

    scored.sort(key=lambda item: (-item[0], int(item[1]["edb_id"] or 0)))
    total = len(scored)
    return {
        "query": str(query or ""),
        "cve": cve_key,
        "platform": str(platform or ""),
        "type": str(etype or ""),
        "verified_only": bool(verified_only),
        "total": total,
        "count": min(total, limit_value),
        "entries": [entry for _, entry in scored[:limit_value]],
    }


def _parse_technology(raw: Any) -> tuple[str, str]:
    if isinstance(raw, dict):
        name = (
            raw.get("name")
            or raw.get("tech")
            or raw.get("product")
            or raw.get("software")
        )
        version = raw.get("version") or raw.get("ver") or ""
        return str(name or "").strip(), str(version or "").strip()
    if not isinstance(raw, str):
        raise ValueError("technologies must be strings or objects")
    text = raw.strip()
    if not text:
        return "", ""
    parts = text.split()
    if len(parts) >= 2 and re.match(r"^v?\d", parts[1]):
        return parts[0], parts[1].lstrip("vV")
    return text, ""


def _cve_public(cve: dict[str, Any]) -> dict[str, Any]:
    public = dict(cve)
    public.setdefault("_version_verified", False)
    exploits = search_exploits(cve=str(cve.get("id") or ""), limit=5)
    public["exploits"] = [entry["id"] for entry in exploits["entries"]]
    return public


def tech_to_cve(technologies: list[Any]) -> list[dict[str, Any]]:
    """Link WhatWeb/Wappalyzer fingerprints to curated CVEs (version-aware)."""
    if not isinstance(technologies, list):
        raise ValueError("technologies must be a list")
    db = _cve_db()
    results: list[dict[str, Any]] = []
    for raw in technologies:
        name, version = _parse_technology(raw)
        if not name:
            continue
        svc = Service(port=0, service=name, info=version)
        hits = db.match_service(svc, version=version or None, product=name)
        public: list[dict[str, Any]] = []
        seen: set[str] = set()
        for cve in hits:
            cve_id = str(cve.get("id") or "").upper()
            if cve_id in seen:
                continue
            seen.add(cve_id)
            public.append(_cve_public(cve))
        results.append(
            {
                "name": name,
                "version": version,
                "cve_count": len(public),
                "exploit_count": sum(
                    len(item.get("exploits") or []) for item in public
                ),
                "cves": public,
            }
        )
    return results


def _module_name(raw: Any) -> str:
    if isinstance(raw, dict):
        raw = raw.get("name") or raw.get("module") or raw.get("fullname") or ""
    if not isinstance(raw, str):
        raise ValueError("modules must be strings or objects")
    return raw.strip()


def _module_map(items: list[Any]) -> dict[str, str]:
    if not isinstance(items, list):
        raise ValueError("modules must be a list")
    mapping: dict[str, str] = {}
    for raw in items:
        name = _module_name(raw)
        if not name:
            continue
        mapping.setdefault(name.lower(), name)
    return mapping


def msf_delta(
    modules: list[Any], baseline_modules: list[Any] | None = None
) -> dict[str, Any]:
    """Compare current Metasploit modules with a baseline list (offline)."""
    current = _module_map(modules)
    baseline = _module_map(baseline_modules or [])
    added_keys = sorted(set(current) - set(baseline))
    removed_keys = sorted(set(baseline) - set(current))
    persisted = len(set(current) & set(baseline))
    module_cves = {
        str(cve.get("msf_module") or "").lower(): str(cve.get("id") or "")
        for cve in _cve_db().cves
        if cve.get("msf_module")
    }
    added = [current[key] for key in added_keys]
    removed = [baseline[key] for key in removed_keys]
    linked = [
        {"module": current[key], "cve": module_cves[key]}
        for key in added_keys
        if key in module_cves
    ]
    return {
        "baseline_provided": baseline_modules is not None,
        "current_count": len(current),
        "baseline_count": len(baseline),
        "added_count": len(added),
        "removed_count": len(removed),
        "persisted_count": persisted,
        "added": added,
        "removed": removed,
        "added_with_cve": linked,
    }


def analyze(
    exploit_query: str = "",
    cve: str = "",
    platform: str = "",
    etype: str = "",
    verified_only: bool = False,
    exploit_limit: int = 10,
    technologies: list[Any] | None = None,
    modules: list[Any] | None = None,
    baseline_modules: list[Any] | None = None,
) -> dict[str, Any]:
    """Build whichever exploit/CVE/delta sections the request asked for."""
    technologies = technologies or []
    modules = modules or []
    if not isinstance(technologies, list):
        raise ValueError("technologies must be a list")
    if not isinstance(modules, list):
        raise ValueError("modules must be a list")
    if baseline_modules is not None and not isinstance(baseline_modules, list):
        raise ValueError("baseline_modules must be a list")

    wants_search = bool(
        str(exploit_query or "").strip()
        or str(cve or "").strip()
        or str(platform or "").strip()
        or str(etype or "").strip()
    )
    wants_delta = bool(modules or baseline_modules)
    if not (wants_search or wants_delta or technologies):
        raise ValueError("exploit query, cve, technologies or modules required")

    exploits = None
    if wants_search:
        exploits = search_exploits(
            query=exploit_query,
            cve=cve,
            platform=platform,
            etype=etype,
            limit=exploit_limit,
            verified_only=verified_only,
        )

    delta = msf_delta(modules, baseline_modules) if wants_delta else None
    linked = tech_to_cve(technologies) if technologies else []
    summary = {
        "exploit_matches": exploits["count"] if exploits else 0,
        "technologies": len(linked),
        "technology_cves": sum(item["cve_count"] for item in linked),
        "technology_exploits": sum(item["exploit_count"] for item in linked),
        "msf_added": delta["added_count"] if delta else 0,
        "msf_added_with_cve": len(delta["added_with_cve"]) if delta else 0,
    }
    return {
        "catalog": catalog_info(),
        "exploits": exploits,
        "msf_delta": delta,
        "technologies": linked,
        "summary": summary,
        "limitations": LIMITATIONS,
        "sandbox": False,
    }


def to_ledger(host: str, result: dict[str, Any]) -> list[dict[str, Any]]:
    """Map linked technology CVEs and new MSF modules to engagement rows."""
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for tech in result.get("technologies") or []:
        name = str(tech.get("name") or "").strip()
        version = str(tech.get("version") or "").strip()
        for cve in tech.get("cves") or []:
            reference = str(cve.get("id") or "").strip()
            key = (name.lower(), reference.upper())
            if not reference or key in seen:
                continue
            seen.add(key)
            rows.append(
                {
                    "host": host,
                    "name": f"{reference} {name} {version}".strip()[:220],
                    "severity": str(cve.get("severity") or "MEDIUM").upper(),
                    "module": "vuln-intel",
                    "reference": reference,
                    "cwe": "CWE-1104",
                    "detail": (
                        f"tech={name} version={version or 'unknown'} "
                        f"version_verified={bool(cve.get('_version_verified'))} "
                        f"exploits={','.join(cve.get('exploits') or [])} "
                        f"{cve.get('title', '')}"
                    ).strip()[:400],
                }
            )
    for item in (result.get("msf_delta") or {}).get("added_with_cve") or []:
        reference = str(item.get("cve") or "").strip()
        module = str(item.get("module") or "").strip()
        key = (module.lower(), reference.upper())
        if not reference or key in seen:
            continue
        seen.add(key)
        rows.append(
            {
                "host": host,
                "name": f"{reference} MSF {module}"[:220],
                "severity": "MEDIUM",
                "module": "msf-delta",
                "reference": reference,
                "cwe": "CWE-1104",
                "detail": f"new module since baseline: {module}"[:400],
            }
        )
    return rows


def sandbox_result() -> dict[str, Any]:
    """Deterministic canned intel result for sandbox mode and CI."""
    result = analyze(
        exploit_query="log4j",
        technologies=[{"name": "log4j", "version": "2.14.1"}],
        modules=["exploit/multi/http/log4shell_header_injection"],
        baseline_modules=["exploit/multi/http/apache_normalize_path_rce"],
    )
    result["sandbox"] = True
    return result
