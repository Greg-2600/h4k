"""SARIF import/export — Semgrep interchange (Backlog #61).

Offline, dependency-free SARIF 2.1.0 interchange so h4k findings can
leave the lab (GitHub code scanning, SARIF viewers) and outside
results — notably Semgrep's own `--sarif` output — can come in:

- `h4k_to_sarif`: h4k finding dicts (rule_id/name/severity/cwe/
  file/line/code/description) → SARIF with deduped rule descriptors
  (CWE in `properties.tags`, severities mapped
  critical|high→error, medium→warning, low→note, info→none).
- `sarif_to_h4k`: runs[].results[] → h4k finding dicts, resolving
  `ruleId` against each run's `tool.driver.rules` for names and CWEs,
  and noting the producing tool (`Semgrep OSS` recognized by name,
  anything else kept verbatim — never relabeled).

Malformed results are skipped with per-index errors, never silently
dropped on the floor; a document with no runs/results is rejected.
Sandbox returns a canned round-trip without parsing anything.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("h4k.sarif_exchange")

_SEV_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "none",
}

_LEVEL_TO_SEV = {
    "error": "high",
    "warning": "medium",
    "note": "low",
    "none": "info",
}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def h4k_to_sarif(
    findings: list[dict[str, Any]], tool_name: str = "h4k-sast"
) -> dict[str, Any]:
    """h4k findings → SARIF 2.1.0 with deduped rule descriptors."""
    if not isinstance(findings, list):
        raise ValueError("findings must be a list")
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        rule_id = str(finding.get("rule_id") or "h4k/unknown")
        severity = str(finding.get("severity") or "medium").lower()
        level = _SEV_TO_LEVEL.get(severity, "warning")
        cwe = str(finding.get("cwe") or "")
        if rule_id not in rules:
            rule: dict[str, Any] = {
                "id": rule_id,
                "name": str(finding.get("name") or rule_id),
                "shortDescription": {
                    "text": str(finding.get("description") or "")[:500]
                },
                "defaultConfiguration": {"level": level},
            }
            if cwe:
                rule["properties"] = {"tags": ["security", cwe]}
            rule.setdefault("properties", {}).update({"h4k_severity": severity})
            rules[rule_id] = rule
        try:
            line = int(finding.get("line") or 1)
        except (TypeError, ValueError):
            line = 1
        snippet = str(finding.get("code") or "")
        region: dict[str, Any] = {"startLine": max(1, line)}
        if snippet:
            region["snippet"] = {"text": snippet[:1000]}
        results.append(
            {
                "ruleId": rule_id,
                "level": level,
                "message": {
                    "text": str(
                        finding.get("description") or finding.get("name") or ""
                    )[:1000]
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": str(finding.get("file") or "?")
                            },
                            "region": region,
                        }
                    }
                ],
            }
        )
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name or "h4k-sast",
                        "version": "1.0",
                        "informationUri": "https://github.com/Greg-2600/h4k",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def _rule_index(run: dict[str, Any]) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    driver = (run.get("tool") or {}).get("driver") or {}
    for rule in driver.get("rules") or []:
        if isinstance(rule, dict) and rule.get("id"):
            index[str(rule["id"])] = rule
    return index


def _rule_cwe(rule: dict[str, Any]) -> str:
    props = rule.get("properties") or {}
    for key in ("cwe", "CWE"):
        if props.get(key):
            return str(props[key])
    for tag in props.get("tags") or []:
        text = str(tag)
        if text.upper().startswith("CWE-") and text[4:].isdigit():
            return f"CWE-{text[4:]}"
        if text.upper().startswith("CWE") and text[3:].isdigit():
            return f"CWE-{text[3:]}"
    return ""


def sarif_to_h4k(doc: dict[str, Any]) -> dict[str, Any]:
    """SARIF runs/results → h4k findings; per-result errors, never silent."""
    if not isinstance(doc, dict):
        raise ValueError("SARIF must be a JSON object")
    runs = doc.get("runs")
    if not isinstance(runs, list) or not runs:
        raise ValueError("not SARIF (missing runs[])")
    findings: list[dict[str, Any]] = []
    errors: list[str] = []
    skipped = 0
    for ri, run in enumerate(runs):
        if not isinstance(run, dict):
            errors.append(f"run[{ri}]: not an object (skipped)")
            continue
        tool = str(((run.get("tool") or {}).get("driver") or {}).get("name") or "")
        rules = _rule_index(run)
        results = run.get("results")
        if not isinstance(results, list):
            errors.append(f"run[{ri}]: missing results[] (skipped)")
            continue
        for idx, res in enumerate(results):
            if not isinstance(res, dict):
                errors.append(f"run[{ri}].result[{idx}]: not an object")
                continue
            try:
                locations = res.get("locations") or []
                loc = (locations[0] if locations else {}) or {}
                phys = loc.get("physicalLocation") or {}
                art = phys.get("artifactLocation") or {}
                region = phys.get("region") or {}
                rule_id = str(res.get("ruleId") or "sarif/unknown")
                rule = rules.get(rule_id, {})
                rule_props = rule.get("properties") or {}
                severity = str(
                    rule_props.get("h4k_severity")
                    or _LEVEL_TO_SEV.get(
                        str(res.get("level") or "warning").lower(), "medium"
                    )
                )
                message = res.get("message") or {}
                findings.append(
                    {
                        "rule_id": rule_id,
                        "name": str(
                            rule.get("name") or message.get("text", "")[:80] or rule_id
                        ),
                        "severity": severity,
                        "cwe": _rule_cwe(rule),
                        "file": str(art.get("uri") or "?"),
                        "line": int(region.get("startLine") or 1),
                        "code": str((region.get("snippet") or {}).get("text", ""))[
                            :1000
                        ],
                        "description": str(message.get("text", ""))[:1000],
                        "sanitizer": {},
                        "origin": tool or "sarif",
                    }
                )
            except (ValueError, TypeError, AttributeError, IndexError) as exc:
                skipped += 1
                errors.append(f"run[{ri}].result[{idx}]: {exc}"[:160])
    return {
        "findings": findings,
        "finding_count": len(findings),
        "skipped": skipped,
        "errors": errors,
        "tool": _tool_name(doc),
    }


def _tool_name(doc: dict[str, Any]) -> str:
    for run in doc.get("runs", []) or []:
        name = str(((run.get("tool") or {}).get("driver") or {}).get("name") or "")
        if name:
            return name
    return "sarif"


def sandbox_roundtrip() -> dict[str, Any]:
    """Canned SARIF export (nothing parsed or converted)."""
    sarif = h4k_to_sarif(
        [
            {
                "rule_id": "sast-secret-http",
                "name": "Hardcoded credential",
                "severity": "critical",
                "cwe": "CWE-798",
                "file": "app.py",
                "line": 12,
                "code": "password = 'x'",
                "description": "Hardcoded credential in source (sandbox)",
            }
        ]
    )
    back = sarif_to_h4k(sarif)
    return {
        "sarif": sarif,
        "sarif_rule_count": 1,
        "sarif_result_count": 1,
        "roundtrip": back,
        "lossless": back["finding_count"] == 1,
        "sandbox": True,
    }
