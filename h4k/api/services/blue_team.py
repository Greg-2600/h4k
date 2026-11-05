# Blue-team handoff: turn an engagement's ATT&CK-mapped findings into
# defender artifacts — an ATT&CK Navigator layer, Sigma detection skeletons,
# and a written defender summary.
#
# Everything here is derived from what h4k actually observed (hosts, services,
# verified findings) plus the curated technique catalog. Sigma rules are
# explicitly marked experimental/tune-me: they encode the right telemetry to
# look at, not finished detections.
from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import yaml

TECHNIQUE_RE = r"^T\d{4}(\.\d{3})?$"

# technique -> Sigma logsource hint + generic detection sketch. Deliberately
# generic: the operator tunes field names to their SIEM. Each rule carries
# the observed evidence so tuning starts from something real.
SIGMA_SKETCHES: dict[str, dict[str, Any]] = {
    "T1046": {
        "logsource": {"category": "firewall", "product": "all"},
        "detection": {
            "selection": {"dst_port|gt": 0, "connection_count|gt": 100},
            "condition": "selection",
        },
    },
    "T1018": {
        "logsource": {"category": "network_connection"},
        "detection": {
            "selection": {"DestinationIp|endswith": ["/24"], "Initiated": "true"},
            "condition": "selection",
        },
    },
    "T1016": {
        "logsource": {"category": "process_creation", "product": "all"},
        "detection": {
            "selection": {
                "Image|endswith": [
                    "/ip",
                    "/ifconfig",
                    "/route",
                    "/netstat",
                    "\\netstat.exe",
                    "\\ipconfig.exe",
                ]
            },
            "condition": "selection",
        },
    },
    "T1110": {
        "logsource": {"category": "authentication", "product": "all"},
        "detection": {
            "selection": {
                "EventID": [4625, 4771],
                "FailureReason|contains": "bad password",
            },
            "filter": {"EventID": 4624},
            "condition": "selection and not filter",
        },
    },
    "T1078": {
        "logsource": {"category": "authentication", "product": "all"},
        "detection": {
            "selection": {"LogonType": [3, 10], "NewLogonAccount": "*"},
            "condition": "selection",
        },
    },
    "T1021": {
        "logsource": {"category": "authentication", "product": "all"},
        "detection": {
            "selection": {
                "LogonType": [3, 10],
                "Service": ["ssh", "smb", "rdp", "winrm"],
            },
            "condition": "selection",
        },
    },
    "T1190": {
        "logsource": {"category": "webserver"},
        "detection": {
            "selection": {"cs-method": ["GET", "POST"], "sc-status": [500, 404]},
            "condition": "selection",
        },
    },
    "T1611": {
        "logsource": {"category": "container", "product": "falco"},
        "detection": {
            "selection": {
                "falco_rule": [
                    "Container Escape",
                    "Sensitive mount",
                    "Privileged container",
                ]
            },
            "condition": "selection",
        },
    },
    "T1499": {
        "logsource": {"category": "application"},
        "detection": {
            "selection": {
                "level": ["fatal", "critical"],
                "msg|contains": ["segfault", "SIGSEGV", "abort"],
            },
            "condition": "selection",
        },
    },
    "T1059": {
        "logsource": {"category": "process_creation", "product": "all"},
        "detection": {
            "selection": {
                "ParentImage|endswith": ["w3wp.exe", "httpd", "nginx", "apache2"],
                "Image|endswith": ["/sh", "/bash", "cmd.exe", "powershell.exe"],
            },
            "condition": "selection",
        },
    },
    "T1005": {
        "logsource": {"category": "file_access", "product": "all"},
        "detection": {
            "selection": {
                "TargetFilename|contains": ["passwd", "shadow", "ntds.dit", ".ssh/id_"]
            },
            "condition": "selection",
        },
    },
}

_SEV_LEVEL = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "informational",
}


def _stable_uuid(namespace: str, name: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"h4k:{namespace}:{name}"))


def _max_level(items: list[dict[str, Any]]) -> str:
    order = ["informational", "low", "medium", "high", "critical"]
    best = "low"
    for it in items:
        lvl = _SEV_LEVEL.get(str(it.get("severity") or "low").lower(), "low")
        if order.index(lvl) > order.index(best):
            best = lvl
    return best


def build_navigator_layer(
    enriched: dict[str, Any], engagement_name: str
) -> dict[str, Any]:
    """ATT&CK Navigator layer (v4.5) for an enriched engagement."""
    techniques = enriched.get("techniques", []) or []
    max_count = max([t.get("count", 0) for t in techniques] + [1])
    stamped = datetime.now(UTC).isoformat(timespec="seconds")
    entries = []
    for t in sorted(techniques, key=lambda x: x.get("id", "")):
        tid = t.get("id", "")
        count = int(t.get("count", 0) or 0)
        entries.append(
            {
                "techniqueID": tid,
                "tactic": t.get("tactic", ""),
                "score": count,
                "color": "",
                "comment": f"{t.get('name', tid)} — {count} finding(s) in {engagement_name}",
                "enabled": True,
                "metadata": [
                    {"name": "finding count", "value": str(count)},
                    {"name": "source", "value": f"h4k engagement {engagement_name}"},
                ],
                "showSubtechniques": False,
            }
        )
    return {
        "name": f"h4k {engagement_name} — {stamped}",
        "versions": {"attack": "v17", "navigator": "v5.0", "layer": "v4.5"},
        "domain": "enterprise-attack",
        "description": (
            f"Techniques observed by h4k against {engagement_name} "
            f"({stamped}). Curated subset: only techniques h4k actually exercises. "
            "Score = number of mapped findings."
        ),
        "filters": {
            "platforms": ["Linux", "macOS", "Windows", "Network", "Containers"]
        },
        "sorting": 0,
        "viewMode": 0,
        "hideDisabled": False,
        "techniques": entries,
        "gradient": {
            "colors": ["#ffffff", "#ffe766", "#ff6666"],
            "minValue": 0,
            "maxValue": max_count,
        },
        "legendItems": [
            {"label": "observed (score = finding count)", "color": "#ff6666"},
            {"label": "not observed", "color": "#ffffff"},
        ],
    }


def build_sigma_bundle(
    enriched: dict[str, Any],
    engagement_name: str,
    items: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """One experimental Sigma rule per observed technique, grounded in evidence.

    Each rule says what was actually seen (finding_refs) and is marked
    tuning-required: field names fit the common Sigma taxonomies but must be
    adapted to the operator's SIEM.
    """
    items = items if items is not None else enriched.get("items", [])
    by_tech: dict[str, list[dict[str, Any]]] = {}
    for it in items or []:
        for tid in it.get("techniques", []) or []:
            by_tech.setdefault(tid, []).append(it)
    rules = []
    for tid in sorted(by_tech):
        from services import attck as attck_mod

        meta = attck_mod.detection_for(tid)
        sketch = SIGMA_SKETCHES.get(
            tid,
            {
                "logsource": {"category": "all"},
                "detection": {"selection": {}, "condition": "selection"},
            },
        )
        evidence = sorted(
            {f"{e.get('host', '?')}: {e.get('item', '?')}" for e in by_tech[tid]}
        )
        rule = {
            "title": f"[h4k] Possible {meta.get('name', tid)}",
            "id": _stable_uuid(engagement_name, tid),
            "status": "experimental",
            "description": (
                f"Experimental detection for {tid} {meta.get('name', '')} ({meta.get('tactic', '')}). "
                f"Generated by h4k from engagement {engagement_name}; observed {len(by_tech[tid])} related finding(s). "
                "TUNE BEFORE USE: adapt field names to your SIEM and set thresholds from baseline traffic."
            ),
            "author": "h4k",
            "date": datetime.now(UTC).date().isoformat(),
            "logsource": sketch["logsource"],
            "detection": sketch["detection"],
            "level": _max_level(by_tech[tid]),
            "tags": [f"attack.{tid.lower().replace('.', '_')}"],
            "references": [
                f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"
            ],
            "finding_refs": evidence[:10],
            "tuned": False,
        }
        det = meta.get("detection") or {}
        if det.get("log_sources"):
            rule["telemetry"] = det["log_sources"]
        rules.append(rule)
    return rules


def rules_to_yaml(rules: list[dict[str, Any]]) -> str:
    """Render the bundle as multi-doc Sigma YAML (one doc per rule)."""
    docs = []
    for r in rules:
        doc = {k: v for k, v in r.items() if k not in ("finding_refs", "tuned")}
        doc["description"] = (
            f"{r.get('description', '')} Evidence in this engagement: "
            + "; ".join(r.get("finding_refs", [])[:5])
        ) + f" [tuned={r.get('tuned', False)}]"
        docs.append(yaml.safe_dump(doc, sort_keys=False, allow_unicode=True).strip())
    return "\n---\n".join(docs) + ("\n" if docs else "")


def defender_summary(enriched: dict[str, Any], engagement_name: str) -> str:
    """Written defender handoff: what was seen, where to look, what it means."""
    from services import attck as attck_mod

    lines = [
        f"# Blue-team handoff — {engagement_name}",
        "",
        f"*generated {datetime.now(UTC).isoformat(timespec='seconds')} by h4k*",
        "",
        "What follows is detection *guidance* derived from findings h4k actually "
        "recorded in this engagement — not finished detections. Tune every rule "
        "to local telemetry before relying on it.",
        "",
    ]
    tactics: dict[str, list[dict[str, Any]]] = {}
    for t in enriched.get("techniques", []) or []:
        tactics.setdefault(t.get("tactic", "Unknown"), []).append(t)
    if not tactics:
        lines.append("No techniques observed — nothing to hand off.")
        return "\n".join(lines)
    for tactic in sorted(tactics):
        lines.append(f"## {tactic}")
        lines.append("")
        for t in sorted(tactics[tactic], key=lambda x: x.get("id", "")):
            det = attck_mod.detection_for(t.get("id", ""))
            dd = det.get("detection", {}) or {}
            lines.append(
                f"### {t['id']} — {t.get('name', '')} ({t.get('count', 0)} finding(s))"
            )
            if det.get("description"):
                lines.append(f"{det['description']}")
            if dd.get("log_sources"):
                lines.append(f"- look at: {', '.join(dd['log_sources'])}")
            if dd.get("event_ids"):
                lines.append(f"- event IDs: {', '.join(dd['event_ids'])}")
            if dd.get("notes"):
                lines.append(f"- note: {dd['notes']}")
            lines.append("")
    return "\n".join(lines)
