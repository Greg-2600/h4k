"""MITRE ATT&CK technique mapping + defender detection guidance.

h4k speaks the attacker's language (modules, CVEs, ports). A client's
defender speaks ATT&CK techniques and telemetry. This module bridges the two:
every action h4k can take and every finding it can produce is mapped to one or
more ATT&CK technique IDs, and each technique carries the log sources and event
IDs a defender would use to spot it.

It is deliberately a curated, honest subset — only techniques h4k's own
capabilities actually exercise are included, rather than a full matrix dump.
"""

from __future__ import annotations

from typing import Any

# technique id -> metadata
TECHNIQUES: dict[str, dict[str, Any]] = {
    "T1016": {
        "id": "T1016",
        "name": "System Network Configuration Discovery",
        "tactic": "Discovery",
        "description": "Adversaries discover network configuration (interfaces, routes, DNS) to understand the environment.",
        "detection": {
            "log_sources": ["process creation", "command line auditing"],
            "event_ids": ["Sysmon 1", "Windows 4688", "auditd execve"],
            "notes": "Look for ip/ifconfig/route/netstat invocations from unusual parents.",
        },
    },
    "T1018": {
        "id": "T1018",
        "name": "Remote System Discovery",
        "tactic": "Discovery",
        "description": "Adversaries enumerate remote systems on the network.",
        "detection": {
            "log_sources": ["network flow", "IDS/IPS", "ARP traffic"],
            "event_ids": ["NetFlow", "Suricata alerts"],
            "notes": "Bursts of ARP/ICMP sweeps and short-lived connections to many hosts.",
        },
    },
    "T1046": {
        "id": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "description": "Adversaries scan for open ports and services.",
        "detection": {
            "log_sources": ["firewall", "IDS/IPS", "host firewall"],
            "event_ids": ["Suricata scan signatures", "Windows 5156"],
            "notes": "Sequential port probes, SYN half-open scans, service banners requested.",
        },
    },
    "T1110": {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversaries try many passwords until one works.",
        "detection": {
            "log_sources": ["authentication logs", "SSH/auth.log", "Windows 4625"],
            "event_ids": ["Linux auth.log failed password", "Windows 4625", "4771"],
            "notes": "Many failed logins from one source, then a success; lockout thresholds.",
        },
    },
    "T1078": {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Defense Evasion / Lateral Movement",
        "description": "Adversaries use compromised valid credentials.",
        "detection": {
            "log_sources": ["authentication logs", "IAM audit"],
            "event_ids": ["Windows 4624 (type 3/10)", "CloudTrail ConsoleLogin"],
            "notes": "New source IPs, unusual hours, credential reuse across hosts.",
        },
    },
    "T1021": {
        "id": "T1021",
        "name": "Remote Services",
        "tactic": "Lateral Movement",
        "description": "Adversaries use remote services (SSH, SMB, RDP) to move laterally.",
        "detection": {
            "log_sources": ["SSH logs", "SMB audit", "RDP logs"],
            "event_ids": ["Windows 4624 type 3/10", "sshd accepted"],
            "notes": "Lateral login chains, new admin sessions, pass-the-hash indicators.",
        },
    },
    "T1190": {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Adversaries exploit vulnerabilities in internet-facing applications.",
        "detection": {
            "log_sources": ["WAF", "web server access logs", "IDS/IPS"],
            "event_ids": ["HTTP 500/404 spikes", "Suricata CVE signatures"],
            "notes": "Unusual request payloads, exploit signatures, process spawns from web servers.",
        },
    },
    "T1611": {
        "id": "T1611",
        "name": "Escape to Host",
        "tactic": "Privilege Escalation",
        "description": "Adversaries escape container isolation to the host.",
        "detection": {
            "log_sources": ["container runtime audit", "kernel audit", "Falco"],
            "event_ids": ["Falco container_escape", "auditd container breakout"],
            "notes": "Sensitive mount access, capability use, cgroup release_agent writes.",
        },
    },
    "T1499": {
        "id": "T1499",
        "name": "Endpoint Denial of Service",
        "tactic": "Impact",
        "description": "Adversaries crash or exhaust a service.",
        "detection": {
            "log_sources": ["application logs", "crash dumps", "APM"],
            "event_ids": ["segfault/core dump", "service restart"],
            "notes": "Repeated crashes, ASan reports, anomalous input sizes.",
        },
    },
    "T1059": {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Adversaries execute commands via shells or scripts.",
        "detection": {
            "log_sources": ["process creation", "shell history"],
            "event_ids": ["Sysmon 1", "Windows 4688"],
            "notes": "Shells spawned by web servers or unusual parents.",
        },
    },
    "T1005": {
        "id": "T1005",
        "name": "Data from Local System",
        "tactic": "Collection",
        "description": "Adversaries collect data from the local system.",
        "detection": {
            "log_sources": ["file access audit", "DLP"],
            "event_ids": ["Windows 4663", "auditd open"],
            "notes": "Bulk reads of sensitive files, DB dumps, credential stores.",
        },
    },
}

# action name -> technique ids
ACTION_MAP: dict[str, list[str]] = {
    "discover": ["T1018", "T1016"],
    "neighbor_discovery": ["T1018"],
    "port_scan": ["T1046"],
    "fingerprint": ["T1046"],
    "vuln_scan": ["T1190"],
    "default_creds": ["T1110", "T1078"],
    "hydra": ["T1110"],
    "exploit": ["T1190", "T1059"],
    "lateral": ["T1021"],
    "propagate": ["T1078", "T1021"],
    "container_escape": ["T1611"],
    "fuzz": ["T1499"],
    "db_interrogate": ["T1005"],
    "sast": [],
    "sca": [],
}

# finding keyword -> technique ids
FINDING_KEYWORDS: list[tuple[str, list[str]]] = [
    ("ssh", ["T1021"]),
    ("smb", ["T1021"]),
    ("rdp", ["T1021"]),
    ("ftp", ["T1190"]),
    ("http", ["T1190"]),
    ("sql", ["T1190"]),
    ("container", ["T1611"]),
    ("escape", ["T1611"]),
    ("brute", ["T1110"]),
    ("credential", ["T1078"]),
    ("password", ["T1110"]),
]


def techniques_for_action(action: str) -> list[str]:
    return list(ACTION_MAP.get(str(action).lower().strip(), []))


def techniques_for_finding(finding: dict[str, Any]) -> list[str]:
    out: set[str] = set()
    text = " ".join(
        str(finding.get(k, ""))
        for k in ("name", "title", "detail", "service", "module", "cwe")
    ).lower()
    for kw, techs in FINDING_KEYWORDS:
        if kw in text:
            out.update(techs)
    # vuln findings with an msf module are exploitable
    if finding.get("module") or "msf:" in text:
        out.add("T1190")
    return sorted(out)


def detection_for(technique_id: str) -> dict[str, Any]:
    t = TECHNIQUES.get(technique_id)
    if not t:
        return {
            "id": technique_id,
            "name": "Unknown",
            "tactic": "Unknown",
            "detection": {},
        }
    return t


def enrich_engagement(store: Any, engagement_id: str) -> dict[str, Any]:
    """Map an engagement's findings/actions to ATT&CK techniques + detection."""
    vulns = store.vulns(engagement_id)
    items: list[dict[str, Any]] = []
    for v in vulns:
        techs = techniques_for_finding(v)
        items.append(
            {
                "host": v.get("host"),
                "item": v.get("name"),
                "severity": v.get("severity"),
                "techniques": techs,
                "detection": [detection_for(t) for t in techs],
            }
        )
    # credential access -> valid accounts
    for c in store.credentials(engagement_id):
        if not c.get("verified"):
            continue
        items.append(
            {
                "host": (c.get("hosts") or [{}])[0].get("host"),
                "item": f"verified credential {c.get('user')}@{c.get('service')}",
                "severity": "high",
                "techniques": ["T1078", "T1110"],
                "detection": [detection_for(t) for t in ("T1078", "T1110")],
            }
        )
    # aggregate technique counts
    counts: dict[str, int] = {}
    for it in items:
        for t in it["techniques"]:
            counts[t] = counts.get(t, 0) + 1
    techniques = []
    for tid, n in sorted(counts.items()):
        t = detection_for(tid)
        techniques.append(
            {"id": tid, "name": t["name"], "tactic": t["tactic"], "count": n}
        )
    return {
        "engagement_id": engagement_id,
        "items": items,
        "techniques": techniques,
        "technique_catalog": list(TECHNIQUES.values()),
    }
