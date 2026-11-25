"""The "next move" queue: what should the operator do now?

A CTF operator does not want a list of findings; they want a ranked list of
*actions*, each with a one-line rationale. This module turns the engagement
graph, the attack-path results and the fuzzing history into that list.

Scoring is deliberately simple and explainable:

  * a crown-jewel attack path that is reachable          -> 200 * path.score
  * a CVE with a Metasploit module on a host that has
    a verified credential                                  -> 120 * cvss
  * a CVE with a Metasploit module                           -> 90  * cvss
  * a default-credential target (no creds yet)               -> 60
  * an unexplored host with open services                    -> 30
  * a fuzzing-lab target that has never been fuzzed          -> 40
  * a passive-sniffing lead (cleartext credential)           -> 80

Only the top N (default 5) are returned, so the queue stays short and
actionable.
"""

from __future__ import annotations

import logging
import os
from typing import Any

logger = logging.getLogger("h4k.next_move")

MAX_MOVES = 8

# Services that actually accept a username/password. HTTP is deliberately
# excluded: default creds on a web endpoint are path-specific, and treating
# every http service as a credential target is how h4k's own API (3137) ended
# up in the next-move queue.
CRED_SERVICE_HINTS = (
    "ssh",
    "ftp",
    "telnet",
    "mysql",
    "postgres",
    "mssql",
    "ms-sql",
    "redis",
    "mongo",
    "smb",
    "netbios",
    "microsoft-ds",
    "rdp",
    "ms-wbt",
    "winrm",
    "vnc",
    "ldap",
    "smtp",
    "pop3",
    "imap",
)

# Control-plane ports belong to h4k itself, never to a credential target.
CONTROL_PORTS = {int(os.environ.get("API_PORT", "3137")), 3137}


def _candidate_actions(
    store: Any, engagement_id: str, fuzzed_targets: set[str] | None = None
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []

    # attack paths to crown jewels
    try:
        from services.attack_paths import compute_attack_paths

        paths = compute_attack_paths(store, engagement_id)
        for path in paths.get("paths", [])[:3]:
            candidates.append(
                {
                    "kind": "attack_path",
                    "priority": 200 * (path.get("score") or 0) / 100.0,
                    "host": path.get("entry"),
                    "title": (
                        f"Pivot to {path.get('crown_jewel_label') or path.get('crown_jewel_host')} "
                        f"via {path.get('entry')} ({path.get('hops')} hop(s))"
                    ),
                    "rationale": (
                        f"verified credential chain reaches the objective; "
                        f"techniques: {', '.join(path.get('techniques') or []) or 'n/a'}"
                    ),
                    "action": "attack",
                    "module": None,
                }
            )
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("next_move: attack paths failed: %s", exc)

    # CVEs with modules
    try:
        for vuln in store.vulns(engagement_id):
            module = vuln.get("module")
            if not module:
                continue
            host = vuln.get("host")
            sev = str(vuln.get("severity") or "").lower()
            cvss = {"critical": 9.8, "high": 8.0, "medium": 5.0, "low": 2.0}.get(
                sev, 5.0
            )
            has_cred = False
            try:
                for c in store.credentials(engagement_id):
                    if c.get("verified") and any(
                        h.get("host") == host for h in (c.get("hosts") or [])
                    ):
                        has_cred = True
            except Exception:
                pass
            priority = 120 * cvss if has_cred else 90 * cvss
            candidates.append(
                {
                    "kind": "exploit",
                    "priority": priority,
                    "host": host,
                    "title": f"Exploit {vuln.get('name') or 'a known CVE'} on {host}",
                    "rationale": (
                        f"module {module} is available"
                        + (" and a verified credential exists" if has_cred else "")
                    ),
                    "action": "attack",
                    "module": module,
                    "port": vuln.get("port"),
                }
            )
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("next_move: vuln scan failed: %s", exc)

    # default-cred targets
    try:
        services = store.services(engagement_id)
        seen_hosts: set[str] = set()
        for svc in services:
            if str(svc.get("state") or "open").lower() != "open":
                continue
            name = (svc.get("service") or "").lower()
            if not any(k in name for k in CRED_SERVICE_HINTS):
                continue
            try:
                port = int(svc.get("port") or 0)
            except (TypeError, ValueError):
                port = 0
            if port in CONTROL_PORTS:
                continue
            host = svc.get("host")
            if not host or host in {"127.0.0.1", "::1", "localhost"}:
                continue
            if host in seen_hosts:
                continue
            has_cred = any(
                c.get("verified")
                and any(h.get("host") == host for h in (c.get("hosts") or []))
                for c in store.credentials(engagement_id)
            )
            if has_cred:
                continue
            seen_hosts.add(host)
            candidates.append(
                {
                    "kind": "default_creds",
                    "priority": 60.0,
                    "host": host,
                    "title": f"Try default credentials on {host}:{svc.get('port')}",
                    "rationale": "no verified credential for this host yet",
                    "action": "creds",
                    "service": name,
                    "port": svc.get("port"),
                }
            )
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("next_move: cred scan failed: %s", exc)

    # unexplored hosts with open services
    try:
        for asset in store.assets(engagement_id):
            host = asset.get("host")
            open_services = [
                svc
                for svc in asset.get("services") or []
                if str(svc.get("state") or "open").lower() == "open"
            ]
            if not open_services:
                continue
            has_vuln = any(v.get("host") == host for v in store.vulns(engagement_id))
            has_cred = any(
                c.get("verified")
                and any(h.get("host") == host for h in (c.get("hosts") or []))
                for c in store.credentials(engagement_id)
            )
            if has_vuln or has_cred:
                continue
            candidates.append(
                {
                    "kind": "recon",
                    "priority": 30.0,
                    "host": host,
                    "title": f"Deep-scan {host} ({len(open_services)} services)",
                    "rationale": "host is up but has no findings and no credentials yet",
                    "action": "scan",
                }
            )
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("next_move: asset scan failed: %s", exc)

    # fuzzing-lab target: prefer a discovered service over a hardcoded host
    fuzzed = fuzzed_targets or set()
    fuzz_target = None
    fuzz_host = None
    try:
        for asset in store.assets(engagement_id):
            for svc in asset.get("services") or []:
                if not svc.get("port"):
                    continue
                if str(svc.get("state") or "open").lower() != "open":
                    continue
                try:
                    if int(svc["port"]) in CONTROL_PORTS:
                        continue
                except (TypeError, ValueError):
                    continue
                host = asset.get("host")
                if not host or host in {"127.0.0.1", "::1", "localhost"}:
                    continue
                name = (svc.get("service") or "").lower()
                if name in {
                    "http",
                    "https",
                    "rtnt-2",
                    "unknown",
                    "",
                } or "vulnlab" in str(asset.get("hostname") or ""):
                    fuzz_target = f"{host}:{svc['port']}"
                    fuzz_host = host
                    break
            if fuzz_target:
                break
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("next_move: fuzz target lookup failed: %s", exc)

    if fuzz_target and fuzz_target not in fuzzed and fuzz_host not in fuzzed:
        candidates.append(
            {
                "kind": "fuzz",
                "priority": 40.0,
                "host": fuzz_host,
                "title": f"Fuzz {fuzz_target} (crash -> triage loop)",
                "rationale": "crash -> minimize -> triage -> patch loop has not run",
                "action": "fuzz",
                "target": fuzz_target,
            }
        )

    candidates.sort(key=lambda c: -c["priority"])
    return candidates[:MAX_MOVES]


def build_next_move(
    store: Any, engagement_id: str, fuzzed_targets: set[str] | None = None
) -> dict[str, Any]:
    """Build the 'next move' queue for an engagement."""
    if not store.get_engagement(engagement_id):
        return {"engagement_id": engagement_id, "moves": [], "summary": "no engagement"}
    moves = _candidate_actions(store, engagement_id, fuzzed_targets)
    return {
        "engagement_id": engagement_id,
        "moves": moves,
        "summary": (
            f"{len(moves)} recommended action(s); " f"top: {moves[0]['title']}"
            if moves
            else "nothing to do right now"
        ),
    }
