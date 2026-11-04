"""Passive auto-scan: build a network and service map as soon as h4k starts.

The operator should not have to click anything to see what is on their
network. As soon as the API comes up, this module:

  1. detects the local subnet from the default route,
  2. creates (or reuses) a default engagement scoped to it,
  3. runs a recon-only scan (no credential testing, no exploitation) on a
     background thread,
  4. folds the result into the engagement graph,
  5. re-scans on a cadence so the map stays current.

Everything here is **passive reconnaissance**: ARP discovery, port scanning,
banner fingerprinting and CVE correlation. It never tests credentials and
never exploits anything. Aggressive actions remain opt-in and require the
operator to arm a scope explicitly.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import subprocess  # nosec B404 - reads the routing table
import threading
import time
from typing import Any

logger = logging.getLogger("h4k.auto_scan")

ENV_ENABLED = "H4K_AUTO_SCAN"
ENV_CIDR = "H4K_AUTO_SCAN_CIDR"
ENV_INTERVAL = "H4K_AUTO_SCAN_INTERVAL"
ENV_DEPTH = "H4K_AUTO_SCAN_DEPTH"

_state: dict[str, Any] = {
    "running": False,
    "thread": None,
    "cidr": None,
    "engagement_id": None,
    "last_run": None,
    "last_status": "idle",
    "hosts_found": 0,
    "services_found": 0,
    "vulns_found": 0,
    "runs": 0,
    "error": None,
}
_lock = threading.Lock()


def enabled() -> bool:
    return os.environ.get(ENV_ENABLED, "1").strip() in ("1", "true", "yes", "on")


def detect_local_cidr() -> str:
    """Best-effort detection of the local subnet from the default route.

    Falls back to 192.168.1.0/24 if nothing can be detected (the common
    case for a home lab).
    """
    override = os.environ.get(ENV_CIDR, "").strip()
    if override:
        return override
    try:
        proc = subprocess.run(  # nosec B603 B607 - fixed argv, no shell
            ["ip", "route", "show", "default"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        for line in (proc.stdout or "").splitlines():
            parts = line.split()
            # "default via 192.168.1.1 dev eth0 src 192.168.1.13"
            if "src" in parts:
                idx = parts.index("src")
                ip = parts[idx + 1]
                # validate it parses; assume a /24 for a home network
                net = ipaddress.ip_network(f"{ip}/24", strict=False)
                return str(net)
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("cidr detection failed: %s", exc)
    return "192.168.1.0/24"


def _ensure_engagement(cidr: str) -> str | None:
    """Reuse an existing auto-scan engagement or create one.

    Returns the engagement id, or None if the store is unavailable.
    """
    try:
        from services.engagement import EngagementStore

        store = EngagementStore()
    except Exception as exc:
        logger.warning("auto-scan: engagement store unavailable: %s", exc)
        return None
    for eng in store.list_engagements():
        if eng.get("name") == "auto-scan" and cidr in (eng.get("scope") or []):
            return eng["id"]
    try:
        eng = store.create_engagement(
            "auto-scan", [cidr], "created automatically by passive auto-scan"
        )
        return eng["id"]
    except Exception as exc:
        logger.warning("auto-scan: could not create engagement: %s", exc)
        return None


def _run_one_pass(cidr: str, engagement_id: str | None) -> dict[str, Any]:
    """Run a single passive scan pass.

    Passive-first: discover hosts from the ARP cache / ARP sweep (fast, no
    port sweep), then fingerprint just those hosts on the common ports, then
    correlate CVEs. This finishes in seconds instead of minutes, so the map
    appears almost immediately after the container starts.

    No credential testing, no exploitation -- recon only.
    """
    from services.cve_lookup import CveDb
    from services.discovery import NeighborFinder
    from services.engagement import EngagementStore
    from services.toolkit import ToolkitRunner

    msf = None
    try:
        from app_state import msf_client as _msf

        msf = _msf
    except Exception:
        msf = None

    # 1. passive discovery: ARP cache + arp-scan + MSF arp_sweep
    hosts_found: list[dict[str, Any]] = []
    try:
        finder = NeighborFinder(msf)
        neighbors = finder.discover(cidr)
        for n in neighbors:
            hosts_found.append({"ip": n.ip, "mac": n.mac, "hostname": n.hostname})
    except Exception as exc:
        logger.debug("auto-scan: discovery failed: %s", exc)

    # 2. targeted fingerprint on the common ports (fast, per-host, not a sweep)
    runner = ToolkitRunner(progress=lambda m, p: None)
    common_ports = (
        "22,80,443,445,3389,8080,8443,21,23,25,53,110,143,3306,5432,5900,6379,9200"
    )
    all_hosts: list[dict[str, Any]] = []
    for h in hosts_found:
        ip = h["ip"]
        if not ip or ":" in ip:
            continue
        argv = [
            "nmap",
            "-sS",
            "-sV",
            "-O",
            "-T4",
            "-Pn",
            "-p",
            common_ports,
            "--max-retries",
            "1",
            "--host-timeout",
            "6s",
            "-oX",
            "-",
            ip,
        ]
        result = runner.run_tool("nmap", argv, timeout=15)
        parsed: list[dict[str, Any]] = []
        try:
            from routers.scan import _parse_nmap_xml

            parsed = (
                _parse_nmap_xml(result["stdout"]) if result["status"] == "ok" else []
            )
        except Exception:
            parsed = []
        if parsed:
            entry = parsed[0]
            entry["mac"] = entry.get("mac") or h.get("mac")
            entry["hostname"] = entry.get("hostname") or h.get("hostname")
            all_hosts.append(entry)
        else:
            all_hosts.append(
                {
                    "ip": ip,
                    "mac": h.get("mac"),
                    "hostname": h.get("hostname"),
                    "services": [],
                    "os": None,
                }
            )

    # 3. CVE correlation per service
    cve_db = None
    try:
        cve_db = CveDb()
    except Exception:
        cve_db = None

    vulns: list[dict[str, Any]] = []
    if cve_db is not None:
        try:
            from routers.scan import _match_service_vulns

            for host in all_hosts:
                for svc in host.get("services", []) or []:
                    if svc.get("state") != "open":
                        continue
                    matched = _match_service_vulns(host["ip"], svc)
                    for v in matched:
                        vulns.append(
                            {
                                "host": host["ip"],
                                "name": v.get("vid") or v.get("name"),
                                "severity": v.get("severity"),
                                "detail": v.get("detail"),
                                "port": svc.get("port"),
                            }
                        )
        except Exception as exc:
            logger.debug("auto-scan: cve match failed: %s", exc)

    # 4. build a report-shaped dict
    report_hosts = []
    for host in all_hosts:
        report_hosts.append(
            {
                "address": host["ip"],
                "os": host.get("os"),
                "mac": host.get("mac"),
                "hostname": host.get("hostname"),
                "services": host.get("services", []),
            }
        )
    report = {
        "target": cidr,
        "mode": "overt",
        "hosts": report_hosts,
        "vulns": vulns,
        "notes": ["passive auto-scan (recon only)"],
        "fingerprints": [],
        "credentials": [],
        "attacks": [],
        "security": [],
        "coverage": {
            "depth": "quick",
            "ports_spec": "common",
            "max_ports": 18,
            "complete": False,
        },
    }

    # 5. fold into the engagement graph
    if engagement_id:
        try:
            store = EngagementStore()
            if store.get_engagement(engagement_id):
                store.ingest_scan(engagement_id, report)
        except Exception as exc:
            logger.debug("auto-scan: ingest failed: %s", exc)

    return {
        "hosts": len(all_hosts),
        "services": sum(len(h.get("services") or []) for h in all_hosts),
        "vulns": len(vulns),
    }


def _loop() -> None:
    cidr = detect_local_cidr()
    with _lock:
        _state["cidr"] = cidr
        _state["last_status"] = "starting"
    engagement_id = _ensure_engagement(cidr)
    with _lock:
        _state["engagement_id"] = engagement_id
        _state["last_status"] = "running"

    interval = int(os.environ.get(ENV_INTERVAL, "3600"))

    while True:
        with _lock:
            if not _state["running"]:
                break
        try:
            with _lock:
                _state["last_status"] = "scanning"
            summary = _run_one_pass(cidr, engagement_id)
            with _lock:
                _state["last_run"] = time.time()
                _state["last_status"] = "idle"
                _state["hosts_found"] = summary["hosts"]
                _state["services_found"] = summary["services"]
                _state["vulns_found"] = summary["vulns"]
                _state["runs"] += 1
                _state["error"] = None
            logger.info(
                "[auto-scan] pass complete: %d host(s), %d service(s), %d vuln(s)",
                summary["hosts"],
                summary["services"],
                summary["vulns"],
            )
        except Exception as exc:
            logger.warning("[auto-scan] pass failed: %s", exc)
            with _lock:
                _state["last_status"] = "error"
                _state["error"] = str(exc)[:200]
        # wait for the next pass
        for _ in range(interval):
            with _lock:
                if not _state["running"]:
                    break
            time.sleep(1)


def start(force: bool = False) -> None:
    """Start the background auto-scan thread (idempotent).

    `force=True` starts it even when `H4K_AUTO_SCAN=0`: an explicit operator
    request overrides the boot-time default.
    """
    with _lock:
        if _state["running"]:
            return
        if not force and not enabled():
            _state["last_status"] = "disabled"
            return
        _state["running"] = True
    thread = threading.Thread(target=_loop, name="h4k-auto-scan", daemon=True)
    thread.start()
    with _lock:
        _state["thread"] = thread
    logger.info(
        "[auto-scan] started (cidr=%s, interval=%s)",
        os.environ.get(ENV_CIDR, "auto"),
        os.environ.get(ENV_INTERVAL, "3600"),
    )


def stop() -> None:
    with _lock:
        _state["running"] = False
        _state["last_status"] = "stopped"


def status() -> dict[str, Any]:
    with _lock:
        return {
            "enabled": enabled(),
            "running": _state["running"],
            "cidr": _state["cidr"],
            "engagement_id": _state["engagement_id"],
            "last_run": _state["last_run"],
            "last_status": _state["last_status"],
            "hosts_found": _state["hosts_found"],
            "services_found": _state["services_found"],
            "vulns_found": _state["vulns_found"],
            "runs": _state["runs"],
            "error": _state["error"],
        }
