# Lab Watch: continuous change detection for an engagement's estate.
#
# Every auto-scan pass (and any explicit baseline) records a canonical
# snapshot of the in-scope estate; each snapshot is diffed against the
# previous one. Anything that moved — new/vanished hosts, opened/closed
# services, changed banners, new/cleared CVE matches — is stored as a change
# event the UI, the report, and qualify can read.
#
# Pure normalize/diff helpers live here (unit-tested, no DB). Persistence
# lives on EngagementStore so snapshots inherit scope enforcement and the
# H4K_DATA_DIR runtime path.
from __future__ import annotations

from contextlib import suppress
from typing import Any


def _svc_key(svc: dict[str, Any]) -> tuple:
    port = svc.get("port")
    if port is not None:
        with suppress(TypeError, ValueError):
            port = int(port)
    return (port, str(svc.get("proto") or "tcp"))


def _norm_svc(svc: dict[str, Any]) -> dict[str, Any]:
    return {
        "service": svc.get("service"),
        "product": svc.get("product") or svc.get("info"),
        "version": svc.get("version"),
        "state": svc.get("state"),
    }


def canonicalize(report: dict[str, Any]) -> dict[str, Any]:
    """Reduce a scan report to the comparable estate shape.

    {hosts: {addr: {os, mac, hostname, services: {(port, proto): {...}}}},
     vulns: {(host, name, port): {severity}}}
    """
    hosts: dict[str, Any] = {}
    for host in report.get("hosts") or []:
        addr = host.get("address")
        if not addr:
            continue
        services: dict[tuple, dict[str, Any]] = {}
        for svc in host.get("services") or []:
            if svc.get("port") is None:
                continue
            services[_svc_key(svc)] = _norm_svc(svc)
        hosts[str(addr)] = {
            "os": host.get("os") or host.get("os_name"),
            "mac": host.get("mac"),
            "hostname": host.get("hostname") or host.get("name"),
            "services": services,
        }
    vulns: dict[tuple, dict[str, Any]] = {}
    for vuln in report.get("vulns") or []:
        host = vuln.get("host")
        name = vuln.get("name") or vuln.get("id")
        if not host or not name:
            continue
        port = vuln.get("port")
        with suppress(TypeError, ValueError):
            port = int(port) if port is not None else None
        vulns[(str(host), str(name), port)] = {"severity": vuln.get("severity")}
    return {"hosts": hosts, "vulns": vulns}


def _jsonable_snapshot(snap: dict[str, Any]) -> dict[str, Any]:
    """Tuple keys don't survive JSON — stringify for storage."""
    hosts = {}
    for addr, host in snap.get("hosts", {}).items():
        hosts[addr] = {
            **{k: v for k, v in host.items() if k != "services"},
            "services": {
                f"{port}": {**(svc or {}), "port": port, "proto": proto}
                for (port, proto), svc in (host.get("services") or {}).items()
            },
        }
    return {
        "hosts": hosts,
        "vulns": {
            f"{h}\x00{n}\x00{p}": v for (h, n, p), v in snap.get("vulns", {}).items()
        },
    }


def _restore_snapshot(data: dict[str, Any]) -> dict[str, Any]:
    hosts = {}
    for addr, host in (data.get("hosts") or {}).items():
        services = {}
        for key, svc in (host.get("services") or {}).items():
            svc = dict(svc or {})
            port = svc.pop("port", key)
            proto = svc.pop("proto", "tcp")
            with suppress(TypeError, ValueError):
                port = int(port)
            services[(port, str(proto))] = svc
        hosts[addr] = {**host, "services": services}
    vulns = {}
    for key, v in (data.get("vulns") or {}).items():
        h, _, rest = key.partition("\x00")
        n, _, p = rest.partition("\x00")
        p_int: Any = p
        with suppress(ValueError):
            p_int = int(p) if p not in ("", "None") else None
        vulns[(h, n, p_int)] = v
    return {"hosts": hosts, "vulns": vulns}


def diff_snapshots(old: dict[str, Any] | None, new: dict[str, Any]) -> dict[str, Any]:
    """Diff two canonical snapshots into a change event (JSON-safe)."""
    old_hosts = (old or {}).get("hosts", {})
    new_hosts = new.get("hosts", {})
    old_vulns = (old or {}).get("vulns", {})
    new_vulns = new.get("vulns", {})

    appeared = sorted(set(new_hosts) - set(old_hosts))
    vanished = sorted(set(old_hosts) - set(new_hosts))

    new_services, closed_services, changed = [], [], []
    for addr in sorted(set(old_hosts) & set(new_hosts)):
        old_svcs = old_hosts[addr].get("services", {})
        new_svcs = new_hosts[addr].get("services", {})
        for key in sorted(new_svcs, key=str):
            if key not in old_svcs:
                port, proto = key
                new_services.append(
                    {"host": addr, "port": port, "proto": proto, **new_svcs[key]}
                )
        for key in sorted(old_svcs, key=str):
            if key not in new_svcs:
                port, proto = key
                closed_services.append(
                    {"host": addr, "port": port, "proto": proto, **old_svcs[key]}
                )
        for key in sorted(set(old_svcs) & set(new_svcs), key=str):
            if old_svcs[key] != new_svcs[key]:
                port, proto = key
                changed.append(
                    {
                        "host": addr,
                        "port": port,
                        "proto": proto,
                        "before": old_svcs[key],
                        "after": new_svcs[key],
                    }
                )

    def _vkey(h: str, n: str, p: Any) -> dict[str, Any]:
        return {"host": h, "name": n, "port": p}

    added_vulns = [
        {**_vkey(h, n, p), **(new_vulns[(h, n, p)] or {})}
        for (h, n, p) in sorted(new_vulns, key=str)
        if (h, n, p) not in old_vulns
    ]
    cleared_list = [
        {**_vkey(h, n, p), **(old_vulns[(h, n, p)] or {})}
        for (h, n, p) in sorted(old_vulns, key=str)
        if (h, n, p) not in new_vulns
    ]

    notable = bool(appeared or new_services or added_vulns)
    total = (
        len(appeared)
        + len(vanished)
        + len(new_services)
        + len(closed_services)
        + len(changed)
        + len(added_vulns)
        + len(cleared_list)
    )
    first = not bool(old)
    if first:
        return {
            "first_baseline": True,
            "appeared_hosts": [],
            "vanished_hosts": [],
            "new_services": [],
            "closed_services": [],
            "changed_services": [],
            "new_vulns": [],
            "cleared_vulns": [],
            "notable": False,
            "change_count": 0,
            "hosts": sorted(new_hosts),
        }
    return {
        "first_baseline": first,
        "appeared_hosts": appeared,
        "vanished_hosts": vanished,
        "new_services": new_services,
        "closed_services": closed_services,
        "changed_services": changed,
        "new_vulns": added_vulns,
        "cleared_vulns": cleared_list,
        "notable": notable,
        "change_count": total,
    }


def summarize(diff: dict[str, Any]) -> str:
    """One-line human summary for logs and the UI badge."""
    if diff.get("first_baseline"):
        hosts = diff.get("hosts", diff.get("appeared_hosts", []))
        return f"baseline recorded ({len(hosts)} host(s))"
    bits = []
    for key, label in (
        ("appeared_hosts", "new host(s)"),
        ("vanished_hosts", "vanished host(s)"),
        ("new_services", "new service(s)"),
        ("closed_services", "closed service(s)"),
        ("changed_services", "changed banner(s)"),
        ("new_vulns", "new finding(s)"),
        ("cleared_vulns", "cleared finding(s)"),
    ):
        n = len(diff.get(key, []))
        if n:
            bits.append(f"{n} {label}")
    return ", ".join(bits) if bits else "no changes"
