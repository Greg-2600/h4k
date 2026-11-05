"""SOCKS-aware scan — service fingerprinting through a pivot (Backlog #35).

`POST /api/net/tunnel/scan` proves *ports* are open through the proxy.
This module answers the next question — *what* is listening — by
matching banners and ports against a keyword table (no extra packets),
then ledgers the fingerprinted services into the engagement
(scope-enforced) so the pivot target joins the asset graph like any
directly-scanned host.
"""

from __future__ import annotations

import re
from typing import Any

# (port, banner regex, service, product, version-group or None).
# A port with an empty pattern means "port alone is enough evidence".
_HINTS: list[tuple[int | None, str, str, str, int | None]] = [
    (22, r"SSH-([\d.]+)-OpenSSH[_-]?([\d.p]+)?", "ssh", "OpenSSH", 2),
    (22, r"SSH", "ssh", "", None),
    (21, r"vsFTPd (\S+)", "ftp", "vsftpd", 1),
    (21, r"FTP|FileZilla|vsFTPd|ProFTPD", "ftp", "", None),
    (25, r"ESMTP|Postfix|Exim|Sendmail", "smtp", "", None),
    (110, r"POP3|Dovecot", "pop3", "", None),
    (143, r"IMAP|Dovecot", "imap", "", None),
    (80, r"Apache/?([\d.]+)?", "http", "Apache", 1),
    (80, r"nginx/?([\d.]+)?", "http", "nginx", 1),
    (80, r"HTTP", "http", "", None),
    (443, r"HTTP", "https", "", None),
    (3306, r"mysql|MariaDB", "mysql", "", None),
    (5432, r"PostgreSQL|FATAL", "postgresql", "", None),
    (6379, r"redis", "redis", "", None),
    (27017, r"mongod|MongoDB", "mongodb", "", None),
    (3389, r"", "ms-wbt-server", "", None),
    (445, r"", "microsoft-ds", "", None),
]

_COMMON: list[tuple[str, str, str, int | None]] = [
    (r"Apache/?([\d.]+)?", "http", "Apache", 1),
    (r"nginx/?([\d.]+)?", "http", "nginx", 1),
    (r"OpenSSH[_-]?([\d.p]+)?", "ssh", "OpenSSH", 1),
    (r"vsFTPd (\S+)", "ftp", "vsftpd", 1),
    (r"220.*FTP", "ftp", "", None),
    (r"220.*SMTP|ESMTP", "smtp", "", None),
    (r"Microsoft", "microsoft-ds", "", None),
]


def guess_service(banner: str, port: int) -> dict[str, str]:
    """Banner + port → {service, product, version} (heuristic, labeled)."""
    text = banner or ""
    for hint_port, pattern, service, product, group in _HINTS:
        if hint_port is not None and hint_port != port:
            continue
        if not pattern:
            return {"service": service, "product": product, "version": ""}
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            version = ""
            if group is not None:
                try:
                    version = (match.group(group) or "").strip()
                except IndexError:
                    version = ""
            return {"service": service, "product": product, "version": version}
    for pattern, service, product, group in _COMMON:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            version = ""
            if group is not None:
                try:
                    version = (match.group(group) or "").strip()
                except IndexError:
                    version = ""
            return {"service": service, "product": product, "version": version}
    return {"service": "", "product": "", "version": ""}


def fingerprint_scan(scan: dict[str, Any]) -> dict[str, Any]:
    """Annotate open ports in a proxied scan with service guesses."""
    results: list[dict[str, Any]] = []
    for probe in scan.get("results", []) or []:
        row = dict(probe)
        if row.get("open"):
            try:
                port = int(row.get("port", 0) or 0)
            except (TypeError, ValueError):
                port = 0
            row.update(guess_service(str(row.get("banner") or ""), port))
        else:
            row.setdefault("service", "")
        results.append(row)
    out = dict(scan)
    out["results"] = results
    out["open"] = [r for r in results if r.get("open")]
    out["open_count"] = len(out["open"])
    fingerprinted = sum(1 for r in out["open"] if r.get("service"))
    out["fingerprinted"] = fingerprinted
    return out


def ledger_scan(
    store: Any, engagement_id: str, host: str, fingerprinted: dict[str, Any]
) -> dict[str, Any]:
    """Record fingerprinted open ports as engagement assets (scope-enforced).

    The asset row is upserted once; each open port with a guessed service
    becomes a service row (`unknown` when the banner gave nothing away).
    Out-of-scope hosts are reported, never stored.
    """
    if not store.get_engagement(engagement_id):
        raise ValueError("unknown engagement")
    if not store.in_scope(engagement_id, host):
        return {"recorded": 0, "skipped_out_of_scope": [host]}
    store.upsert_asset(engagement_id, host)
    recorded = 0
    for probe in fingerprinted.get("results", []) or []:
        if not probe.get("open"):
            continue
        try:
            port = int(probe.get("port", 0) or 0)
        except (TypeError, ValueError):
            continue
        if not port:
            continue
        product = str(probe.get("product") or "").strip()
        version = str(probe.get("version") or "").strip()
        detail = f"{product} {version}".strip()
        recorded += store.upsert_service(
            engagement_id,
            host,
            {
                "port": port,
                "service": probe.get("service") or "unknown",
                "version": detail,
            },
        )
    return {"recorded": recorded, "skipped_out_of_scope": []}
