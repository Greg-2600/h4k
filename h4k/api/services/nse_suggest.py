"""NSE suggest-and-run map (Backlog #6).

`POST /api/nmap/nse` already runs scripts, but nothing told the operator
*which* scripts fit a fingerprinted service. This module is the curated
service → script map: suggest first (offline, pure), run only when the
operator explicitly fires. The run path stays `POST /api/nmap/nse`.
"""

from __future__ import annotations

from typing import Any

# service name (lowercase, as fingerprinted) -> [(script, category, reason)]
_SCRIPT_MAP: dict[str, list[tuple[str, str, str]]] = {
    "ssh": [
        ("ssh-brute", "brute", "credential guessing against OpenSSH and forks"),
        ("ssh-auth-methods", "auth", "which auth methods the server accepts"),
        ("ssh-hostkey", "default", "fingerprint the host key for reuse checks"),
    ],
    "http": [
        ("http-vuln-cve2017-5638", "vuln", "Struts RCE probe"),
        ("http-shellshock", "vuln", "Shellshock header-injection probe"),
        ("http-methods", "default", "risky methods (PUT/DELETE/TRACE)"),
        ("http-title", "default", "banner/title for CVE matching"),
    ],
    "https": [
        ("ssl-heartbleed", "vuln", "Heartbleed memory-leak probe"),
        ("ssl-poodle", "vuln", "POODLE downgrade probe"),
        ("ssl-cert", "default", "cert expiry/weak-signature inventory"),
        ("http-methods", "default", "risky methods (PUT/DELETE/TRACE)"),
    ],
    "ftp": [
        ("ftp-anon", "auth", "anonymous login check"),
        ("ftp-brute", "brute", "credential guessing"),
        ("ftp-vsftpd-backdoor", "vuln", "vsftpd 2.3.4 backdoor probe"),
    ],
    "smb": [
        ("smb-vuln-ms17-010", "vuln", "EternalBlue probe"),
        ("smb-vuln-ms08-067", "vuln", "legacy SMB RCE probe"),
        ("smb-enum-shares", "default", "share/ACL enumeration"),
        ("smb-brute", "brute", "credential guessing"),
    ],
    "microsoft-ds": [
        ("smb-vuln-ms17-010", "vuln", "EternalBlue probe"),
        ("smb-enum-shares", "default", "share/ACL enumeration"),
        ("smb-brute", "brute", "credential guessing"),
    ],
    "telnet": [
        ("telnet-brute", "brute", "credential guessing"),
        ("telnet-encryption", "default", "cleartext transport check"),
    ],
    "smtp": [
        ("smtp-open-relay", "vuln", "open-relay probe"),
        ("smtp-commands", "default", "verb/advertised-auth inventory"),
    ],
    "dns": [
        ("dns-recursion", "default", "open-recursion check"),
        ("dns-zone-transfer", "vuln", "AXFR disclosure probe"),
    ],
    "mysql": [
        ("mysql-brute", "brute", "credential guessing"),
        ("mysql-empty-password", "auth", "empty-password account check"),
        ("mysql-vuln-cve2012-2122", "vuln", "auth-bypass probe"),
    ],
    "mssql": [
        ("ms-sql-brute", "brute", "credential guessing"),
        ("ms-sql-empty-password", "auth", "empty-password account check"),
    ],
    "postgres": [
        ("pgsql-brute", "brute", "credential guessing"),
    ],
    "postgresql": [
        ("pgsql-brute", "brute", "credential guessing"),
    ],
    "rdp": [
        ("rdp-vuln-ms12-020", "vuln", "BlueKeep-class RDP probe"),
        ("rdp-brute", "brute", "credential guessing"),
    ],
    "ms-wbt-server": [
        ("rdp-vuln-ms12-020", "vuln", "BlueKeep-class RDP probe"),
        ("rdp-brute", "brute", "credential guessing"),
    ],
    "snmp": [
        ("snmp-brute", "brute", "community-string guessing"),
        ("snmp-info", "default", "system/process inventory"),
    ],
    "ldap": [
        ("ldap-rootdse", "default", "naming-context inventory"),
        ("ldap-brute", "brute", "credential guessing"),
    ],
}

_GENERIC = [
    ("vuln", "vuln", "broad vulnerability sweep for unmapped services"),
    ("default", "default", "safe inventory scripts for unmapped services"),
]


def _norm(service: str | None) -> str:
    return (service or "").strip().lower()


def suggest(service: str | None, product: str | None = None) -> dict[str, Any]:
    """Suggest NSE scripts for a fingerprinted service.

    Pure and offline. Unknown services fall back to the generic
    `vuln,default` sweep rather than inventing script names.
    """
    key = _norm(service)
    scripts = list(_SCRIPT_MAP.get(key, []))
    if not scripts:
        scripts = [(s, c, f"{r} (generic fallback)") for s, c, r in _GENERIC]
    items = [
        {
            "script": s,
            "category": c,
            "reason": r,
            "product": (product or "").strip() or None,
        }
        for s, c, r in scripts
    ]
    return {
        "service": key or "unknown",
        "product": (product or "").strip() or None,
        "scripts": items,
        "script_arg": ",".join(s for s, _, _ in scripts),
        "count": len(items),
    }


def services_covered() -> list[str]:
    """Service names with curated suggestions."""
    return sorted(_SCRIPT_MAP)
