# OPSEC mode configuration: stealth / tor / overt.
# Each mode decides proxy routing, scan timing, and the set of auxiliary
# scanners to run for a given target host.
from __future__ import annotations

import os
from typing import Any

TOR_PORT = int(os.environ.get("TOR_PORT", "9050"))
TOR_SOCKS = f"socks5:127.0.0.1:{TOR_PORT}"

# Common auxiliary scanner families, keyed by the service they probe.
# These are the "vuln + enum" module set we reuse from Metasploit's built-ins.
AUX_SCANNERS = {
    "http": [
        "auxiliary/scanner/http/http_version",
        "auxiliary/scanner/http/title",
        "auxiliary/scanner/http/http_header",
    ],
    "smb": [
        "auxiliary/scanner/smb/smb_version",
        "auxiliary/scanner/smb/smb_enumshares",
        "auxiliary/scanner/smb/smb_enumusers",
        "auxiliary/scanner/smb/smb_login",
        "auxiliary/scanner/smb/ms17_010_eternalblue",
    ],
    "netbios": [
        "auxiliary/scanner/netbios/nbname",
        "auxiliary/scanner/netbios/nbdomain",
    ],
    "msrpc": [
        "auxiliary/scanner/dcerpc/endpoint_mapper",
        "auxiliary/scanner/dcerpc/hidden",
        "auxiliary/scanner/dcerpc/management",
    ],
    "ldap": [
        "auxiliary/scanner/ldap/ldap_search",
        "auxiliary/scanner/ldap/ldap_hashdump",
    ],
    "ftp": [
        "auxiliary/scanner/ftp/ftp_version",
        "auxiliary/scanner/ftp/anonymous",
    ],
    "ssh": [
        "auxiliary/scanner/ssh/ssh_version",
    ],
    "rdp": [
        "auxiliary/scanner/rdp/rdp_scanner",
    ],
    "mysql": [
        "auxiliary/scanner/mysql/mysql_version",
    ],
    "mssql": [
        "auxiliary/scanner/mssql/mssql_ping",
    ],
    "postgres": [
        "auxiliary/scanner/postgres/postgres_version",
    ],
    "telnet": [
        "auxiliary/scanner/telnet/telnet_version",
    ],
}

# Which scanners run per detected service. Order matters (quick, low-risk first).
SERVICE_TO_SCANNERS = {
    "http": AUX_SCANNERS["http"],
    "https": AUX_SCANNERS["http"],
    "smb": AUX_SCANNERS["smb"],
    "netbios-ssn": AUX_SCANNERS["smb"],
    "microsoft-ds": AUX_SCANNERS["smb"],
    "netbios-ns": AUX_SCANNERS["netbios"],
    "msrpc": AUX_SCANNERS["msrpc"],
    "ldap": AUX_SCANNERS["ldap"],
    "ftp": AUX_SCANNERS["ftp"],
    "ssh": AUX_SCANNERS["ssh"],
    "ms-wbt-server": AUX_SCANNERS["rdp"],
    "rdp": AUX_SCANNERS["rdp"],
    "mysql": AUX_SCANNERS["mysql"],
    "mssql": AUX_SCANNERS["mssql"],
    "ms-sql-s": AUX_SCANNERS["mssql"],
    "postgresql": AUX_SCANNERS["postgres"],
    "telnet": AUX_SCANNERS["telnet"],
}


# Port coverage is a SEPARATE axis from stealth/tor/overt. Stealth controls
# *how* we probe (timing, scan type); it must not silently decide *how much*
# we probe. These two used to be conflated, and every mode shipped
# `--top-ports` -- so a "full" overt scan silently checked 500 ports and
# reported nothing open on 11435/1716/18799. The report must always carry
# which ports were actually enumerated (see `Coverage` in schemas.py).
DEPTHS: dict[str, dict[str, Any]] = {
    "quick": {
        "nmap_args": ["--top-ports", "100"],
        "ports_spec": "top-100",
        "max_ports": 100,
        "complete": False,
    },
    "standard": {
        "nmap_args": ["--top-ports", "1000"],
        "ports_spec": "top-1000",
        "max_ports": 1000,
        "complete": False,
    },
    "full": {
        "nmap_args": ["-p-"],
        "ports_spec": "1-65535",
        "max_ports": 65535,
        "complete": True,
    },
}

# A full 65535-port sweep with -sV -O needs far longer than the bounded
# top-ports runs; the old 120s host-timeout truncated it into a silent
# partial result.
_FULL_HOST_TIMEOUT = "900s"
_FULL_MIN_RATE = "3000"


class ScanModeConfig:
    def __init__(
        self,
        name: str,
        proxies: str | None,
        nmap_args: list[str],
        depth: str = "standard",
    ):
        self.name = name
        self.proxies = proxies  # Metasploit Proxies datastore option
        self.depth = depth
        # Kept verbatim so we can re-derive args for any depth without
        # parsing flags back out (a value could collide with a flag name).
        self.base_args = list(nmap_args)
        self.nmap_args = self._args_for(depth)

    def _args_for(self, depth: str) -> list[str]:
        args = list(self.base_args)
        if depth == "full":
            args = [_retune_for_full(a) for a in args]
        return args + list(DEPTHS[depth]["nmap_args"])

    def with_depth(self, depth: str) -> ScanModeConfig:
        if depth == self.depth:
            return self
        return ScanModeConfig(
            name=self.name, proxies=self.proxies, nmap_args=self.base_args, depth=depth
        )

    def coverage(self) -> dict[str, object]:
        """Coverage metadata for the report. Never claims a sweep it didn't do."""
        d = DEPTHS[self.depth]
        return {
            "depth": self.depth,
            "ports_spec": d["ports_spec"],
            "max_ports": d["max_ports"],
            "complete": d["complete"],
        }


def _retune_for_full(arg: str) -> str:
    """Raise the pacing/timeouts for a full sweep so it isn't cut short."""
    if arg == "120s":  # overt host-timeout
        return _FULL_HOST_TIMEOUT
    if arg == "1000":  # overt min-rate
        return _FULL_MIN_RATE
    return arg


MODES = {
    "stealth": ScanModeConfig(
        name="stealth",
        proxies=None,
        # Slow, non-invasive: low parallelism, no OS detection, high timing.
        # Port breadth comes from `depth` (see DEPTHS), not from here.
        nmap_args=[
            "-Pn",
            "-sT",
            "-T2",
            "--host-timeout",
            "240",
            "--max-retries",
            "1",
            "--randomize-hosts",
            "-sV",
            "--version-intensity",
            "0",
        ],
    ),
    "tor": ScanModeConfig(
        name="tor",
        # Route module outbound traffic through Tor's SOCKS.
        proxies=TOR_SOCKS,
        # proxychains wraps the whole process; nmap flags similar to stealth to
        # be polite through a slow circuit. Port breadth comes from `depth`.
        nmap_args=[
            "-Pn",
            "-sT",
            "-T2",
            "--host-timeout",
            "240",
            "--max-retries",
            "1",
            "-sV",
            "--version-intensity",
            "1",
        ],
    ),
    "overt": ScanModeConfig(
        name="overt",
        proxies=None,
        # Fast default: OS detection + service versions, top-N ports where N is
        # the requested depth (default standard/top-1000). Pass depth="full"
        # for a real 1-65535 sweep.
        nmap_args=[
            "-Pn",
            "-sS",
            "-T4",
            "-sV",
            "-O",
            "--min-rate",
            "1000",
            "--max-retries",
            "0",
            "--host-timeout",
            "120s",
        ],
    ),
}


def get_mode(mode: str, depth: str = "standard") -> ScanModeConfig:
    base = MODES.get(mode) or MODES["overt"]
    return base.with_depth(depth if depth in DEPTHS else "standard")


def scanners_for_service(service: str) -> list[str]:
    service = (service or "").lower()
    for key in SERVICE_TO_SCANNERS:
        if key in service:
            return SERVICE_TO_SCANNERS[key]
    return []
