# OPSEC mode configuration: stealth / tor / overt.
# Each mode decides proxy routing, scan timing, and the set of auxiliary
# scanners to run for a given target host.
import os

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


class ScanModeConfig:
    def __init__(self, name: str, proxies: str | None, nmap_args: list[str]):
        self.name = name
        self.proxies = proxies  # Metasploit Proxies datastore option
        self.nmap_args = nmap_args  # passed to db_nmap / nmap


MODES = {
    "stealth": ScanModeConfig(
        name="stealth",
        proxies=None,
        # Slow, non-invasive: low parallelism, top-100 ports, no OS detection,
        # high timing. Kept bounded so the scan completes within a sane window.
        nmap_args=[
            "-Pn",
            "-sT",
            "-T2",
            "--top-ports",
            "100",
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
        # be polite through a slow circuit.
        nmap_args=[
            "-Pn",
            "-sT",
            "-T2",
            "--top-ports",
            "100",
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
        # Fast, full: OS detection + service versions. Speeds: top-500 ports,
        # a floor on send rate, retries off, short host timeout, few parallel.
        nmap_args=[
            "-Pn",
            "-sS",
            "-T4",
            "-sV",
            "-O",
            "--top-ports",
            "500",
            "--min-rate",
            "1000",
            "--max-retries",
            "0",
            "--host-timeout",
            "120s",
        ],
    ),
}


def get_mode(mode: str) -> ScanModeConfig:
    return MODES.get(mode) or MODES["overt"]


def scanners_for_service(service: str) -> list[str]:
    service = (service or "").lower()
    for key in SERVICE_TO_SCANNERS:
        if key in service:
            return SERVICE_TO_SCANNERS[key]
    return []
