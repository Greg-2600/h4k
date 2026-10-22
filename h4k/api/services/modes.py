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
        "auxiliary/scanner/ssh/ssh_login",
        "auxiliary/scanner/ssh/ssh_enumusers",
    ],
    "rdp": [
        "auxiliary/scanner/rdp/rdp_scanner",
    ],
    "mysql": [
        "auxiliary/scanner/mysql/mysql_version",
        "auxiliary/scanner/mysql/mysql_login",
    ],
    "mssql": [
        "auxiliary/scanner/mssql/mssql_ping",
        "auxiliary/scanner/mssql/mssql_login",
    ],
    "postgres": [
        "auxiliary/scanner/postgres/postgres_version",
        "auxiliary/scanner/postgres/postgres_login",
    ],
    "telnet": [
        "auxiliary/scanner/telnet/telnet_version",
    ],
    "redis": [
        "auxiliary/scanner/redis/redis_version",
        "auxiliary/scanner/redis/redis_login",
    ],
    "mongodb": [
        "auxiliary/scanner/mongodb/mongodb_version",
    ],
    "vnc": [
        "auxiliary/scanner/vnc/vnc_none_auth",
        "auxiliary/scanner/vnc/vnc_login",
    ],
    "snmp": [
        "auxiliary/scanner/snmp/snmp_login",
        "auxiliary/scanner/snmp/snmp_enum",
        "auxiliary/scanner/snmp/snmp_enumusers",
    ],
    "nfs": [
        "auxiliary/scanner/nfs/nfsmount",
    ],
    "smtp": [
        "auxiliary/scanner/smtp/smtp_version",
        "auxiliary/scanner/smtp/smtp_enum",
    ],
    "imap": [
        "auxiliary/scanner/imap/imap_version",
    ],
    "pop3": [
        "auxiliary/scanner/pop3/pop3_version",
    ],
    "dns": [
        "auxiliary/scanner/dns/dns_amp",
        "auxiliary/scanner/dns/dns_enum",
    ],
    "ntp": [
        "auxiliary/scanner/ntp/ntp_readvar",
        "auxiliary/scanner/ntp/ntp_monlist",
    ],
    "cups": [
        "auxiliary/scanner/misc/cups_browsed_info_disclosure",
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
    "redis": AUX_SCANNERS["redis"],
    "mongodb": AUX_SCANNERS["mongodb"],
    "vnc": AUX_SCANNERS["vnc"],
    "snmp": AUX_SCANNERS["snmp"],
    "nfs": AUX_SCANNERS["nfs"],
    "smtp": AUX_SCANNERS["smtp"],
    "imap": AUX_SCANNERS["imap"],
    "pop3": AUX_SCANNERS["pop3"],
    "dns": AUX_SCANNERS["dns"],
    "ntp": AUX_SCANNERS["ntp"],
    "cups": AUX_SCANNERS["cups"],
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
        "udp_nmap_args": ["-sU", "--top-ports", "50", "-T4"],
        "ports_spec": "top-100",
        "max_ports": 100,
        "complete": False,
    },
    "standard": {
        "nmap_args": ["--top-ports", "1000"],
        "udp_nmap_args": ["-sU", "--top-ports", "100", "-T4"],
        "ports_spec": "top-1000",
        "max_ports": 1000,
        "complete": False,
    },
    "full": {
        "nmap_args": ["-p-"],
        "udp_nmap_args": [
            "-sU",
            "-p",
            "7,11,17,19,35,37,42,49,53,67,68,69,77,102,111,113,117,119,123,"
            "135,137,138,139,143,144,161,162,177,179,194,197,201,264,318,381,"
            "383,389,411,412,413,427,443,445,464,465,497,500,514,515,517,518,"
            "520,521,540,548,554,587,591,593,623,625,631,636,639,646,691,860,"
            "873,902,989,990,992,1022,1025,1026,1029,1080,1194,1214,1234,1241,"
            "1311,1337,1433,1434,1521,1524,1604,1645,1646,1701,1718,1719,1720,"
            "1723,1755,1812,1813,1863,1900,1935,2000,2001,2002,2049,2077,2078,"
            "2082,2083,2086,2087,2095,2096,2100,2105,2121,2181,2222,2323,2375,"
            "2376,2379,2424,2483,2484,2525,2548,2598,2638,2967,3000,3001,3050,"
            "3100,3128,3260,3283,3306,3389,3478,3632,3690,3749,3780,3784,3790,"
            "3892,3945,4000,4064,4154,4200,4300,4443,4444,4445,4500,4664,4730,"
            "4786,4840,4843,4848,4899,4949,5000,5009,5050,5060,5061,5104,5114,"
            "5159,5190,5200,5222,5223,5225,5226,5247,5280,5353,5357,5432,5433,"
            "5553,5554,5555,5556,5631,5632,5666,5672,5718,5800,5801,5802,5803,"
            "5900,5901,5902,5938,5984,6000,6001,6004,6050,6060,6100,6112,6379,"
            "6443,6502,6503,6543,6660,6661,6662,6663,6664,6665,6666,6667,6668,"
            "6669,6697,6881,6882,6883,6884,6885,6886,6887,6888,6889,6969,7000,"
            "7001,7002,7003,7004,7005,7006,7007,7008,7009,7010,7070,7100,7144,"
            "7181,7200,7210,7272,7300,7301,7306,7307,7308,7474,7547,7548,7549,"
            "7648,7777,7778,7779,7800,8000,8001,8008,8009,8010,8042,8080,8081,"
            "8082,8083,8084,8085,8086,8087,8088,8089,8090,8091,8092,8093,8094,"
            "8095,8096,8097,8098,8099,8100,8118,8123,8138,8139,8140,8180,8181,"
            "8200,8222,8243,8280,8281,8291,8300,8333,8334,8400,8443,8444,8445,"
            "8500,8530,8531,8600,8686,8787,8800,8834,8880,8881,8888,8889,8983,"
            "9000,9001,9002,9003,9009,9010,9011,9042,9050,9051,9080,9081,9090,"
            "9091,9092,9093,9094,9095,9096,9097,9098,9099,9100,9101,9102,9103,"
            "9104,9105,9110,9111,9191,9200,9201,9290,9300,9301,9306,9333,9390,"
            "9391,9392,9393,9394,9395,9396,9397,9398,9399,9418,9443,9500,9530,"
            "9595,9600,9675,9676,9695,9800,9898,9900,9943,9944,9981,9999,10000,"
            "10001,10010,10080,10081,10082,10243,10443,10880,11001,11211,11311,"
            "12000,12345,12443,13000,13364,13443,14000,14001,14443,15000,16000,"
            "16080,17000,17001,17171,18000,18080,18081,18091,18092,19000,19080,"
            "19888,20000,20880,22000,22001,22222,23000,24000,25000,25010,25050,"
            "25565,26000,26001,26002,26003,27000,27001,27017,27080,27081,27082,"
            "28000,28001,29000,29080,30000,31000,32000,32400,33000,34000,35000,"
            "36000,37000,38000,39000,40000,41000,42000,43000,44000,44444,45000,"
            "46000,47000,48000,49000,49152,50000,50030,50060,50070,50090,51000,"
            "51413,52000,53000,54000,55000,55555,57000,60000",
        ],
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
        self.base_args = list(nmap_args)
        self.nmap_args = self._args_for(depth)
        self.udp_nmap_args = self._udp_args_for(depth)

    def _args_for(self, depth: str) -> list[str]:
        args = list(self.base_args)
        if depth == "full":
            args = [_retune_for_full(a) for a in args]
        return args + list(DEPTHS[depth]["nmap_args"])

    def _udp_args_for(self, depth: str) -> list[str]:
        udp_base = ["-sU", "-Pn"]
        if depth == "full":
            udp_base = [
                _retune_for_full(a) if "host-timeout" in a else a for a in udp_base
            ]
        return udp_base + list(DEPTHS[depth].get("udp_nmap_args", []))

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
            "udp_ports_spec": (
                d.get("udp_nmap_args", ["-sU"])[-1]
                if d.get("udp_nmap_args")
                else "none"
            ),
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
