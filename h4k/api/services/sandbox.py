"""Sandbox mode: deterministic, offline, zero-touch stand-ins for real tools.

h4k is a lab tool: it shells out to nmap/hydra/Metasploit to do real work on
systems the operator owns. That is exactly what makes it hard to demo, test,
or CI -- a "scan" depends on whatever happens to be reachable on the network,
and the output differs every run.

`H4K_SANDBOX=1` swaps the three external dependencies for canned,
deterministic equivalents:

* `NeighborFinder` returns a fixed set of lab hosts,
* `ToolkitRunner.run_tool` returns canned nmap XML / hydra output,
* the Metasploit client is replaced by a fake that refuses to "exploit"
  anything and says so honestly.

Nothing here is a shortcut around the real code paths: the same pipeline, the
same parsers, the same scoring run against fixed input. Only the leaves are
replaced. That makes sandbox mode usable for class demos, for CI, and for
Selenium end-to-end tests -- and it never touches a network.
"""

from __future__ import annotations

import logging
import os
from typing import Any

logger = logging.getLogger("h4k.sandbox")

ENV_VAR = "H4K_SANDBOX"

# Fixed lab estate: three hosts with a credential that works on two of them,
# so lateral-movement paths, crown jewels and ATT&CK mapping all have
# something real to chew on.
SANDBOX_HOSTS: list[dict[str, Any]] = [
    {
        "ip": "10.10.10.5",
        "mac": "52:54:00:12:34:56",
        "vendor": "QEMU/KVM",
        "hostname": "web01.lab",
        "services": [
            {"port": 22, "proto": "tcp", "service": "ssh", "version": "OpenSSH 7.4"},
            {"port": 80, "proto": "tcp", "service": "http", "version": "Apache 2.4.6"},
        ],
        "os": "Linux 3.10",
    },
    {
        "ip": "10.10.10.9",
        "mac": "52:54:00:12:34:57",
        "vendor": "QEMU/KVM",
        "hostname": "db01.lab",
        "services": [
            {"port": 22, "proto": "tcp", "service": "ssh", "version": "OpenSSH 7.4"},
            {
                "port": 5432,
                "proto": "tcp",
                "service": "postgresql",
                "version": "PostgreSQL 9.6",
            },
        ],
        "os": "Linux 3.10",
    },
    {
        "ip": "10.10.10.42",
        "mac": "52:54:00:12:34:58",
        "vendor": "QEMU/KVM",
        "hostname": "dc01.lab",
        "services": [
            {
                "port": 445,
                "proto": "tcp",
                "service": "microsoft-ds",
                "version": "Samba 4.1",
            },
            {
                "port": 3389,
                "proto": "tcp",
                "service": "ms-wbt-server",
                "version": "xrdp",
            },
        ],
        "os": "Linux 3.10",
    },
]

SANDBOX_CREDENTIAL = {
    "user": "admin",
    # nosec B105 - sandbox fixture credential, never sent to a real host
    "password": "lab-admin",
    "service": "ssh",
    "hosts": ["10.10.10.5", "10.10.10.9"],
}

# A second credential that only works on the jump host and the DC, so the
# seeded estate has a genuine two-hop pivot path to the crown jewel.
SANDBOX_CREDENTIAL_2 = {
    "user": "backup",
    # nosec B105 - sandbox fixture credential, never sent to a real host
    "password": "backup-svc",
    "service": "ssh",
    "hosts": ["10.10.10.9", "10.10.10.42"],
}

SANDBOX_CROWN_JEWEL = {
    "host": "10.10.10.42",
    "label": "Domain controller",
    "value": 90,
}


def enabled() -> bool:
    """True when sandbox mode is on (H4K_SANDBOX=1)."""
    return os.environ.get(ENV_VAR, "").strip() in ("1", "true", "yes", "on")


def sandbox_scope() -> str:
    """The CIDR the sandbox estate lives in."""
    return "10.10.10.0/24"


def neighbors() -> list[dict[str, Any]]:
    """Canned ARP/neighbour table."""
    return [
        {
            "ip": h["ip"],
            "mac": h["mac"],
            "vendor": h["vendor"],
            "hostname": h["hostname"],
        }
        for h in SANDBOX_HOSTS
    ]


def nmap_xml(ip: str) -> str:
    """Canned `nmap -oX -` output for one host."""
    host = next((h for h in SANDBOX_HOSTS if h["ip"] == ip), None)
    if host is None:
        return (
            '<?xml version="1.0"?>\n'
            '<nmaprun scanner="nmap" args="sandbox">\n'
            '  <host><status state="up"/></host>\n'
            "</nmaprun>\n"
        )
    ports = "".join(
        f'    <port protocol="{s["proto"]}" portid="{s["port"]}">\n'
        f'      <state state="open" reason="syn-ack"/>\n'
        f'      <service name="{s["service"]}" version="{s.get("version", "")}"/>\n'
        f"    </port>\n"
        for s in host["services"]
    )
    return (
        '<?xml version="1.0"?>\n'
        '<nmaprun scanner="nmap" args="sandbox">\n'
        '  <host starttime="0" endtime="1">\n'
        f'    <address addr="{host["ip"]}" addrtype="ipv4"/>\n'
        f'    <address addr="{host["mac"]}" addrtype="mac" vendor="{host["vendor"]}"/>\n'
        f'    <hostnames><hostname name="{host["hostname"]}" type="PTR"/></hostnames>\n'
        f"    <ports>\n{ports}    </ports>\n"
        f'    <os><osmatch name="{host["os"]}" accuracy="95"/></os>\n'
        "  </host>\n"
        "</nmaprun>\n"
    )


def hydra_output(ip: str) -> str:
    """Canned hydra stdout for the lab host that has a known account."""
    if ip not in SANDBOX_CREDENTIAL["hosts"]:
        return ""
    return (
        f" Hydra v9.5 (c) 2023 by h4k sandbox\n"
        f"[INFO] Testing {ip}...\n"
        f"[22][ssh] host: {ip}   login: {SANDBOX_CREDENTIAL['user']}   "
        f"password: {SANDBOX_CREDENTIAL['password']}\n"
        f"1 of 1 target(s) completed, 1 valid password(s) found.\n"
    )


def report() -> dict[str, Any]:
    """A canned scan report for the sandbox estate (ingest-shaped)."""
    hosts = []
    for h in SANDBOX_HOSTS:
        hosts.append(
            {
                "address": h["ip"],
                "os": h["os"],
                "services": [
                    {
                        "port": s["port"],
                        "proto": s["proto"],
                        "service": s["service"],
                        "version": s.get("version"),
                        "state": "open",
                        "info": s.get("version", ""),
                    }
                    for s in h["services"]
                ],
            }
        )
    return {
        "hosts": hosts,
        "fingerprints": [
            {
                "host": h["ip"],
                "os": h["os"],
                "vendor": h["vendor"],
                "technology": [s["service"] for s in h["services"]],
            }
            for h in SANDBOX_HOSTS
        ],
        "credentials": [
            {
                "host": SANDBOX_CREDENTIAL["hosts"][0],
                "port": 22,
                "service": SANDBOX_CREDENTIAL["service"],
                "user": SANDBOX_CREDENTIAL["user"],
                "password": SANDBOX_CREDENTIAL["password"],
                "verified": True,
            }
        ],
        "vulns": [
            {
                "host": "10.10.10.5",
                "name": "OpenSSH outdated (CVE-2021-41617)",
                "severity": "high",
                "cwe": "CWE-1104",
                "port": 22,
            },
            {
                "host": "10.10.10.42",
                "name": "Samba outdated (CVE-2017-0144)",
                "severity": "high",
                "cwe": "CWE-1104",
                "port": 445,
            },
        ],
    }


def seed_engagement(store: Any, name: str = "sandbox lab") -> dict[str, Any]:
    """Create + populate a demo engagement in the sandbox estate.

    Returns the engagement dict. Idempotent-ish: it creates a fresh
    engagement each call, so tests and demos get a clean slate.
    """
    eng = store.create_engagement(name, [sandbox_scope()], "seeded by sandbox mode")
    store.ingest_scan(eng["id"], report())
    for cred in (SANDBOX_CREDENTIAL, SANDBOX_CREDENTIAL_2):
        for host in cred["hosts"]:
            store.record_credential(
                eng["id"],
                cred["user"],
                cred["password"],
                cred["service"],
                origin_host=host,
                origin_port=22,
                verified=True,
            )
    store.add_crown_jewel(
        eng["id"],
        SANDBOX_CROWN_JEWEL["host"],
        SANDBOX_CROWN_JEWEL["label"],
        SANDBOX_CROWN_JEWEL["value"],
    )
    return store.get_engagement(eng["id"]) or eng


_HYDRA_TAKES_VALUE = {"-L", "-P", "-t", "-W", "-s", "-o", "-M", "-e", "-m", "-u", "-p"}


def _hydra_target(argv: list[str]) -> str:
    """Best-effort target extraction: first non-flag token that is not a
    known service name or a flag's value (robust to -R/-W/tune additions)."""
    skip_next = False
    for tok in argv[1:]:
        if skip_next:
            skip_next = False
            continue
        if tok in _HYDRA_TAKES_VALUE:
            skip_next = True
            continue
        if tok.startswith("-") or tok in ("-f", "-R", "-F", "-q"):
            continue
        if tok.lower() in (
            "ssh",
            "ftp",
            "telnet",
            "mysql",
            "http-get",
            "http-post-form",
            "smb",
            "rdp",
            "postgres",
            "mssql",
            "oracle",
            "sip",
        ):
            continue
        if "://" in tok or ":" in tok or "." in tok or tok.replace("_", "").isalnum():
            if "." in tok or ":" in tok or "/" in tok:
                return tok.split("://")[-1].split("/")[0].split(":")[0]
            return tok
    return ""


def tool_result(tool: str, argv: list[str]) -> dict[str, Any] | None:
    """Canned result for a tool run, or None if we have no canned output."""
    stdout = ""
    if tool == "nmap":
        target = argv[-1]
        stdout = nmap_xml(target)
    elif tool == "hydra":
        target = _hydra_target(argv)
        stdout = hydra_output(target)
    else:
        return None
    return {
        "tool": tool,
        "stdout": stdout,
        "stderr": "",
        "rc": 0,
        "elapsed": 0.01,
        "timed_out": False,
        "status": "ok",
    }


class FakeModule:
    """Stand-in for a Metasploit module object."""

    def __init__(self, mtype: str, mname: str):
        self.type = mtype
        self.name = mname
        self.description = f"sandbox stub for {mname}"
        self.options: dict[str, Any] = {}
        self.uuid = "00000000-0000-0000-0000-000000000000"

    def __setitem__(self, key: str, value: Any) -> None:
        self.options[key] = value

    def execute(self) -> dict[str, Any]:
        # Honest: sandbox mode never "exploits" anything.
        return {
            "error": "sandbox mode: exploit execution is disabled",
            "status": "failed",
        }

    def check(self) -> dict[str, Any]:
        return {"status": "failed", "error": "sandbox mode: no real target"}


class FakeModules:
    def __init__(self) -> None:
        self.module_types: dict[str, list[str]] = {
            "exploit": [
                "exploit/multi/handler",
                "exploit/unix/ssh/openssh_ssh_login_module",
            ],
            "auxiliary": ["auxiliary/scanner/discovery/arp_sweep"],
        }

    def use(self, mtype: str, mname: str) -> FakeModule:
        return FakeModule(mtype, mname)

    def results(self, _uuid: str) -> dict[str, Any]:
        return {}


class FakeDb:
    def __init__(self) -> None:
        self.workspace = "default"

    def __getattr__(self, _name: str) -> Any:  # pragma: no cover - defensive
        return None


class FakeSessions:
    def __init__(self) -> None:
        self.list: list[dict[str, Any]] = []


class FakeJobs:
    def __init__(self) -> None:
        self.list: list[dict[str, Any]] = []


class FakeCore:
    def __init__(self) -> None:
        self.version = "6.5.9 (h4k sandbox)"


class FakeMsfClient:
    """A Metasploit client that never touches a daemon.

    It implements exactly the surface h4k uses (`core.version`, `modules.use`,
    `db.workspace`, `call`, `sessions.list`, `jobs.list`) and returns honest
    "not available" answers instead of pretending a target was exploited.
    """

    def __init__(  # nosec B107 - mirrors MsfClient; the value is never used
        self, host: str = "", port: int = 0, password: str = ""
    ):
        self.host = host
        self.port = port
        self.core = FakeCore()
        self.modules = FakeModules()
        self.db = FakeDb()
        # no live sessions/jobs in sandbox mode
        self._sessions = FakeSessions()
        self._jobs = FakeJobs()

    # -- MsfClient-compatible API -----------------------------------------

    def execute(self, mtype: str, mname: str, opts: dict) -> dict[str, Any]:
        return {
            "error": "sandbox mode: module execution is disabled",
            "status": "failed",
        }

    def check(self, mtype: str, mname: str, opts: dict) -> dict[str, Any]:
        return {"status": "failed", "error": "sandbox mode: no real target"}

    def call(self, method: str, _args: list) -> dict[str, Any]:
        key = method.rsplit(".", 1)[-1]
        if key in ("hosts", "services", "vulns"):
            return {key: []}
        return {}

    def hosts(self, workspace: str = "default") -> list:
        return []

    def services(self, workspace: str = "default") -> list:
        return []

    def vulns(self, workspace: str = "default") -> list:
        return []

    def current_workspace(self) -> str:
        return self.db.workspace

    def report_host(self, address: str, **kwargs: Any) -> dict[str, Any]:
        return {"address": address, "recorded": False, "sandbox": True}

    def analyze_host(self, ip: str, workspace: str = "default") -> dict[str, Any]:
        return {"sandbox": True}

    def sessions(self) -> dict[str, Any]:
        return {}

    def jobs(self) -> dict[str, Any]:
        return {}

    def module_results(self, uuid: str) -> dict[str, Any]:
        return {}

    def list_modules(self, mtype: str) -> list[str]:
        return list(self.modules.module_types.get(mtype, []))

    def get_module_info(self, mtype: str, mname: str) -> dict[str, Any]:
        return {
            "name": mname,
            "description": f"sandbox stub for {mname}",
            "options": [],
            "mtype": mtype,
            "fullname": mname,
        }

    def find_exploits(
        self, service: str | None = None, port: int | None = None
    ) -> list[dict[str, Any]]:
        return []
