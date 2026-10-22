# Opt-in non-Metasploit attack toolkit: a per-service runner that shells out to
# classic offensive tools (hydra, john, sqlmap, gobuster/ffuf, nikto, smbmap,
# masscan, ncrack, dnsrecon, zap, aircrack-ng, tshark...) against an authorized
# lab target. Separate from the Metasploit RPC path; only runs when a deep-attack
# is explicitly requested. Also includes container escape, lateral movement,
# DB interrogation, hash cracking, wireless, and packet analysis.
import logging
import shutil
import subprocess  # nosec B404 - runs external offensive tools
import time
from collections.abc import Callable
from typing import Any

logger = logging.getLogger("h4k.toolkit")

# web content wordlist (dirb ships a 'common' list; gobuster/ffuf use it)
COMMON_WORDLIST = "/usr/share/dirb/wordlists/common.txt"
# small credential lists for hydra/ncrack (bundled in image)
USERLIST = "/opt/h4k/data/users.txt"
PASSLIST = "/opt/h4k/data/passwords.txt"


def _as_text(data: str | bytes | None) -> str:
    """TimeoutExpired hands back bytes or str depending on text mode."""
    if data is None:
        return ""
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    return data


def _which(tool: str) -> str | None:
    """Return path to tool if installed, else None."""
    return shutil.which(tool)


# Map of tool names to their binary paths (checked at startup)
TOOL_CHECKS = {
    "hydra": ["hydra"],
    "nikto": ["nikto"],
    "gobuster": ["gobuster"],
    "ffuf": ["ffuf"],
    "sqlmap": ["sqlmap"],
    "nmap": ["nmap"],
    "john": ["john"],
    "zip": ["zip"],
    "smbmap": ["smbmap"],
    "smbclient": ["smbclient"],
    "rpcclient": ["rpcclient"],
    "secretsdump": ["secretsdump"],
    "ldapsearch": ["ldapsearch"],
    "getnpusers": ["GetNPUsers.py"],
    "getuserspns": ["GetUserSPNs.py"],
    "wpscan": ["wpscan"],
    "dnsrecon": ["dnsrecon"],
    "zap": ["zap"],
    "aircrack": ["aircrack-ng"],
    "tshark": ["tshark"],
    "tcpdump": ["tcpdump"],
    "snmpwalk": ["snmpwalk"],
    "netdiscover": ["netdiscover"],
    "ping": ["ping"],
    "nc": ["nc", "netcat"],
    "ncat": ["ncat"],
    "socat": ["socat"],
    "chisel": ["chisel"],
    "proxychains": ["proxychains"],
}


class ToolkitRunner:
    def __init__(
        self,
        progress: Callable[[str, float], None] | None = None,
    ):
        self.progress = progress or (lambda msg, pct: None)
        self._available_tools: dict[str, str] = {}
        self._check_tools()

    def _check_tools(self) -> None:
        """Check which tools are available and cache their paths."""
        for tool, names in TOOL_CHECKS.items():
            for name in names:
                path = _which(name)
                if path:
                    self._available_tools[tool] = path
                    break

    def is_tool_available(self, tool: str) -> bool:
        """Check if a tool is available."""
        return tool in self._available_tools

    def get_available_tools(self) -> dict[str, str]:
        """Return dict of available tool -> path."""
        return dict(self._available_tools)

    def get_missing_tools(self, tools: list[str]) -> list[str]:
        """Return list of tools from the given list that are not available."""
        return [t for t in tools if t not in self._available_tools]

    def run_tool(self, tool: str, argv: list[str], timeout: int = 300) -> dict:
        """Run an external tool.

        Returns {tool, stdout, stderr, rc, elapsed, timed_out, status}. On a
        timeout we keep whatever partial output the tool produced -- brute
        force tools stream progress continuously and may well have found
        something before the deadline, so discarding stdout on timeout can
        hide a real result.
        """
        self.progress(f"[toolkit:{tool}] {' '.join(argv[:6])}…", 0)
        started = time.time()
        try:
            proc = subprocess.run(  # nosec B603 B607 - fixed argv, no shell
                argv,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            return {
                "tool": tool,
                "stdout": (proc.stdout or "")[-4000:],
                "stderr": (proc.stderr or "")[-2000:],
                "rc": proc.returncode,
                "elapsed": round(time.time() - started, 2),
                "timed_out": False,
                "status": "ok",
            }
        except FileNotFoundError:
            return {
                "tool": tool,
                "stdout": "",
                "stderr": "tool not installed",
                "rc": -1,
                "elapsed": round(time.time() - started, 2),
                "timed_out": False,
                "status": "missing",
            }
        except subprocess.TimeoutExpired as exc:
            return {
                "tool": tool,
                "stdout": _as_text(exc.stdout)[-4000:],
                "stderr": _as_text(exc.stderr)[-2000:],
                "rc": None,
                "elapsed": round(time.time() - started, 2),
                "timed_out": True,
                "status": "timeout",
            }
        except Exception as exc:  # pragma: no cover - defensive
            return {
                "tool": tool,
                "stdout": "",
                "stderr": str(exc),
                "rc": -1,
                "elapsed": round(time.time() - started, 2),
                "timed_out": False,
                "status": "error",
            }


class ToolkitPlan:
    """Map discovered services/types to a set of toolkit runs."""

    @staticmethod
    def for_target(req: Any) -> list[dict]:
        """Return a list of {tool, argv} runs based on a deep-attack request."""
        host = req.host
        runs: list[dict] = []

        # SSH brute force (only if user supplied cred lists exist)
        if _has("ssh", req.services):
            runs.append(
                {
                    "tool": "hydra",
                    "argv": [
                        "hydra",
                        "-L",
                        USERLIST,
                        "-P",
                        PASSLIST,
                        "-t",
                        "4",
                        host,
                        "ssh",
                    ],
                }
            )

        # HTTP: nikto vuln scan + gobuster content discovery + ffuf
        if _has("http", req.services):
            url = f"http://{host}"
            runs.append(
                {"tool": "nikto", "argv": ["nikto", "-host", url, "-maxtime", "120s"]}
            )
            runs.append(
                {
                    "tool": "gobuster",
                    "argv": [
                        "gobuster",
                        "dir",
                        "-u",
                        url,
                        "-w",
                        _web_wordlist(),
                        "-q",
                        "-t",
                        "10",
                    ],
                }
            )
            runs.append(
                {
                    "tool": "ffuf",
                    "argv": [
                        "ffuf",
                        "-u",
                        f"{url}/FUZZ",
                        "-w",
                        _web_wordlist(),
                        "-mc",
                        "200,204,301,302",
                        "-s",
                        "-t",
                        "10",
                    ],
                }
            )

            # OWASP ZAP web app scan
            runs.append(
                {
                    "tool": "zap",
                    "argv": [
                        "python3",
                        "-c",
                        f"""
import sys
sys.path.insert(0, '/opt/h4k/api')
from services.zap import zap_scan
result = zap_scan('{url}', mode='full')
import json
print(json.dumps(result, default=str))
""",
                    ],
                }
            )

        # SMB enumeration + share listing + RPC null-session info
        if _has("smb", req.services) or _has("microsoft-ds", req.services):
            runs.append({"tool": "smbmap", "argv": ["smbmap", "-H", host, "-g"]})
            runs.append(
                {"tool": "smbclient", "argv": ["smbclient", "-L", "//" + host, "-N"]}
            )
            runs.append(
                {
                    "tool": "rpcclient",
                    "argv": ["rpcclient", "-U", "%", "-c", "srvinfo", host],
                }
            )
            # impacket secretsdump (anonymous / guest) — high-value for Windows labs
            runs.append(
                {
                    "tool": "secretsdump",
                    "argv": ["secretsdump.py", "-just-dc", f"anonymous:@{host}"],
                }
            )

        # LDAP enumeration when 389/636 is exposed
        if _has("ldap", req.services):
            runs.append(
                {
                    "tool": "ldapsearch",
                    "argv": [
                        "ldapsearch",
                        "-x",
                        "-H",
                        f"ldap://{host}",
                        "-b",
                        "",
                        "s",
                        "",
                    ],
                }
            )

        # Active Directory / Kerberos: AS-REP roasting + kerberoasting (impacket)
        if _has("ldap", req.services) or _has("kerberos-sec", req.services):
            runs.append(
                {
                    "tool": "GetNPUsers",
                    "argv": [
                        "GetNPUsers.py",
                        "-dc-ip",
                        host,
                        "-usersfile",
                        "/opt/h4k/data/users.txt",
                        "-no-pass",
                        "-format",
                        "hashcat",
                        ".",
                    ],
                }
            )
            runs.append(
                {
                    "tool": "GetUserSPNs",
                    "argv": ["GetUserSPNs.py", "-dc-ip", host, ".", "-request"],
                }
            )

        # WordPress scan (fast on non-WP too; harmless)
        if _has("http", req.services):
            runs.append(
                {
                    "tool": "wpscan",
                    "argv": [
                        "wpscan",
                        "--url",
                        f"http://{host}/",
                        "--no-banner",
                        "--disable-tls-checks",
                    ],
                }
            )

        # web app SQL injection check (sqlmap, no banner grab)
        if _has("http", req.services):
            runs.append(
                {
                    "tool": "sqlmap",
                    "argv": [
                        "sqlmap",
                        "-u",
                        f"http://{host}/",
                        "--batch",
                        "--crawl",
                        "1",
                        "--smart",
                        "--level",
                        "1",
                    ],
                }
            )

        # DNS recon
        if _has("dns", req.services) or _looks_domain(req.target):
            runs.append(
                {
                    "tool": "dnsrecon",
                    "argv": ["dnsrecon", "-d", req.host, "-t", "std,zone"],
                }
            )

        # John the Ripper hash cracking
        if (
            _has("ssh", req.services)
            or _has("smb", req.services)
            or _has("ldap", req.services)
        ):
            runs.append(
                {
                    "tool": "john",
                    "argv": [
                        "python3",
                        "-c",
                        """
import sys
sys.path.insert(0, '/opt/h4k/api')
from services.john import JohnRunner
jr = JohnRunner()
# Try common CTF hash formats
result = jr.crack_ctf_hashes(["$1$salt$hash", "hash"], formats=["md5", "sha256", "nt"])
import json
print(json.dumps(result, default=str))
""",
                    ],
                }
            )

        # Enhanced Nmap with NSE scripts
        runs.append(
            {
                "tool": "nmap_nse",
                "argv": [
                    "nmap",
                    "-sV",
                    "-sC",
                    "--script",
                    "vuln,auth,default",
                    "-T4",
                    host,
                ],
            }
        )

        # Container escape checks
        runs.append(
            {
                "tool": "container_escape",
                "argv": [
                    "python3",
                    "-c",
                    """
import sys
sys.path.insert(0, '/opt/h4k/api')
from services.container_escape import ContainerEscape
ce = ContainerEscape()
result = ce.detect()
import json
print(json.dumps(result, default=str))
""",
                ],
            }
        )

        # Lateral movement / network discovery
        runs.append(
            {
                "tool": "network_discovery",
                "argv": [
                    "python3",
                    "-c",
                    """
import sys
sys.path.insert(0, '/opt/h4k/api')
from services.lateral import LateralMovement
lm = LateralMovement()
result = lm.discover_network()
import json
print(json.dumps(result, default=str))
""",
                ],
            }
        )

        # Database interrogation
        runs.append(
            {
                "tool": "db_interrogate",
                "argv": [
                    "python3",
                    "-c",
                    """
import sys
sys.path.insert(0, '/opt/h4k/api')
from services.db_interrogate import DBInterrogate
di = DBInterrogate()
result = di.interrogate_all()
import json
print(json.dumps(result, default=str))
""",
                ],
            }
        )

        # Aircrack-ng wireless (if wireless interface available)
        runs.append(
            {
                "tool": "aircrack_check",
                "argv": [
                    "python3",
                    "-c",
                    """
import sys
sys.path.insert(0, '/opt/h4k/api')
from services.aircrack import AircrackService
svc = AircrackService()
result = svc.check_interfaces()
import json
print(json.dumps(result, default=str))
""",
                ],
            }
        )

        # Tshark packet analysis (if pcap available)
        runs.append(
            {
                "tool": "tshark_check",
                "argv": [
                    "python3",
                    "-c",
                    """
import sys
sys.path.insert(0, '/opt/h4k/api')
from services.tshark import TsharkService
svc = TsharkService()
result = svc.list_interfaces()
import json
print(json.dumps(result, default=str))
""",
                ],
            }
        )

        return runs


def _web_wordlist() -> str:
    """Pick a web wordlist present in the image, with a sane fallback."""
    if _file_nonexistent(COMMON_WORDLIST):
        # dirb/common.txt not present; generate a tiny internal list
        return "/opt/h4k/data/web-words.txt"
    return COMMON_WORDLIST


def _file_nonexistent(path: str) -> bool:
    try:
        import os

        return not os.path.isfile(path)
    except Exception:
        return True


def _has(name: str, services: Any) -> bool:
    for s in services or []:
        s = (s or "").lower()
        if name in s:
            return True
        # smb appears as microsoft-ds / netbios-ssn in nmap output
        if name in ("smb",) and s in ("microsoft-ds", "netbios-ssn"):
            return True
    return False


def _looks_domain(target: str) -> bool:
    return "." in (target or "") and not target.replace(".", "").isdigit()
