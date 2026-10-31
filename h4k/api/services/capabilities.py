"""What can this h4k instance actually do?

The health endpoint answers "is the API up". This answers the question an
operator really has before a run: *which tools are installed, is Metasploit's
database loaded, where is my data, and what will silently not work?*

It is also what the UI badge and `scripts/sanity_check.py` read.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger("h4k.capabilities")

# The tools that make the platform useful. Each entry says what the tool is
# for, so a missing one is a sentence rather than a mystery.
TOOLS: dict[str, str] = {
    "nmap": "port scan + service fingerprinting",
    "arp-scan": "L2 neighbour discovery",
    "hydra": "password attacks (ssh/ftp/http/smb)",
    "nikto": "web vulnerability scanner",
    "gobuster": "content/ directory discovery",
    "sqlmap": "SQL injection testing",
    "semgrep": "static analysis (SAST)",
    "osv-scanner": "supply-chain CVE lookup",
    "trivy": "SBOM + secret + license scanning",
    "adb": "Android/Fire TV debug bridge",
    "john": "hash cracking",
    "msfconsole": "Metasploit driver",
    "docker": "container runtime",
}


# Tools whose version we bother to report.
VERSIONED = ("nmap", "semgrep", "osv-scanner", "trivy", "john", "hydra")


def _version(cmd: list[str], timeout: float = 2.0) -> str | None:
    """Best-effort version string for a tool."""
    try:
        proc = subprocess.run(  # nosec B603 - fixed argv, no shell
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
    except Exception:
        return None
    out = (proc.stdout or proc.stderr or "").strip()
    if not out:
        return None
    return out.splitlines()[0][:120]


# The tool inventory and its version strings do not change while the process
# runs, so they are cached for much longer than the rest of the report.
_TOOL_CACHE_TTL = 600.0
_tool_cache: dict[str, Any] = {"at": 0.0, "value": None}


def tool_report(force: bool = False) -> dict[str, Any]:
    """Which tools are installed, and what do they do.

    The version probes run in parallel: doing a dozen of them one after
    another took long enough for the UI to look broken.
    """
    from concurrent.futures import ThreadPoolExecutor

    if (
        not force
        and _tool_cache["value"] is not None
        and time.time() - float(_tool_cache["at"]) < _TOOL_CACHE_TTL
    ):
        return dict(_tool_cache["value"])

    tools: dict[str, Any] = {}
    for name, purpose in TOOLS.items():
        path = shutil.which(name)
        tools[name] = {"purpose": purpose, "installed": bool(path), "path": path}

    def probe(name: str) -> str | None:
        path = tools[name]["path"]
        if not path or name not in VERSIONED:
            return None
        return _version([path, "--version"])

    with ThreadPoolExecutor(max_workers=8) as pool:
        versions = dict(zip(list(tools), pool.map(probe, list(tools)), strict=True))
    for name, version in versions.items():
        if version:
            tools[name]["version"] = version
    _tool_cache["at"] = time.time()
    _tool_cache["value"] = dict(tools)
    return tools


def metasploit_report(msf: Any = None) -> dict[str, Any]:
    """Metasploit reachability, database state and module catalogue size."""
    out: dict[str, Any] = {"reachable": False, "database": "unknown", "modules": 0}
    if msf is None:
        return out
    try:
        version = msf.client.core.version
        out["reachable"] = True
        out["version"] = version.get("version") if isinstance(version, dict) else None
    except Exception as exc:
        out["error"] = str(exc)[:160]
        return out
    try:
        mods = msf.list_modules("exploit") or []
        out["modules"] = len(mods)
    except Exception:
        out["modules"] = 0
    try:
        # a workspace list means the DB is connected and usable
        ws = msf.client.call("db.workspaces", [])
        out["database"] = (
            "connected"
            if isinstance(ws, dict) and ws.get("workspaces")
            else "not connected"
        )
    except Exception as exc:
        out["database"] = "not connected"
        out["db_error"] = str(exc)[:120]
    return out


def storage_report() -> dict[str, Any]:
    """Where the data lives, whether we can write there, what is in it."""
    from paths import data_dir, external_wordlists, is_writable, wordlist_path

    directory = data_dir()
    entries = []
    for kind in ("users", "passwords", "web-words"):
        path = wordlist_path(kind)
        entries.append(
            {
                "kind": kind,
                "path": str(path),
                "present": path.is_file(),
                "lines": _count_lines(path) if path.is_file() else 0,
            }
        )
    return {
        "data_dir": str(directory),
        "writable": is_writable(directory),
        "wordlists": entries,
        "external_wordlists": external_wordlists(),
    }


def _count_lines(path: Path) -> int:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            return sum(1 for _ in handle)
    except OSError:
        return 0


# The tool set does not change between runs and the UI polls this every
# 30 seconds, so the report is cached for a minute.
_CACHE_TTL = 60.0
_cache: dict[str, Any] = {"at": 0.0, "value": None}


def build_report(
    msf: Any = None, use_cache: bool = True, force: bool = False
) -> dict[str, Any]:
    """The full readiness report."""
    from services.sandbox import enabled as sandbox_enabled

    sandbox = sandbox_enabled()
    # the cache is keyed by the sandbox flag: flipping it changes what the
    # platform can do, so the old answer must not be reused
    cache_key = f"sandbox={sandbox}"
    if (
        use_cache
        and _cache["value"] is not None
        and _cache.get("key") == cache_key
        and time.time() - float(_cache["at"]) < _CACHE_TTL
    ):
        cached = dict(_cache["value"])
        cached["cached"] = True
        return cached

    tools = tool_report(force=force)
    installed = [name for name, info in tools.items() if info["installed"]]
    msf_report = metasploit_report(msf)
    storage = storage_report()
    try:
        from services.privesc import docker_group_report

        privilege = docker_group_report()
    except Exception as exc:  # pragma: no cover - defensive
        privilege = {"error": str(exc)[:120], "vectors": [], "at_risk": False}

    # what the platform can do right now
    features = {
        "recon": "nmap" in installed,
        "l2_discovery": "arp-scan" in installed,
        "password_attacks": "hydra" in installed,
        "metasploit_exploitation": bool(msf_report.get("reachable")),
        "metasploit_database": msf_report.get("database") == "connected",
        "static_analysis": "semgrep" in installed,
        "supply_chain": "osv-scanner" in installed or "trivy" in installed,
    }
    # the things that are quietly degraded
    warnings: list[str] = []
    if not features["recon"]:
        warnings.append("nmap is missing: scans will return an empty inventory")
    if not features["password_attacks"]:
        warnings.append("hydra is missing: password attacks are unavailable")
    if msf_report.get("reachable") and not features["metasploit_database"]:
        warnings.append(
            "Metasploit's database is not connected: db_nmap finds no hosts"
        )
    if not features["metasploit_exploitation"]:
        warnings.append("Metasploit is unreachable: exploit modules cannot run")
    if not storage["writable"]:
        warnings.append(f"data dir {storage['data_dir']} is not writable")
    if sandbox_enabled():
        warnings.append(
            "sandbox mode is ON: nmap/hydra/Metasploit are stubbed and nothing "
            "reaches the network"
        )
    if isinstance(privilege, dict) and privilege.get("at_risk"):
        if privilege.get("is_root"):
            warnings.append("API runs as uid 0: image has no USER drop")
        elif privilege.get("docker_groups") and privilege.get(
            "docker_reachable_without_sudo"
        ):
            warnings.append(
                "docker group grants host-root without sudo "
                "(see labs/docker-group-to-root/)"
            )

    report = {
        "ok": not warnings,
        "cached": False,
        "sandbox": sandbox,
        "features": features,
        "warnings": warnings,
        "tools": tools,
        "installed_tools": sorted(installed),
        "metasploit": msf_report,
        "storage": storage,
        "privilege": privilege,
        "environment": {
            "api_port": os.environ.get("API_PORT", "3137"),
            "msf_host": os.environ.get("MSF_HOST", "127.0.0.1"),
            "msf_port": os.environ.get("MSF_PORT", "55553"),
        },
    }
    _cache["at"] = time.time()
    _cache["key"] = cache_key
    _cache["value"] = report
    return report
