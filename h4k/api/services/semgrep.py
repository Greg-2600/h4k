# Semgrep-based SAST engine. Runs the real `semgrep` binary over a source tree
# and maps its JSON findings onto finding records. Falls back silently to regex
# heuristics (sast.py) when semgrep isn't installed or errors.
import json
import logging
import os
import shutil
import subprocess  # nosec B404 - runs semgrep for static analysis
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger("h4k.semgrep")


@dataclass
class SemgrepFinding:
    check_id: str
    severity: str  # ERROR -> high/critical, WARNING -> medium, INFO -> low
    path: str
    line: int
    end_line: int
    message: str
    rule_id: str
    cwe: str
    confidence: str = ""


_SEV = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}


def _cwe_from(tags: list[str]) -> str:
    for t in tags or []:
        if t.upper().startswith("CWE-"):
            return t.upper()
    return "CWE-710"


def _semgrep_bin() -> str:
    """Locate semgrep. Prefer the current venv's bin, then PATH."""
    venv_bin = Path(sys.prefix) / "bin" / "semgrep"
    if venv_bin.exists():
        return str(venv_bin)
    exe = shutil.which("semgrep")
    if exe:
        return exe
    return "semgrep"


def scan_semgrep(root: Path) -> list[SemgrepFinding]:
    """Run `semgrep scan --json` over root/. Returns [] on any failure."""
    binary = _semgrep_bin()
    env = dict(os.environ)
    venv_bin = str(Path(sys.prefix) / "bin")
    if venv_bin not in env.get("PATH", ""):
        env["PATH"] = venv_bin + os.pathsep + env.get("PATH", "")

    fd, tmpname = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    out_file = Path(tmpname)
    try:
        subprocess.run(  # nosec B603 B607 - fixed argv, no shell
            [
                binary,
                "scan",
                "--json",
                "--quiet",
                "--no-rewrite-rule-ids",
                "-o",
                str(out_file),
                str(root),
            ],
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
            env=env,
        )
    except FileNotFoundError:
        logger.debug("semgrep not installed; skipping")
        return []
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("semgrep run failed: %s", exc)
        return []

    try:
        data = json.loads(out_file.read_text(encoding="utf-8") or "{}")
    except (OSError, json.JSONDecodeError):
        logger.warning("semgrep produced no JSON output")
        data = {}
    finally:
        if out_file.exists():
            out_file.unlink()

    findings: list[SemgrepFinding] = []
    for result in data.get("results", []):
        path = result.get("path", "")
        start = result.get("start") or {}
        end = result.get("end") or {}
        extra = result.get("extra", {})
        cid = result.get("check_id", "") or ""
        sev = extra.get("severity", "INFO")
        msg = (extra.get("message") or "").strip()[:200]
        meta = extra.get("metadata", {}) or {}
        tags = meta.get("tags", []) if isinstance(meta, dict) else []
        findings.append(
            SemgrepFinding(
                check_id=cid,
                severity=_SEV.get(sev, "medium"),
                path=path,
                line=start.get("line", 0),
                end_line=end.get("line", start.get("line", 0)),
                message=msg,
                rule_id=_rule_id(cid, msg),
                cwe=_cwe_from(tags),
            )
        )
    return findings


def _rule_id(cid: str, message: str) -> str:
    import re

    base = cid.split(".")[-1].lower() or ""
    if not base:
        m = re.search(r"([A-Za-z_\-]+)", message or "")
        base = (m.group(1) if m else "semgrep").lower()
    return f"sast-semgrep-{base}"
