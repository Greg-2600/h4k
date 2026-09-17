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
from typing import Any

logger = logging.getLogger("h4k.semgrep")

# Directory of bundled Semgrep rule sets for fully-offline scanning.
# Populated at image build time (see Dockerfile). If present, we prefer these
# so SAST works with no network.
OFFLINE_RULES = Path("/opt/h4k/data/semgrep-rules")


def _is_offline() -> bool:
    """True if we should run semgrep against the bundled (offline) registry."""
    return OFFLINE_RULES.exists() and any(OFFLINE_RULES.iterdir())


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
    """Run `semgrep scan --json` over root/. Returns [] on any failure.

    If a bundled offline rules dir exists we use it (with --offline) so SAST
    works fully without network; otherwise rely on semgrep's default registry.
    """
    binary = _semgrep_bin()
    env = dict(os.environ)
    venv_bin = str(Path(sys.prefix) / "bin")
    if venv_bin not in env.get("PATH", ""):
        env["PATH"] = venv_bin + os.pathsep + env.get("PATH", "")

    fd, tmpname = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    out_file = Path(tmpname)
    argv = [binary, "scan", "--json", "--quiet", "--no-rewrite-rule-ids"]
    # Offline mode: --config points at the bundled rules dir and --offline tells
    # semgrep not to fetch anything.
    if _is_offline():
        argv += ["--config", str(OFFLINE_RULES), "--offline"]
    argv += ["-o", str(out_file), str(root)]
    try:
        subprocess.run(  # nosec B603 B607 - fixed argv, no shell
            argv,
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


def test_rule(req: Any) -> dict[str, Any]:
    """Validate a custom Semgrep-style rule against sample code.

    Builds a temporary YAML rule + test file and runs `semgrep scan`. Returns
    whether the pattern matched the sample and any semgrep error output.
    """
    import tempfile

    rule_yaml = _build_rule_yaml(req)
    tmp = Path(tempfile.mkdtemp(prefix="h4k-rule-"))
    rule_file = tmp / "rule.yml"
    test_file = tmp / ("test." + _ext_for(req))
    rule_file.write_text(rule_yaml, encoding="utf-8")
    test_file.write_text(req.test_code or "", encoding="utf-8")

    binary = _semgrep_bin()
    env = dict(os.environ)
    venv_bin = str(Path(sys.prefix) / "bin")
    if venv_bin not in env.get("PATH", ""):
        env["PATH"] = venv_bin + os.pathsep + env.get("PATH", "")

    try:
        proc = subprocess.run(  # nosec B603 B607 - fixed argv, no shell
            [
                binary,
                "scan",
                "--config",
                str(rule_file),
                "--json",
                "--quiet",
                str(test_file),
            ],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
            env=env,
        )
    except FileNotFoundError:
        return {"ok": False, "error": "semgrep not installed"}
    stdout = proc.stdout or ""
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return {"ok": False, "error": (proc.stderr or stdout)[:300]}
    matched = len(data.get("results", [])) > 0
    return {
        "ok": True,
        "matched": matched,
        "results": data.get("results", []),
        "rule_id": req.rule_id,
    }


def _build_rule_yaml(req: Any) -> str:
    # A minimal valid Semgrep YAML rule from the request fields.
    sev = (req.severity or "medium").upper()
    lang = '"' + '", "'.join(req.languages or ["python"]) + '"'
    return (
        "rules:\n"
        "  - id: " + req.rule_id + "\n"
        "    languages: [" + lang + "]\n"
        "    message: " + (req.message or req.name or req.rule_id) + "\n"
        "    severity: " + sev + "\n"
        "    pattern: " + (req.pattern or "eval(...)") + "\n"
    )


def _ext_for(req: Any) -> str:
    langs = req.languages or ["python"]
    base = {lang.lower() for lang in langs}
    if "python" in base:
        return "py"
    if "javascript" in base or "js" in base:
        return "js"
    if "c" in base:
        return "c"
    return "py"
