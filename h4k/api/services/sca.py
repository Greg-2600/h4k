# Software Composition Analysis (SCA): builds an SBOM from an analyzed source
# tree and cross-checks the declared dependencies for known CVEs using
# osv-scanner (Google) with a CycloneDX SBOM. This tells you *what vulnerable
# software you're running* — the 2020s supply-chain view on top of the
# static-analysis findings.
import json
import logging
import shutil
import subprocess  # nosec B404 - runs trivy/osv-scanner for SCA
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger("h4k.sca")

SBOM_DIR: Path | None = None


def _sbom_out_dir() -> Path:
    global SBOM_DIR
    if SBOM_DIR is None:
        import tempfile

        SBOM_DIR = Path(tempfile.mkdtemp(prefix="h4k-sbom-"))
    return SBOM_DIR


def _which(tool: str) -> str | None:
    return shutil.which(tool)


def _tool_cmd(name: str) -> str | None:
    """Return a path to tool if installed (absolute), else None."""
    exe = _which(name)
    return exe


@dataclass
class ScaResult:
    tool: str
    osv_vulns: list[dict] = field(default_factory=list)
    cve_ids: list[str] = field(default_factory=list)
    packages: list[str] = field(default_factory=list)
    pkg_cves: dict[str, list[str]] = field(default_factory=dict)
    sbom_available: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "osv_vulns": self.osv_vulns,
            "cve_ids": self.cve_ids,
            "packages": self.packages,
            "pkg_cves": self.pkg_cves,
            "sbom_available": self.sbom_available,
        }


def _run(
    cmd: list[str], cwd: Path | None = None, timeout: int = 180
) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(  # nosec B603 B607 - fixed argv, no shell
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(cwd) if cwd else None,
            check=False,
        )
    except FileNotFoundError:
        return -1, "", f"{cmd[0]} not installed"
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except Exception as exc:  # pragma: no cover - defensive
        return -1, "", str(exc)
    return proc.returncode, proc.stdout, proc.stderr


def generate_sbom(root: Path) -> Path | None:
    """Generate a CycloneDX JSON SBOM using trivy (or fall back to osv-scanner)."""
    out_dir = _sbom_out_dir()
    out = out_dir / f"sbom-{root.name or 'src'}.cdx.json"

    # Prefer trivy for a full CycloneDX SBOM.
    trivy = _tool_cmd("trivy")
    if trivy:
        rc, _so, _se = _run(
            [
                trivy,
                "fs",
                "--scanners",
                "license,secret",
                "--format",
                "cyclonedx",
                "--output",
                str(out),
                str(root),
            ],
            timeout=240,
        )
        if rc == 0 and out.exists():
            return out

    # Fallback: osv-scanner --sbom can scan an SBOM; if absent we just return
    # the root and let SCA run osv-scanner directly on the source tree.
    return None


def scan_osv(root: Path) -> ScaResult:
    """Run osv-scanner over the source tree for known-vuln dependencies."""
    res = ScaResult(tool="osv-scanner")
    osv = _tool_cmd("osv-scanner")
    if not osv:
        logger.debug("osv-scanner not installed; SCA skipped")
        return res

    # osv-scanner can scan a directory (lockfiles+manifest) directly.
    out_dir = _sbom_out_dir()
    out = out_dir / f"osv-{root.name}.json"
    rc, so, se = _run(
        [osv, "--format", "json", "--output", str(out), str(root)], timeout=240
    )
    if rc != 0 or not out.exists():
        # try capturing stdout as JSON directly
        rc, so, se = _run([osv, "--format", "json", str(root)], timeout=240)
        if rc == 0 and so.strip():
            out.write_text(so, encoding="utf-8")
        else:
            logger.warning("osv-scanner failed: %s", se[:200])
            return res

    try:
        data = json.loads(out.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        logger.warning("osv-scanner returned non-JSON")
        return res

    vulns: list[dict] = []
    cves: list[str] = []
    pkgs: list[str] = []
    pkg_cves: dict[str, list[str]] = {}  # package name -> [cve...]

    # osv-scanner output: {"results": [{"source": {...}, "packages": [...]
    #   , "vulnerabilities": [{"id": "GHSA/PYSEC/OSV", "aliases":["CVE-..."], ...}]}]}
    for grp in data.get("results", []):
        # packages in this group (name@version or name)
        group_pkgs: list[str] = []
        for pkg in grp.get("packages", []):
            name = pkg.get("package", {}).get("name", "")
            if name:
                group_pkgs.append(name)
                if name not in pkgs:
                    pkgs.append(name)
        for vuln in grp.get("vulnerabilities", []):
            vid = vuln.get("id", "")
            aliases = vuln.get("aliases", []) or []
            cve = next((a for a in aliases if a.startswith("CVE-")), vid)
            intro = vuln.get("details", "")[:200]
            vulns.append({"id": vid, "cve": cve, "summary": intro})
            if cve and cve not in cves:
                cves.append(cve)
            # attribute the CVE to any package in this group
            for name in group_pkgs:
                pkg_cves.setdefault(name, [])
                if cve not in pkg_cves[name]:
                    pkg_cves[name].append(cve)

    res.osv_vulns = vulns
    res.cve_ids = cves
    res.packages = pkgs
    res.pkg_cves = pkg_cves
    return res


def sca_scan(root: Path, with_sbom: bool = True) -> dict[str, Any]:
    """Run the full SCA flow; return a combined dict (SBOM availability + CVEs)."""
    out_dir = _sbom_out_dir()
    sbom = generate_sbom(root) if with_sbom else None
    osv = scan_osv(root)
    leaks = scan_secrets(root)
    return {
        "cves": osv.cve_ids,
        "vulnerabilities": osv.osv_vulns,
        "packages": osv.packages,
        "pkg_cves": osv.pkg_cves,
        "sbom_available": sbom is not None,
        "sbom_path": str(sbom) if sbom else None,
        "sbom_dir": str(out_dir),
        "secrets": leaks,
    }


def scan_secrets(root: Path) -> list[dict]:
    """Grep for common hardcoded-secret patterns (best-effort, opt-in).

    Returns a list of {file, line, kind}. This is a lightweight heuristic on
    top of the committed-code scan; real secret scanning uses dedicated tools.
    """
    import re

    patterns = {
        "aws-akid": r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
        "private-key": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "github-token": r"\bgh[pousr]_[A-Za-z0-9]{20,}\b",
        "slack-token": r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b",
        "generic-secret": r"(?:password|passwd|secret|api[_-]?key|token)\s*=\s*"
        r"(?:\"|')?(?:\$\{)?[A-Za-z0-9_\-]{12,}",
    }
    found: list[dict] = []
    compiled = {k: re.compile(v, re.IGNORECASE) for k, v in patterns.items()}
    skip_dirs = {
        ".git",
        "node_modules",
        ".venv",
        "vendor",
        "__pycache__",
        "dist",
        "build",
    }
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in skip_dirs for part in path.parts):
            continue
        try:
            with open(path, encoding="utf-8", errors="ignore") as fh:
                for lineno, line in enumerate(fh, 1):
                    for kind, rx in compiled.items():
                        if rx.search(line):
                            found.append(
                                {
                                    "file": str(path.relative_to(root)),
                                    "line": lineno,
                                    "kind": kind,
                                    "code": line.strip()[:80],
                                }
                            )
                            break  # one finding per line is enough
        except OSError:
            continue
    return found
