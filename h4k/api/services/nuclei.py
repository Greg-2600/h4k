# Nuclei integration: fast template-based vulnerability scanner.
# Supports nuclei templates, custom templates, and scanning with various protocols.
# For authorized vulnerability scanning only.
import contextlib
import json
import logging
import subprocess  # nosec B404 - fixed-argv nuclei wrapper
from collections.abc import Callable
from pathlib import Path
from typing import Any

logger = logging.getLogger("h4k.nuclei")

NUCLEI_BIN = "nuclei"

# Offline template bundle: container path first, repo checkout second.
# Mirrors the semgrep offline-registry pattern so CVE-template scans work
# with no network (no template update fetch).
BUNDLE_CANDIDATES = (
    Path("/opt/h4k/data/nuclei-templates"),
    Path(__file__).resolve().parent.parent.parent / "data" / "nuclei-templates",
)


def bundle_dir() -> Path | None:
    """The offline template bundle dir, or None when not installed."""
    for cand in BUNDLE_CANDIDATES:
        try:
            if cand.is_dir() and any(cand.iterdir()):
                return cand
        except OSError:
            continue
    return None


def bundle_templates() -> list[str]:
    """Sorted template IDs shipped in the offline bundle."""
    bdir = bundle_dir()
    if bdir is None:
        return []
    try:
        return sorted(p.stem for p in bdir.glob("*.yaml"))
    except OSError:
        return []


class NucleiService:
    """Nuclei template-based vulnerability scanner."""

    def __init__(self, progress: Callable[[str, float], None] | None = None) -> None:
        self.progress = progress or (lambda msg, pct: None)

    def _run(self, argv: list[str], timeout: int = 300) -> dict[str, Any]:
        self.progress(f"[nuclei] {' '.join(argv[:8])}...", 0)
        try:
            proc = subprocess.run(  # nosec B603 - fixed argv, no shell
                argv,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            return {
                "stdout": proc.stdout or "",
                "stderr": proc.stderr or "",
                "rc": proc.returncode,
                "success": proc.returncode == 0,
                "timed_out": False,
            }
        except subprocess.TimeoutExpired as exc:
            return {
                "stdout": _as_text(exc.stdout),
                "stderr": _as_text(exc.stderr),
                "rc": None,
                "success": False,
                "timed_out": True,
            }
        except FileNotFoundError:
            return {
                "stdout": "",
                "stderr": "nuclei not installed",
                "rc": -1,
                "success": False,
                "timed_out": False,
            }
        except Exception as exc:  # pragma: no cover - defensive
            return {
                "stdout": "",
                "stderr": str(exc),
                "rc": -1,
                "success": False,
                "timed_out": False,
            }

    def scan(
        self,
        target: str,
        templates: list[str] | None = None,
        severity: str | None = None,
        tags: list[str] | None = None,
        exclude_tags: list[str] | None = None,
        rate_limit: int = 150,
        timeout: int = 300,
        verbose: bool = False,
        offline: bool = False,
    ) -> dict[str, Any]:
        """Scan a target with nuclei.

        `offline=True` runs only the bundled templates (no update fetch),
        so the scan works with no network.
        """
        argv = [NUCLEI_BIN, "-target", target, "-jsonl", "-silent"]
        if offline:
            bdir = bundle_dir()
            if bdir is not None:
                argv += ["-t", str(bdir)]
            elif not templates:
                return {
                    "stdout": "",
                    "stderr": "offline bundle not installed",
                    "rc": -1,
                    "success": False,
                    "timed_out": False,
                    "findings": [],
                    "finding_count": 0,
                    "offline": True,
                }
        if templates:
            for t in templates:
                argv += ["-t", t]
        if severity:
            argv += ["-severity", severity]
        if tags:
            for t in tags:
                argv += ["-tags", t]
        if exclude_tags:
            for t in exclude_tags:
                argv += ["-exclude-tags", t]
        argv += ["-rate-limit", str(rate_limit)]
        if verbose:
            argv.append("-v")

        result = self._run(argv, timeout=timeout + 60)

        # Parse JSON lines output
        findings = []
        for line in result["stdout"].strip().split("\n"):
            if line.strip():
                with contextlib.suppress(json.JSONDecodeError):
                    findings.append(json.loads(line))

        return {
            **result,
            "findings": findings,
            "finding_count": len(findings),
            "offline": offline,
        }

    def update_templates(self) -> dict[str, Any]:
        """Update nuclei templates to latest."""
        return self._run([NUCLEI_BIN, "-update-templates"], timeout=300)

    def list_templates(self, tags: list[str] | None = None) -> dict[str, Any]:
        """List available templates."""
        argv = [NUCLEI_BIN, "-tl"]
        if tags:
            for t in tags:
                argv += ["-tags", t]
        return self._run(argv, timeout=60)

    def validate_templates(self, template_paths: list[str]) -> dict[str, Any]:
        """Validate template syntax."""
        argv = [NUCLEI_BIN, "-validate"]
        for t in template_paths:
            argv += ["-t", t]
        return self._run(argv, timeout=60)


class NucleiRunner:
    """High-level orchestration for CTF/vuln scanning."""

    def __init__(self, progress: Callable[[str, float], None] | None = None) -> None:
        self.nuclei = NucleiService(progress)
        self.progress = progress or (lambda msg, pct: None)

    def full_scan(
        self,
        target: str,
        severity: str = "critical,high,medium",
        exclude_tags: list[str] | None = None,
        rate_limit: int = 150,
        timeout: int = 300,
    ) -> dict[str, Any]:
        """Full vulnerability scan with default critical+high+medium."""
        return self.nuclei.scan(
            target=target,
            severity=severity,
            exclude_tags=exclude_tags,
            rate_limit=rate_limit,
            timeout=timeout,
        )

    def cve_scan(self, target: str, cves: list[str]) -> dict[str, Any]:
        """Scan for specific CVEs."""
        templates = [f"cves/{cve}" for cve in cves]
        return self.nuclei.scan(target=target, templates=templates)

    def technology_scan(self, target: str, tech: list[str]) -> dict[str, Any]:
        """Scan for specific technologies."""
        return self.nuclei.scan(target=target, tags=tech)


def _as_text(data: str | bytes | None) -> str:
    if data is None:
        return ""
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    return data


def _finding_host(finding: dict[str, Any], fallback: str) -> str:
    """Best-effort host for a nuclei finding (matched URL -> host)."""
    matched = str(finding.get("matched") or finding.get("host") or "")
    host = matched.split("://")[-1].split("/")[0].split(":")[0].strip()
    return host or fallback


def _finding_severity(finding: dict[str, Any]) -> str:
    raw_info = finding.get("info")
    info: dict[str, Any] = raw_info if isinstance(raw_info, dict) else {}
    sev = str(info.get("severity") or finding.get("severity") or "unknown")
    return sev.strip().lower() or "unknown"


def to_ledger(target: str, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Map nuclei findings onto engagement vuln records (ledger entries).

    Pure function: no I/O. Each entry carries host/name/severity plus the
    template id as the module and the CVE reference when present.
    """
    out: list[dict[str, Any]] = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        raw_info = f.get("info")
        info: dict[str, Any] = raw_info if isinstance(raw_info, dict) else {}
        name = str(
            info.get("name")
            or f.get("template")
            or f.get("template-id")
            or "nuclei finding"
        )
        refs: list[str] = []
        for key in ("reference", "reference-links"):
            val = info.get(key)
            if isinstance(val, list):
                refs.extend(str(v) for v in val)
            elif val:
                refs.append(str(val))
        meta_raw = info.get("metadata")
        meta: dict[str, Any] = meta_raw if isinstance(meta_raw, dict) else {}
        out.append(
            {
                "host": _finding_host(f, target),
                "name": name,
                "severity": _finding_severity(f),
                "cwe": str(meta.get("cwe") or info.get("cwe") or ""),
                "module": str(f.get("template") or f.get("template-id") or "nuclei"),
                "reference": refs[0] if refs else "",
            }
        )
    return out


def sandbox_result(target: str) -> dict[str, Any]:
    """Deterministic offline stand-in for nuclei (sandbox/e2e only)."""
    finding = {
        "template": "h4k-log4shell",
        "template-id": "h4k-log4shell",
        "matched": f"http://{target}/?h4k_probe=sandbox",
        "info": {
            "name": "Apache Log4Shell (CVE-2021-44228)",
            "severity": "critical",
            "metadata": {"cve": "CVE-2021-44228", "cwe": "CWE-502"},
        },
    }
    return {
        "stdout": json.dumps(finding),
        "stderr": "",
        "rc": 0,
        "success": True,
        "timed_out": False,
        "findings": [finding],
        "finding_count": 1,
        "offline": True,
        "sandbox": True,
    }


def nuclei_scan(
    target: str,
    templates: list[str] | None = None,
    severity: str | None = None,
    offline: bool = False,
    **kwargs: Any,
) -> dict[str, Any]:
    """Convenience function for API integration."""
    runner = NucleiRunner()
    return runner.nuclei.scan(
        target=target, templates=templates, severity=severity, offline=offline, **kwargs
    )
