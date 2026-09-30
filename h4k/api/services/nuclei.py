# Nuclei integration: fast template-based vulnerability scanner.
# Supports nuclei templates, custom templates, and scanning with various protocols.
# For authorized vulnerability scanning only.
import contextlib
import json
import logging
import subprocess  # nosec B404 - fixed-argv nuclei wrapper
from collections.abc import Callable
from typing import Any

logger = logging.getLogger("h4k.nuclei")

NUCLEI_BIN = "nuclei"


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
    ) -> dict[str, Any]:
        """Scan a target with nuclei."""
        argv = [NUCLEI_BIN, "-target", target, "-jsonl", "-silent"]
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


def nuclei_scan(
    target: str,
    templates: list[str] | None = None,
    severity: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """Convenience function for API integration."""
    runner = NucleiRunner()
    return runner.nuclei.scan(
        target=target, templates=templates, severity=severity, **kwargs
    )
