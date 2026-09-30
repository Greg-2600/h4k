# SQLMap integration: automated SQL injection and database takeover.
# Supports detection, exploitation, fingerprinting, and data extraction.
# For authorized SQL injection testing only.
import logging
import subprocess  # nosec B404 - fixed-argv sqlmap wrapper
from collections.abc import Callable
from typing import Any

logger = logging.getLogger("h4k.sqlmap")

SQLMAP_BIN = "sqlmap"


class SQLMapService:
    """SQLMap wrapper for automated SQL injection."""

    def __init__(self, progress: Callable[[str, float], None] | None = None) -> None:
        self.progress = progress or (lambda msg, pct: None)

    def _run(self, argv: list[str], timeout: int = 600) -> dict[str, Any]:
        self.progress(f"[sqlmap] {' '.join(argv[:10])}...", 0)
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
                "stderr": "sqlmap not installed",
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
        url: str,
        method: str = "GET",
        data: str | None = None,
        param: str | None = None,
        cookie: str | None = None,
        headers: dict[str, str] | None = None,
        level: int = 1,
        risk: int = 1,
        technique: str | None = None,
        dbms: str | None = None,
        timeout: int = 300,
        batch: bool = True,
        crawl: int | None = None,
        threads: int = 1,
        output_dir: str | None = None,
    ) -> dict[str, Any]:
        """Scan a URL for SQL injection vulnerabilities."""
        argv = [SQLMAP_BIN, "-u", url]

        if method != "GET":
            argv += ["--method", method]
        if data:
            argv += ["--data", data]
        if param:
            argv += ["-p", param]
        if cookie:
            argv += ["--cookie", cookie]
        if headers:
            for k, v in headers.items():
                argv += ["-H", f"{k}: {v}"]
        if level:
            argv += ["--level", str(level)]
        if risk:
            argv += ["--risk", str(risk)]
        if technique:
            argv += ["--technique", technique]
        if dbms:
            argv += ["--dbms", dbms]
        if batch:
            argv.append("--batch")
        if crawl:
            argv += ["--crawl", str(crawl)]
        if threads:
            argv += ["--threads", str(threads)]
        if output_dir:
            argv += ["--output-dir", output_dir]

        result = self._run(argv, timeout=timeout + 60)

        # Try to parse JSON output if available
        findings = self._parse_findings(result["stdout"])

        return {
            **result,
            "findings": findings,
        }

    def _parse_findings(self, output: str) -> list[dict[str, Any]]:
        """Parse sqlmap output for findings."""
        findings = []
        lines = output.strip().split("\n")
        for line in lines:
            if "SQL injection" in line or "vulnerable" in line.lower():
                findings.append({"type": "sqli", "detail": line.strip()})
        return findings

    def dump_tables(
        self,
        url: str,
        database: str | None = None,
        tables: list[str] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Dump database tables."""
        argv = [SQLMAP_BIN, "-u", url, "--dump"]
        if database:
            argv += ["-D", database]
        if tables:
            argv += ["-T", ",".join(tables)]
        argv.append("--batch")
        result = self._run(argv, timeout=600)
        return result

    def get_databases(self, url: str, **kwargs: Any) -> dict[str, Any]:
        """Enumerate databases."""
        argv = [SQLMAP_BIN, "-u", url, "--dbs", "--batch"]
        result = self._run(argv, timeout=300)
        return result

    def get_tables(self, url: str, database: str, **kwargs: Any) -> dict[str, Any]:
        """Enumerate tables in a database."""
        argv = [SQLMAP_BIN, "-u", url, "-D", database, "--tables", "--batch"]
        result = self._run(argv, timeout=300)
        return result

    def get_columns(
        self, url: str, database: str, table: str, **kwargs: Any
    ) -> dict[str, Any]:
        """Enumerate columns in a table."""
        argv = [
            SQLMAP_BIN,
            "-u",
            url,
            "-D",
            database,
            "-T",
            table,
            "--columns",
            "--batch",
        ]
        result = self._run(argv, timeout=300)
        return result


class SQLMapRunner:
    """High-level SQL injection testing orchestration."""

    def __init__(self, progress: Callable[[str, float], None] | None = None) -> None:
        self.sqlmap = SQLMapService(progress)
        self.progress = progress or (lambda msg, pct: None)

    def full_scan(self, url: str, **kwargs: Any) -> dict[str, Any]:
        """Full SQL injection scan with default parameters."""
        self.progress(f"Starting full SQLi scan on {url}", 10)
        result = self.sqlmap.scan(url, level=3, risk=2, timeout=600, **kwargs)
        self.progress("Scan completed", 100)
        return result

    def blind_sqli_scan(self, url: str, param: str, **kwargs: Any) -> dict[str, Any]:
        """Targeted blind SQL injection scan."""
        return self.sqlmap.scan(
            url, param=param, technique="BEUSTQ", level=5, risk=3, **kwargs
        )


def _as_text(data: str | bytes | None) -> str:
    if data is None:
        return ""
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    return data


def sqlmap_scan(url: str, **kwargs: Any) -> dict[str, Any]:
    """Convenience function for API integration."""
    return SQLMapService().scan(url, **kwargs)
