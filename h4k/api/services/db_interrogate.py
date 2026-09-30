# Database interrogation and API enumeration.
# Enumerates internal APIs and extracts candidate secrets/flag-shaped strings
# from SQLite DBs, JSON blobs, environment variables and config files. Pointed
# at an authorized host/container only.
import json
import logging
import os
import re
import sqlite3
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

logger = logging.getLogger("h4k.db_interrogate")

# Where to look. A blind walk of "/" is both slow and noisy; these are the
# places application data actually lives.
# Search roots only; no temp file is created here (B108 is a false positive).
DEFAULT_SEARCH_ROOTS = (
    "/opt",
    "/app",
    "/data",
    "/srv",
    "/tmp",
    "/home",
    "/var/lib",
)  # nosec B108 - read-only search root
MAX_FILES = 200
MAX_FILE_BYTES = 512_000

_FLAG_PATTERNS = (
    re.compile(r"flag\{[^}]{1,200}\}", re.I),
    re.compile(r"ctf\{[^}]{1,200}\}", re.I),
    re.compile(r"key\{[^}]{1,200}\}", re.I),
    re.compile(
        r"(?:secret|password|passwd|api[_-]?key|token)"
        r"[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9_\-]{6,})",
        re.I,
    ),
)

_DB_SUFFIXES = {".db", ".sqlite", ".sqlite3", ".db3"}


class DBInterrogate:
    """Interrogate databases and internal APIs for flags/secrets."""

    def __init__(
        self,
        progress: Callable[[str, float], None] | None = None,
        search_roots: list[str] | None = None,
    ) -> None:
        self.progress = progress or (lambda msg, pct: None)
        self.search_roots = search_roots or list(DEFAULT_SEARCH_ROOTS)

    def interrogate_all(self, target: str = "127.0.0.1") -> dict[str, Any]:
        """Full interrogation of target."""
        results: dict[str, Any] = {
            "target": target,
            "apis": self._enumerate_apis(target),
            "databases": self._search_files(target_suffixes=True),
            "env_vars": self._extract_env_secrets(),
            "config_files": self._scan_config_files(),
        }
        results["flags"] = self._find_flags(results)
        return results

    @staticmethod
    def _find_flags(results: dict[str, Any]) -> list[str]:
        text = json.dumps(results, default=str)
        found: set[str] = set()
        for pattern in _FLAG_PATTERNS:
            for match in pattern.findall(text):
                found.add(match if isinstance(match, str) else match[0])
        return sorted(found)

    def _iter_candidate_files(self, suffixes: set[str]) -> list[Path]:
        found: list[Path] = []
        seen: set[Path] = set()
        for root in self.search_roots:
            base = Path(root)
            if not base.exists():
                continue
            for path in base.rglob("*"):
                if len(found) >= MAX_FILES:
                    return found
                try:
                    if not path.is_file() or path.suffix.lower() not in suffixes:
                        continue
                    resolved = path.resolve()
                    if resolved in seen:
                        continue
                    if path.stat().st_size > MAX_FILE_BYTES:
                        continue
                    seen.add(resolved)
                    found.append(path)
                except OSError:
                    continue
        return found

    def _search_files(self, target_suffixes: bool = True) -> dict[str, Any]:
        suffixes = _DB_SUFFIXES | {".json"}
        results: dict[str, Any] = {}
        for path in self._iter_candidate_files(suffixes):
            try:
                if path.suffix.lower() in _DB_SUFFIXES:
                    results[str(path)] = self._dump_sqlite(path)
                else:
                    results[str(path)] = self._read_json(path)
            except Exception as exc:  # pragma: no cover - defensive
                results[str(path)] = {"error": str(exc)}
        return results

    @staticmethod
    def _dump_sqlite(db_path: Path) -> dict[str, Any]:
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = [row[0] for row in cursor.fetchall()]
            data: dict[str, Any] = {}
            for table in tables[:10]:
                try:
                    # `table` comes from sqlite_master of a DB opened RO; no user input.
                    cursor.execute(f"SELECT * FROM {table} LIMIT 100")  # nosec B608
                    cols = [desc[0] for desc in cursor.description or []]
                    rows = cursor.fetchall()
                    data[table] = [dict(zip(cols, row, strict=False)) for row in rows]
                except sqlite3.Error:
                    continue
            conn.close()
            return {"tables": tables, "data": data}
        except sqlite3.Error as exc:
            return {"error": str(exc)}

    @staticmethod
    def _read_json(json_path: Path) -> Any:
        try:
            return json.loads(json_path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError) as exc:
            return {"error": str(exc)}

    @staticmethod
    def _extract_env_secrets() -> dict[str, str]:
        sensitive = (
            "PASSWORD",
            "SECRET",
            "TOKEN",
            "API_KEY",
            "PRIVATE_KEY",
            "JWT",
            "SESSION",
            "CREDENTIAL",
        )
        out: dict[str, str] = {}
        for key, value in os.environ.items():
            if any(marker in key.upper() for marker in sensitive):
                out[key] = value[:100]
        return out

    def _scan_config_files(self) -> dict[str, Any]:
        patterns = (
            "/etc/passwd",
            "/etc/hosts",
            "/etc/environment",
            "/root/.bash_history",
            "/root/.ssh/config",
        )
        results: dict[str, Any] = {}
        for pattern in patterns:
            path = Path(pattern)
            try:
                if path.is_file() and path.stat().st_size < MAX_FILE_BYTES:
                    results[str(path)] = path.read_text(
                        encoding="utf-8", errors="replace"
                    )[:5000]
            except OSError as exc:  # pragma: no cover - defensive
                results[str(path)] = {"error": str(exc)}
        return results

    @staticmethod
    def _http_json(url: str, timeout: int = 3) -> dict[str, Any]:
        req = urllib.request.Request(url, headers={"User-Agent": "h4k/1.0"})
        # Only operator-supplied local endpoints; not user-controlled remote URLs.
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310
            body = resp.read().decode("utf-8", errors="replace")
        try:
            return json.loads(body)
        except ValueError:
            return {"status": resp.status, "body": body[:2000]}

    def _enumerate_apis(self, target: str) -> dict[str, Any]:
        ports = {
            4546: "zhc3_orchestrator",
            11434: "ollama",
            11435: "ollama_alt",
            18799: "cad_worker",
            9000: "portainer",
            9443: "portainer_tls",
            8080: "http_alt",
            8443: "https_alt",
        }
        apis: dict[str, Any] = {}
        for port, name in ports.items():
            try:
                apis[name] = {
                    "port": port,
                    **self._http_json(f"http://{target}:{port}"),
                }
            except Exception as exc:
                apis[name] = {"port": port, "error": str(exc)}
        return apis

    def interrogate_zhc3(
        self, base_url: str = "http://127.0.0.1:4546"
    ) -> dict[str, Any]:
        """Probe a small set of read-only zhc3 orchestrator endpoints."""
        endpoints = (
            "/inventions",
            "/system/state",
            "/system/db_status",
            "/metrics/quality_trends",
            "/suggestions",
        )
        results: dict[str, Any] = {}
        for ep in endpoints:
            try:
                results[ep] = self._http_json(f"{base_url}{ep}", timeout=5)
            except Exception as exc:
                results[ep] = {"error": str(exc)}
        return results

    def interrogate_ollama(
        self, base_url: str = "http://127.0.0.1:11434"
    ) -> dict[str, Any]:
        """List models exposed by a local Ollama daemon."""
        try:
            return {"models": self._http_json(f"{base_url}/api/tags", timeout=5)}
        except Exception as exc:
            return {"models": {"error": str(exc)}}

    def interrogate_cad_worker(
        self, base_url: str = "http://127.0.0.1:18799"
    ) -> dict[str, Any]:
        """Read a CAD worker's health endpoint."""
        try:
            return {"health": self._http_json(f"{base_url}/health", timeout=5)}
        except Exception as exc:
            return {"health": {"error": str(exc)}}
