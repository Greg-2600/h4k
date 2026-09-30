# John the Ripper integration: offline password hash cracking.
# Supports multiple hash formats, wordlists, rules and sessions. All runs are
# local and offline; nothing is sent over the network.
import contextlib
import logging
import os
import subprocess  # nosec B404 - fixed-argv john wrapper
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

logger = logging.getLogger("h4k.john")

JOHN_BIN = "john"
WORDLISTS_DIR = Path("/opt/h4k/data/wordlists")
DEFAULT_WORDLIST = WORDLISTS_DIR / "rockyou.txt"

# Formats worth trying for a CTF in this order (cheap + common first).
CTF_FORMATS = (
    "raw-md5",
    "raw-sha1",
    "raw-sha256",
    "nt",
    "md5crypt",
    "sha256crypt",
    "sha512crypt",
    "bcrypt",
    "netntlmv2",
)


class JohnService:
    """John the Ripper wrapper for hash cracking."""

    def __init__(self, progress: Callable[[str, float], None] | None = None) -> None:
        self.progress = progress or (lambda msg, pct: None)

    def _run(self, argv: list[str], timeout: int = 3600) -> dict[str, Any]:
        self.progress(f"[john] {' '.join(argv[:6])}...", 0)
        try:
            proc = subprocess.run(  # nosec B603 - fixed argv, no shell
                argv, capture_output=True, text=True, timeout=timeout, check=False
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
                "stderr": "john not installed",
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

    def crack(
        self,
        hashes: str | list[str],
        format: str | None = None,
        wordlist: str | None = None,
        max_time: int = 300,
    ) -> dict[str, Any]:
        """Crack hashes from a string or list; returns parsed `cracked`."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".hashes", delete=False
        ) as fh:
            content = "\n".join(hashes) if isinstance(hashes, list) else hashes
            fh.write(content)
            hash_file = fh.name
        try:
            argv = self._build_argv(hash_file, format, wordlist, max_time)
            result = self._run(argv, timeout=max_time + 60)
            show_res = self._run(self._show_argv(hash_file, format))
            return {**result, "cracked": self._parse_show(show_res["stdout"])}
        finally:
            with contextlib.suppress(OSError):
                os.unlink(hash_file)

    def crack_file(
        self,
        hash_file: str,
        format: str | None = None,
        wordlist: str | None = None,
        max_time: int = 300,
    ) -> dict[str, Any]:
        """Crack hashes from an existing file."""
        result = self._run(
            self._build_argv(hash_file, format, wordlist, max_time),
            timeout=max_time + 60,
        )
        show_res = self._run(self._show_argv(hash_file, format))
        return {**result, "cracked": self._parse_show(show_res["stdout"])}

    def _build_argv(
        self,
        hash_file: str,
        format: str | None,
        wordlist: str | None,
        max_time: int,
    ) -> list[str]:
        argv = [JOHN_BIN]
        if format:
            argv += ["--format", format]
        if wordlist:
            argv += ["--wordlist", wordlist]
        elif DEFAULT_WORDLIST.exists():
            argv += ["--wordlist", str(DEFAULT_WORDLIST)]
        if max_time:
            argv += ["--max-run-time", str(max_time)]
        argv.append(hash_file)
        return argv

    def _show_argv(self, hash_file: str, format: str | None) -> list[str]:
        argv = [JOHN_BIN, "--show"]
        if format:
            argv += ["--format", format]
        argv.append(hash_file)
        return argv

    @staticmethod
    def _parse_show(output: str) -> list[dict[str, Any]]:
        """Parse `john --show` output (hash:password[:user])."""
        cracked: list[dict[str, Any]] = []
        for line in output.strip().split("\n"):
            if ":" not in line or line.startswith("#"):
                continue
            parts = line.split(":", 2)
            if len(parts) >= 2:
                cracked.append(
                    {
                        "hash": parts[0],
                        "password": parts[1],
                        "username": parts[2] if len(parts) > 2 else None,
                    }
                )
        return cracked

    def status(self) -> dict[str, Any]:
        """Parse the running session status (best-effort)."""
        result = self._run([JOHN_BIN, "--status"])
        info: dict[str, Any] = {"running": False, "raw": result["stdout"]}
        for line in result["stdout"].split("\n"):
            low = line.lower()
            if "guesses:" in low:
                info["guesses"] = line.split(":", 1)[1].strip()
            elif "time:" in low:
                info["time"] = line.split(":", 1)[1].strip()
            elif "c/s:" in low:
                info["cps"] = line.split(":", 1)[1].strip()
            elif "trying:" in low:
                info["trying"] = line.split(":", 1)[1].strip()
            elif "active" in low:
                info["running"] = True
        return info

    def list_formats(self) -> list[str]:
        """List locally supported hash formats."""
        result = self._run([JOHN_BIN, "--list=formats"])
        return [
            line.strip()
            for line in result["stdout"].split("\n")
            if line.strip() and not line.startswith("#")
        ]

    @staticmethod
    def wordlist_stats(wordlist: str | None = None) -> dict[str, Any]:
        """Word count for a wordlist (counted in-process, no shell pipe)."""
        path = Path(wordlist) if wordlist else DEFAULT_WORDLIST
        if not path.exists():
            return {"wordlist": str(path), "lines": 0, "error": "missing"}
        try:
            count = 0
            with path.open("rb") as fh:
                for _ in fh:
                    count += 1
            return {"wordlist": str(path), "lines": count}
        except OSError as exc:
            return {"wordlist": str(path), "lines": 0, "error": str(exc)}


class JohnRunner:
    """High-level orchestration for CTF hash cracking."""

    def __init__(self, progress: Callable[[str, float], None] | None = None) -> None:
        self.john = JohnService(progress)
        self.progress = progress or (lambda msg, pct: None)

    def crack_ctf_hashes(
        self,
        hashes: str | list[str],
        formats: list[str] | None = None,
        wordlist: str | None = None,
        max_time_per_format: int = 60,
    ) -> dict[str, Any]:
        """Try a bounded set of common formats, stopping once each is cracked.

        Every hash is attempted once per format. `max_time_per_format` keeps a
        single unlucky format from monopolising the whole run.
        """
        formats = formats or list(CTF_FORMATS)
        total = len(hashes) if isinstance(hashes, list) else 1
        pending = list(hashes) if isinstance(hashes, list) else [hashes]
        results: dict[str, Any] = {
            "total": total,
            "cracked": [],
            "by_format": {},
            "formats_tried": [],
        }

        for fmt in formats:
            if not pending:
                break
            self.progress(f"trying format: {fmt}", 0)
            res = self.john.crack(
                pending, format=fmt, wordlist=wordlist, max_time=max_time_per_format
            )
            results["formats_tried"].append(fmt)
            cracked = res.get("cracked") or []
            if cracked:
                results["by_format"][fmt] = cracked
                results["cracked"].extend(cracked)
                done = {c["hash"] for c in cracked}
                pending = [h for h in pending if h not in done]
                self.progress(f"cracked {len(cracked)} with {fmt}", 0)

        results["remaining"] = pending
        return results


def _as_text(data: str | bytes | None) -> str:
    if data is None:
        return ""
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    return data


def john_crack(
    hashes: str | list[str], format: str | None = None, **kwargs: Any
) -> dict:
    """Convenience one-shot crack."""
    return JohnService().crack(hashes, format=format, **kwargs)
