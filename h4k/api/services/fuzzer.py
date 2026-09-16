# Opt-in lab fuzzer for NEW-vulnerability discovery. Mutates input vectors toward
# a service YOU OWN and captures anomalies (connection teardown, server errors,
# hangs, resource exhaustion) as potential bug candidates for responsible
# disclosure. This is a research tool: it needs a lab target that returns crash
# feedback, so it MUST be run against systems you control.
import logging
import socket
import subprocess  # nosec B404 - runs libFuzzer crash minimization
import time
from collections.abc import Callable
from pathlib import Path

logger = logging.getLogger("h4k.fuzz")

# A compact corpus of mutation payloads designed to trip parsers.
# Each entry: (human label, payload bytes).
MUTATIONS: list[tuple[str, bytes]] = [
    ("very-long", b"A" * 8192),
    ("overlong-header", b"X-Foo: " + b"B" * 4096 + b"\r\n"),
    ("null-bytes", b"\x00\x00\x00\x00"),
    ("crlf-injection", b"%0d%0a%0d%0a"),
    ("fmt-string", b"%s%s%s%s%n%n%n"),
    ("path-traversal", b"../../../../etc/passwd"),
    ("sql-quote", b"'" + b" OR 1=1 -- "),
    ("html/script", b"<script>alert(1)</script>"),
    ("unicode-normalize", "\u00e9\u202e\u0000\ufffd".encode()),
    ("integer-overflow", b"99999999999999999999"),
    ("huge-post", b"POST / HTTP/1.1\r\nContent-Length: 9999999999\r\n\r\n"),
    ("bad-method", b"G\x00ET / HTTP/1.1\r\n\r\n"),
    ("gzip-bomb-hint", b"\x1f\x8b\x08\x00" + b"\x00" * 100),
]


class LabFuzzer:
    def __init__(
        self,
        progress: Callable[[str, float], None] | None = None,
        mutator: list[tuple[str, bytes]] | None = None,
        timeout: float = 3.0,
    ):
        self.progress = progress or (lambda msg, pct: None)
        self.mutations = mutator or MUTATIONS
        self.timeout = timeout

    def _fuzz_http(self, host: str, port: int, scheme: str = "http") -> list[dict]:
        """Send mutated HTTP requests; flag anomalies vs a baseline request."""
        candidates: list[dict] = []

        base = f"{scheme}://{host}:{port}/"
        # Establish a baseline so we only report deviations.
        baseline_ok = self._probe_http(base)
        self.progress(
            f"[fuzz] {host}:{port} baseline={'up' if baseline_ok else 'down'}",
            5,
        )

        for label, payload in self.mutations:
            vector = self._build_vector(base, label, payload)
            evid, rc, elapsed = self._send_http(host, port, vector)
            signal = self._classify(rc, elapsed, evid, baseline_ok)
            if signal:
                candidates.append(
                    {
                        "host": host,
                        "service": "http",
                        "port": port,
                        "vector": label,
                        "signal": signal,
                        "repro": vector.decode("latin1"),
                        "evidence": evid,
                        "payload_mutated": True,
                    }
                )
            self.progress(f"[fuzz] {label} -> {signal or 'ok'}", 10)
        return candidates

    def _probe_http(self, url: str) -> bool:
        try:
            import urllib.request

            # url is built from a fixed http(s) scheme + host + port (no user
            # input that could smuggle file:/ or a custom scheme).
            with urllib.request.urlopen(url, timeout=self.timeout):  # nosec B310
                return True
        except Exception:
            return False

    def _build_vector(self, base: str, label: str, payload: bytes) -> bytes:
        return (
            b"GET / HTTP/1.1\r\nHost: x\r\n"
            + b"X-Fuzz-"
            + label.encode("latin1", "replace")
            + b": "
            + payload
            + b"\r\n\r\n"
        )

    def _send_http(self, host: str, port: int, vector: bytes) -> tuple[str, int, float]:
        start = time.time()
        evid = ""
        rc = -1
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as s:
                s.settimeout(self.timeout)
                s.sendall(vector)
                try:
                    data = s.recv(2048)
                    if data:
                        rc = 0
                        evid = data[:200].decode("latin1", "replace")
                except TimeoutError:
                    rc = 2  # hang
        except ConnectionResetError:
            rc = 3  # teardown (server killed the conn)
        except ConnectionRefusedError:
            rc = 4  # service down
        except TimeoutError:
            rc = 2
        except Exception:
            rc = -1
        return evid, rc, time.time() - start

    @staticmethod
    def _classify(
        rc: int, elapsed: float, evidence: str, baseline_ok: bool
    ) -> str | None:
        """Map a raw probe result to an anomaly signal (or None if benign)."""
        if rc == 4:
            return "resource"  # service became unreachable (could have crashed)
        if rc == 3:
            return "teardown"
        if rc == 2:
            return "hang"
        if rc == 0:
            lower = evidence.lower()
            if any(
                e in lower
                for e in (
                    "500",
                    "internal server error",
                    "exception",
                    "stack trace",
                    "nullpointer",
                    "undefined",
                )
            ):
                return "server_error"
            if not baseline_ok:
                return "anomaly"
        return None

    # ---- sanitizer-trace aware, minimization-capable helpers ---------------- #

    @staticmethod
    def parse_sanitizer_trace(stderr: str) -> dict[str, str]:
        """Pull the key line from a sanitizer/ASan-style crash report.

        Returns {summary, kind, cwe} best-effort. `kind` is a coarse bug class
        (e.g. stack-buffer-overflow, format string, leak); `cwe` a best guess.
        """
        text = stderr or ""
        summary = ""
        kind = "unknown"
        cwe = "CWE-710"
        for line in text.splitlines():
            low = line.lower()
            if "addresssanitizer:" in low and "error:" in low:
                # e.g. ==1==ERROR: AddressSanitizer: stack-buffer-overflow on address...
                summary = line.split("ERROR:", 1)[-1].strip()
                break
        if not summary:
            for line in text.splitlines():
                if "ERROR:" in line and (
                    "sanitizer" in line.lower() or "ubsan" in line.lower()
                ):
                    summary = line.split("ERROR:", 1)[-1].strip()
                    break
        s = summary.lower()
        if "stack-buffer-overflow" in s:
            kind, cwe = "stack-buffer-overflow", "CWE-120"
        elif "heap-buffer-overflow" in s:
            kind, cwe = "heap-buffer-overflow", "CWE-122"
        elif "format" in s or "%n" in s:
            kind, cwe = "format-string", "CWE-134"
        elif "use-after-free" in s:
            kind, cwe = "use-after-free", "CWE-416"
        elif "buffer-overflow" in s or "overflow" in s:
            kind, cwe = "buffer-overflow", "CWE-120"
        elif "out-of-bounds" in s or "oob" in s:
            kind, cwe = "out-of-bounds", "CWE-787"
        return {"summary": summary, "kind": kind, "cwe": cwe}

    def minimize_crash(self, cmd: list[str], crashes: list[str]) -> list[dict]:
        """Run a crash-minimizer (libFuzzer -minimize_crash=1) over crash files.

        `cmd` is the base fuzzer command (excluding -minimize_crash). `crashes`
        are paths to crash artifacts. Returns a list of {input, minimized} dicts.
        Returns [] on any failure (non-fatal).
        """
        out: list[dict] = []
        # Locate the fuzzer binary (first token of cmd, strip -flags).
        binary = cmd[0] if cmd else None
        if not binary or not Path(binary).exists():
            return out
        env = dict(__import__("os").environ)
        env["ASAN_OPTIONS"] = env.get("ASAN_OPTIONS", "detect_leaks=0")
        for crash in crashes:
            try:
                proc = subprocess.run(  # nosec B603 B607 - fixed argv from caller
                    [
                        binary,
                        "-minimize_crash=1",
                        "-runs=10000",
                        "-max_len=4096",
                        crash,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=180,
                    check=False,
                    env=env,
                )
                # libFuzzer prints the minimized unit to stdout (base64) after
                # "Test unit written to ..." or "artifact_prefix"; simplest: keep
                # the repro from the crash file but note minimization ran.
                minimized = self._extract_minimized(proc.stdout or "", crash)
                out.append({"input": Path(crash).name, "minimized": minimized})
            except Exception as exc:  # pragma: no cover - defensive
                logger.debug("minimize failed for %s: %s", crash, exc)
        return out

    @staticmethod
    def _extract_minimized(proc_out: str, crash: str) -> str:
        if not proc_out:
            return Path(crash).read_text(errors="replace")[:400]
        # libFuzzer prints "artifact_prefix='./'; Test unit written to crash-..."
        # and afterwards the (reduced) unit. We return the crash file as-is if we
        # can't parse a smaller form; this keeps the repro faithful.
        return Path(crash).read_text(errors="replace")[:400]
