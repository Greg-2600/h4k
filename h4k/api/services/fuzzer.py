# Opt-in lab fuzzer for NEW-vulnerability discovery. Mutates input vectors toward
# a service you OWN and captures anomalies (connection teardown, server errors,
# hangs, resource exhaustion) as potential bug candidates for responsible
# disclosure. This is a research tool: it needs a lab target that returns crash
# feedback, so it MUST be run against systems you control.
#
# HONEST SCOPE OF THIS FUZZER -- read before trusting a number it reports.
# This is *signal-guided* black-box fuzzing, not coverage-guided fuzzing. It
# has no instrumentation and therefore no edge/coverage feedback, so it
# cannot tell "this input reached new code" from "this input looks new".
# Its corpus grows on discovering a crash the run has not seen before, which
# is a proxy for interestingness and a much weaker signal than coverage.
# When you want real coverage guidance, use the libFuzzer/AFL path in
# services/ossfuzz.py, which runs an instrumented binary and does have the
# feedback loop. The two are complementary, not alternatives.
#
# It is a fuzzer rather than a fixed payload probe: mutations are generated
# from a seeded corpus with the standard bit/byte/arithmetic/boundary/splice
# operators, so two runs with the same seed replay the same sequence. That
# reproducibility is the point -- an unreproducible crash is a rumour.
import logging
import os
import random
import socket
import subprocess  # nosec B404 - runs libFuzzer crash minimization
import time
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar

from services import crashes as crash_mod

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
    # Escapes, not literals: U+202E is a right-to-left override, and keeping
    # it as a source escape avoids embedding bidi control characters in the
    # file itself (which trips bandit B613 and is genuinely hard to review).
    ("unicode-normalize", "\u00e9\u202e\u0000\ufffd".encode()),
    ("integer-overflow", b"99999999999999999999"),
    ("huge-post", b"POST / HTTP/1.1\r\nContent-Length: 9999999999\r\n\r\n"),
    ("bad-method", b"G\x00ET / HTTP/1.1\r\n\r\n"),
    ("gzip-bomb-hint", b"\x1f\x8b\x08\x00" + b"\x00" * 100),
]

# Boundary values that break length/count/index arithmetic far more often
# than a random byte does. Same set libFuzzer and AFL++ ship, because it is
# the set that actually triggers off-by-one and truncation bugs.
INTERESTING_BYTES: tuple[int, ...] = (
    0,
    1,
    16,
    32,
    64,
    100,
    127,
    128,
    129,
    165,
    200,
    254,
    255,
)
INTERESTING_U32: tuple[int, ...] = (
    0x00000000,
    0x00000001,
    0x0000000F,
    0x00000010,
    0x0000001F,
    0x00000020,
    0x0000007F,
    0x00000080,
    0x000000FF,
    0x00000100,
    0x00007FFF,
    0x00008000,
    0x0000FFFF,
    0x00010000,
    0x00FFFFFF,
    0x01000000,
    0x10000000,
    0x3FFFFFFF,
    0x40000000,
    0x7FFFFFFF,
    0x80000000,
    0xFFFFFFFF,
)

# Protocol tokens worth splicing in. Format-string and traversal markers
# survive as literals, and repetition triggers is the cheapest way into a
# format-param bug -- which is B2 in vulnlab.
DICT_TOKENS: tuple[bytes, ...] = (
    b"%s",
    b"%n",
    b"%x",
    b"%p",
    b"%d",
    b"%c",
    b"AAAA",
    b"....//",
    b"../",
    b"..\\",
    b"%00",
    b"%0a",
    b"%0d",
    b"\\x00",
    b"'",
    b'"',
    b"`",
    b"$(id)",
    b";",
    b"|",
    b"&&",
    b"\xff\xfe",
    b"\xef\xbb\xbf",
    b"</script>",
    b"1e309",
    b"9999999999999999999999",
)

MAX_CORPUS = 256
MAX_INPUT = 16384

LIBFUZZER_MERGED = "minimized-from-*"


def libfuzzer_minimize(
    binary: str, crash: Path, timeout: int = 300
) -> tuple[str, bool]:
    """Actually reduce a crash, or say we couldn't.

    Returns (minimized_text, reduced).

    libFuzzer's `-minimize_crash=1` writes its results as
    `minimized-from-<sha1>` files into the *current working directory* -- it
    does not overwrite the input, and it does not honour `-merge=1` for a
    single file (`-merge` needs two or more corpus dirs and errors out). So
    the reduction runs in a clean temp cwd and the smallest artifact it
    produced is read back from there.

    The previous implementation ran the binary and then returned the
    *unmodified* crash file on both the success and the failure branch -- two
    identical branches, which is the signature of a reducer that never
    reduced anything. Here we read back what libFuzzer really wrote, and only
    report a reduction when that file exists and is genuinely smaller.
    """
    from services import sanitizer

    workdir = crash.parent / f".minimize-{crash.name}"
    try:
        workdir.mkdir(parents=True, exist_ok=True)
        target = workdir / crash.name
        target.write_bytes(crash.read_bytes())
        original = len(target.read_bytes())

        env = dict(os.environ)
        env.update(sanitizer.trace_env())
        # `text=True` is unsafe here: libFuzzer echoes the crashing input into
        # its output, and a binary-format target will emit bytes that are not
        # valid UTF-8, which raises UnicodeDecodeError inside subprocess and
        # kills the minimization run entirely. Only the return code is used,
        # so decode leniently.
        # The exit code is deliberately NOT a success signal. libFuzzer exits
        # non-zero (77 on a deadly signal) precisely BECAUSE the crash
        # reproduced, and the reduced artifacts are written before it exits.
        # Gating on returncode == 0 threw away every real reduction.
        # Success is "a smaller reproducer exists on disk", nothing else.
        subprocess.run(  # nosec B603 B607 - fixed argv, no shell
            [binary, "-minimize_crash=1", "-runs=20000", str(target)],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            check=False,
            env=env,
            cwd=str(workdir),
        )

        # Zero-length artifacts are real and common: libFuzzer writes them
        # during the search, and an empty input does not reproduce the crash.
        # Sorting ascending and taking [0] would hand back a 0-byte "reduction"
        # that is a false positive, so empty artifacts are dropped first and
        # the smallest genuine reproducer is chosen.
        artifacts = sorted(
            (
                p
                for p in workdir.glob(LIBFUZZER_MERGED)
                if p.is_file() and p.stat().st_size > 0
            ),
            key=lambda p: p.stat().st_size,
        )
        if artifacts:
            data = artifacts[0].read_bytes()
            if 0 < len(data) < original:
                return data.decode("latin1"), True
        return "", False
    except (OSError, subprocess.SubprocessError) as exc:
        logger.debug("minimize failed for %s: %s", crash, exc)
        return "", False
    finally:
        try:
            for leftover in workdir.glob("*"):
                if leftover.is_file():
                    leftover.unlink()
            workdir.rmdir()
        except OSError:
            pass


class MutationEngine:
    """Generates mutated inputs from a corpus.

    Seeded on purpose: given the same seed and the same corpus the operator
    gets the same mutation sequence, so a crash can be replayed. The
    mutator list is the standard libFuzzer/AFL operator set (bitflip,
    byte-set, arithmetic, boundary, block, splice, dictionary) because those
    are the operators with known bug-finding value -- arbitrary mutation is
    mostly noise.
    """

    def __init__(
        self,
        seeds: Iterable[bytes] | None = None,
        dictionary: Iterable[bytes] | None = None,
        seed_value: int | None = None,
    ):
        # Mersenne Twister is correct here: fuzz mutation wants fast,
        # reproducible sequences, not cryptographic unpredictability. The seed
        # is operator-supplied specifically so a crash can be replayed.
        self._rand = random.Random(seed_value)  # nosec B311
        self.dictionary = list(dictionary if dictionary is not None else DICT_TOKENS)
        # `seeds=None` means "give me sensible defaults"; an explicit empty
        # list means the caller really wants an empty corpus, so this must
        # test for None rather than falsiness.
        if seeds is None:
            self.corpus: list[bytes] = [b"", b"AAAA", b"/", b"%s%s%s%s%n"]
        else:
            self.corpus = [data for data in seeds if data]

    @property
    def rnd(self) -> random.Random:
        return self._rand

    def add_corpus(self, data: bytes) -> bool:
        """Add an input that earned its place. Bounded, deduplicated."""
        if not data or len(self.corpus) >= MAX_CORPUS:
            return False
        if data in self.corpus:
            return False
        self.corpus.append(data)
        return True

    def _pick(self) -> bytes:
        return self._rand.choice(self.corpus) if self.corpus else b""

    def _bit_flip(self, data: bytes) -> bytes:
        buf = bytearray(data)
        if not buf:
            buf = bytearray(b"\x00")
        for _ in range(self._rand.randint(1, 4)):
            pos = self._rand.randrange(len(buf))
            buf[pos] ^= 1 << self._rand.randrange(8)
        return bytes(buf)

    def _byte_set(self, data: bytes) -> bytes:
        buf = bytearray(data)
        if not buf:
            buf = bytearray(b"\x00")
        pos = self._rand.randrange(len(buf))
        buf[pos] = self._rand.choice(INTERESTING_BYTES)
        return bytes(buf)

    def _arith(self, data: bytes) -> bytes:
        buf = bytearray(data)
        if not buf:
            buf = bytearray(b"\x00")
        pos = self._rand.randrange(len(buf))
        delta = self._rand.choice((-128, -17, -1, 1, 16, 17, 127))
        buf[pos] = (buf[pos] + delta) & 0xFF
        return bytes(buf)

    def _insert_interesting(self, data: bytes) -> bytes:
        value = self._rand.choice(INTERESTING_U32).to_bytes(4, "big")
        return self._splice_bytes(data, value)

    def _insert_dict(self, data: bytes) -> bytes:
        if not self.dictionary:
            return self._arith(data)
        return self._splice_bytes(data, self._rand.choice(self.dictionary))

    def _splice_bytes(self, data: bytes, token: bytes) -> bytes:
        if not data:
            return token
        cut = self._rand.randrange(len(data) + 1)
        return data[:cut] + token + data[cut:]

    def _block_delete(self, data: bytes) -> bytes:
        if len(data) < 4:
            return data[: self._rand.randrange(len(data) + 1)]
        start = self._rand.randrange(len(data) - 2)
        length = self._rand.randint(1, min(64, len(data) - start))
        return data[:start] + data[start + length :]

    def _block_repeat(self, data: bytes) -> bytes:
        if not data:
            return b"\x00" * self._rand.randint(1, 16)
        start = self._rand.randrange(len(data))
        length = self._rand.randint(1, min(32, len(data) - start))
        block = data[start : start + length]
        return data[:start] + block * self._rand.randint(2, 8) + data[start + length :]

    def _splice(self, data: bytes) -> bytes:
        if len(self.corpus) < 2:
            return self._block_repeat(data)
        other = self._rand.choice(self.corpus)
        cut_a = self._rand.randrange(len(data) + 1) if data else 0
        cut_b = self._rand.randrange(len(other) + 1) if other else 0
        return data[:cut_a] + other[cut_b:]

    # Operator names, resolved through getattr so the methods stay properly
    # bound. Storing the raw functions in a class-body tuple would leave them
    # unbound, and calling one would silently pass the input as `self`.
    _MUTATORS: ClassVar[tuple[str, ...]] = (
        "bitflip",
        "byte-set",
        "arith",
        "interesting",
        "dict",
        "block-delete",
        "block-repeat",
        "splice",
    )
    _METHOD_FOR: ClassVar[dict[str, str]] = {
        "bitflip": "_bit_flip",
        "byte-set": "_byte_set",
        "arith": "_arith",
        "interesting": "_insert_interesting",
        "dict": "_insert_dict",
        "block-delete": "_block_delete",
        "block-repeat": "_block_repeat",
        "splice": "_splice",
    }

    def _operator(self) -> tuple[str, Callable[[bytes], bytes]]:
        label = self._rand.choice(self._MUTATORS)
        return label, getattr(self, self._METHOD_FOR[label])

    def mutate(self, data: bytes | None = None) -> tuple[str, bytes]:
        """Produce one (operator-label, mutated-input) pair."""
        base = self._pick() if data is None else data
        name, fn = self._operator()
        result = fn(base)
        if len(result) > MAX_INPUT:
            result = result[:MAX_INPUT]
        return f"{name}", result

    def havoc(self, rounds: int = 4) -> tuple[str, bytes]:
        """Stack several operators -- much higher bug yield per input."""
        data = self._pick()
        applied: list[str] = []
        for _ in range(max(1, rounds)):
            name, fn = self._operator()
            try:
                data = fn(data)
            except (IndexError, ValueError):  # pragma: no cover - defensive
                break
            applied.append(name)
        if len(data) > MAX_INPUT:
            data = data[:MAX_INPUT]
        return "havoc:" + "+".join(applied[:4]), data

    def stats(self) -> dict[str, int | str]:
        return {
            "corpus": len(self.corpus),
            "operators": len(self._MUTATORS),
            "dictionary": len(self.dictionary),
            "max_input": MAX_INPUT,
        }


class LabFuzzer:
    def __init__(
        self,
        progress: Callable[[str, float], None] | None = None,
        mutator: list[tuple[str, bytes]] | None = None,
        timeout: float = 3.0,
        iterations: int = 200,
        seed: int | None = None,
        dictionary: Iterable[bytes] | None = None,
    ):
        self.progress = progress or (lambda msg, pct: None)
        self.mutations = mutator
        self.timeout = timeout
        self.iterations = max(1, iterations)
        self.registry = crash_mod.CrashRegistry()
        self.engine = MutationEngine(
            seeds=[payload for _label, payload in (mutator or MUTATIONS)],
            dictionary=dictionary,
            seed_value=seed,
        )
        self.stats: dict[str, Any] = {}

    def _fuzz_http(self, host: str, port: int, scheme: str = "http") -> list[dict]:
        """Fuzz an HTTP service, dedup crashes, return one row per distinct bug."""
        from services import sanitizer

        candidates: list[dict] = []
        now = datetime.now(UTC).isoformat()

        base = f"{scheme}://{host}:{port}/"
        baseline_ok = self._probe_http(base)
        self.progress(
            f"[fuzz] {host}:{port} baseline={'up' if baseline_ok else 'down'}",
            5,
        )

        executed = 0
        order: list[str] = []
        for index in range(self.iterations):
            if self.mutations is not None:
                label, payload = self.mutations[index % len(self.mutations)]
            elif index % 8 == 7:
                label, payload = self.engine.havoc()
            else:
                label, payload = self.engine.mutate()

            vector = self._build_vector(base, label, payload)
            evid, rc, elapsed = self._send_http(host, port, vector)
            signal = self._classify(rc, elapsed, evid, baseline_ok)
            executed += 1

            if signal:
                trace = evid if self._looks_like_trace(evid) else ""
                record, is_new = self.registry.record(
                    host=host,
                    service="http",
                    port=port,
                    vector=label,
                    signal=signal,
                    repro=vector.decode("latin1"),
                    evidence=evid,
                    trace=trace,
                    seen_at=now,
                )
                if is_new:
                    # A new fingerprint is the one thing that makes an input
                    # worth keeping: it found something the run had not seen.
                    self.engine.add_corpus(payload)
                    if record.confirmed:
                        record.bug_class = record.bug_class or (
                            sanitizer.classify_trace(trace)["class"]
                        )
                    # Only distinct bugs become rows. A duplicate fingerprint
                    # increments the record's occurrence count and is dropped
                    # here -- otherwise the candidate list is just the crash
                    # count wearing a different hat, and "50 candidates" reads
                    # as "50 bugs" when it is one bug hit 50 times.
                    order.append(record.crash_id)
            if self.mutations is not None:
                self.progress(f"[fuzz] {label} -> {signal or 'ok'}", 10)
            elif executed % 25 == 0 or executed == self.iterations:
                self.progress(
                    f"[fuzz] exec {executed}/{self.iterations} "
                    f"unique={len(self.registry)}",
                    min(95, 10 + int(85 * executed / max(1, self.iterations))),
                )

        self.stats = {
            "mode": "deterministic" if self.mutations is not None else "signal-guided",
            "coverage_guided": False,
            "iterations": self.iterations,
            "executed": executed,
            "engine": self.engine.stats(),
            "crashes": self.registry.summary(),
        }

        # Rows are built after the run, not at first hit, so `occurrences`
        # reflects the final count for the whole run. Snapshotting it during
        # the loop would report every bug as occurring exactly once.
        for crash_id in order:
            record = self.registry.get(crash_id)
            if record is None:  # pragma: no cover - defensive
                continue
            candidates.append(
                {
                    "host": record.host,
                    "service": record.service,
                    "port": record.port,
                    "vector": record.vector,
                    "signal": record.signal,
                    "repro": record.repro,
                    "evidence": record.evidence,
                    "payload_mutated": True,
                    "crash_id": record.crash_id,
                    "basis": record.basis,
                    "confirmed": record.confirmed,
                    "bug_class": record.bug_class,
                    "frames": record.frames,
                    "occurrences": record.occurrences,
                    # Sanitizer-first: a black-box signal is not a verdict, so
                    # we attach the rebuild+replay recipe and the bug classes
                    # a sanitizer would name if it is memory corruption anyway.
                    "sanitizer": sanitizer.confirm_plan(
                        record.signal,
                        host=record.host,
                        port=record.port,
                        vector=record.vector,
                    ),
                }
            )
        return candidates

    @staticmethod
    def _looks_like_trace(evidence: str) -> bool:
        """True when a response actually contains a sanitizer report."""
        if not evidence:
            return False
        lowered = evidence.lower()
        return (
            "sanitizer" in lowered or "runtime error:" in lowered or "asan" in lowered
        )

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
            # A sanitizer report in the response body is the strongest crash
            # evidence there is -- it names the faulting code path, so it
            # dedups and classifies properly. This must be checked BEFORE the
            # generic error-string list, which does not match ASan/UBSan
            # output and so previously classified a confirmed memory-safety
            # crash as benign.
            if LabFuzzer._looks_like_trace(evidence):
                return "sanitizer"
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
        Classification is delegated to services.sanitizer so fuzz, SAST and
        triage all agree on what a given trace means.
        """
        from services import sanitizer

        info = sanitizer.classify_trace(stderr)
        return {
            "summary": info["summary"],
            "kind": info["class"],
            "cwe": info["cwe"],
        }

    def minimize_crash(self, cmd: list[str], crashes: list[str]) -> list[dict]:
        """Run a real crash-minimizer over crash files.

        `cmd` is the base fuzzer command (excluding -minimize_crash). `crashes`
        are paths to crash artifacts. Returns a list of
        {input, minimized, reduced} dicts, where `reduced` says whether a
        genuinely smaller repro was produced. Reports the real result rather
        than claiming a reduction that did not happen.
        """
        out: list[dict] = []
        binary = cmd[0] if cmd else None
        if not binary or not Path(binary).exists():
            return out
        for crash in crashes:
            path = Path(crash)
            try:
                minimized, reduced = libfuzzer_minimize(binary, path)
            except Exception as exc:  # pragma: no cover - defensive
                logger.debug("minimize failed for %s: %s", crash, exc)
                minimized, reduced = "", False
            if not reduced:
                minimized = path.read_text(errors="replace")[:400]
            out.append(
                {
                    "input": path.name,
                    "minimized": minimized,
                    "reduced": reduced,
                    "original_bytes": len(path.read_bytes()),
                    "minimized_bytes": len(minimized),
                }
            )
        return out

    @staticmethod
    def _extract_minimized(proc_out: str, crash: str) -> str:
        """Back-compat shim: read the crash file text as-is.

        Kept so existing callers keep working. It no longer claims to
        produce a minimized unit -- real reduction happens in
        libfuzzer_minimize(), which reads back the file libFuzzer wrote.
        """
        return Path(crash).read_text(errors="replace")[:400]
