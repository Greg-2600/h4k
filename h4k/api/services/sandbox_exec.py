# Sandbox profiles and resource caps for every subprocess h4k launches.
#
# The threat model is not "a hostile kernel exploit" — it is an expensive or
# wedged tool taking the whole console down: hydra spawning 64 threads, a
# runaway fuzzer filling the disk, nmap ignoring its timeout, a half-written
# 4 GB pcap. A profile declares the tool allowlist plus CPU/memory/process/
# file-size/runtime ceilings; the runner enforces them with setrlimit in a
# throw-away working directory, kills the whole process group on timeout, and
# truncates output so one noisy tool cannot exhaust API memory.
#
# A profile can also run remotely in the `h4k-sandbox` sidecar (H4K_SANDBOX_URL)
# when the operator wants tool blast radius out of the API container.
import contextlib
import logging
import os
import resource
import shutil
import signal
import subprocess  # nosec B404 - fixed argv, no shell
import tempfile
import threading
import time
import urllib.error
import urllib.request
from contextlib import suppress
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from services import approval

logger = logging.getLogger("h4k.sandbox")

_SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


@dataclass(frozen=True)
class SandboxProfile:
    """Resource envelope for one class of tooling."""

    name: str
    description: str
    tools: tuple[str, ...]
    cpu_seconds: int = 120
    memory_mb: int = 512
    processes: int = 64
    file_mb: int = 64
    runtime_s: int = 300
    max_output_kb: int = 512
    max_concurrent: int = 2
    network: bool = True
    notes: str = ""

    def public(self) -> dict[str, Any]:
        data = asdict(self)
        data["tools"] = list(self.tools)
        return data


def _p(
    name: str,
    description: str,
    tools: tuple[str, ...],
    *,
    cpu_seconds: int,
    memory_mb: int,
    processes: int,
    file_mb: int,
    runtime_s: int,
    max_concurrent: int = 2,
    network: bool = True,
    notes: str = "",
) -> SandboxProfile:
    return SandboxProfile(
        name=name,
        description=description,
        tools=tools,
        cpu_seconds=cpu_seconds,
        memory_mb=memory_mb,
        processes=processes,
        file_mb=file_mb,
        runtime_s=runtime_s,
        max_concurrent=max_concurrent,
        network=network,
        notes=notes,
    )


PROFILES: dict[str, SandboxProfile] = {
    "recon": _p(
        "recon",
        "Port/service discovery — bounded CPU, short runtime, no local writes",
        ("nmap", "masscan", "arp-scan", "dig", "host", "nslookup", "traceroute"),
        cpu_seconds=180,
        memory_mb=768,
        processes=64,
        file_mb=32,
        runtime_s=600,
        max_concurrent=2,
        notes="masscan needs NET_RAW; degrade to nmap -sT when unavailable.",
    ),
    "web": _p(
        "web",
        "Web assessment — nikto/nuclei/ffuf/gobuster/sqlmap/zap",
        (
            "nikto",
            "nikto.pl",
            "nuclei",
            "ffuf",
            "gobuster",
            "sqlmap",
            "whatweb",
            "zap",
            "zap.sh",
            "curl",
        ),
        cpu_seconds=240,
        memory_mb=1024,
        processes=96,
        file_mb=128,
        runtime_s=900,
        max_concurrent=1,
        notes="ZAP is JVM-heavy; one at a time and a 1 GiB cap.",
    ),
    "creds": _p(
        "creds",
        "Password testing — hydra/ncrack/john with tight process caps",
        ("hydra", "ncrack", "john", "hashcat", "smbclient", "rpcclient"),
        cpu_seconds=300,
        memory_mb=768,
        processes=32,
        file_mb=32,
        runtime_s=600,
        max_concurrent=1,
        notes="Low process count is deliberate: a spray must stay inside lockout "
        "policy, not saturate the target.",
    ),
    "ad": _p(
        "ad",
        "Active Directory tooling — impacket, ldap, bloodhound.py",
        (
            "ldapsearch",
            "ldapwhoami",
            "rpcclient",
            "smbclient",
            "nmap",
            "bloodhound-python",
            "GetNPUsers.py",
            "GetUserSPNs.py",
            "secretsdump.py",
            "wmiexec.py",
            "smbexec.py",
            "getTGT.py",
            "python3",
        ),
        cpu_seconds=180,
        memory_mb=1024,
        processes=48,
        file_mb=256,
        runtime_s=900,
        max_concurrent=1,
        notes="python3 is present for impacket's .py entrypoints; the profile "
        "still has no shell and no inherited environment.",
    ),
    "fuzz": _p(
        "fuzz",
        "Fuzzing — compiled harnesses and minimizers",
        (
            "python3",
            "afl-fuzz",
            "afl-tmin",
            "afl-showmap",
            "./parse_fuzzer",
            "parse_fuzzer",
            "parse_afl",
            "llvm-symbolizer",
        ),
        cpu_seconds=300,
        memory_mb=2048,
        processes=128,
        file_mb=512,
        runtime_s=1800,
        max_concurrent=1,
        notes="Corpus/crash artifacts can be large; the 512 MiB file cap stops a "
        "runaway mutator from filling the volume.",
    ),
    "lab": _p(
        "lab",
        "Lab traffic and IoT/OT probes — short-lived, read-only helpers",
        ("python3", "curl", "dig", "mqtt", "mosquitto_pub", "mosquitto_sub"),
        cpu_seconds=60,
        memory_mb=256,
        processes=16,
        file_mb=8,
        runtime_s=120,
        max_concurrent=2,
        network=True,
        notes="Traffic generation is built in-process; this profile is for "
        "optional packet helpers.",
    ),
    "full": _p(
        "full",
        "Everything above — admin-only escape hatch",
        (),
        cpu_seconds=600,
        memory_mb=4096,
        processes=256,
        file_mb=1024,
        runtime_s=3600,
        max_concurrent=1,
        notes="Union of every profile's allowlist, computed after definition.",
    ),
}


def _union_tools() -> tuple[str, ...]:
    names = ("recon", "web", "creds", "ad", "fuzz", "lab")
    return tuple(sorted({tool for name in names for tool in PROFILES[name].tools}))


# Replace the empty placeholder with the real union now that all profiles exist.
PROFILES["full"] = SandboxProfile(
    name="full",
    description=PROFILES["full"].description,
    tools=_union_tools(),
    cpu_seconds=600,
    memory_mb=4096,
    processes=256,
    file_mb=1024,
    runtime_s=3600,
    max_output_kb=1024,
    max_concurrent=1,
    notes=PROFILES["full"].notes,
)


class SandboxError(Exception):
    def __init__(self, message: str, *, status_code: int = 400) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.message = message


_active: dict[str, int] = {}
_active_lock = threading.Lock()
_semaphores: dict[str, threading.BoundedSemaphore] = {}


def _semaphore(profile: SandboxProfile) -> threading.BoundedSemaphore:
    with _active_lock:
        sem = _semaphores.get(profile.name)
        if sem is None:
            sem = threading.BoundedSemaphore(profile.max_concurrent)
            _semaphores[profile.name] = sem
        return sem


def active_count() -> dict[str, int]:
    with _active_lock:
        return dict(_active)


def _limits(profile: SandboxProfile) -> list[tuple[int, int, int]]:
    """(resource, soft, hard) triples applied in the child before exec.

    RLIMIT_NPROC is per-UID on Linux/macOS, not per-process-tree. Applying it in
    the API container would count every unrelated process owned by the same UID
    and make ordinary tools fail to fork, so local mode leaves it opt-in. The
    sidecar image runs tools as a dedicated user and enables it by default.
    """
    mb = 1024 * 1024
    limits = [
        (resource.RLIMIT_CPU, profile.cpu_seconds, profile.cpu_seconds + 5),
        (resource.RLIMIT_AS, profile.memory_mb * mb, profile.memory_mb * mb),
        (resource.RLIMIT_FSIZE, profile.file_mb * mb, profile.file_mb * mb),
        (resource.RLIMIT_CORE, 0, 0),
        (resource.RLIMIT_NOFILE, 256, 256),
    ]
    if os.environ.get("H4K_SANDBOX_NPROC", "0").lower() in {"1", "true", "yes"}:
        limits.append((resource.RLIMIT_NPROC, profile.processes, profile.processes))
    return limits


def _preexec(profile: SandboxProfile) -> Any:
    limits = _limits(profile)

    def _apply() -> None:  # pragma: no cover - runs in the forked child
        for resource_id, soft, hard in limits:
            with contextlib.suppress(ValueError, OSError):
                resource.setrlimit(resource_id, (soft, hard))

    return _apply


def _truncate(text: str, limit_kb: int) -> tuple[str, bool]:
    limit = max(1, limit_kb) * 1024
    if len(text) <= limit:
        return text, False
    return text[:limit] + f"\n…[truncated at {limit_kb} KiB]…", True


class SandboxRunner:
    """Execute an allowlisted tool inside a profile's resource envelope."""

    def __init__(
        self,
        profile: str | SandboxProfile,
        *,
        remote_url: str = "",
        token: str = "",
    ) -> None:
        if isinstance(profile, str):
            resolved = PROFILES.get(profile)
            if resolved is None:
                raise SandboxError(
                    f"unknown sandbox profile: {profile} "
                    f"(choices: {', '.join(sorted(PROFILES))})"
                )
            profile = resolved
        self.profile = profile
        self.remote_url = (remote_url or os.environ.get("H4K_SANDBOX_URL", "")).rstrip(
            "/"
        )
        self.token = token or os.environ.get("H4K_SANDBOX_TOKEN", "")

    # -- validation ---------------------------------------------------------
    def validate(self, argv: list[str]) -> str:
        if not argv or not str(argv[0]).strip():
            raise SandboxError("argv must name a tool")
        if len(argv) > 256:
            raise SandboxError("argv is too long")
        for token in argv:
            if "\x00" in str(token) or "\n" in str(token):
                raise SandboxError("argv contains a control character")
        raw = str(argv[0])
        resolved = Path(raw).name if "/" in raw else raw
        if resolved not in self.profile.tools:
            raise SandboxError(
                f"{resolved!r} is not allowed by the {self.profile.name} profile "
                f"(allowed: {', '.join(self.profile.tools) or 'none'})",
                status_code=403,
            )
        if not self.remote_url and shutil.which(raw) is None:
            raise SandboxError(f"{raw} is not installed in this container")
        return resolved

    # -- local execution ----------------------------------------------------
    def run(
        self,
        argv: list[str],
        *,
        timeout: float | None = None,
        stdin: str = "",
        env: dict[str, str] | None = None,
        approval_id: str = "",
    ) -> dict[str, Any]:
        tool = self.validate(argv)
        approval.ApprovalStore().check(
            [str(a) for a in argv],
            tool=tool,
            approval_id=approval_id,
            context={"profile": self.profile.name, "limits": self.profile.public()},
        )
        if self.remote_url:
            return self._run_remote(argv, timeout=timeout, stdin=stdin, env=env)

        sem = _semaphore(self.profile)
        if not sem.acquire(blocking=False):
            raise SandboxError(
                f"profile {self.profile.name} is at its concurrency limit "
                f"({self.profile.max_concurrent})",
                status_code=429,
            )
        started = time.monotonic()
        workdir = tempfile.mkdtemp(prefix=f"h4k-{self.profile.name}-")
        child_env = {
            "PATH": _SAFE_PATH,
            "HOME": workdir,
            "TMPDIR": workdir,
            "LANG": "C.UTF-8",
            "TERM": "dumb",
        }
        for key, value in (env or {}).items():
            if key.startswith("H4K_") or key in {"LC_ALL", "TZ"}:
                child_env[key] = str(value)
        budget = float(timeout or self.profile.runtime_s)
        with _active_lock:
            _active[self.profile.name] = _active.get(self.profile.name, 0) + 1
        try:
            proc = subprocess.Popen(  # nosec B603 - argv list, no shell
                [str(x) for x in argv],
                cwd=workdir,
                env=child_env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                preexec_fn=_preexec(self.profile),
                start_new_session=True,
            )
            timed_out = False
            try:
                out, err = proc.communicate(input=stdin, timeout=budget)
            except subprocess.TimeoutExpired:
                timed_out = True
                _kill_group(proc)
                out, err = proc.communicate(timeout=5)
            stdout, out_trunc = _truncate(out or "", self.profile.max_output_kb)
            stderr, err_trunc = _truncate(err or "", self.profile.max_output_kb)
            duration = round(time.monotonic() - started, 3)
            result = {
                "ok": proc.returncode == 0 and not timed_out,
                "rc": proc.returncode,
                "tool": tool,
                "profile": self.profile.name,
                "stdout": stdout,
                "stderr": stderr,
                "timed_out": timed_out,
                "truncated": out_trunc or err_trunc,
                "duration_s": duration,
                "limits": {
                    "cpu_seconds": self.profile.cpu_seconds,
                    "memory_mb": self.profile.memory_mb,
                    "processes": self.profile.processes,
                    "file_mb": self.profile.file_mb,
                    "runtime_s": budget,
                },
                "mode": "local",
            }
            return result
        finally:
            with _active_lock:
                _active[self.profile.name] = max(
                    0, _active.get(self.profile.name, 1) - 1
                )
            sem.release()
            shutil.rmtree(workdir, ignore_errors=True)

    # -- sidecar execution --------------------------------------------------
    def _run_remote(
        self,
        argv: list[str],
        *,
        timeout: float | None,
        stdin: str,
        env: dict[str, str] | None,
    ) -> dict[str, Any]:
        import json

        payload = json.dumps(
            {
                "profile": self.profile.name,
                "argv": [str(x) for x in argv],
                "timeout_s": float(timeout or self.profile.runtime_s),
                "stdin": stdin,
                "env": {
                    k: v
                    for k, v in (env or {}).items()
                    if k.startswith("H4K_") or k in {"LC_ALL", "TZ"}
                },
            }
        ).encode()
        req = urllib.request.Request(
            f"{self.remote_url}/run",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "X-Sandbox-Token": self.token,
            },
        )
        started = time.monotonic()
        try:
            with urllib.request.urlopen(
                req, timeout=float(timeout or 600) + 15
            ) as resp:  # nosec B310
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:500]
            raise SandboxError(
                f"sandbox sidecar rejected the job ({exc.code}): {detail}",
                status_code=502,
            ) from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            raise SandboxError(f"sandbox sidecar unreachable: {exc}") from exc
        data.setdefault("mode", "sidecar")
        data["duration_s"] = round(time.monotonic() - started, 3)
        return data

    # -- introspection ------------------------------------------------------
    def status(self) -> dict[str, Any]:
        return {
            "mode": "sidecar" if self.remote_url else "local",
            "profile": self.profile.name,
            "limits": self.profile.public(),
            "active": active_count().get(self.profile.name, 0),
        }


def _kill_group(proc: subprocess.Popen[str]) -> None:
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        with suppress(OSError):  # already gone
            proc.kill()


def profiles() -> list[dict[str, Any]]:
    return [PROFILES[name].public() for name in sorted(PROFILES)]


def run_in_sandbox(profile: str, argv: list[str], **kwargs: Any) -> dict[str, Any]:
    """Convenience wrapper used by opt-in tool routes."""
    return SandboxRunner(profile).run(argv, **kwargs)


# Keep a small, explicit surface for callers that build a profile at runtime.
__all__ = [
    "PROFILES",
    "SandboxError",
    "SandboxProfile",
    "SandboxRunner",
    "active_count",
    "profiles",
    "run_in_sandbox",
]
