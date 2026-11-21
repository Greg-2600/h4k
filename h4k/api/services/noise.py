# Per-host target noise governor.
#
# The scanner knobs already exist (stealth/tor/overt, sandbox limits), but they
# are per-tool or per-process. This module adds a shared per-host budget so an
# HTTP probe, a lab-traffic job and an IoT sweep cannot collectively hammer one
# target. It also produces tool-specific low-and-slow guidance for scanners we
# launch as subprocesses (nmap/nuclei/ffuf/hydra/sqlmap/masscan), where the only
# reliable brake is their own rate flags.
#
# Profiles: off, quiet (2 req/s), balanced (5 req/s), aggressive (20 req/s).
# Backoff is explicit: a 429/503 blocks the host for Retry-After or a short
# default. `H4K_NOISE_PROFILE` sets the startup profile; the API can override it
# at runtime without a restart.
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("h4k.noise")


@dataclass(frozen=True)
class NoiseProfile:
    name: str
    rps: float
    burst: int
    max_in_flight: int
    jitter_ms: int
    timing: str
    retries: int


PROFILES: dict[str, NoiseProfile] = {
    "off": NoiseProfile("off", 0.0, 0, 0, 0, "", 0),
    "quiet": NoiseProfile("quiet", 2.0, 4, 1, 120, "-T2", 2),
    "balanced": NoiseProfile("balanced", 5.0, 10, 2, 60, "-T3", 2),
    "aggressive": NoiseProfile("aggressive", 20.0, 40, 4, 20, "-T4", 1),
}


@dataclass
class _HostState:
    tokens: float = 0.0
    updated: float = 0.0
    in_flight: int = 0
    blocked_until: float = 0.0
    requests: int = 0
    blocked: int = 0


@dataclass
class Permit:
    host: str
    status_code: int = 0
    retry_after: float = 0.0
    acquired_at: float = field(default_factory=time.monotonic)


_lock = threading.Lock()
_hosts: dict[str, _HostState] = {}
_runtime_profile: str | None = None


def profile_name() -> str:
    raw = _runtime_profile or os.environ.get("H4K_NOISE_PROFILE", "off")
    raw = str(raw).strip().lower()
    return raw if raw in PROFILES else "off"


def profile() -> NoiseProfile:
    return PROFILES[profile_name()]


def set_profile(name: str) -> dict[str, Any]:
    global _runtime_profile
    name = str(name or "").strip().lower()
    if name not in PROFILES:
        raise ValueError(f"unknown noise profile: {name}")
    _runtime_profile = name
    with _lock:
        _hosts.clear()
    logger.info("noise profile set to %s", name)
    return status()


def reset() -> dict[str, Any]:
    global _runtime_profile
    _runtime_profile = None
    with _lock:
        _hosts.clear()
    return status()


def _state(host: str, now: float) -> _HostState:
    state = _hosts.get(host)
    if state is None:
        state = _HostState(tokens=float(profile().burst), updated=now)
        _hosts[host] = state
    return state


def _refill(state: _HostState, cfg: NoiseProfile, now: float) -> None:
    elapsed = max(0.0, now - state.updated)
    state.tokens = min(float(cfg.burst), state.tokens + elapsed * cfg.rps)
    state.updated = now


def acquire(host: str, *, timeout: float = 60.0) -> Permit | None:
    """Wait for a token and an in-flight slot. Returns None when the profile is off."""
    cfg = profile()
    if cfg.name == "off":
        return None
    host = str(host or "unknown")
    deadline = time.monotonic() + max(0.0, float(timeout))
    while True:
        now = time.monotonic()
        with _lock:
            state = _state(host, now)
            _refill(state, cfg, now)
            if state.blocked_until > now:
                wait = min(state.blocked_until - now, deadline - now)
            elif state.tokens >= 1.0 and state.in_flight < cfg.max_in_flight:
                state.tokens -= 1.0
                state.in_flight += 1
                state.requests += 1
                return Permit(host)
            else:
                wait = 0.05 if cfg.rps <= 0 else max(0.01, 1.0 / cfg.rps)
                wait = min(wait, max(0.0, deadline - now))
        if wait <= 0 or time.monotonic() >= deadline:
            raise TimeoutError(f"noise governor timeout waiting for {host}")
        # add jitter without exceeding the caller's timeout
        jitter = (cfg.jitter_ms / 1000.0) * 0.5
        time.sleep(min(wait, jitter or wait))


def release(permit: Permit | None, *, status_code: int = 0) -> None:
    if permit is None:
        return
    cfg = profile()
    now = time.monotonic()
    with _lock:
        state = _state(permit.host, now)
        state.in_flight = max(0, state.in_flight - 1)
        if status_code in (429, 503):
            retry = max(0.0, float(permit.retry_after or 0.0))
            state.blocked_until = now + (
                retry if retry > 0 else max(2.0, 2.0 / max(cfg.rps, 0.1))
            )
            state.blocked += 1


def note_response(
    permit: Permit | None, status_code: int, retry_after: str = ""
) -> None:
    if permit is None:
        return
    permit.status_code = int(status_code or 0)
    try:
        permit.retry_after = float(str(retry_after or "").strip() or 0.0)
    except ValueError:
        permit.retry_after = 0.0


def status() -> dict[str, Any]:
    cfg = profile()
    now = time.monotonic()
    with _lock:
        hosts = []
        for host, state in sorted(_hosts.items()):
            hosts.append(
                {
                    "host": host,
                    "tokens": round(state.tokens, 2),
                    "in_flight": state.in_flight,
                    "blocked_for_s": round(max(0.0, state.blocked_until - now), 1),
                    "requests": state.requests,
                    "blocked": state.blocked,
                }
            )
    return {
        "profile": cfg.name,
        "source": "runtime" if _runtime_profile else "env",
        "rps": cfg.rps,
        "burst": cfg.burst,
        "max_in_flight": cfg.max_in_flight,
        "jitter_ms": cfg.jitter_ms,
        "hosts": hosts,
        "profiles": list(PROFILES),
    }


def guidance(tool: str = "") -> dict[str, Any]:
    """Tool-specific low-and-slow flags for the current profile."""
    cfg = profile()
    tool = str(tool or "").lower()
    if cfg.name == "off":
        return {"profile": "off", "tool": tool, "flags": "", "note": "no pacing"}
    rps = max(1, round(cfg.rps))
    conc = max(1, cfg.max_in_flight)
    delay = round(1.0 / max(cfg.rps, 0.1), 2)
    flags = {
        "nmap": f"{cfg.timing} --max-rate {rps} --max-retries {cfg.retries}",
        "masscan": f"--rate {rps}",
        "nuclei": f"-rate-limit {rps} -c {conc}",
        "httpx": f"-rl {rps} -t {conc}",
        "ffuf": f"-rate {rps} -t {conc}",
        "gobuster": f"--delay {int(delay * 1000)}ms --threads {conc}",
        "hydra": f"-t {conc} -W {max(1, int(delay))}",
        "sqlmap": f"--delay={delay} --threads=1",
        "nikto": "-Tuning 1 -maxtime 60s",
    }.get(tool, "")
    return {
        "profile": cfg.name,
        "tool": tool,
        "flags": flags,
        "rps": cfg.rps,
        "max_in_flight": cfg.max_in_flight,
        "delay_s": delay,
        "note": (
            "The governor paces h4k's own HTTP/TCP/UDP probes. Raw scanner "
            "subprocesses are not intercepted; use these flags."
        ),
    }


def reset_for_tests() -> None:
    global _runtime_profile
    _runtime_profile = None
    with _lock:
        _hosts.clear()
