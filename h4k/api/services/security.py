# Educated, traceroute + scan-signal based guess at a host's security posture.
# This is heuristic inference, not a pentest: it looks for firewall hops,
# exposed management/services, weak fingerprint strings, and network hops that
# suggest how likely a target is to be patched, firewalled, or monitored.
import logging
import re
import subprocess  # nosec B404 - runs traceroute for path/posture analysis
from collections.abc import Callable
from typing import Any

logger = logging.getLogger("h4k.security")


class SecurityAssessmentService:
    def __init__(
        self,
        progress: Callable[[str, float], None] | None = None,
    ):
        self.progress = progress or (lambda msg, pct: None)

    # ---- traceroute capture -------------------------------------------------

    def traceroute(self, target: str, hops: int = 20) -> str:
        """Run traceroute and return its raw text (empty on failure)."""
        try:
            proc = subprocess.run(  # nosec B603 B607 - bare argv, fixed binary
                ["traceroute", "-n", "-m", str(hops), target],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            return (proc.stdout or proc.stderr or "").strip()
        except FileNotFoundError:
            logger.debug("traceroute not installed; skipping")
        except Exception as exc:
            logger.warning("traceroute failed for %s: %s", target, exc)
        return ""

    # ---- analysis -----------------------------------------------------------

    def assess(self, target: str, host: dict | None = None) -> dict:
        """Compute a security assessment for one host target.

        `host` is an optional discovered host dict (services/vulns/creds) used
        to enrich the heuristic with exposure signals beyond traceroute.
        """
        route = self.traceroute(target)
        signals: list[str] = []
        rationale: list[str] = []

        self._traceroute_signals(route, signals, rationale)
        if host:
            self._host_signals(host, signals, rationale)

        # score 0..100 where higher = more exposed / easier target
        score = _score(signals)
        level = _level(score)
        confidence = _confidence(signals)

        return {
            "host": target,
            "level": level,
            "score": float(round(score, 1)),
            "signals": signals,
            "rationale": rationale,
            "confidence": confidence,
        }

    def _traceroute_signals(self, route: str, signals: list, rationale: list) -> None:
        if not route:
            rationale.append("traceroute returned no data (may be firewalled/off).")
            signals.append("icmp-blocked-or-no-route")
            return

        lines = route.splitlines()
        hops_that_answered = 0
        star_hops = 0
        private_count = 0
        public_count = 0

        for line in lines:
            if _is_hop_line(line):
                hops_that_answered += 1
                if _is_star(line):
                    star_hops += 1
                elif _is_private_ip(line):
                    private_count += 1
                else:
                    public_count += 1

        total = hops_that_answered or 1
        star_ratio = star_hops / total

        if star_ratio > 0.5:
            signals.append("many-star-hops")
            rationale.append(
                ">50% of traceroute hops timed out — suggests firewalling/filtering."
            )
        if private_count >= 2:
            signals.append("all-internal-path")
            rationale.append(
                "path is within RFC1918 space; this looks like a local/lab-only "
                "device with little internet exposure."
            )
        elif public_count >= 2:
            signals.append("public-internet-path")
            rationale.append(
                "path crosses public IPs; the device is reachable beyond the LAN "
                "and faces broader exposure."
            )

    def _host_signals(self, host: dict, signals: list, rationale: list) -> None:
        services = host.get("services") or []
        exposed = [s for s in services if str(s.get("state", "")).lower() == "open"]

        if len(exposed) <= 1:
            signals.append("minimal-service-surface")
            rationale.append("few (<=1) open services — tight, small attack surface.")
        elif len(exposed) <= 4:
            signals.append("moderate-service-surface")
            rationale.append("a handful of open services; typical of routers/NAS.")
        else:
            signals.append("large-service-surface")
            rationale.append("many open services — likely higher-value / less patched.")

        # look for management-ish services
        svc_names = " ".join((s.get("service") or "") for s in exposed).lower()
        if any(
            m in svc_names
            for m in (
                "telnet",
                "snmp",
                "mikrotik",
                "router",
                "http-admin",
                "deviceconfig",
            )
        ):
            signals.append("plaintext-mgmt")
            rationale.append(
                "exposes telnet/simple-mgmt — suggests legacy, lax hardening."
            )

    @staticmethod
    def to_dict(a: dict) -> dict[str, Any]:
        return a


def _is_hop_line(line: str) -> bool:
    return bool(re.match(r"\s*\d+\s", line))


def _is_star(line: str) -> bool:
    return "*" in line


def _is_private_ip(line: str) -> bool:
    m = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
    if not m:
        return False
    import ipaddress

    try:
        return ipaddress.ip_address(m.group(1)).is_private
    except ValueError:
        return False


def _score(signals: list[str]) -> float:
    """Higher score = more exposed / easier-to-reach. Heuristic weights."""
    weights = {
        "large-service-surface": 30,
        "moderate-service-surface": 18,
        "plaintext-mgmt": 15,
        "public-internet-path": 20,
        "minimal-service-surface": -15,
        "all-internal-path": -10,
        "many-star-hops": -20,
        "icmp-blocked-or-no-route": -25,
    }
    s = 40  # baseline mid
    for sig in signals:
        s += weights.get(sig, 0)
    return max(0.0, min(100.0, s))


def _level(score: float) -> str:
    if score >= 70:
        return "low"  # low security / high exposure -> easier target
    if score >= 45:
        return "medium"
    return "high"


def _confidence(signals: list[str]) -> str:
    if len(signals) >= 4:
        return "high"
    if len(signals) >= 2:
        return "medium"
    return "low"
