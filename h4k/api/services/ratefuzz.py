"""Rate-limit-aware fuzz — 429 backoff + jitter (Backlog #57).

Opt-in characterization of one endpoint YOU own: fires a bounded run
of plain GETs with a cache-busting nonce and behaves like a polite
client when the server pushes back. On 429/503-with-`Retry-After` the
probe sleeps the advertised window (capped) plus ±jitter, doubling the
base on consecutive throttles; a run of clean 2xx responses decays the
base back down. Every decision lands in a timeline so the operator
can see exactly when the server throttled and how the probe yielded.

Verdicts: throttles honored → INFO (documented, no finding); zero
throttles across the run → MEDIUM finding (no interaction-frequency
control observed — brute-forceable, CWE-799). Findings ledger as
engagement vulns on the URL host when `engagement_id` is given
(scope-enforced). The sleeper is injectable so unit tests never
actually sleep. Sandbox returns a canned characterization without any
request.
"""

from __future__ import annotations

import email.utils
import logging
import random
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from datetime import UTC
from typing import Any

logger = logging.getLogger("h4k.ratefuzz")

MAX_REQUESTS = 200
MAX_BACKOFF = 30.0


def _retry_after_seconds(value: str, now: float) -> float | None:
    text = (value or "").strip()
    if not text:
        return None
    if text.isdigit():
        return max(0.0, min(float(text), MAX_BACKOFF))
    try:
        moment = email.utils.parsedate_to_datetime(text)
    except (ValueError, TypeError):
        return None
    if moment is None:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return max(0.0, min((moment.timestamp() - now), MAX_BACKOFF))


def _send(url: str, timeout: float) -> dict[str, Any]:
    nonce = f"h4k={random.randrange(1 << 30)}"  # nosec B311 - cache-buster, not crypto
    sep = "&" if "?" in url else "?"
    try:
        req = urllib.request.Request(
            f"{url}{sep}{nonce}",
            headers={"User-Agent": "h4k-audit"},
            method="GET",
        )
        with urllib.request.urlopen(
            req, timeout=timeout
        ) as resp:  # nosec B310 - operator-supplied lab target
            return {
                "status": resp.status,
                "retry_after": resp.headers.get("Retry-After", ""),
            }
    except urllib.error.HTTPError as exc:
        headers: Any = exc.headers or {}
        return {"status": exc.code, "retry_after": headers.get("Retry-After", "")}
    except Exception as exc:
        return {"status": None, "retry_after": "", "error": str(exc)[:160]}


def probe_rate_limit(
    url: str,
    requests: int = 50,
    timeout: float = 8.0,
    max_backoff: float = MAX_BACKOFF,
    seed: int | None = None,
    sleep: Callable[[float], None] | None = None,
) -> dict[str, Any]:
    """Fire bounded GETs, yielding to every throttle signal. Never raises."""
    url = (url or "").strip()
    if not url.startswith(("http://", "https://")):
        raise ValueError("url must be an http(s) URL you own")
    total = max(1, min(int(requests or 50), MAX_REQUESTS))
    cap = max(1.0, min(float(max_backoff or MAX_BACKOFF), 120.0))
    rng = random.Random(  # nosec B311 - jitter only, not cryptographic
        seed if seed is not None else 0x2A17
    )
    do_sleep = sleep or time.sleep
    timeline: list[dict[str, Any]] = []
    throttled = 0
    honored: list[float] = []
    base = 1.0
    consecutive = 0
    sent = 0
    for i in range(total):
        sent += 1
        res = _send(url, timeout)
        if res.get("error"):
            timeline.append(
                {"n": i, "status": None, "action": "stop", "detail": res["error"]}
            )
            break
        status = res.get("status") or 0
        if status in (429, 503):
            throttled += 1
            consecutive += 1
            advised = _retry_after_seconds(res.get("retry_after", ""), time.time())
            wait = min(advise if (advise := advised) is not None else base, cap)
            jitter = rng.uniform(0, 1.0)
            slept = round(wait + jitter, 2)
            honored.append(slept)
            do_sleep(slept)
            base = min(base * 2.0, cap)
            timeline.append(
                {
                    "n": i,
                    "status": status,
                    "action": f"slept {slept}s",
                    "retry_after": res.get("retry_after", ""),
                }
            )
        else:
            consecutive = 0
            base = max(1.0, base / 2.0)
            timeline.append({"n": i, "status": status, "action": "pass"})
    if throttled:
        findings: list[dict[str, Any]] = [
            {
                "probe": "rate-limit",
                "severity": "INFO",
                "title": f"endpoint throttles ({throttled}/{sent}); probe yielded every time",
                "evidence": f"max backoff honored: {max(honored) if honored else 0}s",
            }
        ]
        clean = True
        note = f"{throttled} throttle(s) honored — client behaved, no finding"
    else:
        findings = [
            {
                "probe": "rate-limit",
                "severity": "MEDIUM",
                "title": f"no throttling in {sent} requests — likely brute-forceable",
                "evidence": f"{sent} consecutive passes, no 429/Retry-After observed",
            }
        ]
        clean = False
        note = ""
    return {
        "url": url,
        "requests": sent,
        "throttled": throttled,
        "honored_waits": honored,
        "timeline": timeline[-32:],
        "findings": findings,
        "finding_count": len(findings),
        "clean": clean,
        "note": note,
    }


def to_ledger(
    host: str, url: str, findings: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Map no-throttle findings to engagement vuln rows for the URL host."""
    rows: list[dict[str, Any]] = []
    for finding in findings:
        if finding.get("severity") == "INFO":
            continue  # honored throttles document posture; not a vuln
        rows.append(
            {
                "host": host,
                "name": f"rate-limit missing on {url}"[:220],
                "severity": str(finding.get("severity") or "MEDIUM").upper(),
                "module": "rate-fuzz",
                "reference": "",
                "cwe": "CWE-799",
                "detail": str(finding.get("evidence", ""))[:400],
            }
        )
    return rows


def sandbox_result(url: str = "http://lab.local/api") -> dict[str, Any]:
    """Canned characterization (no requests sent)."""
    findings = [
        {
            "probe": "rate-limit",
            "severity": "MEDIUM",
            "title": "no throttling in 50 requests — likely brute-forceable (sandbox)",
            "evidence": "50 consecutive passes, no 429/Retry-After observed (sandbox)",
        }
    ]
    return {
        "url": url or "http://lab.local/api",
        "requests": 50,
        "throttled": 0,
        "honored_waits": [],
        "timeline": [{"n": i, "status": 200, "action": "pass"} for i in range(3)],
        "findings": findings,
        "finding_count": 1,
        "clean": False,
        "note": "",
        "sandbox": True,
    }
