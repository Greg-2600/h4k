"""Lockout-aware spray guard (Backlog #10).

Replaying credentials is one failed login away from locking the account
everyone shares. This module is the safety policy around
:class:`PropagationService`:

- **per-user cap**: at most N attempts per username per engagement
  (ledgered attempts count, so re-runs stay bounded too),
- **jitter**: a random pause between attempts so logins do not land in a
  lockout-tripping burst (off by default, skipped in tests/sandbox),
- **ledger stop**: users with a recorded `locked` result are never
  retried, and a lockout signal in a module error is recorded as `locked`
  instead of a plain miss.

Pure helpers here; the service wires them into plan/run.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Any

DEFAULT_MAX_PER_USER = 25
DEFAULT_JITTER_MAX = 0.0

LOCKOUT_MARKERS = (
    "locked out",
    "account locked",
    "too many failures",
    "too many failed",
    "password must change",
)


@dataclass(frozen=True)
class SprayPolicy:
    """Bounded spray policy for one propagation run."""

    max_per_user: int = DEFAULT_MAX_PER_USER
    jitter_max: float = DEFAULT_JITTER_MAX

    def normalized(self) -> SprayPolicy:
        return SprayPolicy(
            max_per_user=max(1, min(int(self.max_per_user), 500)),
            jitter_max=max(0.0, min(float(self.jitter_max), 60.0)),
        )


def is_lockout_signal(text: str | None) -> bool:
    """True when tool output smells like an account lockout."""
    low = (text or "").lower()
    return any(m in low for m in LOCKOUT_MARKERS)


def user_attempt_counts(attempt_rows: list[dict[str, Any]]) -> dict[str, int]:
    """Ledgered attempts per username (all results count toward the cap)."""
    counts: dict[str, int] = {}
    for row in attempt_rows:
        user = str(row.get("user") or "")
        if user:
            counts[user] = counts.get(user, 0) + 1
    return counts


def locked_users(attempt_rows: list[dict[str, Any]]) -> set[str]:
    """Usernames with a recorded `locked` result — never retried."""
    return {
        str(row.get("user") or "")
        for row in attempt_rows
        if str(row.get("result") or "").lower() == "locked" and row.get("user")
    }


def jitter_delay(policy: SprayPolicy, rng: random.Random | None = None) -> float:
    """Random pause for one gap; 0 when jitter is off (tests stay fast)."""
    if policy.jitter_max <= 0:
        return 0.0
    return (rng or random).uniform(0, policy.jitter_max)


def apply_policy(
    pairs: list[dict[str, Any]],
    attempt_rows: list[dict[str, Any]],
    policy: SprayPolicy,
) -> dict[str, Any]:
    """Filter planned pairs through the cap + locked set.

    Returns the filtered pairs plus stats explaining what was held back.
    """
    policy = policy.normalized()
    counts = user_attempt_counts(attempt_rows)
    locked = locked_users(attempt_rows)
    kept: list[dict[str, Any]] = []
    held_locked = 0
    held_capped = 0
    for pair in pairs:
        user = str(pair.get("user") or "")
        if user in locked:
            held_locked += 1
            continue
        if counts.get(user, 0) >= policy.max_per_user:
            held_capped += 1
            continue
        counts[user] = counts.get(user, 0) + 1
        kept.append(pair)
    return {
        "pairs": kept,
        "held_locked": held_locked,
        "held_capped": held_capped,
        "policy": {
            "max_per_user": policy.max_per_user,
            "jitter_max": policy.jitter_max,
        },
    }
