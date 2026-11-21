# Process-local AI call/token budget.
#
# ARTEX caps a task's planner/worker spend; h4k's AI calls are per-request, so
# the useful analogue is a per-scope (engagement/session/default) budget that
# stops a retry loop from quietly turning into a billing incident. Counters live
# in memory: a restart starts fresh, which is honest and documented.
#
# Estimates are deliberately approximate (4 characters ≈ 1 token). Operators
# should treat the numbers as a guardrail, not an invoice.
import os
import threading
from dataclasses import dataclass
from typing import Any

_lock = threading.Lock()


@dataclass
class _Usage:
    calls: int = 0
    tokens: int = 0


_usage: dict[str, _Usage] = {}


def estimate_tokens(text: str) -> int:
    return max(1, len(str(text or "")) // 4)


def _limits() -> tuple[int, int]:
    try:
        tokens = max(0, int(os.environ.get("H4K_AI_BUDGET_TOKENS", "0")))
    except ValueError:
        tokens = 0
    try:
        calls = max(0, int(os.environ.get("H4K_AI_BUDGET_CALLS", "0")))
    except ValueError:
        calls = 0
    return tokens, calls


def _scope(scope: str) -> str:
    return str(scope or "default")[:120]


def check(scope: str, input_text: str) -> dict[str, Any]:
    """Return whether one more call fits the scope's budget."""
    max_tokens, max_calls = _limits()
    estimated = estimate_tokens(input_text)
    name = _scope(scope)
    with _lock:
        usage = _usage.setdefault(name, _Usage())
        calls_ok = max_calls == 0 or usage.calls < max_calls
        tokens_ok = max_tokens == 0 or usage.tokens + estimated <= max_tokens
        allowed = calls_ok and tokens_ok
        reason = ""
        if not calls_ok:
            reason = f"AI call budget exhausted ({usage.calls}/{max_calls})"
        elif not tokens_ok:
            reason = (
                f"AI token budget would be exceeded "
                f"({usage.tokens}+{estimated}/{max_tokens})"
            )
        return {
            "allowed": allowed,
            "scope": name,
            "estimated_input_tokens": estimated,
            "calls": usage.calls,
            "tokens": usage.tokens,
            "max_calls": max_calls,
            "max_tokens": max_tokens,
            "reason": reason,
        }


def record(
    scope: str, *, input_text: str = "", output_text: str = ""
) -> dict[str, Any]:
    name = _scope(scope)
    tokens = estimate_tokens(input_text) + estimate_tokens(output_text)
    with _lock:
        usage = _usage.setdefault(name, _Usage())
        usage.calls += 1
        usage.tokens += tokens
    return status(name)


def status(scope: str = "") -> dict[str, Any]:
    max_tokens, max_calls = _limits()
    with _lock:
        if scope:
            name = _scope(scope)
            usage = _usage.get(name)
            scopes = (
                {name: {"calls": usage.calls, "tokens": usage.tokens}}
                if usage is not None
                else {}
            )
        else:
            scopes = {
                name: {"calls": value.calls, "tokens": value.tokens}
                for name, value in sorted(_usage.items())
            }
    return {
        "max_tokens": max_tokens,
        "max_calls": max_calls,
        "scopes": scopes,
        "estimate": "4 characters ≈ 1 token; in-memory, resets on restart",
    }


def reset(scope: str = "") -> dict[str, Any]:
    with _lock:
        if scope:
            _usage.pop(_scope(scope), None)
        else:
            _usage.clear()
    return status(scope)


def reset_for_tests() -> None:
    with _lock:
        _usage.clear()
