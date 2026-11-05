"""Blue-team handoff card renders techniques for the seeded engagement."""

from __future__ import annotations

from .helpers import go_to, wait_text


def test_handoff_card_lists_techniques(page, seeded):
    # seeded engagement records verified credentials -> T1078/T1110
    go_to(page, "score")
    wait_text(page, "handoff-status", "technique", timeout=60)
    wait_text(page, "handoff-list", "T1078", timeout=60)
