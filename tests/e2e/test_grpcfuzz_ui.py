"""gRPC fuzz card through the real UI (sandbox canned + seeded scope)."""

from __future__ import annotations

from typing import Any

from .helpers import click, fill, go_to, wait_text, wait_visible


def test_grpc_fuzz_and_ledger(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "exploit")
    fill(page, "grpc-target", "10.10.10.77:50051")
    fill(page, "grpc-method", "/lab.Echo/Echo")
    fill(page, "grpc-iters", "8")
    click(page, "btn-grpc-start")
    wait_visible(page, "grpc-output", timeout=60)
    wait_text(page, "grpc-output", "candidate(s)", timeout=120)
    wait_text(page, "grpc-output", "in ledger", timeout=60)
