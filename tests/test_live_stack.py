"""Live-stack integration test.

Runs the same checks as `scripts/sanity_check.py` against a **running**
deployment, so CI (or a laptop with the stack up) can prove the whole system
works end to end: API, Metasploit RPC, web console, engagement lifecycle,
scan -> inventory -> ingest, crown jewels -> attack paths, ATT&CK mapping and
the fuzzing lab.

Opt-in: it needs a live stack, so it is skipped unless H4K_LIVE=1.

    H4K_LIVE=1 pytest tests/test_live_stack.py -v
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "sanity_check.py"
URL = os.environ.get("H4K_URL", "http://127.0.0.1:3137")
LAB = os.environ.get("H4K_LAB_URL", "http://127.0.0.1:3138")

pytestmark = pytest.mark.skipif(
    os.environ.get("H4K_LIVE") != "1",
    reason="live-stack test disabled (set H4K_LIVE=1 and start the stack)",
)


@pytest.fixture(scope="module")
def sanity_report():
    """Run the sanity script once and return its parsed JSON results."""
    proc = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--url",
            URL,
            "--lab",
            LAB,
            "--json",
        ],
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    assert proc.stdout.strip(), f"sanity script produced no output:\n{proc.stderr}"
    import json

    return json.loads(proc.stdout)


def test_every_sanity_check_passed(sanity_report):
    failed = [r for r in sanity_report if not r["ok"] and not r.get("warn")]
    assert not failed, "failed checks:\n" + "\n".join(
        f"  - {r['check']}: {r['detail']}" for r in failed
    )


def test_core_capabilities_are_present(sanity_report):
    """The interesting ones must actually have done something."""
    by_check = {r["check"]: r for r in sanity_report}
    assert by_check["api reachable"]["ok"]
    assert by_check["metasploit reachable"]["ok"]
    assert by_check["scan produced an inventory"]["ok"]
    assert "path(s)" in by_check["attack paths computed"]["detail"]
    assert "technique(s)" in by_check["attck mapping"]["detail"]
    assert by_check["fuzzing lab answers"]["ok"]
