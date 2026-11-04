"""Lab Watch card: baselines and estate changes render in the UI."""

from __future__ import annotations

from .helpers import go_to, wait_text


def _report(extra_service=False):
    hosts = [
        {
            "address": "10.10.10.5",
            "services": [
                {"port": 22, "proto": "tcp", "service": "ssh", "version": "9.2"}
            ],
        }
    ]
    if extra_service:
        hosts[0]["services"].append({"port": 80, "proto": "tcp", "service": "http"})
    return {"hosts": hosts, "vulns": []}


def test_watch_card_lists_baseline_and_change(page, api, seeded):
    eng_id = seeded["id"]
    status, first = api.post(f"/api/engagement/{eng_id}/watch/baseline", _report())
    assert status == 200, first
    second = _report(extra_service=True)
    status, res = api.post(f"/api/engagement/{eng_id}/watch/baseline", second)
    assert status == 200, res
    assert res["notable"] is True
    page.refresh()
    go_to(page, "score")
    wait_text(page, "watch-list", "baseline recorded", timeout=60)
    wait_text(page, "watch-list", "new service(s)", timeout=60)
