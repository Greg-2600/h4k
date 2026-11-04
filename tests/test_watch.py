"""Lab Watch: canonicalize + diff are pure functions — pin the semantics."""

from services import watch as watch_mod

REPORT_A = {
    "hosts": [
        {
            "address": "10.0.0.5",
            "os": "Linux",
            "mac": "aa:bb",
            "hostname": "web",
            "services": [
                {
                    "port": 22,
                    "proto": "tcp",
                    "service": "ssh",
                    "version": "9.2p1",
                    "state": "open",
                },
                {
                    "port": 80,
                    "proto": "tcp",
                    "service": "http",
                    "version": "2.4.52",
                    "state": "open",
                },
            ],
        },
        {
            "address": "10.0.0.6",
            "services": [
                {"port": 445, "proto": "tcp", "service": "smb", "state": "open"}
            ],
        },
    ],
    "vulns": [
        {"host": "10.0.0.5", "name": "CVE-2021-1", "port": 22, "severity": "high"}
    ],
}


def test_canonicalize_keys_services_by_port_proto():
    snap = watch_mod.canonicalize(REPORT_A)
    assert snap["hosts"]["10.0.0.5"]["services"][(22, "tcp")]["version"] == "9.2p1"
    assert snap["vulns"][("10.0.0.5", "CVE-2021-1", 22)]["severity"] == "high"


def test_first_snapshot_is_baseline_with_no_changes():
    snap = watch_mod.canonicalize(REPORT_A)
    diff = watch_mod.diff_snapshots(None, snap)
    assert diff["first_baseline"] is True
    assert diff["change_count"] == 0
    assert diff["appeared_hosts"] == []
    assert watch_mod.summarize(diff).startswith("baseline recorded")


def test_json_round_trip_is_stable():
    snap = watch_mod.canonicalize(REPORT_A)
    restored = watch_mod._restore_snapshot(watch_mod._jsonable_snapshot(snap))
    assert watch_mod.diff_snapshots(snap, restored)["change_count"] == 0


def test_diff_detects_every_change_class():
    old = watch_mod.canonicalize(REPORT_A)
    report_b = {
        "hosts": [
            {
                "address": "10.0.0.5",
                "services": [
                    # ssh banner changed, http closed
                    {
                        "port": 22,
                        "proto": "tcp",
                        "service": "ssh",
                        "version": "9.3p1",
                        "state": "open",
                    },
                    {"port": 443, "proto": "tcp", "service": "https", "state": "open"},
                ],
            },
            {"address": "10.0.0.9", "services": []},  # brand-new host
        ],
        "vulns": [{"host": "10.0.0.9", "name": "CVE-2026-1", "severity": "critical"}],
    }
    new = watch_mod.canonicalize(report_b)
    diff = watch_mod.diff_snapshots(old, new)
    assert diff["appeared_hosts"] == ["10.0.0.9"]
    assert diff["vanished_hosts"] == ["10.0.0.6"]
    assert {(s["host"], s["port"]) for s in diff["new_services"]} == {("10.0.0.5", 443)}
    assert {(s["host"], s["port"]) for s in diff["closed_services"]} == {
        ("10.0.0.5", 80)
    }
    assert len(diff["changed_services"]) == 1
    assert diff["changed_services"][0]["before"]["version"] == "9.2p1"
    assert diff["changed_services"][0]["after"]["version"] == "9.3p1"
    assert {(v["host"], v["name"]) for v in diff["new_vulns"]} == {
        ("10.0.0.9", "CVE-2026-1")
    }
    assert {(v["host"], v["name"]) for v in diff["cleared_vulns"]} == {
        ("10.0.0.5", "CVE-2021-1")
    }
    assert diff["notable"] is True
    summary = watch_mod.summarize(diff)
    assert "1 new host(s)" in summary and "1 new finding(s)" in summary


def test_identical_rescans_are_quiet():
    snap = watch_mod.canonicalize(REPORT_A)
    diff = watch_mod.diff_snapshots(snap, watch_mod.canonicalize(REPORT_A))
    assert diff["change_count"] == 0
    assert diff["notable"] is False
    assert watch_mod.summarize(diff) == "no changes"
