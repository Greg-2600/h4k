"""Tests for flag tracking and the next-move queue."""

import pytest
from services.flags import FlagStore


def test_flag_detection_ctf_shape():
    text = "the flag is CTF{hello_world_123} and also FLAG{another_one}"
    from services.flags import FlagStore as FS

    found = FS.detect(text)
    assert "CTF{hello_world_123}" in found
    assert "FLAG{another_one}" in found


def test_flag_detection_dedups():
    text = "CTF{same} appears twice: CTF{same}"
    from services.flags import FlagStore as FS

    assert FS.detect(text) == ["CTF{same}"]


def test_flag_detection_empty():
    from services.flags import FlagStore as FS

    assert FS.detect("") == []
    assert FS.detect("no flags here") == []


def test_flag_detection_hex():
    text = "the digest is 5d41402abc4b2a76b9719d911017c592"
    from services.flags import FlagStore as FS

    found = FS.detect(text)
    assert "5d41402abc4b2a76b9719d911017c592" in found


def test_flag_store_round_trip(tmp_path):
    fs = FlagStore(tmp_path / "flags.db")
    flag = fs.record("eng1", "CTF{hello}", host="10.0.0.5", auto=True)
    assert flag["value"] == "CTF{hello}"
    flags = fs.list_flags("eng1")
    assert len(flags) == 1
    assert flags[0]["value"] == "CTF{hello}"
    assert flags[0]["auto"] == 1


def test_flag_store_dedups_value(tmp_path):
    fs = FlagStore(tmp_path / "flags.db")
    fs.record("eng1", "CTF{dup}")
    fs.record("eng1", "CTF{dup}")
    assert fs.count("eng1") == 1


def test_flag_store_delete(tmp_path):
    fs = FlagStore(tmp_path / "flags.db")
    flag = fs.record("eng1", "CTF{to_delete}")
    assert fs.delete(flag["id"]) is True
    assert fs.count("eng1") == 0
    assert fs.delete("nope") is False


def test_flag_store_empty_value_rejected(tmp_path):
    fs = FlagStore(tmp_path / "flags.db")
    with pytest.raises(ValueError):
        fs.record("eng1", "  ")


def test_flag_store_list_all_engagements(tmp_path):
    fs = FlagStore(tmp_path / "flags.db")
    fs.record("eng1", "CTF{a}")
    fs.record("eng2", "CTF{b}")
    assert len(fs.list_flags()) == 2
    assert len(fs.list_flags("eng1")) == 1


def test_next_move_empty_engagement(tmp_path):
    from services.engagement import EngagementStore
    from services.next_move import build_next_move

    store = EngagementStore(tmp_path / "e.db")
    eng = store.create_engagement("lab", ["10.0.0.0/24"])
    result = build_next_move(store, eng["id"], fuzzed_targets={"vulnlab"})
    assert result["moves"] == []
    assert "nothing to do" in result["summary"]


def test_next_move_unknown_engagement(tmp_path):
    from services.engagement import EngagementStore
    from services.next_move import build_next_move

    store = EngagementStore(tmp_path / "e.db")
    result = build_next_move(store, "nope")
    assert result["moves"] == []
    assert result["engagement_id"] == "nope"


def test_next_move_fuzzing_lab_suggested(tmp_path):
    from services.engagement import EngagementStore
    from services.next_move import build_next_move

    store = EngagementStore(tmp_path / "e.db")
    eng = store.create_engagement("lab", ["10.0.0.0/24"])
    result = build_next_move(store, eng["id"], fuzzed_targets=set())
    kinds = [m["kind"] for m in result["moves"]]
    assert "fuzz" in kinds


def test_next_move_fuzzing_not_suggested_when_done(tmp_path):
    from services.engagement import EngagementStore
    from services.next_move import build_next_move

    store = EngagementStore(tmp_path / "e.db")
    eng = store.create_engagement("lab", ["10.0.0.0/24"])
    result = build_next_move(store, eng["id"], fuzzed_targets={"vulnlab"})
    kinds = [m["kind"] for m in result["moves"]]
    assert "fuzz" not in kinds


def test_next_move_returns_top_n(tmp_path):
    from services.engagement import EngagementStore
    from services.next_move import MAX_MOVES, build_next_move

    store = EngagementStore(tmp_path / "e.db")
    eng = store.create_engagement("lab", ["10.0.0.0/24"])
    store.ingest_scan(
        eng["id"],
        {
            "hosts": [
                {"address": "10.0.0.5", "services": [{"port": 22, "service": "ssh"}]}
            ],
            "vulns": [
                {
                    "host": "10.0.0.5",
                    "name": "OpenSSH outdated",
                    "severity": "high",
                    "module": "exploit/multi/ssh/sshexec",
                    "port": 22,
                }
            ],
        },
    )
    result = build_next_move(store, eng["id"])
    assert len(result["moves"]) <= MAX_MOVES
    assert result["moves"][0]["kind"] == "exploit"
    assert "OpenSSH" in result["moves"][0]["title"]
