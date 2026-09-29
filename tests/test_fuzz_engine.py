"""Mutation engine and the real libFuzzer-backed minimizer.

The engine has to be reproducible (same seed -> same sequence) or a crash
report is unreplayable, and the minimizer has to actually reduce or say it
did not.
"""

import subprocess

from services.fuzzer import (
    DICT_TOKENS,
    INTERESTING_BYTES,
    INTERESTING_U32,
    MAX_CORPUS,
    MUTATIONS,
    LabFuzzer,
    MutationEngine,
    libfuzzer_minimize,
)

# The engine takes raw inputs; MUTATIONS is a (label, payload) probe table.
SEEDS = [payload for _label, payload in MUTATIONS]


# --- engine construction -----------------------------------------------------


def test_engine_seeds_from_mutation_table():
    eng = MutationEngine(seeds=SEEDS)
    assert len(eng.corpus) == len(MUTATIONS)
    assert eng.stats()["operators"] >= 8


def test_engine_falls_back_to_default_seeds():
    assert MutationEngine().corpus


def test_engine_defaults_only_when_seeds_is_none():
    # An explicit empty corpus is respected; only None means "use defaults".
    assert MutationEngine().corpus
    assert MutationEngine(seeds=[]).corpus == []


def test_boundary_value_sets_cover_off_by_one_edges():
    assert 0 in INTERESTING_BYTES and 255 in INTERESTING_BYTES
    assert 127 in INTERESTING_BYTES and 128 in INTERESTING_BYTES
    assert 0x7FFFFFFF in INTERESTING_U32 and 0xFFFFFFFF in INTERESTING_U32
    assert 0x80000000 in INTERESTING_U32


# --- reproducibility ---------------------------------------------------------


def test_same_seed_replays_the_same_sequence():
    a = MutationEngine(seeds=SEEDS, seed_value=1234)
    b = MutationEngine(seeds=SEEDS, seed_value=1234)
    assert [a.mutate()[1] for _ in range(25)] == [b.mutate()[1] for _ in range(25)]


def test_different_seed_diverges():
    a = MutationEngine(seeds=SEEDS, seed_value=1)
    b = MutationEngine(seeds=SEEDS, seed_value=999)
    assert [a.mutate()[1] for _ in range(25)] != [b.mutate()[1] for _ in range(25)]


def test_havoc_is_reproducible():
    a = MutationEngine(seeds=SEEDS, seed_value=7)
    b = MutationEngine(seeds=SEEDS, seed_value=7)
    assert a.havoc()[1] == b.havoc()[1]


# --- operators ---------------------------------------------------------------


def test_mutators_produce_bytes_and_labels():
    eng = MutationEngine(seeds=SEEDS, seed_value=3)
    for _ in range(200):
        label, data = eng.mutate()
        assert isinstance(label, str) and label
        assert isinstance(data, bytes)


def test_mutation_actually_changes_input():
    eng = MutationEngine(seeds=[b"AAAAAAAAAAAAAAAA"], seed_value=11)
    changed = 0
    for _ in range(60):
        if eng.mutate(b"AAAAAAAAAAAAAAAA")[1] != b"AAAAAAAAAAAAAAAA":
            changed += 1
    assert changed > 0


def test_block_delete_never_increases_length():
    eng = MutationEngine(seeds=SEEDS, seed_value=5)
    for _ in range(50):
        assert len(eng._block_delete(b"ABCDEFGH")) <= 8
    assert len(eng._block_delete(b"")) == 0


def test_mutate_picks_varied_operators():
    # A fuzzer that only ever bit-flips is barely a fuzzer.
    eng = MutationEngine(seeds=SEEDS, seed_value=21)
    labels = {eng.mutate()[0] for _ in range(300)}
    assert len(labels) >= 5


def test_havoc_label_lists_its_operators():
    eng = MutationEngine(seeds=SEEDS, seed_value=2)
    label, _ = eng.havoc(rounds=3)
    assert label.startswith("havoc:")


def test_havoc_with_zero_rounds_still_works():
    eng = MutationEngine(seeds=SEEDS, seed_value=2)
    assert eng.havoc(rounds=0)[1] is not None


def test_output_is_length_capped():
    eng = MutationEngine(seeds=[b"A" * 40000], seed_value=4)
    eng.corpus = [b"A" * 40000]
    assert len(eng.havoc(rounds=8)[1]) <= 16384


def test_operators_handle_empty_input():
    eng = MutationEngine(seeds=[b""], seed_value=1)
    for _ in range(40):
        assert isinstance(eng.mutate(b"")[1], bytes)


def test_splice_without_enough_corpus_falls_back():
    eng = MutationEngine(seeds=[b"x"], seed_value=1)
    for _ in range(30):
        eng.mutate(b"x")


def test_dictionary_is_used_and_replaceable():
    eng = MutationEngine(seeds=SEEDS, seed_value=6, dictionary=[b"@@MARK@@"])
    assert eng.dictionary == [b"@@MARK@@"]
    assert eng.stats()["dictionary"] == 1
    assert MutationEngine().dictionary == list(DICT_TOKENS)


def test_empty_dictionary_falls_back_to_arith():
    eng = MutationEngine(seeds=[b"abcd"], dictionary=[], seed_value=1)
    assert isinstance(eng.mutate(b"abcd")[1], bytes)


# --- corpus management -------------------------------------------------------


def test_corpus_add_dedupes():
    eng = MutationEngine(seeds=[], seed_value=1)
    assert eng.add_corpus(b"AAAA") is True
    assert eng.add_corpus(b"AAAA") is False


def test_corpus_rejects_empty():
    eng = MutationEngine(seeds=[], seed_value=1)
    assert eng.add_corpus(b"") is False


def test_corpus_is_bounded():
    eng = MutationEngine(seeds=[], seed_value=1)
    for i in range(MAX_CORPUS + 50):
        eng.add_corpus(f"input-{i}".encode())
    assert len(eng.corpus) <= MAX_CORPUS


# --- real minimization -------------------------------------------------------


def test_minimize_reports_reduction_when_libfuzzer_shrinks_it(tmp_path, monkeypatch):
    crash = tmp_path / "crash-big"
    crash.write_bytes(b"A" * 500)
    binary = tmp_path / "fz"
    binary.write_text("#!/bin/sh\n", encoding="utf-8")

    def fake_run(cmd, **kwargs):
        # Simulate libFuzzer writing the reduced unit into the corpus dir.
        workdir = tmp_path / f".minimize-{crash.name}"
        (workdir / "minimized-from-abc123").write_bytes(b"AB")
        return subprocess.CompletedProcess(cmd, 0, "merged 1 inputs", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    text, reduced = libfuzzer_minimize(str(binary), crash)
    assert reduced is True
    assert text == "AB"


def test_minimize_declines_when_libfuzzer_fails(tmp_path, monkeypatch):
    crash = tmp_path / "crash-x"
    crash.write_bytes(b"Z" * 50)
    binary = tmp_path / "fz"
    binary.write_text("#!/bin/sh\n", encoding="utf-8")

    monkeypatch.setattr(
        subprocess,
        "run",
        lambda cmd, **kw: subprocess.CompletedProcess(cmd, 1, "", "boom"),
    )
    text, reduced = libfuzzer_minimize(str(binary), crash)
    assert reduced is False
    assert text == ""


def test_minimize_declines_when_merged_file_is_not_smaller(tmp_path, monkeypatch):
    crash = tmp_path / "crash-x"
    crash.write_bytes(b"Z" * 10)
    binary = tmp_path / "fz"
    binary.write_text("#!/bin/sh\n", encoding="utf-8")

    def fake_run(cmd, **kwargs):
        workdir = tmp_path / f".minimize-{crash.name}"
        (workdir / "minimized-from-abc123").write_bytes(b"L" * 999)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    _text, reduced = libfuzzer_minimize(str(binary), crash)
    assert reduced is False


def test_minimize_declines_on_empty_merged_output(tmp_path, monkeypatch):
    crash = tmp_path / "crash-x"
    crash.write_bytes(b"Z" * 10)
    binary = tmp_path / "fz"
    binary.write_text("#!/bin/sh\n", encoding="utf-8")

    def fake_run(cmd, **kwargs):
        workdir = tmp_path / f".minimize-{crash.name}"
        (workdir / "minimized-from-abc123").write_bytes(b"")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    _text, reduced = libfuzzer_minimize(str(binary), crash)
    assert reduced is False


def test_minimize_swallows_oserrors(tmp_path, monkeypatch):
    crash = tmp_path / "crash-x"
    crash.write_bytes(b"Z")
    binary = tmp_path / "fz"
    binary.write_text("#!/bin/sh\n", encoding="utf-8")

    def boom(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd="fz", timeout=1)

    monkeypatch.setattr(subprocess, "run", boom)
    assert libfuzzer_minimize(str(binary), crash) == ("", False)


def test_minimize_cleans_up_its_workdir(tmp_path, monkeypatch):
    crash = tmp_path / "crash-y"
    crash.write_bytes(b"A" * 40)
    binary = tmp_path / "fz"
    binary.write_text("#!/bin/sh\n", encoding="utf-8")

    def fake_run(cmd, **kwargs):
        workdir = tmp_path / f".minimize-{crash.name}"
        (workdir / "minimized-from-abc123").write_bytes(b"A")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    libfuzzer_minimize(str(binary), crash)
    assert not (tmp_path / f".minimize-{crash.name}").exists()


# --- fuzzer wiring -----------------------------------------------------------


def test_fuzzer_defaults_to_engine_mode():
    f = LabFuzzer()
    assert f.mutations is None
    assert f.stats == {}


def test_fuzzer_iterations_floor_is_one():
    assert LabFuzzer(iterations=0).iterations == 1
    assert LabFuzzer(iterations=-5).iterations == 1


def test_looks_like_trace_detects_real_sanitizer_output():
    assert LabFuzzer._looks_like_trace(
        "==1==ERROR: AddressSanitizer: stack-buffer-overflow"
    )
    assert LabFuzzer._looks_like_trace("runtime error: signed integer overflow")
    assert not LabFuzzer._looks_like_trace("HTTP/1.1 500 Internal Server Error")
    assert not LabFuzzer._looks_like_trace("")


# --- engine-driven fuzz loop end to end --------------------------------------

ASAN_TRACE = (
    "==1==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x60200000\n"
    "    #0 0x7f3c9a2b1000 in parse_header /src/vulnlab.c:47:10\n"
    "    #1 0x55d3a2 in vulnlab_parse /src/vulnlab.c:40:5"
)


def _engine_fuzzer(monkeypatch, script, **kwargs):
    f = LabFuzzer(**kwargs)
    monkeypatch.setattr(f, "_probe_http", lambda url: True)
    seq = list(script)

    def send(host, port, vector):
        return seq.pop(0) if seq else ("HTTP/1.1 200 OK", 0, 0.001)

    monkeypatch.setattr(f, "_send_http", send)
    return f


def test_engine_loop_honours_iterations(monkeypatch):
    calls = []
    f = LabFuzzer(iterations=40, seed=1)
    monkeypatch.setattr(f, "_probe_http", lambda url: True)
    monkeypatch.setattr(
        f, "_send_http", lambda h, p, v: calls.append(v) or ("", 0, 0.001)
    )
    f._fuzz_http("127.0.0.1", 80, "http")
    assert len(calls) == 40


def test_engine_loop_dedups_repeated_identical_crashes(monkeypatch):
    # Every input crashes the same way. One bug, not 50.
    f = _engine_fuzzer(
        monkeypatch,
        [(ASAN_TRACE, 0, 0.001)] * 50,
        iterations=50,
        seed=2,
    )
    out = f._fuzz_http("127.0.0.1", 80, "http")
    assert len(out) == 1, "one distinct bug must produce one candidate row"
    assert out[0]["occurrences"] == 50
    assert f.stats["crashes"]["unique_crashes"] == 1
    assert f.stats["crashes"]["total_occurrences"] == 50
    assert f.stats["crashes"]["confirmed_bugs"] == 1


def test_engine_loop_marks_blackbox_signals_unconfirmed(monkeypatch):
    f = _engine_fuzzer(monkeypatch, [("", 3, 0.001)] * 3, iterations=6, seed=3)
    out = f._fuzz_http("127.0.0.1", 80, "http")
    assert out
    assert out[0]["confirmed"] is False
    assert out[0]["basis"] == "signal"
    assert f.stats["crashes"]["confirmed_bugs"] == 0
    assert f.stats["crashes"]["unconfirmed_leads"] >= 1


def test_engine_loop_records_sanitizer_frames_on_candidate(monkeypatch):
    f = _engine_fuzzer(monkeypatch, [(ASAN_TRACE, 0, 0.001)], iterations=2, seed=4)
    out = f._fuzz_http("127.0.0.1", 80, "http")
    assert out[0]["confirmed"] is True
    assert out[0]["bug_class"] == "stack-buffer-overflow"
    assert out[0]["frames"]
    assert out[0]["crash_id"]


def test_engine_stats_declare_signal_guided_not_coverage_guided(monkeypatch):
    f = _engine_fuzzer(monkeypatch, [], iterations=5, seed=5)
    f._fuzz_http("127.0.0.1", 80, "http")
    assert f.stats["mode"] == "signal-guided"
    assert f.stats["coverage_guided"] is False
    assert f.stats["executed"] == 5
    assert f.stats["engine"]["operators"] >= 8


def test_corpus_grows_only_on_new_fingerprints(monkeypatch):
    f = _engine_fuzzer(
        monkeypatch, [(ASAN_TRACE, 0, 0.001)] * 12, iterations=12, seed=6
    )
    before = len(f.engine.corpus)
    f._fuzz_http("127.0.0.1", 80, "http")
    after = len(f.engine.corpus)
    # Grows by exactly one -- the first discovery of the bug. The other 11
    # crashes re-found it and must not each pad the corpus.
    assert after == before + 1


def test_minimize_picks_the_smallest_artifact(tmp_path, monkeypatch):
    # libFuzzer leaves several `minimized-from-<sha1>` files of differing
    # sizes; the smallest is the real reduction, so we must not take the
    # first or the last one.
    crash = tmp_path / "crash-x"
    crash.write_bytes(b"A" * 5000)
    binary = tmp_path / "fz"
    binary.write_text("#!/bin/sh\n", encoding="utf-8")

    def fake_run(cmd, **kwargs):
        workdir = tmp_path / f".minimize-{crash.name}"
        (workdir / "minimized-from-aaa").write_bytes(b"Z" * 900)
        (workdir / "minimized-from-bbb").write_bytes(b"Z" * 256)
        (workdir / "minimized-from-ccc").write_bytes(b"Z" * 1024)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    text, reduced = libfuzzer_minimize(str(binary), crash)
    assert reduced is True
    assert len(text) == 256


def test_minimize_ignores_the_input_copy_when_globbing(tmp_path, monkeypatch):
    # The crash itself is copied into the workdir; it must not be mistaken
    # for a reduction artifact.
    crash = tmp_path / "crash-y"
    crash.write_bytes(b"A" * 3000)
    binary = tmp_path / "fz"
    binary.write_text("#!/bin/sh\n", encoding="utf-8")

    def fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    _text, reduced = libfuzzer_minimize(str(binary), crash)
    assert reduced is False, "the copied input must never count as a reduction"


def test_minimize_skips_zero_length_artifacts(tmp_path, monkeypatch):
    # Regression from live libFuzzer: a 0-byte minimized-from-* file is
    # written during the search and sorts first, but an empty input does not
    # reproduce the crash. Taking [0] would report a 0-byte "reduction".
    crash = tmp_path / "crash-z"
    crash.write_bytes(b"A" * 4000)
    binary = tmp_path / "fz"
    binary.write_text("#!/bin/sh\n", encoding="utf-8")

    def fake_run(cmd, **kwargs):
        workdir = tmp_path / f".minimize-{crash.name}"
        (workdir / "minimized-from-empty").write_bytes(b"")
        (workdir / "minimized-from-real").write_bytes(b"Z" * 256)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    text, reduced = libfuzzer_minimize(str(binary), crash)
    assert reduced is True
    assert len(text) == 256


def test_minimize_declines_when_only_empty_artifacts_exist(tmp_path, monkeypatch):
    crash = tmp_path / "crash-w"
    crash.write_bytes(b"A" * 400)
    binary = tmp_path / "fz"
    binary.write_text("#!/bin/sh\n", encoding="utf-8")

    def fake_run(cmd, **kwargs):
        workdir = tmp_path / f".minimize-{crash.name}"
        (workdir / "minimized-from-empty").write_bytes(b"")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert libfuzzer_minimize(str(binary), crash) == ("", False)


def test_minimize_accepts_nonzero_exit_when_artifact_exists(tmp_path, monkeypatch):
    # Regression from live libFuzzer: it exits 77 ("deadly signal") precisely
    # BECAUSE the crash reproduced, and writes the reduced artifacts before
    # exiting. Gating on returncode == 0 discarded every real reduction.
    crash = tmp_path / "crash-77"
    crash.write_bytes(b"A" * 4000)
    binary = tmp_path / "fz"
    binary.write_text("#!/bin/sh\n", encoding="utf-8")

    def fake_run(cmd, **kwargs):
        workdir = tmp_path / f".minimize-{crash.name}"
        (workdir / "minimized-from-abc").write_bytes(b"Z" * 256)
        return subprocess.CompletedProcess(cmd, 77, "", "deadly signal")

    monkeypatch.setattr(subprocess, "run", fake_run)
    text, reduced = libfuzzer_minimize(str(binary), crash)
    assert reduced is True
    assert len(text) == 256


def test_minimize_tolerates_non_utf8_output(tmp_path, monkeypatch):
    # libFuzzer echoes the crashing input, so a binary-format target emits
    # bytes that are not valid UTF-8. `text=True` without `errors` raises
    # UnicodeDecodeError and kills the whole run.
    crash = tmp_path / "crash-bin"
    crash.write_bytes(b"A" * 900)
    binary = tmp_path / "fz"
    binary.write_text("#!/bin/sh\n", encoding="utf-8")

    def fake_run(cmd, **kwargs):
        assert kwargs.get("errors") == "replace", "must decode leniently"
        workdir = tmp_path / f".minimize-{crash.name}"
        (workdir / "minimized-from-abc").write_bytes(b"\xf2\x00raw")
        return subprocess.CompletedProcess(cmd, 77, "", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    text, reduced = libfuzzer_minimize(str(binary), crash)
    assert reduced is True
    assert text == "\xf2\x00raw"
