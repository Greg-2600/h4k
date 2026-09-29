"""Crash dedup: fingerprints must survive ASLR and separate distinct bugs.

The property under test throughout is the one that makes crash counts
meaningful: two different crashing inputs that fault through the same code
path are ONE bug, and a different faulting path is a DIFFERENT bug.
"""

from services import crashes

TRACE_A = """==1==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x6020
    #0 0x7f3c9a2b1000 in parse_header /src/vulnlab.c:47:10
    #1 0x55d3a2 in vulnlab_parse /src/vulnlab.c:40:5
    #2 0x7f8e in __interceptor_strlen
SUMMARY: AddressSanitizer: stack-buffer-overflow /src/vulnlab.c:47 in parse_header"""

# Same bug: different load address (ASLR), different line (unrelated edit above).
TRACE_A_RELOAD = """==9==ERROR: AddressSanitizer: stack-buffer-overflow at 0x6011
    #0 0x7f9911cc8840 in parse_header /src/vulnlab.c:52:10
    #1 0x7fd22 in vulnlab_parse /src/vulnlab.c:40:5
    #2 0x7a11 in __interceptor_strlen
SUMMARY: AddressSanitizer: stack-buffer-overflow /src/vulnlab.c:52 parse_header"""

# Different bug, same source function: format-param rather than overflow.
TRACE_FORMAT = """==1==ERROR: AddressSanitizer: format-param on address 0x602000000f80
    #0 0x7f3c9a2b9999 in parse_header /src/vulnlab.c:55:3
    #1 0x55d3a2 in vulnlab_parse /src/vulnlab.c:40:5"""


# --- fingerprinting ----------------------------------------------------------


def test_fingerprint_survives_aslr_and_line_shift():
    assert crashes.fingerprint(TRACE_A) == crashes.fingerprint(TRACE_A_RELOAD)


def test_fingerprint_separates_distinct_bug_classes():
    assert crashes.fingerprint(TRACE_A) != crashes.fingerprint(TRACE_FORMAT)


def test_fingerprint_empty_for_non_trace():
    # Nothing to fingerprint -> we must NOT invent a bug id.
    assert crashes.fingerprint("just a log line") == ""
    assert crashes.fingerprint("") == ""


def test_error_class_extracted():
    assert crashes.error_class(TRACE_A) == "stack-buffer-overflow"
    assert crashes.error_class("no sanitizer here") == "unknown"


def test_extract_frames_strips_volatile_parts():
    frames = crashes.extract_frames(TRACE_A)
    assert frames[0] == "parse_header /src/vulnlab.c"
    assert all("0x" not in f for f in frames)
    assert not any(f.endswith(":47") for f in frames)


def test_extract_frames_dedupes_repeats():
    trace = TRACE_A + "\n" + TRACE_A_RELOAD
    frames = crashes.extract_frames(trace)
    assert len(frames) == len(set(frames))


def test_extract_frames_caps_depth():
    deep = "\n".join(f"    #{i} 0x7f{i} in fn_{i} /src/f.c:{i}:1" for i in range(40))
    assert len(crashes.extract_frames(deep)) <= 6


def test_signal_fingerprint_is_stable_and_distinct():
    a = crashes.signal_fingerprint("teardown", "10.0.0.5:80")
    assert a == crashes.signal_fingerprint("teardown", "10.0.0.5:80")
    assert a != crashes.signal_fingerprint("teardown", "10.0.0.6:80")
    assert a != crashes.signal_fingerprint("hang", "10.0.0.5:80")
    assert a != crashes.signal_fingerprint("teardown")


def test_signal_fingerprint_ignores_the_mutation_operator():
    # Regression: keying on the operator reported one dead service as many
    # unrelated "distinct crashes", because different operators reach the same
    # observed condition. The operator is an artifact of how we probed.
    reg = crashes.CrashRegistry()
    _record(reg, "", vector="bitflip", signal="resource")
    _record(reg, "", vector="splice", signal="resource")
    _record(reg, "", vector="havoc:arith+dict", signal="resource")
    assert len(reg) == 1, "same signal on the same target is one lead"
    assert reg.records[0].occurrences == 3


# --- registry accounting -----------------------------------------------------


def _record(registry, trace="", vector="bitflip", signal="teardown"):
    return registry.record(
        host="10.0.0.5",
        service="http",
        port=80,
        vector=vector,
        signal=signal,
        repro="GET / HTTP/1.1",
        trace=trace,
        seen_at="2026-01-01T00:00:00+00:00",
    )


def test_registry_collapses_same_bug_and_counts_occurrences():
    reg = crashes.CrashRegistry()
    _, first = _record(reg, TRACE_A)
    _, second = _record(reg, TRACE_A_RELOAD)

    assert first is True
    assert second is False, "same bug via different ASLR base must dedup"
    assert len(reg) == 1
    assert reg.records[0].occurrences == 2


def test_registry_keeps_distinct_bugs_apart():
    reg = crashes.CrashRegistry()
    _record(reg, TRACE_A)
    _record(reg, TRACE_FORMAT)
    assert len(reg) == 2


def test_registry_marks_sanitizer_backed_as_confirmed():
    reg = crashes.CrashRegistry()
    rec, _ = _record(reg, TRACE_A)
    assert rec.confirmed is True
    assert rec.basis == crashes.SANITIZER_BASIS
    assert rec.bug_class == "stack-buffer-overflow"
    assert rec.frames


def test_registry_does_not_call_a_blackbox_signal_a_confirmed_bug():
    reg = crashes.CrashRegistry()
    rec, _ = _record(reg, "", signal="teardown")
    assert rec.confirmed is False
    assert rec.basis == crashes.SIGNAL_BASIS
    assert rec.frames == []


def test_registry_repeat_lookups_return_same_record():
    reg = crashes.CrashRegistry()
    first, _ = _record(reg, TRACE_A)
    again, is_new = _record(reg, TRACE_A)
    assert again is first
    assert is_new is False


def test_registry_supports_membership_and_get():
    reg = crashes.CrashRegistry()
    rec, _ = _record(reg, TRACE_A)
    assert rec.crash_id in reg
    assert reg.get(rec.crash_id) is rec
    assert reg.get("nope") is None


def test_registry_first_and_last_seen_recorded():
    reg = crashes.CrashRegistry()
    reg.record(
        host="h",
        service="http",
        port=80,
        vector="v",
        signal="teardown",
        repro="r",
        trace=TRACE_A,
        seen_at="first",
    )
    rec = reg.records[0]
    assert rec.first_seen == "first"
    rec.last_seen = "second"
    assert rec.last_seen == "second"


# --- minimization bookkeeping -------------------------------------------------


def test_attach_minimized_requires_an_actual_reduction():
    reg = crashes.CrashRegistry()
    rec, _ = _record(reg, TRACE_A)
    rec.original_bytes = 100

    # Not smaller -> refuses, so we never claim a reduction that didn't happen.
    assert reg.attach_minimized(rec.crash_id, "A" * 100, b"A" * 100) is False
    assert reg.attach_minimized(rec.crash_id, "A" * 200, b"A" * 100) is False
    assert reg.attach_minimized(rec.crash_id, "", b"A" * 100) is False
    assert reg.attach_minimized("unknown-id", "A", b"A" * 100) is False

    assert reg.attach_minimized(rec.crash_id, "A" * 10, b"A" * 100) is True
    assert rec.minimized_bytes == 10


def test_attach_minimized_needs_a_known_original_size():
    reg = crashes.CrashRegistry()
    rec, _ = _record(reg, TRACE_A)
    assert reg.attach_minimized(rec.crash_id, "A" * 10) is False


# --- summary -----------------------------------------------------------------


def test_summary_separates_confirmed_bugs_from_leads():
    reg = crashes.CrashRegistry()
    _record(reg, TRACE_A)
    _record(reg, TRACE_FORMAT)
    _record(reg, "", signal="teardown", vector="v1")
    _record(reg, "", signal="hang", vector="v2")

    summary = reg.summary()
    assert summary["confirmed_bugs"] == 2
    assert summary["unconfirmed_leads"] == 2
    assert summary["unique_crashes"] == 4
    assert summary["total_occurrences"] == 4


def test_summary_exposes_occurrences_so_counts_cannot_be_confused():
    reg = crashes.CrashRegistry()
    for _ in range(50):
        _record(reg, TRACE_A_RELOAD)
    summary = reg.summary()
    # The whole point: 50 crashes is 1 bug, and both numbers are reported so
    # nobody reads "50 crashes" as "50 vulnerabilities".
    assert summary["unique_crashes"] == 1
    assert summary["total_occurrences"] == 50
    assert summary["confirmed_bugs"] == 1


def test_summary_counts_minimized_records():
    reg = crashes.CrashRegistry()
    rec, _ = _record(reg, TRACE_A)
    reg.attach_minimized(rec.crash_id, "A" * 4, b"A" * 400)
    assert reg.summary()["minimized"] == 1


# --- serialization -----------------------------------------------------------


def test_to_dict_includes_reduction_percentage():
    reg = crashes.CrashRegistry()
    rec, _ = _record(reg, TRACE_A)
    reg.attach_minimized(rec.crash_id, "A" * 50, b"A" * 100)
    payload = rec.to_dict()
    assert payload["reduction_pct"] == 50.0
    assert payload["minimized"] == "A" * 50
    assert payload["confirmed"] is True


def test_to_dict_omits_minimization_fields_when_absent():
    reg = crashes.CrashRegistry()
    rec, _ = _record(reg, TRACE_A)
    payload = rec.to_dict()
    assert "minimized" not in payload
    assert "reduction_pct" not in payload
