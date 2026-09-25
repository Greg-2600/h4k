# Tests for the shared sanitizer service: classification of real ASan/UBSan
# traces, and the per-finding "confirm under sanitizer" plans attached to SAST
# and fuzz findings.
from schemas import SourceFinding
from services import fuzzer, sanitizer, sast, semgrep


def test_classify_asan_stack_buffer_overflow():
    trace = (
        "==1==ERROR: AddressSanitizer: stack-buffer-overflow on address "
        "0x7ffd1234 at pc 0x00055d8a1b2c3 bp 0x7ffd1200 sp 0x7ffd11f0\n"
        "WRITE of size 8 at 0x7ffd1234 thread T0\n"
    )
    r = sanitizer.classify_trace(trace)
    assert r["class"] == "stack-buffer-overflow"
    assert r["cwe"] == "CWE-120"
    assert "stack-buffer-overflow" in r["summary"]


def test_classify_asan_use_after_free():
    trace = (
        "==1==ERROR: AddressSanitizer: heap-use-after-free on address 0x60300000eff8"
    )
    r = sanitizer.classify_trace(trace)
    assert r["class"] == "use-after-free"
    assert r["cwe"] == "CWE-416"


def test_classify_ubsan_signed_overflow():
    trace = (
        "repro.c:9:20: runtime error: signed integer overflow: "
        "2147483647 + 1 cannot be represented in type 'int'"
    )
    r = sanitizer.classify_trace(trace)
    assert r["class"] == "signed-integer-overflow"
    assert r["cwe"] == "CWE-190"


def test_classify_leak_and_double_free():
    r = sanitizer.classify_trace("==1==ERROR: LeakSanitizer: detected memory leaks")
    assert r["class"] == "leak"
    r2 = sanitizer.classify_trace(
        "==1==ERROR: AddressSanitizer: attempting double-free on 0x602000000010"
    )
    assert r2["class"] == "double-free"


def test_classify_unknown_does_not_guess():
    # A non-sanitizer crash must NOT be forced into a memory-safety class.
    r = sanitizer.classify_trace("Segmentation fault (core dumped)")
    assert r["class"] == "unknown"
    assert r["cwe"] == "CWE-710"


def test_tables_are_internally_consistent():
    # Guards against a class key/pattern typo silently becoming "unknown".
    for cls, info in sanitizer.BUG_CLASSES.items():
        assert info["cwe"].startswith("CWE-"), cls
    for _cwe, cls in sanitizer.CWE_TO_CLASS.items():
        assert cls in sanitizer.BUG_CLASSES, cls
    for name, _pat in sanitizer._CLASS_PATTERNS:
        assert name in sanitizer.BUG_CLASSES, name


def test_verify_plan_for_memory_class_is_relevant():
    p = sanitizer.verify_plan("CWE-120", rule_id="sast-buffer-copy", file="a.c")
    assert p["relevant"] is True
    assert p["class"] == "stack-buffer-overflow"
    assert "AddressSanitizer" in p["expect"]
    assert "-fsanitize=address" in p["build_flags"]
    assert "abort_on_error=1" in p["env"]["ASAN_OPTIONS"]


def test_verify_plan_for_injection_class_is_honest():
    # SQL injection cannot be adjudicated by a sanitizer -> say so.
    p = sanitizer.verify_plan("CWE-89")
    assert p["relevant"] is False
    assert p["class"] is None
    assert "cannot confirm or refute" in p["note"]


def test_confirm_plan_teardown_has_candidates_not_verdict():
    p = sanitizer.confirm_plan(
        "teardown", host="127.0.0.1", port=8080, vector="very-long"
    )
    assert p["relevant"] is True
    assert p["class"] is None  # unknown until a trace names it
    assert "CWE-416" in p["cwe_candidates"]
    assert "very-long" in p["replay"]
    assert "127.0.0.1:8080" in p["replay"]


def test_confirm_plan_server_error_not_sanitizable():
    p = sanitizer.confirm_plan("server_error")
    assert p["relevant"] is False
    assert p["cwe_candidates"] == []


def test_replay_command_is_copy_pasteable():
    cmd = sanitizer.replay_command("repro.c", "repro")
    assert cmd.startswith("clang ")
    assert "-fsanitize=address,undefined" in cmd
    assert "./repro" in cmd


def test_fuzzer_parse_sanitizer_trace_uses_shared_table():
    out = fuzzer.LabFuzzer.parse_sanitizer_trace(
        "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602"
    )
    assert out["kind"] == "heap-buffer-overflow"
    assert out["cwe"] == "CWE-122"


def test_sast_finding_carries_sanitizer_plan():
    f = sast.Finding(
        "sast-buffer-copy",
        "Unchecked buffer copy",
        "high",
        "CWE-120",
        "a.c",
        12,
        "strcpy(d, s);",
        "x",
    )
    d = f.to_dict()
    assert d["sanitizer"]["relevant"] is True
    assert d["sanitizer"]["class"] == "stack-buffer-overflow"


def test_sast_finding_injection_rule_not_sanitizer_relevant():
    f = sast.Finding(
        "sast-sql-injection",
        "SQL concat",
        "high",
        "CWE-89",
        "a.py",
        3,
        "q = 'select ' + x",
        "x",
    )
    assert f.to_dict()["sanitizer"]["relevant"] is False


def test_schema_defaults_tolerate_missing_sanitizer():
    # Older cached payloads without the new field must still validate.
    sf = SourceFinding(
        rule_id="r", name="n", severity="low", cwe="CWE-1", file="a", line=1
    )
    assert sf.sanitizer == {}


# --- semgrep CWE extraction (so SAST findings can carry a sanitizer plan) ---


def test_cwe_from_metadata_tags():
    assert semgrep._cwe_from({"tags": ["CWE-89: SQL Injection"]}) == "CWE-89"


def test_cwe_from_metadata_cwe_key():
    meta = {"cwe": "CWE-120: Copy of Buffer without Checking Size of Input"}
    assert semgrep._cwe_from(meta) == "CWE-120"


def test_cwe_from_message_fallback():
    meta = {"message": "gets() is unbounded (CWE-120)."}
    assert semgrep._cwe_from(meta) == "CWE-120"


def test_cwe_from_rule_id_heuristic_when_metadata_absent():
    # Upstream rules often carry no CWE at all; fall back to rule-id keywords.
    assert semgrep._cwe_from({}, "sast-semgrep-buffer") == "CWE-120"
    assert semgrep._cwe_from({}, "sast-semgrep-format") == "CWE-134"
    assert semgrep._cwe_from({}, "sast-semgrep-pickle-load") == "CWE-502"


def test_cwe_from_returns_unknown_when_nothing_matches():
    assert semgrep._cwe_from({}, "sast-semgrep-totally-unrelated-xyz") == "CWE-710"


def test_bundled_offline_rules_all_declare_a_cwe():
    import yaml
    from services.semgrep import OFFLINE_RULES

    rules_path = OFFLINE_RULES / "offline.yml"
    if not rules_path.exists():
        return  # installed outside the image layout
    rules = yaml.safe_load(rules_path.read_text(encoding="utf-8"))["rules"]
    assert rules
    for r in rules:
        cwe = r.get("metadata", {}).get("cwe", "")
        assert cwe.startswith("CWE-"), r["id"]
