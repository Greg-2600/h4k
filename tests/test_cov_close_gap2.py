# Gap-closer wave 2: ~20 cheapest uncovered lines.
from types import SimpleNamespace


def test_triage_bug_class_branches():
    from services.triage import build_triage, infer_bug_class

    assert infer_bug_class(SimpleNamespace(name="sql query", cwe="", rule_id="")) == (
        "sql-injection",
        "CWE-89",
    )
    assert infer_bug_class(SimpleNamespace(name="eval call", cwe="", rule_id=""))[
        1
    ] == ("CWE-95")
    assert infer_bug_class(SimpleNamespace(name="deserial pickle", cwe="", rule_id=""))[
        1
    ] == ("CWE-502")
    assert infer_bug_class(SimpleNamespace(name="path join", cwe="", rule_id=""))[
        1
    ] == ("CWE-22")
    # relevant sanitizer plan -> covers the confirm-line branch
    rep = build_triage(
        "AAAA", SimpleNamespace(name="strcpy overflow", cwe="", rule_id="")
    )
    assert any("Confirm it's a stack-buffer-overflow" in s for s in rep.steps)


def test_flags_count_and_substring_skip(tmp_path):
    from services.flags import FlagStore

    fs = FlagStore(tmp_path / "flags.db")
    assert fs.count() == 0  # no-engagement branch
    # CTF{...} wins; the inner 32-hex run is dropped as a substring
    found = FlagStore.detect("leak CTF{abcdef1234567890abcdef1234567890} end")
    assert found == ["CTF{abcdef1234567890abcdef1234567890}"]
    assert FlagStore.detect("") == []


def test_sandbox_fake_module_edges():
    from services.sandbox import FakeModule, FakeModules

    assert FakeModule("exploit", "exploit/multi/handler").check()["status"] == "failed"
    assert FakeModules().results("nope") == {}


def test_sanitizer_recipe_and_classify():
    from services.sanitizer import classify_trace, replay_command

    assert "< input.txt" in replay_command(stdin="input.txt")
    out = classify_trace("SUMMARY: AddressSanitizer: heap-buffer-overflow")
    assert out["class"] == "heap-buffer-overflow"


def test_vulnleads_empty_and_unknown():
    from services.vulnleads import analyze_service

    assert analyze_service("h", "ssh", "") == []
    assert analyze_service("h", "not-a-service", "blah 1.2.3") == []


def test_creds_as_meta():
    from services.creds import CredArchive

    meta = CredArchive().as_meta()
    assert "universal" in meta and "vendors" in meta


def test_merged_report_fuzz_and_triage_sections():
    from services.merged_report import render_markdown

    md = render_markdown(
        {
            "fuzz": [{"vector": "http", "signal": "crash", "evidence": "e" * 80}],
            "triage": [
                {
                    "bug_class": "stack-buffer-overflow",
                    "cwe": "CWE-120",
                    "minimized_trigger": "AA",
                }
            ],
        }
    )
    assert "Fuzzing candidates" in md
    assert "stack-buffer-overflow" in md
