# Tests for SCA, triage, and AI-assist helper logic (no network).
from services.triage import _attempt_minimize, build_triage, infer_bug_class


def test_infer_bug_class_buffer():
    class F:
        name = "strcpy overflow"
        cwe = "CWE-120"
        rule_id = "sast-buffer-copy"

    assert infer_bug_class(F())[0] == "stack-buffer-overflow"


def test_infer_bug_class_format():
    class F:
        name = "printf user"
        cwe = "CWE-134"
        rule_id = "sast-format-string"

    assert infer_bug_class(F())[0] == "format-string"


def test_infer_bug_class_none():
    assert infer_bug_class(None)[0] == "unknown"


def test_build_triage_generates_report():
    r = build_triage("long-payload-abc")
    assert r.candidate == "long-payload-abc"
    assert r.cwe in ("CWE-120", "CWE-710")
    assert "patch" in r.suggested_patch.lower() or "fix" in r.suggested_patch.lower()
    assert isinstance(r.steps, list) and r.steps


def test_build_triage_with_finding():
    class F:
        name = "command injection"
        cwe = "CWE-78"
        rule_id = "sast-cmd-injection"
        file = "app.py"
        line = 3
        code = "subprocess(cmd, shell=True)"
        description = "x"

    r = build_triage("; id", F())
    assert r.bug_class == "command-injection"
    assert "shell" in r.suggested_patch.lower()


def test_attempt_minimize_format():
    assert _attempt_minimize("anything", "format-string") == "%s"


# --- triage -> exploit/download round-trip shape (no import cycles) ---
def test_triage_to_dict_keys():
    d = build_triage("x").to_dict()
    assert {
        "candidate",
        "bug_class",
        "cwe",
        "minimized_trigger",
        "suggested_patch",
        "steps",
    } <= set(d)
