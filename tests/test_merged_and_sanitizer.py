# Tests for merged-report and sanitizer-trace helpers.
from services.fuzzer import LabFuzzer
from services.merged_report import build_merged_report, render_json, render_markdown


def test_build_merged_report_dedupes_cves():
    rep = build_merged_report(
        sca={
            "cves": ["CVE-1", "CVE-1", "CVE-2"],
            "vulnerabilities": [{"cve": "CVE-3"}],
        },
    )
    assert rep["sca"]["cves"] == ["CVE-1", "CVE-2", "CVE-3"]
    assert rep["summary"]["sca_cves"] == 3


def test_build_merged_counts():
    rep = build_merged_report(
        scan=[{"address": "1.2.3.4", "services": []}],
        sast=[{"severity": "high"}],
        fuzz=[{"vector": "x", "signal": "crash"}],
        triage=[{"bug_class": "buf"}],
    )
    assert rep["summary"]["hosts_scanned"] == 1
    assert rep["summary"]["sast_findings"] == 1
    assert rep["summary"]["fuzz_candidates"] == 1
    assert rep["summary"]["triage_reports"] == 1


def test_render_markdown_sections():
    rep = build_merged_report(
        sast=[
            {
                "severity": "high",
                "file": "a.py",
                "line": 3,
                "name": "eval",
                "cwe": "CWE-95",
            }
        ],
        sca={"cves": ["CVE-1"], "packages": ["pkg"]},
    )
    md = render_markdown(rep)
    assert "Static analysis" in md
    assert "Supply-chain" in md
    assert "CVE-1" in md


def test_render_json_roundtrip():
    rep = build_merged_report(scan=[{"address": "x"}])
    import json

    d = json.loads(render_json(rep))
    assert d["summary"]["hosts_scanned"] == 1


def test_sanitizer_trace_parse_overflow():
    trace = "==1==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7f..."
    parsed = LabFuzzer.parse_sanitizer_trace(trace)
    assert parsed["kind"] == "stack-buffer-overflow"
    assert parsed["cwe"] == "CWE-120"


def test_sanitizer_trace_parse_heap():
    parsed = LabFuzzer.parse_sanitizer_trace(
        "==2==ERROR: AddressSanitizer: heap-buffer-overflow"
    )
    assert parsed["kind"] == "heap-buffer-overflow"
    assert parsed["cwe"] == "CWE-122"


def test_sanitizer_trace_parse_ufa():
    parsed = LabFuzzer.parse_sanitizer_trace(
        "ERROR: AddressSanitizer: heap-use-after-free"
    )
    assert parsed["kind"] == "use-after-free"


def test_sanitizer_trace_parse_unknown():
    assert LabFuzzer.parse_sanitizer_trace("just a log line")["kind"] == "unknown"
