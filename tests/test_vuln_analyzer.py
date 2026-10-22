# Tests for vuln_analyzer.py
from pathlib import Path

import pytest

from h4k.api.services.vuln_analyzer import (
    Finding,
    VulnerabilityAnalyzer,
    detect_language,
    scan_directory,
    scan_file,
)


class TestDetectLanguage:
    @pytest.mark.parametrize(
        "ext,expected",
        [
            (".py", "python"),
            (".js", "javascript"),
            (".ts", "javascript"),
            (".java", "java"),
            (".go", "go"),
            (".rs", "rust"),
            (".c", "c_cpp"),
            (".cpp", "c_cpp"),
            (".php", "php"),
            (".rb", "ruby"),
            (".swift", "swift"),
            (".dart", "dart"),
            (".txt", None),
            (".xyz", None),
        ],
    )
    def test_detect_language(self, ext, expected):
        assert detect_language(Path(f"file{ext}")) == expected

    def test_case_insensitive(self):
        assert detect_language(Path("file.PY")) == "python"
        assert detect_language(Path("file.JS")) == "javascript"


class TestFindingClass:
    def test_finding_init(self):
        f = Finding(
            file_path="/src/app.py",
            line_number=10,
            column=5,
            rule_id="python.exec",
            rule_name="Exec Usage",
            severity="HIGH",
            cwe="CWE-95",
            description="Use of exec detected",
            code_snippet="exec(user_input)",
            language="python",
        )
        assert f.file_path == "/src/app.py"
        assert f.line_number == 10
        assert f.column == 5
        assert f.rule_id == "python.exec"
        assert f.severity == "HIGH"

    def test_finding_to_dict(self):
        f = Finding(
            file_path="/src/app.py",
            line_number=10,
            column=5,
            rule_id="python.exec",
            rule_name="Exec Usage",
            severity="HIGH",
            cwe="CWE-95",
            description="Use of exec",
            language="python",
        )
        d = f.to_dict()
        assert d["file_path"] == "/src/app.py"
        assert d["line_number"] == 10
        assert d["rule_id"] == "python.exec"


class TestVulnerabilityAnalyzerInit:
    def test_init(self):
        va = VulnerabilityAnalyzer()
        assert va.findings == []


class TestVulnerabilityAnalyzerAnalyzeFile:
    def test_nonexistent_file(self, tmp_path):
        va = VulnerabilityAnalyzer()
        findings = va.analyze_file(tmp_path / "nonexistent.py")
        assert findings == []

    def test_unsupported_language(self, tmp_path):
        va = VulnerabilityAnalyzer()
        f = tmp_path / "file.txt"
        f.write_text("some content")
        findings = va.analyze_file(f)
        assert findings == []

    def test_finds_eval_in_python(self, tmp_path):
        va = VulnerabilityAnalyzer()
        f = tmp_path / "bad.py"
        f.write_text("eval(user_input)")
        findings = va.analyze_file(f)
        assert len(findings) >= 1
        ids = [fnd.rule_id for fnd in findings]
        assert any("python.eval" in r for r in ids)

    def test_finds_subprocess_shell_true(self, tmp_path):
        va = VulnerabilityAnalyzer()
        f = tmp_path / "bad.py"
        f.write_text("subprocess.run(cmd, shell=True)")
        findings = va.analyze_file(f)
        ids = [fnd.rule_id for fnd in findings]
        assert any("python.subprocess_shell" in r for r in ids)

    def test_finds_yaml_load_unsafe(self, tmp_path):
        va = VulnerabilityAnalyzer()
        f = tmp_path / "bad.py"
        f.write_text("yaml.load(data)")
        findings = va.analyze_file(f)
        ids = [fnd.rule_id for fnd in findings]
        assert any("python.yaml_load" in r for r in ids)

    def test_finds_hardcoded_password_generic(self, tmp_path):
        va = VulnerabilityAnalyzer()
        f = tmp_path / "config.py"
        f.write_text('password = "supersecret123"')
        findings = va.analyze_file(f)
        ids = [fnd.rule_id for fnd in findings]
        assert any(
            "generic.hardcoded_password" in r or "python.hardcoded_secret" in r
            for r in ids
        )

    def test_finds_aws_key(self, tmp_path):
        va = VulnerabilityAnalyzer()
        f = tmp_path / "keys.js"
        f.write_text('const key = "AKIAIOSFODNN7EXAMPLE"')
        findings = va.analyze_file(f)
        ids = [fnd.rule_id for fnd in findings]
        assert any("generic.aws_key" in r for r in ids)

    def test_finds_jwt_token(self, tmp_path):
        va = VulnerabilityAnalyzer()
        f = tmp_path / "auth.py"
        f.write_text(
            'token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9Pl3UP3TES4Kc"'
        )
        findings = va.analyze_file(f)
        ids = [fnd.rule_id for fnd in findings]
        assert any("generic.jwt_token" in r for r in ids)

    def test_finds_private_key(self, tmp_path):
        va = VulnerabilityAnalyzer()
        f = tmp_path / "key.pem"
        f.write_text(
            "-----BEGIN RSA PRIVATE KEY-----MIIBOgIBAAJBALRiMLAHudeSA2aaaaaa-----END RSA PRIVATE KEY-----"
        )
        findings = va.analyze_file(f)
        ids = [fnd.rule_id for fnd in findings]
        assert any("generic.private_key" in r for r in ids)

    def test_finds_innerHTML_xss(self, tmp_path):
        va = VulnerabilityAnalyzer()
        f = tmp_path / "bad.js"
        f.write_text("element.innerHTML = userInput")
        findings = va.analyze_file(f)
        ids = [fnd.rule_id for fnd in findings]
        assert any("javascript.innerHTML" in r for r in ids)

    def test_finds_runtime_exec_java(self, tmp_path):
        va = VulnerabilityAnalyzer()
        f = tmp_path / "Bad.java"
        f.write_text("Runtime.getRuntime().exec(cmd)")
        findings = va.analyze_file(f)
        ids = [fnd.rule_id for fnd in findings]
        assert any("java.runtime_exec" in r for r in ids)

    def test_finds_command_injection_php(self, tmp_path):
        va = VulnerabilityAnalyzer()
        f = tmp_path / "bad.php"
        f.write_text("$output = shell_exec($_GET['cmd']);")
        findings = va.analyze_file(f)
        ids = [fnd.rule_id for fnd in findings]
        assert any("php.exec" in r for r in ids)

    def test_finds_command_injection_go(self, tmp_path):
        va = VulnerabilityAnalyzer()
        f = tmp_path / "bad.go"
        f.write_text('exec.Command("ls " + userInput)')
        findings = va.analyze_file(f)
        ids = [fnd.rule_id for fnd in findings]
        assert any("go.command_injection" in r for r in ids)

    def test_finds_format_string_c(self, tmp_path):
        va = VulnerabilityAnalyzer()
        f = tmp_path / "bad.c"
        f.write_text('printf("%s", user_input)')
        findings = va.analyze_file(f)
        ids = [fnd.rule_id for fnd in findings]
        assert any("c_cpp.format_string" in r for r in ids)

    def test_finds_buffer_overflow_c(self, tmp_path):
        va = VulnerabilityAnalyzer()
        f = tmp_path / "bad.c"
        f.write_text("strcpy(dest, src)")
        findings = va.analyze_file(f)
        ids = [fnd.rule_id for fnd in findings]
        assert any("c_cpp.buffer_overflow" in r for r in ids)


class TestVulnerabilityAnalyzerScanDirectory:
    def test_scans_directory(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "bad.py").write_text("eval(user_input)")
        (src / "good.py").write_text("print('hello')")

        va = VulnerabilityAnalyzer()
        findings = va.scan_directory(src)
        assert len(findings) >= 1

    def test_skips_large_files(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        large = src / "large.py"
        large.write_text("x = 1\n" * 200000)

        va = VulnerabilityAnalyzer()
        findings = va.scan_directory(src)
        ids = [fnd.rule_id for fnd in findings]
        assert not any(r.startswith("python.") for r in ids)

    def test_skips_venv_dirs(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        venv = src / "venv" / "module.py"
        venv.parent.mkdir()
        venv.write_text("eval(user_input)")

        va = VulnerabilityAnalyzer()
        findings = va.scan_directory(src)
        paths = [fnd.file_path for fnd in findings]
        assert not any("venv" in p for p in paths)

    def test_respects_max_files(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        for i in range(10):
            (src / f"file{i}.py").write_text("x = 1\n" * 50)

        va = VulnerabilityAnalyzer()
        va.scan_directory(src, max_files=5)
        assert len(va.findings) == 0

    def test_accumulates_findings(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "a.py").write_text("eval(input())")
        (src / "b.py").write_text("exec(user_input)")

        va = VulnerabilityAnalyzer()
        va.scan_directory(src)
        assert len(va.findings) >= 2


class TestVulnerabilityAnalyzerSummary:
    def test_get_summary(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "bad.py").write_text("eval(input())\nos.system(cmd)")

        va = VulnerabilityAnalyzer()
        va.scan_directory(src)
        summary = va.get_summary()
        assert summary["HIGH"] >= 2
        assert summary["CRITICAL"] >= 1


class TestVulnerabilityAnalyzerFilters:
    def test_get_findings_by_severity(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "bad.py").write_text("eval(input())\nprint(x)")

        va = VulnerabilityAnalyzer()
        va.scan_directory(src)
        high = va.get_findings_by_severity("HIGH")
        assert all(f.severity == "HIGH" for f in high)

    def test_get_findings_by_file(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        f1 = src / "a.py"
        f1.write_text("eval(input())")
        f2 = src / "b.py"
        f2.write_text("exec(input())")

        va = VulnerabilityAnalyzer()
        va.scan_directory(src)
        findings = va.get_findings_by_file(str(f1))
        assert all("a.py" in f.file_path for f in findings)

    def test_get_findings_by_cwe(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "bad.py").write_text("eval(input())")

        va = VulnerabilityAnalyzer()
        va.scan_directory(src)
        cwe95 = va.get_findings_by_cwe("CWE-95")
        assert all(f.cwe == "CWE-95" for f in cwe95)


class TestVulnerabilityAnalyzerExport:
    def test_to_sarif(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "bad.py").write_text("eval(input())")

        va = VulnerabilityAnalyzer()
        va.scan_directory(src)
        sarif = va.to_sarif()

        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1
        assert len(sarif["runs"][0]["results"]) >= 1

    def test_export_json(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "bad.py").write_text("eval(input())")

        va = VulnerabilityAnalyzer()
        va.scan_directory(src)
        exported = va.export_json()

        assert isinstance(exported, list)
        assert all(isinstance(f, dict) for f in exported)


class TestConvenienceFunctions:
    def test_scan_file(self, tmp_path):
        f = tmp_path / "bad.py"
        f.write_text("eval(input())")
        results = scan_file(f)
        assert len(results) >= 1

    def test_scan_directory(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "bad.py").write_text("eval(input())")
        results = scan_directory(src)
        assert len(results) >= 1
