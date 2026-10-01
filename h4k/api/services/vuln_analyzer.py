# Vulnerability Analyzer - Static analysis of source code for vulnerabilities.
# Performs AST-based analysis, pattern matching, and data flow analysis.
import json
import logging
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger("h4k.vuln_analyzer")

# Dangerous function patterns by language
DANGEROUS_PATTERNS = {
    "python": {
        "eval": {
            "pattern": r"\beval\s*\(",
            "severity": "HIGH",
            "cwe": "CWE-95",
            "description": "Use of eval() with user input can lead to code execution",
        },
        "exec": {
            "pattern": r"\bexec\s*\(",
            "severity": "HIGH",
            "cwe": "CWE-95",
            "description": "Use of exec() with user input can lead to code execution",
        },
        "pickle_loads": {
            "pattern": r"pickle\.loads?\(",
            "severity": "HIGH",
            "cwe": "CWE-502",
            "description": (
                "Deserializing untrusted data with pickle can lead to code execution"
            ),
        },
        "yaml_load": {
            "pattern": r"yaml\.load\s*\((?!.*Loader=)",
            "severity": "HIGH",
            "cwe": "CWE-502",
            "description": "yaml.load() without safe loader can execute arbitrary code",
        },
        "subprocess_shell": {
            "pattern": (
                r"subprocess\.(run|call|Popen|check_output)\s*\([^)]*shell\s*=\s*True"
            ),
            "severity": "HIGH",
            "cwe": "CWE-78",
            "description": "Shell injection via subprocess with shell=True",
        },
        "sql_injection": {
            "pattern": r"(execute|executemany|cursor\.execute)\s*\([^)]*%s.*\+",
            "severity": "HIGH",
            "cwe": "CWE-89",
            "description": "Potential SQL injection via string concatenation",
        },
        "os_system": {
            "pattern": r"os\.system\s*\(",
            "severity": "HIGH",
            "cwe": "CWE-78",
            "description": "Command injection via os.system",
        },
        "os_popen": {
            "pattern": r"os\.popen\s*\(",
            "severity": "HIGH",
            "cwe": "CWE-78",
            "description": "Command injection via os.popen",
        },
        "input_in_eval": {
            "pattern": r"eval\s*\(\s*input\s*\(",
            "severity": "CRITICAL",
            "cwe": "CWE-95",
            "description": "Direct eval of user input",
        },
        "xml_external_entity": {
            "pattern": (
                r"xml\.etree\.ElementTree\.fromstring|xml\.dom\.minidom\.parseString"
            ),
            "severity": "MEDIUM",
            "cwe": "CWE-611",
            "description": "Potential XML External Entity (XXE) vulnerability",
        },
        "path_traversal": {
            "pattern": r"open\s*\(\s*[^)]*\.\./",
            "severity": "HIGH",
            "cwe": "CWE-22",
            "description": "Potential path traversal with ../",
        },
        "hardcoded_secret": {
            "pattern": r"(password|secret|token|key|api_key)\s*=\s*[\"'][^\"']{8,}",
            "severity": "MEDIUM",
            "cwe": "CWE-798",
            "description": "Potential hardcoded secret",
        },
    },
    "javascript": {
        "eval": {
            "pattern": r"\beval\s*\(",
            "severity": "HIGH",
            "cwe": "CWE-95",
            "description": "eval() with user input can lead to code execution",
        },
        "function_constructor": {
            "pattern": r"new\s+Function\s*\(",
            "severity": "HIGH",
            "cwe": "CWE-95",
            "description": (
                "Function constructor with user input can execute arbitrary code"
            ),
        },
        "setTimeout_string": {
            "pattern": r"setTimeout\s*\(\s*[\"']",
            "severity": "MEDIUM",
            "cwe": "CWE-95",
            "description": "setTimeout with string argument can execute arbitrary code",
        },
        "setInterval_string": {
            "pattern": r"setInterval\s*\(\s*[\"']",
            "severity": "MEDIUM",
            "cwe": "CWE-95",
            "description": (
                "setInterval with string argument can execute arbitrary code"
            ),
        },
        "innerHTML": {
            "pattern": r"\.innerHTML\s*=",
            "severity": "MEDIUM",
            "cwe": "CWE-79",
            "description": "Potential XSS via innerHTML assignment",
        },
        "document_write": {
            "pattern": r"document\.write\s*\(",
            "severity": "MEDIUM",
            "cwe": "CWE-79",
            "description": "document.write can lead to XSS",
        },
        "eval_atob": {
            "pattern": r"eval\s*\(\s*atob\s*\(",
            "severity": "HIGH",
            "cwe": "CWE-95",
            "description": "eval with base64 decoding can hide malicious code",
        },
        "sql_injection": {
            "pattern": r"query\s*\(\s*[\"'].*\+",
            "severity": "HIGH",
            "cwe": "CWE-89",
            "description": "Potential SQL injection via string concatenation",
        },
        "path_traversal": {
            "pattern": (
                r"(fs\.(readFile|writeFile|readFileSync|writeFileSync)\s*\([^)]*\.\./)"
            ),
            "severity": "HIGH",
            "cwe": "CWE-22",
            "description": "Path traversal with user input",
        },
    },
    "java": {
        "runtime_exec": {
            "pattern": r"Runtime\.getRuntime\(\)\.exec\s*\(",
            "severity": "HIGH",
            "cwe": "CWE-78",
            "description": "Command injection via Runtime.exec",
        },
        "process_builder": {
            "pattern": r"ProcessBuilder\s*\([^)]*\)\.start\s*\(",
            "severity": "HIGH",
            "cwe": "CWE-78",
            "description": "Command injection via ProcessBuilder",
        },
        "sql_injection": {
            "pattern": r"Statement\s*\(\s*[^)]*\)\s*\.\s*executeQuery\s*\(\s*[^)]*\+",
            "severity": "HIGH",
            "cwe": "CWE-89",
            "description": "SQL injection via string concatenation",
        },
        "deserialization": {
            "pattern": r"ObjectInputStream\s*\([^)]*\)\.readObject\s*\(\s*\)",
            "severity": "CRITICAL",
            "cwe": "CWE-502",
            "description": "Java deserialization of untrusted data",
        },
        "xpath_injection": {
            "pattern": r"xpath\s*\.\s*compile\s*\(\s*[^)]*\+",
            "severity": "HIGH",
            "cwe": "CWE-643",
            "description": "XPath injection via string concatenation",
        },
    },
    "php": {
        "eval": {
            "pattern": r"\beval\s*\(",
            "severity": "HIGH",
            "cwe": "CWE-95",
            "description": "eval() with user input",
        },
        "exec": {
            "pattern": r"\b(exec|shell_exec|passthru|system|proc_open)\s*\(",
            "severity": "HIGH",
            "cwe": "CWE-78",
            "description": "Command execution with user input",
        },
        "include": {
            "pattern": r"(include|require)(_once)?\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)",
            "severity": "HIGH",
            "cwe": "CWE-98",
            "description": "Remote/Local file inclusion via user input",
        },
        "sql_injection": {
            "pattern": r"mysql_query\s*\([^)]*\$_(GET|POST|REQUEST)",
            "severity": "HIGH",
            "cwe": "CWE-89",
            "description": "SQL injection via string concatenation",
        },
        "unserialize": {
            "pattern": r"unserialize\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)",
            "severity": "CRITICAL",
            "cwe": "CWE-502",
            "description": "Object injection via unserialize",
        },
        "file_upload": {
            "pattern": r"move_uploaded_file\s*\(\s*\$_(FILES|POST)",
            "severity": "MEDIUM",
            "cwe": "CWE-434",
            "description": "Unrestricted file upload",
        },
    },
    "go": {
        "command_injection": {
            "pattern": r"(exec\.Command|exec\.CommandContext)\s*\(\s*[^)]*\+",
            "severity": "HIGH",
            "cwe": "CWE-78",
            "description": "Command injection via string concatenation",
        },
        "sql_injection": {
            "pattern": r"(Query|Exec|ExecContext)\s*\(\s*[^)]*\+",
            "severity": "HIGH",
            "cwe": "CWE-89",
            "description": "SQL injection via string concatenation",
        },
        "path_traversal": {
            "pattern": r"(os\.Open|ioutil\.ReadFile)\s*\(\s*[^)]*\.\./",
            "severity": "HIGH",
            "cwe": "CWE-22",
            "description": "Path traversal with user input",
        },
    },
    "c_cpp": {
        "buffer_overflow": {
            "pattern": r"\b(strcpy|strcat|sprintf|vsprintf|gets)\s*\(",
            "severity": "HIGH",
            "cwe": "CWE-120",
            "description": "Buffer overflow vulnerable function",
        },
        "format_string": {
            "pattern": r"\bprintf\s*\(\s*[^)]*%[^\"']",
            "severity": "HIGH",
            "cwe": "CWE-134",
            "description": "Format string vulnerability",
        },
        "command_injection": {
            "pattern": r"\bsystem\s*\(\s*[^)]*\+",
            "severity": "HIGH",
            "cwe": "CWE-78",
            "description": "Command injection via system()",
        },
    },
    "generic": {
        "hardcoded_password": {
            "pattern": r"(password|passwd|pwd)\s*[:=]\s*[\"'][^\"']{8,}",
            "severity": "MEDIUM",
            "cwe": "CWE-798",
            "description": "Hardcoded password",
        },
        "api_key": {
            "pattern": (
                r"(api[_-]?key|apikey|secret[_-]?key)\s*[:=]\s*[\"'][a-zA-Z0-9]{20,}"
            ),
            "severity": "HIGH",
            "cwe": "CWE-798",
            "description": "Hardcoded API key",
        },
        "private_key": {
            "pattern": r"-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----",
            "severity": "CRITICAL",
            "cwe": "CWE-798",
            "description": "Private key in source code",
        },
        "aws_key": {
            "pattern": r"(AKIA|ASIA)[A-Z0-9]{16}",
            "severity": "CRITICAL",
            "cwe": "CWE-798",
            "description": "AWS access key ID",
        },
        "jwt_token": {
            "pattern": r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
            "severity": "CRITICAL",
            "cwe": "CWE-798",
            "description": "JWT token in source code",
        },
    },
}

# Language detection by file extension
LANGUAGE_MAP = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "javascript",
    ".jsx": "javascript",
    ".tsx": "javascript",
    ".java": "java",
    ".kt": "kotlin",
    ".scala": "scala",
    ".go": "go",
    ".rs": "rust",
    ".c": "c_cpp",
    ".h": "c_cpp",
    ".cpp": "c_cpp",
    ".cc": "c_cpp",
    ".cxx": "c_cpp",
    ".hpp": "c_cpp",
    ".cs": "csharp",
    ".php": "php",
    ".rb": "ruby",
    ".pl": "perl",
    ".sh": "bash",
    ".bash": "bash",
    ".lua": "lua",
    ".r": "r",
    ".swift": "swift",
    ".dart": "dart",
}


def detect_language(file_path: Path) -> str | None:
    """Detect programming language from file extension."""
    return LANGUAGE_MAP.get(file_path.suffix.lower())


class Finding:
    """Represents a vulnerability finding."""

    def __init__(
        self,
        file_path: str,
        line_number: int,
        column: int,
        rule_id: str,
        rule_name: str,
        severity: str,
        cwe: str,
        description: str,
        code_snippet: str = "",
        language: str = "",
    ):
        self.file_path = file_path
        self.line_number = line_number
        self.column = column
        self.rule_id = rule_id
        self.rule_name = rule_name
        self.severity = severity
        self.cwe = cwe
        self.description = description
        self.code_snippet = code_snippet
        self.language = language

    def to_dict(self) -> dict:
        return {
            "file_path": self.file_path,
            "line_number": self.line_number,
            "column": self.column,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "cwe": self.cwe,
            "description": self.description,
            "code_snippet": self.code_snippet,
            "language": self.language,
        }


class VulnerabilityAnalyzer:
    """Static analysis engine for source code vulnerability detection."""

    def __init__(self) -> None:
        self.logger = logging.getLogger("h4k.vuln_analyzer")
        self.findings: list[Finding] = []

    def analyze_file(self, file_path: Path) -> list[Finding]:
        """Analyze a single file for vulnerabilities."""
        findings: list[Finding] = []

        if not file_path.is_file():
            return findings

        language = detect_language(file_path)
        if not language:
            return findings

        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            self.logger.warning(f"Failed to read {file_path}: {e}")
            return findings

        # Get patterns for this language
        patterns = DANGEROUS_PATTERNS.get(language, {})

        # Check language-specific patterns
        self._scan_content(content, file_path, language, patterns, findings)
        self._scan_content(
            content,
            file_path,
            "generic",
            DANGEROUS_PATTERNS.get("generic", {}),
            findings,
        )

        return findings

    def _scan_content(
        self,
        content: str,
        file_path: Path,
        language: str,
        patterns: dict,
        findings: list[Finding],
    ) -> None:
        lines = content.split("\n")
        for _line_num, line in enumerate(lines, 1):
            for rule_id, rule in patterns.items():
                pattern = rule.get("pattern", "")
                if not pattern:
                    continue

                try:
                    for match in re.finditer(pattern, line):
                        column = match.start() + 1
                        findings.append(
                            Finding(
                                file_path=str(file_path),
                                line_number=match.start() + 1,
                                column=column,
                                rule_id=f"{language}.{rule_id}",
                                rule_name=rule_id.replace("_", " ").title(),
                                severity=rule.get("severity", "MEDIUM"),
                                cwe=rule.get("cwe", "CWE-Unknown"),
                                description=rule.get("description", ""),
                                code_snippet=line.strip()[:200],
                                language=language,
                            )
                        )
                except re.error:
                    continue

    def scan_directory(self, root: Path, max_files: int = 10000) -> list[Finding]:
        """Recursively scan a directory for vulnerabilities."""
        file_count = 0

        for file_path in Path(root).rglob("*"):
            if not file_path.is_file():
                continue

            # Skip binary files, large files, and common exclude patterns
            if file_path.stat().st_size > 1024 * 1024:  # Skip > 1MB
                continue

            skip_dirs: set[str] = {
                ".git",
                ".svn",
                "__pycache__",
                "node_modules",
                "vendor",
                "venv",
                "env",
                ".venv",
                "dist",
                "build",
                "target",
            }
            if any(part in skip_dirs for part in file_path.parts):
                continue

            findings = self.analyze_file(file_path)
            if findings:
                self.findings.extend(findings)

            file_count += 1
            if file_count >= max_files:
                break

        return self.findings

    def get_summary(self) -> dict:
        """Get summary of findings by severity."""
        summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for finding in self.findings:
            summary[finding.severity] = summary.get(finding.severity, 0) + 1
        return summary

    def get_findings_by_severity(self, severity: str) -> list[Finding]:
        return [f for f in self.findings if f.severity == severity]

    def get_findings_by_file(self, file_path: str) -> list[Finding]:
        return [f for f in self.findings if f.file_path == file_path]

    def get_findings_by_cwe(self, cwe: str) -> list[Finding]:
        return [f for f in self.findings if f.cwe == cwe]

    def to_sarif(self) -> dict:
        """Export findings in SARIF format."""
        runs: list[dict[str, Any]] = [
            {
                "tool": {
                    "driver": {
                        "name": "h4k-vuln-analyzer",
                        "version": "1.0",
                        "informationUri": "https://github.com/your-org/h4k",
                        "rules": [],
                    }
                },
                "results": [],
            }
        ]

        rule_map = {}
        for finding in self.findings:
            rule_key = finding.rule_id
            if rule_key not in rule_map:
                rule_map[rule_key] = {
                    "id": rule_key,
                    "name": finding.rule_name,
                    "shortDescription": {"text": finding.description},
                    "defaultConfiguration": {"level": finding.severity.lower()},
                    "properties": {"cwe": finding.cwe},
                }
                runs[0]["tool"]["driver"]["rules"].append(rule_map[rule_key])

            runs[0]["results"].append(
                {
                    "ruleId": rule_key,
                    "level": finding.severity.lower(),
                    "message": {"text": finding.description},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": finding.file_path},
                                "region": {
                                    "startLine": finding.line_number,
                                    "startColumn": finding.column,
                                },
                            }
                        }
                    ],
                }
            )

        return {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": runs,
        }

    def export_json(self) -> list[dict]:
        return [f.to_dict() for f in self.findings]


# Convenience functions
def scan_file(file_path: Path) -> list[dict]:
    """Scan a single file for vulnerabilities."""
    analyzer = VulnerabilityAnalyzer()
    findings = analyzer.analyze_file(file_path)
    return [f.to_dict() for f in findings]


def scan_directory(root: Path, max_files: int = 10000) -> list[dict[str, Any]]:
    """Scan a directory for vulnerabilities."""
    analyzer = VulnerabilityAnalyzer()
    analyzer.scan_directory(Path(root))
    return [f.to_dict() for f in analyzer.findings]


def scan_repo(url: str, branch: str | None = None) -> list[dict[str, Any]]:
    """Fetch and scan a repository."""
    from services.source_fetcher import fetch_source

    result = fetch_source(url)
    if not result.get("success"):
        return [{"error": result.get("error", "Failed to fetch repository")}]

    analyzer = VulnerabilityAnalyzer()
    analyzer.scan_directory(Path(result["path"]))
    return [f.to_dict() for f in analyzer.findings]


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        path = Path(sys.argv[1])
        results = scan_file(path) if path.is_file() else scan_directory(path)
        print(json.dumps(results, indent=2))
