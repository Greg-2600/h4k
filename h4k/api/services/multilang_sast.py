"""Multi-lang SAST — core source→sink Go + Rust rules (Backlog #66).

Same honest matcher as the Python/JS/PHP taint pack (windowed
source→sink with sanitizer clearing, one hit per rule per file), with
a rule table for Go services and one for Rust services:

- Go: `os/exec` command building, `database/sql` string queries,
  `html/template` escape bypass via `template.HTML`, `os` path opens,
  `net/http` client SSRF, `encoding/gob` + `yaml.Unmarshal` decoding.
- Rust: `std::process::Command` building, `sqlx`/`query!` string
  queries, `std::fs` path opens, `reqwest`/`hyper` client SSRF.

Findings ledger as engagement vulns on the labeled host when
`engagement_id` is given (scope-enforced). Sandbox returns canned
findings without parsing anything.
"""

from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger("h4k.multilang_sast")

_WINDOW = 5

# (rule_id, language, severity, cwe, title, sink_re, source_re, sanitizer_re)
RULES: list[tuple[str, str, str, str, str, str, str, str]] = [
    (
        "ml-go-cmd-injection",
        "go",
        "critical",
        "CWE-78",
        "tainted input reaches a shell command",
        r"(?:exec\.Command\s*\(|syscall\.Exec\s*\()",
        r"(?:r\.(?:URL\.Query|FormValue|PostFormValue|Header\.Get)|os\.Args|c\.Query\(|c\.Param\(|mux\.Vars|io\.ReadAll)",
        r"shlex|shellquote|strconv\.Quote",
    ),
    (
        "ml-go-sqli",
        "go",
        "high",
        "CWE-89",
        "tainted input concatenated into SQL",
        r"(?:db\.(?:Query|QueryRow|Exec)\s*\(|tx\.(?:Query|QueryRow|Exec)\s*\()",
        r"(?:fmt\.Sprintf|r\.(?:URL|FormValue)|c\.Query|Sprintf\s*\()",
        r"(?:\$\d+|\?\s*[,)]|sql\.Named|Prepare\s*\()",
    ),
    (
        "ml-go-ssti",
        "go",
        "high",
        "CWE-1336",
        "tainted input marked safe for templates",
        r"template\.HTML\s*\(",
        r"(?:r\.(?:URL|FormValue)|c\.Query|fmt\.Sprintf)",
        r"template\.HTMLEscapeString|html\.EscapeString",
    ),
    (
        "ml-go-traversal",
        "go",
        "medium",
        "CWE-22",
        "tainted input reaches a filesystem path",
        r"(?:os\.(?:Open|OpenFile|ReadFile|Create)\s*\(|http\.ServeFile\s*\(|os\.MkdirAll\s*\()",
        r"(?:r\.(?:URL|FormValue)|c\.Param|os\.Args)",
        r"filepath\.(?:Clean|Join)|path\.Clean",
    ),
    (
        "ml-go-ssrf",
        "go",
        "medium",
        "CWE-918",
        "tainted input reaches an outbound request",
        r"(?:http\.(?:Get|Post|Head)\s*\(|http\.NewRequest\s*\(|client\.(?:Get|Do)\s*\()",
        r"(?:r\.(?:URL|FormValue)|c\.Query|fmt\.Sprintf)",
        r"url\.Parse|net\.ParseIP|whitelist|allowlist",
    ),
    (
        "ml-go-deser",
        "go",
        "high",
        "CWE-502",
        "request bytes reach an unsafe decoder",
        r"(?:gob\.NewDecoder|yaml\.Unmarshal\s*\(|xml\.Unmarshal\s*\()",
        r"(?:r\.Body|ioutil\.ReadAll|io\.ReadAll|ReadAll\s*\()",
        r"json\.(?:Unmarshal|NewDecoder)",
    ),
    (
        "ml-rust-cmd-injection",
        "rust",
        "critical",
        "CWE-78",
        "tainted input reaches a shell command",
        r"(?:Command::new\s*\(|\.arg\s*\()",
        r"(?:std::env::args|req\.(?:query|param)|Json\(|Query\(|Path\(|format!)",
        r"shell-escape|shlex::quote|escape_",
    ),
    (
        "ml-rust-sqli",
        "rust",
        "high",
        "CWE-89",
        "tainted input interpolated into SQL",
        r"(?:sqlx::query\s*\(|query!\s*\(|query_as!\s*\()",
        r"(?:format!|req\.|Json\(|Query\()",
        r"\.bind\s*\(|\$\d",
    ),
    (
        "ml-rust-traversal",
        "rust",
        "medium",
        "CWE-22",
        "tainted input reaches a filesystem path",
        r"(?:std::fs::(?:read|write|read_to_string)|File::(?:open|create)|OpenOptions)",
        r"(?:std::env::args|Path\(|Query\(|req\.)",
        r"canonicalize|strip_prefix|starts_with",
    ),
    (
        "ml-rust-ssrf",
        "rust",
        "medium",
        "CWE-918",
        "tainted input reaches an outbound request",
        r"(?:reqwest::(?:get|post)\s*\(|Client::new|hyper::Client)",
        r"(?:format!|Query\(|req\.)",
        r"Url::parse|parse::<Url>|whitelist|allowlist",
    ),
]

_EXTENSIONS = {".go": "go", ".rs": "rust"}


def _lang_of(path: str) -> str | None:
    lowered = (path or "").lower()
    for ext, lang in _EXTENSIONS.items():
        if lowered.endswith(ext):
            return lang
    return None


def _finder(pattern: str) -> re.Pattern[str] | None:
    try:
        return re.compile(pattern)
    except re.error:
        return None


def scan_files(files: list[dict[str, str]]) -> dict[str, Any]:
    """Run the Go+Rust pack over [{path, content}]."""
    if not files:
        raise ValueError("bundle required (paste sources as === path === blocks)")
    compiled = [
        (rid, lang, sev, cwe, title, _finder(sink), _finder(src), _finder(san))
        for rid, lang, sev, cwe, title, sink, src, san in RULES
    ]
    findings: list[dict[str, Any]] = []
    parsed = 0
    skipped: list[str] = []
    for entry in files:
        path = str(entry.get("path") or "file")
        content = str(entry.get("content") or "")
        if not content.strip():
            continue
        lang = _lang_of(path)
        if not lang:
            skipped.append(path)
            continue
        parsed += 1
        lines = content.splitlines()
        for rid, rule_lang, severity, cwe, title, sink_rx, src_rx, san_rx in compiled:
            if rule_lang != lang or sink_rx is None or src_rx is None:
                continue
            for idx, line in enumerate(lines):
                if not sink_rx.search(line):
                    continue
                window = lines[max(0, idx - _WINDOW) : idx + 1]
                blob = "\n".join(window)
                if not src_rx.search(blob):
                    continue
                if san_rx is not None and san_rx.search(blob):
                    continue
                findings.append(
                    {
                        "rule_id": rid,
                        "name": title,
                        "severity": severity,
                        "cwe": cwe,
                        "file": path,
                        "line": idx + 1,
                        "code": line.strip()[:200],
                        "evidence": f"source→sink within {_WINDOW + 1} lines ending at {idx + 1}",
                    }
                )
                break  # one hit per rule per file keeps the list reviewable
    return {
        "pack": "multilang-sast",
        "files": len(files),
        "parsed": parsed,
        "skipped": skipped,
        "findings": findings,
        "finding_count": len(findings),
        "clean": not findings,
    }


def to_ledger(
    host: str, pack: str, findings: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Map pack findings to engagement vuln rows for the labeled host."""
    rows: list[dict[str, Any]] = []
    for finding in findings:
        title = str(finding.get("name") or "sast").strip() or "sast"
        rows.append(
            {
                "host": host,
                "name": f"sast {pack}: {title}"[:220],
                "severity": str(finding.get("severity") or "UNKNOWN").upper(),
                "module": "multilang-sast",
                "reference": "",
                "cwe": str(finding.get("cwe") or ""),
                "detail": f"rule={finding.get('rule_id', '')} "
                f"file={finding.get('file', '')}:{finding.get('line', '')} "
                f"code={finding.get('code', '')}".strip()[:400],
            }
        )
    return rows


def sandbox_result(pack: str = "multilang-sast") -> dict[str, Any]:
    """Canned pack audit (nothing parsed)."""
    findings = [
        {
            "rule_id": "ml-go-cmd-injection",
            "name": "tainted input reaches a shell command (sandbox)",
            "severity": "CRITICAL",
            "cwe": "CWE-78",
            "file": "main.go",
            "line": 9,
            "code": 'exec.Command("sh", "-c", r.FormValue("cmd")) (sandbox)',
            "evidence": "source→sink within 6 lines (sandbox)",
        },
        {
            "rule_id": "ml-rust-sqli",
            "name": "tainted input interpolated into SQL (sandbox)",
            "severity": "HIGH",
            "cwe": "CWE-89",
            "file": "db.rs",
            "line": 4,
            "code": "sqlx::query(&format!(\"SELECT * FROM u WHERE n='{}'\", n)) (sandbox)",
            "evidence": "source→sink within 6 lines (sandbox)",
        },
    ]
    return {
        "pack": pack or "multilang-sast",
        "files": 2,
        "parsed": 2,
        "skipped": [],
        "findings": findings,
        "finding_count": len(findings),
        "clean": False,
        "sandbox": True,
    }
