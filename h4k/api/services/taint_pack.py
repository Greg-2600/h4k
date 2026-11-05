"""Taint rules pack — source→sink Python/JS/PHP (Backlog #62).

A curated, data-driven pack of source→sink taint rules for Python,
JavaScript/TypeScript and PHP web code. The matcher is an honest
intra-procedural heuristic, not a dataflow engine: for each sink call
it inspects the argument text plus the five preceding lines for a
taint *source*, and clears the hit when a *sanitizer* appears in
between. One-line sinks fed straight from `$_GET`-style globals are
still caught; sanitized flows are not flagged; everything else is
reported with the exact window that matched so the analyst can verify
in seconds.

Rule table (id, language, sink regex, source regex, sanitizer regex,
severity, CWE, title). Findings ledger as engagement vulns on the
labeled host when `engagement_id` is given (scope-enforced). Sandbox
returns canned findings without parsing anything.
"""

from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger("h4k.taint_pack")

_WINDOW = 5

# (rule_id, language, severity, cwe, title, sink_re, source_re, sanitizer_re)
RULES: list[tuple[str, str, str, str, str, str, str, str]] = [
    (
        "taint-py-cmd-injection",
        "python",
        "critical",
        "CWE-78",
        "tainted input reaches a shell command",
        r"(?:os\.system|os\.popen|subprocess\.(?:call|run|Popen|check_output)|commands\.getoutput)\s*\(",
        r"(?:request\.(?:args|form|values|cookies|headers|data|get_json)|input\s*\(|sys\.argv|os\.environ|os\.getenv)",
        r"shlex\.quote|pipes\.quote|re\.escape",
    ),
    (
        "taint-py-code-injection",
        "python",
        "critical",
        "CWE-94",
        "tainted input reaches code execution",
        r"(?:\beval\s*\(|\bexec\s*\(|compile\s*\()",
        r"(?:request\.(?:args|form|values|cookies|headers|data|get_json)|input\s*\(|sys\.argv|os\.environ|os\.getenv)",
        r"(?:ast\.literal_eval|json\.loads)",
    ),
    (
        "taint-py-sqli",
        "python",
        "high",
        "CWE-89",
        "tainted input concatenated into SQL",
        r"(?:cursor\.execute|session\.execute|\.raw\s*\(|query\s*\.\s*(?:filter|filter_by))\s*\(",
        r"(?:request\.(?:args|form|values|cookies|headers|data|get_json)|input\s*\(|sys\.argv)",
        r"(?:%s|:\w+|\?\s*[,)]|sqlalchemy\.text|bindparams)",
    ),
    (
        "taint-py-ssti",
        "python",
        "high",
        "CWE-1336",
        "tainted input reaches a template render",
        r"(?:render_template_string|Template\s*\(|jinja2\.Template)\s*\(",
        r"(?:request\.(?:args|form|values|cookies|headers|data|get_json))",
        r"markupsafe\.escape|bleach\.clean|autoescape",
    ),
    (
        "taint-py-deser",
        "python",
        "high",
        "CWE-502",
        "tainted bytes reach an unsafe deserializer",
        r"(?:pickle\.loads?|cPickle\.loads?|yaml\.load\s*\(|marshal\.loads?|shelve\.open)\s*\(",
        r"(?:request\.(?:data|files|get_data|get_json)|open\s*\(|input\s*\()",
        r"yaml\.safe_load|json\.loads",
    ),
    (
        "taint-py-traversal",
        "python",
        "medium",
        "CWE-22",
        "tainted input reaches a filesystem path",
        r"(?:\bopen\s*\(|send_file\s*\(|send_from_directory\s*\(|os\.path\.join\s*\()",
        r"(?:request\.(?:args|form|values|cookies)|sys\.argv|os\.environ)",
        r"(?:safe_join|basename|abspath|realpath|normpath)",
    ),
    (
        "taint-js-cmd-injection",
        "javascript",
        "critical",
        "CWE-78",
        "tainted input reaches a shell command",
        r"(?:child_process\.(?:exec|execSync|execFile)|(?:\.exec|\.execSync)\s*\()",
        r"(?:req\.(?:query|body|params|headers|cookies)|location\.hash|location\.search|document\.cookie|process\.argv)",
        r"execFile\s*\(|spawn\s*\(|shell\s*:\s*false|escape-shell|shell-quote",
    ),
    (
        "taint-js-code-injection",
        "javascript",
        "critical",
        "CWE-94",
        "tainted input reaches code execution",
        r"(?:\beval\s*\(|new\s+Function\s*\()",
        r"(?:req\.(?:query|body|params)|location\.hash|location\.search|document\.cookie)",
        r"JSON\.parse|Number\s*\(|parseInt",
    ),
    (
        "taint-js-xss",
        "javascript",
        "high",
        "CWE-79",
        "tainted input reaches an HTML sink",
        r"(?:\.innerHTML\s*=|document\.write\s*\(|insertAdjacentHTML\s*\(|\.outerHTML\s*=)",
        r"(?:req\.(?:query|body|params)|location\.hash|location\.search|document\.cookie|fetch\s*\()",
        r"(?:DOMPurify\.sanitize|escape\(|encodeURI|textContent\s*=|innerText\s*=)",
    ),
    (
        "taint-js-sqli",
        "javascript",
        "high",
        "CWE-89",
        "tainted input concatenated into SQL",
        r"(?:\.query\s*\(|\.execute\s*\(|sequelize\.query\s*\()",
        r"(?:req\.(?:query|body|params)|location\.search)",
        r"(?:\?\s*[,)\]]|bind|replacements|sequelize\.escape)",
    ),
    (
        "taint-php-code-injection",
        "php",
        "critical",
        "CWE-94",
        "tainted input reaches code execution",
        r"(?:\beval\s*\(|assert\s*\(|create_function\s*\(|preg_replace\s*\(.*/e['\"])",
        r"(?:\$_(?:GET|POST|REQUEST|COOKIE)|php://input|file_get_contents\s*\(\s*['\"]php://)",
        r"escapeshellarg",
    ),
    (
        "taint-php-cmd-injection",
        "php",
        "critical",
        "CWE-78",
        "tainted input reaches a shell command",
        r"(?:\bexec\s*\(|\bsystem\s*\(|shell_exec\s*\(|passthru\s*\(|popen\s*\(|proc_open\s*\()",
        r"(?:\$_(?:GET|POST|REQUEST|COOKIE)|php://input)",
        r"escapeshellarg|escapeshellcmd",
    ),
    (
        "taint-php-sqli",
        "php",
        "high",
        "CWE-89",
        "tainted input concatenated into SQL",
        r"(?:mysql_query\s*\(|mysqli::?query\s*\(|->query\s*\(|->exec\s*\()",
        r"(?:\$_(?:GET|POST|REQUEST|COOKIE))",
        r"(?:\?\s*[,)]|bind_param|bindParam|prepare\s*\(|real_escape_string|PDO::PARAM)",
    ),
    (
        "taint-php-lfi",
        "php",
        "high",
        "CWE-98",
        "tainted input reaches include/require",
        r"(?:\binclude(?:_once)?\s*[(']|\brequire(?:_once)?\s*[('])",
        r"(?:\$_(?:GET|POST|REQUEST|COOKIE)|php://input|php://filter)",
        r"basename|whitelist|realpath",
    ),
    (
        "taint-php-xss",
        "php",
        "medium",
        "CWE-79",
        "tainted input echoed without escaping",
        r"(?:\becho\b|\bprint\b|printf\s*\()",
        r"(?:\$_(?:GET|POST|REQUEST|COOKIE))",
        r"htmlspecialchars|htmlentities|strip_tags|filter_var",
    ),
]

_EXTENSIONS = {
    ".py": "python",
    ".pyw": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "javascript",
    ".tsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".php": "php",
    ".phtml": "php",
}

_BUNDLE_RE = re.compile(r"^===\s*(.+?)\s*===\s*$")


def parse_bundle(bundle: str) -> list[dict[str, str]]:
    """Split a pasted bundle into [{path, content}] on === path === lines."""
    files: list[dict[str, str]] = []
    current: list[str] = []
    path = "app.py"
    seen_header = False
    for line in (bundle or "").splitlines():
        match = _BUNDLE_RE.match(line.strip())
        if match:
            if seen_header or "\n".join(current).strip():
                files.append({"path": path, "content": "\n".join(current)})
            path = match.group(1).strip() or "app.py"
            current = []
            seen_header = True
        else:
            current.append(line)
    if seen_header or "\n".join(current).strip():
        files.append({"path": path, "content": "\n".join(current)})
    return [f for f in files if f["content"].strip()]


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
    """Run the pack over [{path, content}]; windowed source→sink matching."""
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
    """Map taint findings to engagement vuln rows for the labeled host."""
    rows: list[dict[str, Any]] = []
    for finding in findings:
        title = str(finding.get("name") or "taint").strip() or "taint"
        rows.append(
            {
                "host": host,
                "name": f"taint {pack}: {title}"[:220],
                "severity": str(finding.get("severity") or "UNKNOWN").upper(),
                "module": "taint-pack",
                "reference": "",
                "cwe": str(finding.get("cwe") or ""),
                "detail": f"rule={finding.get('rule_id', '')} "
                f"file={finding.get('file', '')}:{finding.get('line', '')} "
                f"code={finding.get('code', '')}".strip()[:400],
            }
        )
    return rows


def sandbox_result(pack: str = "taint-pack") -> dict[str, Any]:
    """Canned pack audit (nothing parsed)."""
    findings = [
        {
            "rule_id": "taint-py-cmd-injection",
            "name": "tainted input reaches a shell command (sandbox)",
            "severity": "CRITICAL",
            "cwe": "CWE-78",
            "file": "app.py",
            "line": 9,
            "code": "os.system('ping ' + request.args['h']) (sandbox)",
            "evidence": "source→sink within 6 lines (sandbox)",
        },
        {
            "rule_id": "taint-php-sqli",
            "name": "tainted input concatenated into SQL (sandbox)",
            "severity": "HIGH",
            "cwe": "CWE-89",
            "file": "index.php",
            "line": 4,
            "code": "mysql_query('SELECT * FROM u WHERE n=' . $_GET['n']) (sandbox)",
            "evidence": "source→sink within 6 lines (sandbox)",
        },
    ]
    return {
        "pack": pack or "taint-pack",
        "files": 2,
        "parsed": 2,
        "skipped": [],
        "findings": findings,
        "finding_count": len(findings),
        "clean": False,
        "sandbox": True,
    }
