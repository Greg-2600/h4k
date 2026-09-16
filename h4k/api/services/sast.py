# Static source-analysis (SAST) service. Analyzes a source tree (uploaded
# archive or cloned repo) for common vulnerability patterns and can emit a
# PoC/disclosure skeleton for a finding. This is a defensive/analysis tool: it
# reads code the operator provides and produces *evidence* — it never deploys a
# weapon against anyone.
#
# The SAST rules here are lightweight regex heuristics, not a full analysis
# (that's Semgrep/CodeQL territory). Sufficient for a class demo of the
# "find a bug -> reason about it -> write a PoC -> disclose" workflow.
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger("h4k.sast")

# ---------------------------------------------------------------------------
# Rule set. Each rule: (id, name, severity low|medium|high|critical, cwe,
#                  match regex over a single source line, description)
# Regexes are intentionally broad; false positives are fine for a demo — the
# analyst reviews hits.
# ---------------------------------------------------------------------------
RULES: list[tuple[str, str, str, str, str, str]] = [
    (
        "sast-secret-http",
        "Hardcoded credential / URL-embedded password",
        "critical",
        "CWE-798",
        r"(?:password|passwd|pwd|secret|api_key|apikey|token)\s*=\s*"
        r"['\"][^'\"]{4,}['\"]",
        "Potential hardcoded secret in source. Rotate and move to env/secrets.",
    ),
    (
        "sast-sql-injection",
        "String concatenation into SQL",
        "high",
        "CWE-89",
        r"\b(?:execute|exec|query|cursor)\b[^;\n]{0,80}"
        r"(?:select|insert|update|delete|where)\b.*?(\+|\{|\%|\")",
        "SQL built via string concat/interp — injection risk. Use parameterized.",
    ),
    (
        "sast-cmd-injection",
        "Shell command built from variables",
        "high",
        "CWE-78",
        r"(?:system|popen|exec|os\.system|subprocess|Runtime\.getRuntime|"
        r"ProcessBuilder|`)\s*\(?.*?(\$|\{|\+|%)",
        "Command constructed with interpolated data — command injection risk.",
    ),
    (
        "sast-path-traversal",
        "Path from user input without validation",
        "medium",
        "CWE-22",
        r"(?:open|fopen|readfile|file_put|Path|join|send_file)\s*\(?.*?"
        r"(\+|\{|\%s|request|req\.|kwargs|args)",
        "File path built from untrusted input — path traversal risk.",
    ),
    (
        "sast-eval",
        "Dynamic code evaluation",
        "high",
        "CWE-95",
        r"\b(?:eval|exec|system|assert|compile|function\(\s*['\"])",
        "Runtime code execution from a string — unsafe if input reaches it.",
    ),
    (
        "sast-deserialize",
        "Unsafe deserialization",
        "high",
        "CWE-502",
        r"\b(?:pickle\.loads|unserialize|decodeObject|ObjectInputStream|"
        r"readObject|yaml\.load|load\(.*pickle)",
        "Deserialization of untrusted data can lead to RCE.",
    ),
    (
        "sast-buffer-copy",
        "Unchecked buffer/string copy (C-like)",
        "high",
        "CWE-120",
        r"\b(?:strcpy|strcat|sprintf|memcpy|gets|scanf)\b\s*\(",
        "Unbounded C buffer copy — classic overflow (see vulnlab).",
    ),
    (
        "sast-format-string",
        "Non-literal format string",
        "high",
        "CWE-134",
        r"\b(?:printf|fprintf|snprintf|sprintf|vsprintf|syslog)\s*\("
        r"[^,]*?([a-zA-Z_]\w*)\s*[,)]",
        "Format string from a variable — format-string vulnerability.",
    ),
    (
        "sast-insecure-http",
        "Unencrypted / insecure config",
        "low",
        "CWE-319",
        r"(?:http://(?!localhost|127\.)|allowInsecure|ssl_verify=False|"
        r"insecure=true|verify=False)",
        "Cleartext or disabled-TLS usage.",
    ),
    (
        "sast-debug-log",
        "Debug/exception leak",
        "low",
        "CWE-209",
        r"\b(?:print\(|console\.log|logger\.exception|traceback\.print|"
        r"dumpstack|error_stack)\b",
        "Possible sensitive detail in logs/errors.",
    ),
]


@dataclass
class Finding:
    rule_id: str
    name: str
    severity: str
    cwe: str
    file: str
    line: int
    code: str
    description: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "severity": self.severity,
            "cwe": self.cwe,
            "file": self.file,
            "line": self.line,
            "code": self.code,
            "description": self.description,
        }


class SASTScanner:
    """Scan a directory tree for the RULES patterns. Returns Findings."""

    SKIP_DIRS: frozenset[str] = frozenset(
        {
            ".git",
            "__pycache__",
            "node_modules",
            ".venv",
            "vendor",
            ".idea",
            "dist",
            "build",
            "site-packages",
            "poetry.lock",
            ".terraform",
            "coverage",
        }
    )

    SKIP_EXTS = frozenset(
        {
            ".png",
            ".jpg",
            ".jpeg",
            ".gif",
            ".bmp",
            ".ico",
            ".woff",
            ".woff2",
            ".ttf",
            ".pdf",
            ".zip",
            ".gz",
            ".tar",
            ".svg",
            ".eot",
            ".map",
            ".min.js",
        }
    )

    MAX_LINE = 4000

    def __init__(self, rules: list[tuple] | None = None):
        self.rules = rules or RULES
        self._compiled = [
            (rid, name, sev, cwe, re.compile(pat, re.IGNORECASE), desc)
            for rid, name, sev, cwe, pat, desc in self.rules
        ]

    def scan_dir(self, root: str | Path) -> list[Finding]:
        findings: list[Finding] = []
        root = Path(root).resolve()

        # Primary engine: Semgrep (real static-analysis tool with a rule set).
        semgrep_hits = self._scan_semgrep(root)
        if semgrep_hits:
            findings.extend(semgrep_hits)

        # Fallback / enrichment: regex heuristics (handles files Semgrep skips,
        # and runs even when semgrep isn't installed).
        findings.extend(self._scan_regex(root))
        return findings

    def _scan_regex(self, root: Path) -> list[Finding]:
        findings: list[Finding] = []
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if self._skip(path):
                continue
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    for lineno, line in enumerate(fh, start=1):
                        if len(line) > self.MAX_LINE:
                            continue
                        findings.extend(self._match(path, root, lineno, line))
            except OSError:
                continue
        return findings

    def _scan_semgrep(self, root: Path) -> list[Finding]:
        from services.semgrep import scan_semgrep

        hits = []
        try:
            raw = scan_semgrep(root)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("semgrep unavailable, using regex only: %s", exc)
            return []
        for h in raw:
            hits.append(
                Finding(
                    rule_id=h.rule_id,
                    name=h.message or h.rule_id,
                    severity=h.severity,
                    cwe=h.cwe,
                    file=_relpath(h.path, root),
                    line=h.line,
                    code="",
                    description=h.message,
                )
            )
        return hits

    def _match(self, path: Path, root: Path, lineno: int, line: str) -> list[Finding]:
        out: list[Finding] = []
        rel = _relpath(str(path), root)
        for rid, name, sev, cwe, rx, desc in self._compiled:
            if rx.search(line):
                out.append(
                    Finding(
                        rule_id=rid,
                        name=name,
                        severity=sev,
                        cwe=cwe,
                        file=rel,
                        line=lineno,
                        code=line.rstrip()[:200],
                        description=desc,
                    )
                )
        return out

    def _skip(self, path: Path) -> bool:
        if path.suffix.lower() in self.SKIP_EXTS:
            return True
        return any(part in self.SKIP_DIRS for part in path.parts)


# ---------------------------------------------------------------------------
# PoC / disclosure-skeleton generation.
# Produces minimal, clearly-labelled proof-of-concept source for a finding.
# These are teaching artifacts — they contain no working weaponization, they
# document the vulnerability so an owner can verify and patch, and they are
# intended for responsible disclosure, never attacks.
# ---------------------------------------------------------------------------
POC_SNIPPETS: dict[str, str] = {
    "sast-sql-injection": (
        "-- Proof of concept (disclosure only).\n"
        "-- If this app is yours: verify that `id` is bound as a parameter.\n"
        "SELECT * FROM users WHERE id = '<input>' OR '1'='1';\n"
        "-- Expected if vulnerable: returns all rows (injection works).\n"
        "-- Fix: use a prepared statement / parameterized query.\n"
    ),
    "sast-cmd-injection": (
        "# Proof of concept (disclosure only).\n"
        "# If this app is yours: check that user input cannot reach `cmd`.\n"
        "import subprocess\n"
        "cmd = 'ping -c 1 ' + user_input      # vulnerable pattern\n"
        "subprocess.call(cmd, shell=True)     # <-- injection if user_input\n"
        "# Fix: subprocess.call(cmd_list) without shell=True.\n"
    ),
    "sast-path-traversal": (
        "# Proof of concept (disclosure only).\n"
        "# Path traversal check — /../../../etc/passwd must resolve outside root.\n"
        "curl -s 'http://TARGET/download?file=../../../../etc/passwd'\n"
        "# If it returns /etc/passwd content, the path join is unsafe.\n"
        "# Fix: validate with a canonical allow-list, never trust the raw name.\n"
    ),
    "sast-buffer-copy": (
        "// Proof of concept (disclosure only).\n"
        "// char buf[256];  strcpy(buf, attacker_input);  // <-- overflow\n"
        "// Feed >255 bytes; under ASan this aborts with stack-buffer-overflow.\n"
        "// Fix: use strncpy/snprintf with an explicit bound.\n"
    ),
    "sast-format-string": (
        "// Proof of concept (disclosure only).\n"
        "// printf(user_input);  // <-- %n writes, aborts under ASan\n"
        '// Fix: printf("%s", user_input);\n'
    ),
    "sast-eval": (
        "# Proof of concept (disclosure only).\n"
        "# eval(user_input) executes attacker-controlled code.\n"
        "# Fix: never eval untrusted input; use a safe parser/interpreter.\n"
    ),
    "sast-deserialize": (
        "# Proof of concept (disclosure only).\n"
        "# pickle.loads(untrusted) / unserialize() -> RCE.\n"
        "# Fix: only deserialize signed/trusted data; use safe serializers.\n"
    ),
}

DEFAULT_POC = (
    "# Proof of concept (disclosure only).\n"
    "# Manual analysis required — reproduce on a system you own, then\n"
    "# report to the vendor responsibly. Do not run against third parties.\n"
)


def make_poc(finding: Finding, lang: str = "auto") -> str:
    """Return a PoC/disclosure skeleton for a finding (best-effort)."""
    head = (
        f"# {finding.name}  ({finding.cwe}) — PoC / disclosure skeleton\n"
        f"# file: {finding.file}:{finding.line}\n"
        f"# severity: {finding.severity}\n\n"
    )
    snip = POC_SNIPPETS.get(finding.rule_id, DEFAULT_POC)
    return head + snip


def _relpath(path: str, root: Path) -> str:
    """Return `path` relative to `root` (falls back to the raw string)."""
    p = Path(path)
    try:
        return str(p.relative_to(root)) if p.is_absolute() else str(p)
    except ValueError:
        return str(p)
