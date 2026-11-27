"""Vulnerable-dependency → sink paths and VEX statements (Backlog #67).

Offline supply-chain triage for sources the operator is entitled to analyze:
SCA findings (package + CVE) are correlated with a curated library→dangerous
API table, then a windowed taint check decides whether untrusted input reaches
that API in the pasted source tree.

The verdicts are deliberately modest. ``affected`` needs an observed
source→sink window on a file that imports the component. ``not_affected`` means
no such path was seen in the supplied files — not a runtime proof; dynamic
imports and cross-file dataflow are out of scope. Packages without a curated
rule are ``under_investigation``, never silently cleared. Operator-supplied
justifications are recorded verbatim and win over the heuristic verdict.

Nothing here clones a repo, calls a network service, or shells out; sandbox
mode returns canned statements and paths without parsing at all.
"""

from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger("h4k.vuln_vex")

_WINDOW = 8

LIMITATIONS = (
    "Offline heuristic: curated library→sink rules plus a source→sink window "
    "over pasted sources only. not_affected means no tainted path was observed "
    "in these files, not a runtime proof; dynamic imports and cross-file "
    "dataflow are not modelled. Packages without a rule are "
    "under_investigation, never cleared."
)

_SOURCE_RE = re.compile(
    r"(?:request\.(?:args|form|values|cookies|headers|data|get_json|get_data)"
    r"|req\.(?:query|body|params|headers|cookies|param)"
    r"|\$_(?:GET|POST|REQUEST|COOKIE)"
    r"|getParameter\s*\(|input\s*\(|sys\.argv|os\.environ|os\.getenv"
    r"|location\.(?:hash|search)|document\.cookie)"
)
_SANITIZER_RE = re.compile(
    r"(?:shlex\.quote|pipes\.quote|htmlspecialchars|htmlentities"
    r"|DOMPurify\.sanitize|json\.loads|ast\.literal_eval|yaml\.safe_load"
    r"|escapeshellarg|encodeURI)"
)
_IMPORT_HINT_RE = re.compile(r"\b(?:import|require|from|use|include)\b", re.IGNORECASE)

_JUSTIFICATION_TYPES = {
    "tainted_path_to_vulnerable_api": "vulnerable_code_in_execute_path",
    "no_tainted_path_in_provided_sources": "vulnerable_code_not_in_execute_path",
    "component_not_imported": "component_not_present",
    "no_library_rule": "under_investigation",
    "operator_assertion": "operator_assertion",
}


def _rx(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern)


# (aliases, dangerous API, CWE, title, optional narrower source regex)
LIBRARY_RULES: tuple[
    tuple[tuple[str, ...], re.Pattern[str], str, str, re.Pattern[str] | None], ...
] = (
    (
        ("pyyaml", "yaml"),
        _rx(r"\byaml\.load\s*\("),
        "CWE-502",
        "untrusted data reaches an unsafe YAML loader",
        None,
    ),
    (
        ("lodash",),
        _rx(r"(?:_\.|lodash\.)(?:template|merge|defaultsDeep|set)\s*\("),
        "CWE-1321",
        "untrusted data reaches a prototype-pollution sink in lodash",
        None,
    ),
    (
        ("log4j", "log4j-core"),
        _rx(r"(?:logger|log|LOGGER)\.(?:trace|debug|info|warn|error|fatal)\s*\("),
        "CWE-917",
        "log4j message interpolation sink",
        _rx(r"\$\{jndi:|getParameter\s*\(|request\.(?:args|form|parameters)"),
    ),
    (
        ("jinja2",),
        _rx(r"(?:render_template_string|Template\s*\()"),
        "CWE-1336",
        "untrusted data reaches a template-injection sink",
        None,
    ),
    (
        ("axios",),
        _rx(r"axios\.(?:get|post|put|delete)\s*\("),
        "CWE-918",
        "untrusted data reaches an SSRF request URL",
        None,
    ),
    (
        ("jackson-databind",),
        _rx(r"(?:readValue\s*\(|enableDefaultTyping\s*\()"),
        "CWE-502",
        "untrusted data reaches an unsafe deserializer",
        None,
    ),
)


def _name_candidates(dep: dict[str, Any]) -> list[str]:
    raw = str(dep.get("name") or "").strip().lower()
    purl = str(dep.get("purl") or "").strip().lower()
    out: set[str] = set()
    if raw:
        out.add(raw)
    if purl.startswith("pkg:"):
        segment = purl[4:].split("/", 1)[-1]
        out.add(segment.split("@")[0])
        out.add(segment)
    for value in list(out):
        if ":" in value:
            out.add(value.rsplit(":", 1)[-1])
        if "/" in value:
            out.add(value.rsplit("/", 1)[-1])
        if value.startswith("@"):
            out.add(value.lstrip("@"))
    return sorted(value for value in out if value)


def _display_name(dep: dict[str, Any], candidates: list[str]) -> str:
    raw = str(dep.get("name") or "").strip()
    if raw:
        return raw
    return candidates[0] if candidates else "unknown-package"


def _cves(dep: dict[str, Any]) -> list[str]:
    out: list[str] = []
    single = dep.get("cve") or dep.get("cve_id") or ""
    if isinstance(single, str) and single.strip():
        out.append(single.strip())
    for value in dep.get("cves") or []:
        text = str(value).strip()
        if text and text not in out:
            out.append(text)
    return out or ["UNKNOWN"]


def _import_lines(content: str, aliases: tuple[str, ...]) -> list[int]:
    hits: list[int] = []
    for number, line in enumerate(content.splitlines(), 1):
        if not _IMPORT_HINT_RE.search(line):
            continue
        for alias in aliases:
            token = r"(?<![A-Za-z0-9_$-])" + re.escape(alias) + r"(?![A-Za-z0-9_$-])"
            if re.search(token, line, re.IGNORECASE):
                hits.append(number)
                break
    return hits


def _rule_for(candidates: list[str]) -> tuple[Any, ...] | None:
    for rule in LIBRARY_RULES:
        if any(alias in candidates for alias in rule[0]):
            return rule
    return None


def _sink_paths(
    files: list[dict[str, str]],
    imports: dict[str, int],
    cves: list[str],
    rule: tuple[Any, ...],
    package: str,
) -> list[dict[str, Any]]:
    _, sink_re, cwe, title, source_re = rule
    source_pattern = source_re or _SOURCE_RE
    paths: list[dict[str, Any]] = []
    for entry in files:
        path = str(entry.get("path") or "file")
        if path not in imports:
            continue
        lines = str(entry.get("content") or "").splitlines()
        for index, line in enumerate(lines):
            if not sink_re.search(line):
                continue
            start = max(0, index - _WINDOW)
            window = "\n".join(lines[start : index + 1])
            matched = source_pattern.search(window)
            if matched is None or _SANITIZER_RE.search(window):
                continue
            source_line = start + window[: matched.start()].count("\n") + 1
            for cve in cves:
                paths.append(
                    {
                        "cve": cve,
                        "package": package,
                        "file": path,
                        "sink_line": index + 1,
                        "source_line": source_line,
                        "source": matched.group(0)[:120],
                        "sink": line.strip()[:160],
                        "api": title,
                        "cwe": cwe,
                        "evidence": (
                            f"untrusted source at line {source_line} reaches "
                            f"{title} at line {index + 1}; component imported "
                            f"at line {imports[path]}"
                        ),
                    }
                )
            break
    return paths


def _justifications(
    items: list[dict[str, Any]] | None,
) -> tuple[dict[str, str], dict[str, str], dict[str, str]]:
    by_cve: dict[str, str] = {}
    by_package: dict[str, str] = {}
    types: dict[str, str] = {}
    for item in items or []:
        if not isinstance(item, dict):
            raise ValueError("justification entries must be objects")
        reason = str(item.get("reason") or item.get("justification") or "").strip()
        if not reason:
            raise ValueError("justification reason required")
        cve = str(item.get("cve") or "").strip().lower()
        package = str(item.get("package") or item.get("name") or "").strip().lower()
        if not cve and not package:
            raise ValueError("justification needs cve or package")
        if cve:
            by_cve[cve] = reason
            types[cve] = str(
                item.get("justification_type") or "operator_assertion"
            ).strip()
        if package:
            by_package[package] = reason
    return by_cve, by_package, types


def analyze(
    dependencies: list[dict[str, Any]],
    files: list[dict[str, str]],
    justifications: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Correlate vulnerable dependencies with tainted sink paths + VEX."""
    if not dependencies:
        raise ValueError("dependencies required (paste SCA findings)")
    if not files:
        raise ValueError("bundle or files required (paste sources)")
    by_cve, by_package, types = _justifications(justifications)
    statements: list[dict[str, Any]] = []
    paths: list[dict[str, Any]] = []
    packages: set[str] = set()
    cve_set: set[str] = set()
    matched = 0

    for dep in dependencies:
        if not isinstance(dep, dict):
            raise ValueError("dependency entries must be objects")
        candidates = _name_candidates(dep)
        if not candidates:
            raise ValueError("dependency name or purl required")
        package = _display_name(dep, candidates)
        cves = _cves(dep)
        rule = _rule_for(candidates)
        aliases = rule[0] if rule else tuple(candidates)
        imports: dict[str, int] = {}
        for entry in files:
            path = str(entry.get("path") or "file")
            hits = _import_lines(str(entry.get("content") or ""), aliases)
            if hits:
                imports[path] = hits[0]

        if rule is None:
            status = "under_investigation"
            reason = "no_library_rule"
            detail = "No curated sink rule for this package; needs manual review."
            found: list[dict[str, Any]] = []
            cwe = str(dep.get("cwe") or "")
        else:
            matched += 1
            found = _sink_paths(files, imports, cves, rule, package)
            cwe = rule[2]
            if found:
                status = "affected"
                reason = "tainted_path_to_vulnerable_api"
                detail = found[0]["evidence"]
            elif not imports:
                status = "not_affected"
                reason = "component_not_imported"
                detail = f"No import of {package} found in the supplied sources."
            else:
                status = "not_affected"
                reason = "no_tainted_path_in_provided_sources"
                detail = (
                    f"{package} imported at "
                    + ", ".join(f"{p}:{n}" for p, n in sorted(imports.items()))
                    + f"; no untrusted input reaches the {rule[3]} sink."
                )

        packages.add(package)
        cve_set.update(cves)
        for cve in cves:
            override = by_cve.get(cve.lower()) or by_package.get(package.lower())
            justification = "operator_assertion" if override else reason
            if override:
                justification_type = types.get(cve.lower(), "operator_assertion")
            else:
                justification_type = _JUSTIFICATION_TYPES.get(
                    justification, "under_investigation"
                )
            severity = str(
                dep.get("severity") or ("MEDIUM" if rule else "UNKNOWN")
            ).upper()
            statements.append(
                {
                    "cve": cve,
                    "package": package,
                    "version": str(dep.get("version") or ""),
                    "fixed_version": str(dep.get("fixed_version") or ""),
                    "severity": severity,
                    "cwe": cwe,
                    "status": "not_affected" if override else status,
                    "justification": justification,
                    "justification_type": justification_type,
                    "justification_detail": (
                        f"{override} (operator-supplied)" if override else detail
                    ),
                    "evidence": found[0]["evidence"] if found else detail,
                    "path_count": len(found),
                    "source": "operator" if override else "static-heuristic",
                }
            )
        paths.extend(found)

    return {
        "dependencies": len(dependencies),
        "packages": sorted(packages),
        "cves": sorted(cve_set),
        "matched_rules": matched,
        "affected": sum(s["status"] == "affected" for s in statements),
        "not_affected": sum(s["status"] == "not_affected" for s in statements),
        "under_investigation": sum(
            s["status"] == "under_investigation" for s in statements
        ),
        "paths": paths,
        "path_count": len(paths),
        "statements": statements,
        "sandbox": False,
        "limitations": LIMITATIONS,
    }


def to_ledger(host: str, statements: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Ledger only statements still marked affected (VEX wins)."""
    rows: list[dict[str, Any]] = []
    for statement in statements:
        if statement.get("status") != "affected":
            continue
        cve = str(statement.get("cve") or "")
        package = str(statement.get("package") or "")
        rows.append(
            {
                "host": host,
                "name": f"vuln-vex {cve} in {package}"[:220],
                "severity": str(statement.get("severity") or "UNKNOWN").upper(),
                "module": "vuln-vex",
                "reference": cve,
                "cwe": str(statement.get("cwe") or ""),
                "detail": (
                    f"{statement.get('justification', '')}: "
                    f"{statement.get('evidence', '')}"
                ).strip()[:400],
            }
        )
    return rows


def sandbox_result() -> dict[str, Any]:
    """Canned affected / not-affected / operator-asserted VEX statements."""
    path = {
        "cve": "CVE-2017-18342",
        "package": "pyyaml",
        "file": "app.py",
        "sink_line": 9,
        "source_line": 7,
        "source": "request.args.get('cfg') (sandbox)",
        "sink": "yaml.load(cfg) (sandbox)",
        "api": "untrusted data reaches an unsafe YAML loader (sandbox)",
        "cwe": "CWE-502",
        "evidence": "untrusted source at line 7 reaches unsafe YAML loader "
        "at line 9 (sandbox)",
    }
    statements = [
        {
            "cve": "CVE-2017-18342",
            "package": "pyyaml",
            "version": "3.13",
            "fixed_version": "5.1",
            "severity": "CRITICAL",
            "cwe": "CWE-502",
            "status": "affected",
            "justification": "tainted_path_to_vulnerable_api",
            "justification_type": "vulnerable_code_in_execute_path",
            "justification_detail": path["evidence"],
            "evidence": path["evidence"],
            "path_count": 1,
            "source": "static-heuristic",
        },
        {
            "cve": "CVE-2019-10744",
            "package": "lodash",
            "version": "4.17.11",
            "fixed_version": "4.17.12",
            "severity": "CRITICAL",
            "cwe": "CWE-1321",
            "status": "not_affected",
            "justification": "component_not_imported",
            "justification_type": "component_not_present",
            "justification_detail": "No import of lodash found in the supplied "
            "sources (sandbox).",
            "evidence": "No import of lodash found in the supplied sources (sandbox).",
            "path_count": 0,
            "source": "static-heuristic",
        },
        {
            "cve": "CVE-2021-44228",
            "package": "log4j-core",
            "version": "2.14.1",
            "fixed_version": "2.15.0",
            "severity": "CRITICAL",
            "cwe": "CWE-917",
            "status": "not_affected",
            "justification": "operator_assertion",
            "justification_type": "vulnerable_code_not_in_execute_path",
            "justification_detail": "No user input reaches log interpolation "
            "in this deployment (operator-supplied, sandbox).",
            "evidence": "Operator assertion (sandbox).",
            "path_count": 0,
            "source": "operator",
        },
    ]
    return {
        "dependencies": 3,
        "packages": ["lodash", "log4j-core", "pyyaml"],
        "cves": ["CVE-2017-18342", "CVE-2019-10744", "CVE-2021-44228"],
        "matched_rules": 3,
        "affected": 1,
        "not_affected": 2,
        "under_investigation": 0,
        "paths": [path],
        "path_count": 1,
        "statements": statements,
        "sandbox": True,
        "limitations": LIMITATIONS,
    }
