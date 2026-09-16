# Persistent library of user-authored custom Semgrep-style rules. A rule can be
# defined once, saved, and re-run over any source tree — turning the SAST
# workflow from "try one pattern" into "build your own rule pack."
import json
import logging
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger("h4k.rules")

DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data"
RULES_FILE = DATA_DIR / "custom_rules.json"


def _load() -> list[dict[str, Any]]:
    if not RULES_FILE.exists():
        return []
    try:
        return json.loads(RULES_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        logger.warning("could not parse custom_rules.json; starting empty")
        return []


def _save(rules: list[dict[str, Any]]) -> None:
    RULES_FILE.write_text(json.dumps(rules, indent=2), encoding="utf-8")


def list_rules() -> list[dict[str, Any]]:
    return _load()


def save_rule(rule: dict[str, Any]) -> dict[str, Any]:
    rules = _load()
    rid = rule.get("rule_id", "").strip()
    if not rid:
        raise ValueError("rule_id required")
    # replace if id exists, else append
    rules = [r for r in rules if r.get("rule_id") != rid]
    rules.append(rule)
    _save(rules)
    return rule


def delete_rule(rule_id: str) -> bool:
    rules = _load()
    before = len(rules)
    rules = [r for r in rules if r.get("rule_id") != rule_id]
    _save(rules)
    return len(rules) != before


def run_rule_via_regex(rule: dict[str, Any], root: Path) -> list[dict[str, Any]]:
    """Run a saved rule's `pattern` as a regex over the tree (fallback when we
    don't want to shell out). The primary path uses Semgrep's test_rule; this
    is a light complement for quick tree sweeps."""
    pattern = rule.get("pattern", "")
    if not pattern:
        return []
    try:
        rx = re.compile(pattern, re.IGNORECASE)
    except re.error:
        return []
    skip_dirs = {
        ".git",
        "node_modules",
        ".venv",
        "vendor",
        "dist",
        "build",
        "__pycache__",
        "site-packages",
    }
    found: list[dict[str, Any]] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in skip_dirs for part in path.parts):
            continue
        try:
            with open(path, encoding="utf-8", errors="ignore") as fh:
                for lineno, line in enumerate(fh, 1):
                    if rx.search(line):
                        found.append(
                            {
                                "rule_id": rule.get("rule_id", "custom"),
                                "name": rule.get("name", "custom"),
                                "severity": rule.get("severity", "medium"),
                                "cwe": rule.get("cwe", "CWE-710"),
                                "file": str(path.relative_to(root)),
                                "line": lineno,
                                "code": line.strip()[:120],
                            }
                        )
                        break  # one hit per line
        except OSError:
            continue
    return found
