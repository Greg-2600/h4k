# Tests for the custom-rule library and SCA secret scanning.
from pathlib import Path
from tempfile import TemporaryDirectory

from services import rules
from services.sca import scan_secrets


def test_rules_save_load_delete(tmp_path, monkeypatch):
    monkeypatch.setattr(rules, "RULES_FILE", tmp_path / "custom_rules.json")
    rules.save_rule({"rule_id": "r1", "name": "R1", "pattern": "eval(...)"})
    assert [r["rule_id"] for r in rules.list_rules()] == ["r1"]
    assert rules.delete_rule("r1") is True
    assert rules.list_rules() == []
    assert rules.delete_rule("nope") is False


def test_rules_save_replaces_same_id(tmp_path, monkeypatch):
    monkeypatch.setattr(rules, "RULES_FILE", tmp_path / "custom_rules.json")
    rules.save_rule({"rule_id": "r1", "name": "old"})
    rules.save_rule({"rule_id": "r1", "name": "new"})
    rs = rules.list_rules()
    assert len(rs) == 1 and rs[0]["name"] == "new"


def test_rules_require_id(tmp_path, monkeypatch):
    monkeypatch.setattr(rules, "RULES_FILE", tmp_path / "custom_rules.json")
    import pytest

    with pytest.raises(ValueError):
        rules.save_rule({"name": "no id"})


def test_run_rule_via_regex(tmp_path):
    with TemporaryDirectory() as td:
        root = Path(td)
        (root / "a.py").write_text("x = eval(user)\n", encoding="utf-8")
        (root / "b.txt").write_text("hello\n", encoding="utf-8")
        hits = rules.run_rule_via_regex(
            {
                "rule_id": "r1",
                "name": "eval",
                "severity": "high",
                "pattern": r"eval\(.*\)",
            },
            root,
        )
        assert len(hits) == 1
        assert hits[0]["file"] == "a.py"


def test_run_rule_via_regex_bad_pattern(tmp_path):
    with TemporaryDirectory() as td:
        root = Path(td)
        (root / "a.py").write_text("x\n", encoding="utf-8")
        hits = rules.run_rule_via_regex({"rule_id": "r", "pattern": "(unclosed"}, root)
        assert hits == []


def test_scan_secrets_finds_aws_key(tmp_path):
    with TemporaryDirectory() as td:
        root = Path(td)
        (root / "app.py").write_text("aws = 'AKIAIOSFODNN7EXAMPLE'\n", encoding="utf-8")
        found = scan_secrets(root)
        assert any(f["kind"] == "aws-akid" for f in found)


def test_scan_secrets_does_not_crash_empty(tmp_path):
    with TemporaryDirectory() as td:
        root = Path(td)
        (root / "readme.md").write_text("just docs", encoding="utf-8")
        assert scan_secrets(root) == []
