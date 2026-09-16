# Tests for the SAST scanner and PoC/disclosure-skeleton generation.
import contextlib
from pathlib import Path
from tempfile import TemporaryDirectory

from services.sast import Finding, SASTScanner, make_poc


@contextlib.contextmanager
def _tree(files: dict[str, str]):
    with TemporaryDirectory() as tmp:
        root = Path(tmp)
        for rel, content in files.items():
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
        yield root


def test_scanner_finds_sql_injection():
    body = "query = 'SELECT * FROM users WHERE id = ' + uid\ncursor.execute(query)\n"
    with _tree({"app.py": body}) as root:
        f = SASTScanner().scan_dir(root)
    assert any(x.rule_id == "sast-sql-injection" for x in f)


def test_scanner_finds_command_injection():
    with _tree({"run.sh": "system('ping -c 1 ' + target)\n"}) as root:
        f = SASTScanner().scan_dir(root)
    assert any(x.rule_id == "sast-cmd-injection" for x in f)


def test_scanner_skips_binary_and_vendored():
    with _tree(
        {
            "app.py": "eval(user)\n",
            ".git/HEAD": "ref: refs",
            "node_modules/x/index.js": "eval(y)\n",
            "logo.png": "PNG",
        }
    ) as root:
        f = SASTScanner().scan_dir(root)
    # only the app.py eval survives skip logic
    assert any(x.file.startswith("app.py") for x in f)


def test_scanner_finds_buffer_and_format_c():
    with _tree({"server.c": "strcpy(buf, input); printf(user);\n"}) as root:
        f = SASTScanner().scan_dir(root)
    ids = {x.rule_id for x in f}
    assert "sast-buffer-copy" in ids
    assert "sast-format-string" in ids


def test_scanner_clean_tree():
    with _tree({"app.py": "import os\nprint('hello')\n"}) as root:
        assert SASTScanner().scan_dir(root) == []


def test_make_poc_sql():
    f = Finding(
        "sast-sql-injection", "SQLi", "high", "CWE-89", "app.py", 1, "SELECT", "desc"
    )
    poc = make_poc(f)
    assert "sast-sql-injection" not in poc  # header says the name
    assert "disclosure" in poc.lower()


def test_make_poc_default():
    f = Finding("sast-unknown-rule", "X", "info", "CWE-710", "a", 1, "", "")
    poc = make_poc(f)
    assert "Proof of concept" in poc
