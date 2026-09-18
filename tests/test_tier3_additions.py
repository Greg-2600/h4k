# Tests for the Tier 2/3 additions: AI exploit-first loop parser, trivy license
# scan (degraded), and the local TLS lab. All offline-safe.
from pathlib import Path
from tempfile import TemporaryDirectory

from services import sca as sca_mod, tls_lab
from services.ai_loop import _parse_sections


def test_ai_loop_parse_inline_markers():
    raw = (
        "ROOT_CAUSE: stack overflow\n"
        "TRIGGER: send 300 bytes\n"
        "PATCH_CANDIDATE: strncpy with len\n"
        "VERIFY: feed same input\n"
    )
    p = _parse_sections(raw)
    assert p["root_cause"] == "stack overflow"
    assert p["trigger"] == "send 300 bytes"
    assert p["patch_candidate"] == "strncpy with len"
    assert p["verify"] == "feed same input"


def test_ai_loop_parse_bare_markers():
    raw = (
        "ROOT_CAUSE\nstack overflow\n"
        "TRIGGER\nsend 300 bytes\n"
        "PATCH\nstrncpy\n"
        "VERIFY\nre-run\n"
    )
    p = _parse_sections(raw)
    assert p["patch_candidate"] == "strncpy"
    assert p["trigger"] == "send 300 bytes"


def test_ai_loop_parse_bold_markers():
    raw = "**ROOT_CAUSE:** the issue\n**TRIGGER:** minimal poc\n"
    p = _parse_sections(raw)
    assert p["root_cause"] == "the issue"
    assert p["trigger"] == "minimal poc"


def test_scan_licenses_missing_trivy(tmp_path, monkeypatch):
    def _which(t):
        return None if t == "trivy" else "__shutil_which__"

    monkeypatch.setattr(sca_mod, "_tool_cmd", _which)
    with TemporaryDirectory() as td:
        root = Path(td)
        (root / "pkg.json").write_text("{}", encoding="utf-8")
        assert sca_mod.scan_licenses(root) == []


def test_scan_licenses_parses_trivy_output(tmp_path, monkeypatch):
    sample = {
        "Results": [
            {
                "Target": "package-lock.json",
                "Packages": [
                    {
                        "Name": "lodash",
                        "Version": "4.17.20",
                        "Licenses": ["MIT"],
                        "Locations": [{"StartLine": 14}],
                    }
                ],
            }
        ]
    }
    import json as _json

    def _tool_cmd(name):
        return "/usr/bin/trivy" if name == "trivy" else None

    def _fake_run(cmd, timeout=240):
        return 0, _json.dumps(sample), ""

    monkeypatch.setattr(sca_mod, "_tool_cmd", _tool_cmd)
    monkeypatch.setattr(sca_mod, "_run", _fake_run)
    with TemporaryDirectory() as td:
        root = Path(td)
        (root / "package-lock.json").write_text("{}", encoding="utf-8")
        lic = sca_mod.scan_licenses(root)
        assert len(lic) == 1
        assert lic[0]["package"] == "lodash"
        assert "MIT" in lic[0]["licenses"]


def test_tls_lab_status_no_openssl(monkeypatch):
    monkeypatch.setattr(tls_lab, "_which", lambda t: None)
    st = tls_lab.status()
    assert st["available"] is False


def test_scan_secrets_finds_generic(tmp_path):
    with TemporaryDirectory() as td:
        root = Path(td)
        (root / "cfg.py").write_text(
            "password = 'supersecretvalue123'\n", encoding="utf-8"
        )
        found = sca_mod.scan_secrets(root)
        assert any(f["kind"] == "generic-secret" for f in found)
