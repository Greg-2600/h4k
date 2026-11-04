# Tests for the SCA service. osv-scanner / trivy are faked at the subprocess
# boundary; the assertions are about honest parsing (CVE aliasing, package
# attribution, license extraction) and graceful degradation when a tool is
# missing or returns garbage.
import json
import subprocess
from pathlib import Path

import pytest
from services import sca


@pytest.fixture(autouse=True)
def _sbom_dir(tmp_path, monkeypatch):
    d = tmp_path / "sboms"
    d.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(sca, "_sbom_out_dir", lambda: d)
    return d


# --- _run wrapper -----------------------------------------------------------


def test_run_returns_rc_and_output(monkeypatch):
    class P:
        returncode = 0
        stdout = "out"
        stderr = "err"

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: P())
    assert sca._run(["x"]) == (0, "out", "err")


def test_run_handles_missing_binary(monkeypatch):
    def boom(*a, **k):
        raise FileNotFoundError

    monkeypatch.setattr(subprocess, "run", boom)
    rc, _o, err = sca._run(["osv-scanner"])
    assert rc == -1
    assert "not installed" in err


def test_run_handles_timeout(monkeypatch):
    def boom(*a, **k):
        raise subprocess.TimeoutExpired(cmd="x", timeout=1)

    monkeypatch.setattr(subprocess, "run", boom)
    assert sca._run(["x"]) == (-1, "", "timeout")


# --- SBOM generation --------------------------------------------------------


def test_generate_sbom_uses_trivy(tmp_path, monkeypatch):
    monkeypatch.setattr(sca, "_tool_cmd", lambda t: f"/usr/bin/{t}")
    calls = []

    def run(cmd, cwd=None, timeout=180):
        calls.append(cmd)
        Path(cmd[cmd.index("--output") + 1]).write_text("{}", encoding="utf-8")
        return 0, "", ""

    monkeypatch.setattr(sca, "_run", run)
    p = sca.generate_sbom(tmp_path)
    assert p is not None
    # suffix is only the last component; check the full CycloneDX filename
    assert p.name.endswith(".cdx.json")
    argv = calls[0]
    assert "cyclonedx" in argv  # CycloneDX JSON, not trivy's default table format
    assert "license,secret" in argv


def test_generate_sbom_returns_none_without_trivy(tmp_path, monkeypatch):
    monkeypatch.setattr(sca, "_tool_cmd", lambda t: None)
    assert sca.generate_sbom(tmp_path) is None


def test_generate_sbom_none_when_trivy_fails(tmp_path, monkeypatch):
    monkeypatch.setattr(sca, "_tool_cmd", lambda t: "/usr/bin/trivy")
    monkeypatch.setattr(sca, "_run", lambda cmd, cwd=None, timeout=180: (1, "", "boom"))
    assert sca.generate_sbom(tmp_path) is None


# --- osv-scanner parsing ----------------------------------------------------

OSV_FIXTURE = {
    "results": [
        {
            "source": {"path": "package-lock.json", "type": "lockfile"},
            "packages": [
                {
                    "package": {
                        "name": "lodash",
                        "version": "4.17.20",
                        "ecosystem": "npm",
                    }
                },
                {"package": {"name": "minimist", "version": "1.2.0"}},
            ],
            "vulnerabilities": [
                {
                    "id": "GHSA-xxxx-yyyy-zzzz",
                    "aliases": ["CVE-2021-23337"],
                    "details": "Command injection in lodash template.",
                },
                {
                    "id": "GHSA-aaaa-bbbb-cccc",
                    "aliases": [],  # no CVE alias -> falls back to the advisory id
                    "details": "Prototype pollution.",
                },
            ],
        }
    ]
}


def test_scan_osv_missing_tool_is_empty(tmp_path, monkeypatch):
    monkeypatch.setattr(sca, "_tool_cmd", lambda t: None)
    res = sca.scan_osv(tmp_path)
    assert res.cve_ids == []
    assert res.packages == []
    assert res.pkg_cves == {}


def test_scan_osv_parses_cves_and_attributes_packages(tmp_path, monkeypatch):
    monkeypatch.setattr(sca, "_tool_cmd", lambda t: "/usr/bin/osv-scanner")

    def run(cmd, cwd=None, timeout=180):
        if "--output" in cmd:
            Path(cmd[cmd.index("--output") + 1]).write_text(
                json.dumps(OSV_FIXTURE), encoding="utf-8"
            )
        return 0, "", ""

    monkeypatch.setattr(sca, "_run", run)
    res = sca.scan_osv(tmp_path)
    assert "CVE-2021-23337" in res.cve_ids
    # an advisory with no CVE alias keeps its GHSA id rather than inventing one
    assert "GHSA-aaaa-bbbb-cccc" in res.cve_ids
    assert set(res.packages) == {"lodash", "minimist"}
    # both CVEs attributed to both packages in the lockfile group
    assert "CVE-2021-23337" in res.pkg_cves["lodash"]
    assert "CVE-2021-23337" in res.pkg_cves["minimist"]


def test_scan_osv_falls_back_to_stdout(tmp_path, monkeypatch):
    monkeypatch.setattr(sca, "_tool_cmd", lambda t: "/usr/bin/osv-scanner")
    calls = []

    def run(cmd, cwd=None, timeout=180):
        calls.append(cmd)
        if "--output" in cmd:
            return 1, "", "no lockfile found"  # first form fails
        return 0, json.dumps(OSV_FIXTURE), ""  # stdout form works

    monkeypatch.setattr(sca, "_run", run)
    res = sca.scan_osv(tmp_path)
    assert len(calls) == 2
    assert "CVE-2021-23337" in res.cve_ids


def test_scan_osv_hard_failure_is_empty(tmp_path, monkeypatch):
    monkeypatch.setattr(sca, "_tool_cmd", lambda t: "/usr/bin/osv-scanner")
    monkeypatch.setattr(
        sca, "_run", lambda cmd, cwd=None, timeout=180: (1, "", "fatal")
    )
    assert sca.scan_osv(tmp_path).cve_ids == []


def test_scan_osv_non_json_is_empty(tmp_path, monkeypatch):
    monkeypatch.setattr(sca, "_tool_cmd", lambda t: "/usr/bin/osv-scanner")
    monkeypatch.setattr(
        sca, "_run", lambda cmd, cwd=None, timeout=180: (0, "not json", "")
    )
    assert sca.scan_osv(tmp_path).cve_ids == []


def test_scan_osv_does_not_duplicate_cves(tmp_path, monkeypatch):
    monkeypatch.setattr(sca, "_tool_cmd", lambda t: "/usr/bin/osv-scanner")
    dup = {
        "results": [
            {
                "packages": [{"package": {"name": "a"}}],
                "vulnerabilities": [{"id": "X", "aliases": ["CVE-1"]}],
            },
            {
                "packages": [{"package": {"name": "b"}}],
                "vulnerabilities": [{"id": "X", "aliases": ["CVE-1"]}],
            },
        ]
    }

    def run(cmd, cwd=None, timeout=180):
        if "--output" in cmd:
            Path(cmd[cmd.index("--output") + 1]).write_text(
                json.dumps(dup), encoding="utf-8"
            )
        return 0, "", ""

    monkeypatch.setattr(sca, "_run", run)
    res = sca.scan_osv(tmp_path)
    assert res.cve_ids.count("CVE-1") == 1


# --- licenses ---------------------------------------------------------------


def test_scan_licenses_parses_trivy_json(tmp_path, monkeypatch):
    monkeypatch.setattr(sca, "_tool_cmd", lambda t: "/usr/bin/trivy")
    payload = {
        "Results": [
            {
                "Target": "package-lock.json",
                "Packages": [
                    {
                        "Name": "lodash",
                        "Version": "4.17.20",
                        "Licenses": [{"Name": "MIT"}],
                        "Locations": [{"StartLine": 12}],
                    }
                ],
            }
        ]
    }
    monkeypatch.setattr(
        sca, "_run", lambda cmd, cwd=None, timeout=180: (0, json.dumps(payload), "")
    )
    out = sca.scan_licenses(tmp_path)
    assert out[0]["package"] == "lodash"
    assert out[0]["licenses"] == [{"Name": "MIT"}]
    assert out[0]["file"] == 12
    assert out[0]["target"] == "package-lock.json"


def test_scan_licenses_empty_without_trivy(tmp_path, monkeypatch):
    monkeypatch.setattr(sca, "_tool_cmd", lambda t: None)
    assert sca.scan_licenses(tmp_path) == []


def test_scan_licenses_tolerates_bad_json(tmp_path, monkeypatch):
    monkeypatch.setattr(sca, "_tool_cmd", lambda t: "/usr/bin/trivy")
    monkeypatch.setattr(
        sca, "_run", lambda cmd, cwd=None, timeout=180: (0, "<html>", "")
    )
    assert sca.scan_licenses(tmp_path) == []


def test_scan_licenses_tolerates_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(sca, "_tool_cmd", lambda t: "/usr/bin/trivy")
    monkeypatch.setattr(sca, "_run", lambda cmd, cwd=None, timeout=180: (1, "", "err"))
    assert sca.scan_licenses(tmp_path) == []


# --- secrets ----------------------------------------------------------------


def test_scan_secrets_finds_aws_key(tmp_path):
    (tmp_path / "app.py").write_text('AWS = "AKIAIOSFODNN7EXAMPLE"\n', encoding="utf-8")
    found = sca.scan_secrets(tmp_path)
    kinds = {f["kind"] for f in found}
    assert "aws-akid" in kinds
    assert found[0]["file"] == "app.py"
    assert found[0]["line"] == 1


def test_scan_secrets_finds_private_key_and_token(tmp_path):
    (tmp_path / "id_rsa").write_text(
        "-----BEGIN RSA PRIVATE KEY-----\nabc\n", encoding="utf-8"
    )
    (tmp_path / "cfg.py").write_text(
        'token = "ghp_abcdefghijklmnopqrstuvwxyz"\n', encoding="utf-8"
    )
    kinds = {f["kind"] for f in sca.scan_secrets(tmp_path)}
    assert "private-key" in kinds
    assert "github-token" in kinds


def test_scan_secrets_one_finding_per_line(tmp_path):
    (tmp_path / "x.py").write_text('password = "supersecretvalue1"\n', encoding="utf-8")
    found = sca.scan_secrets(tmp_path)
    assert len(found) == 1


def test_scan_secrets_skips_vendor_dirs(tmp_path):
    d = tmp_path / "node_modules" / "pkg"
    d.mkdir(parents=True)
    (d / "index.js").write_text(
        'token = "ghp_abcdefghijklmnopqrstuvwxyz"\n', encoding="utf-8"
    )
    (tmp_path / "keep.py").write_text(
        'token = "ghp_abcdefghijklmnopqrstuvwxyz"\n', encoding="utf-8"
    )
    files = {f["file"] for f in sca.scan_secrets(tmp_path)}
    assert files == {"keep.py"}


def test_scan_secrets_clean_tree(tmp_path):
    (tmp_path / "ok.py").write_text("print('hello')\n", encoding="utf-8")
    assert sca.scan_secrets(tmp_path) == []


# --- combined flow ----------------------------------------------------------


def test_sca_scan_aggregates_everything(tmp_path, monkeypatch):
    monkeypatch.setattr(sca, "generate_sbom", lambda root: tmp_path / "sb.cdx.json")
    monkeypatch.setattr(sca, "scan_osv", lambda root: sca.ScaResult(tool="osv"))
    monkeypatch.setattr(
        sca, "scan_secrets", lambda root: [{"file": "a", "line": 1, "kind": "x"}]
    )
    monkeypatch.setattr(sca, "scan_licenses", lambda root: [{"package": "p"}])
    out = sca.sca_scan(tmp_path, with_sbom=True)
    assert out["sbom_available"] is True
    assert out["secrets"][0]["kind"] == "x"
    assert out["licenses"][0]["package"] == "p"
    assert "sbom_dir" in out


def test_sca_scan_without_sbom(tmp_path, monkeypatch):
    monkeypatch.setattr(sca, "generate_sbom", lambda root: None)
    monkeypatch.setattr(sca, "scan_osv", lambda root: sca.ScaResult(tool="osv"))
    monkeypatch.setattr(sca, "scan_secrets", lambda root: [])
    monkeypatch.setattr(sca, "scan_licenses", lambda root: [])
    out = sca.sca_scan(tmp_path, with_sbom=False)
    assert out["sbom_available"] is False
    assert out["sbom_path"] is None


def test_sca_result_to_dict_shape():
    r = sca.ScaResult(tool="osv-scanner")
    d = r.to_dict()
    for k in ("tool", "cve_ids", "packages", "osv_vulns", "pkg_cves"):
        assert k in d
    # defaults are independent per instance (no shared mutable class state)
    r2 = sca.ScaResult(tool="x")
    r2.cve_ids.append("CVE-1")
    assert sca.ScaResult(tool="y").cve_ids == []


OSV_V2_FIXTURE = {
    # osv-scanner v2 shape: no top-level "vulnerabilities" — hits live in
    # packages[].groups[] (seen live against demos/sca-demo/lockfile).
    "results": [
        {
            "source": {"path": "demos/sca-demo/package-lock.json", "type": "lockfile"},
            "packages": [
                {
                    "package": {
                        "name": "lodash",
                        "version": "4.17.20",
                        "ecosystem": "npm",
                    },
                    "groups": [
                        {
                            "ids": ["GHSA-35jh-r3h4-6jhm"],
                            "aliases": ["CVE-2021-23337", "GHSA-35jh-r3h4-6jhm"],
                            "max_severity": "7.2",
                        }
                    ],
                }
            ],
        }
    ]
}


def test_scan_osv_parses_v2_package_groups(tmp_path, monkeypatch):
    """v2 moved hits to packages[].groups[] — the parser must follow."""
    monkeypatch.setattr(sca, "_tool_cmd", lambda t: "/usr/bin/osv-scanner")
    calls = []

    def run(cmd, cwd=None, timeout=180):
        calls.append(cmd)
        if "--output" in cmd:
            Path(cmd[cmd.index("--output") + 1]).write_text(
                json.dumps(OSV_V2_FIXTURE), encoding="utf-8"
            )
        return 0, "", ""

    monkeypatch.setattr(sca, "_run", run)
    res = sca.scan_osv(tmp_path)
    assert "-r" in calls[0], "osv must walk recursively or nested lockfiles are missed"
    assert "CVE-2021-23337" in res.cve_ids
    assert res.packages == ["lodash"]
    assert "CVE-2021-23337" in res.pkg_cves["lodash"]


def test_scan_osv_accepts_vulns_found_exit_code(tmp_path, monkeypatch):
    """osv exits 1 when it FINDS vulns — that is success with a report."""
    monkeypatch.setattr(sca, "_tool_cmd", lambda t: "/usr/bin/osv-scanner")

    def run(cmd, cwd=None, timeout=180):
        if "--output" in cmd:
            Path(cmd[cmd.index("--output") + 1]).write_text(
                json.dumps(OSV_V2_FIXTURE), encoding="utf-8"
            )
        return 1, "", ""  # 1 = vulnerabilities found, report written

    monkeypatch.setattr(sca, "_run", run)
    res = sca.scan_osv(tmp_path)
    assert "CVE-2021-23337" in res.cve_ids
