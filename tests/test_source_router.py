# API-level tests for the /api/source router. Ingest, SCA and AI services are
# faked so nothing clones from the network or shells out; the router itself,
# its validation, its response models and its error mapping are exercised for
# real through TestClient.
import json
from contextlib import asynccontextmanager

import pytest


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setenv("H4K_REFRESH_CVE", "0")
    import app_state
    import main as main_module

    class FakeMsf:
        @property
        def client(self):
            return self

        @property
        def core(self):
            class C:
                @property
                def version(self):
                    return {"version": "6.5.0", "ruby": "", "api": "1.0"}

            return C()

        def hosts(self, *a, **k):
            return []

        def services(self, *a, **k):
            return []

        def vulns(self, *a, **k):
            return []

    class CveDbStub:
        def refresh(self, *a, **k):
            return False

        def enrich(self, hosts, vulns):
            return {"services": {}, "vulns": {}}

    app_state.msf_client = FakeMsf()
    app_state.cve_db = CveDbStub()

    @asynccontextmanager
    async def _noop(_app):
        yield

    main_module.app.router.lifespan_context = _noop
    from fastapi.testclient import TestClient

    return TestClient(main_module.app)


@pytest.fixture()
def fake_ingest(tmp_path, monkeypatch):
    """Replace ingest with a version that 'clones' a real local source tree."""
    import services.ingest as ingest

    src = tmp_path / "src"
    src.mkdir(exist_ok=True)
    (src / "parser.c").write_text(
        "#include <string.h>\nvoid f(char *in){char b[8];strcpy(b,in);}\n",
        encoding="utf-8",
    )
    (src / "app.py").write_text(
        "import subprocess\ndef r(u):\n    subprocess.run('ls '+u, shell=True)\n",
        encoding="utf-8",
    )
    (src / "package-lock.json").write_text(
        json.dumps(
            {
                "name": "demo",
                "version": "1.0.0",
                "dependencies": {"lodash": {"version": "4.17.20"}},
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(ingest, "clone_git", lambda url, dest: None)
    monkeypatch.setattr(ingest, "find_source_root", lambda work: src)
    monkeypatch.setattr(ingest, "make_workdir", lambda: tmp_path / "work")
    return src


@pytest.fixture()
def fake_sca(monkeypatch, tmp_path):
    """Stub the SCA/SBOM layer with a deterministic CycloneDX document."""
    import services.sca as sca_service

    sbom = tmp_path / "sbom.cdx.json"
    sbom.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "components": [
                    {"bom-ref": "pkg:app", "name": "demo", "version": "1.0.0"},
                    {"bom-ref": "lodash", "name": "lodash", "version": "4.17.20"},
                ],
                "dependencies": [{"ref": "pkg:app", "dependsOn": ["lodash"]}],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(sca_service, "generate_sbom", lambda root: sbom)
    monkeypatch.setattr(
        sca_service,
        "sca_scan",
        lambda root, with_sbom=True: {
            "cves": ["CVE-2021-23337"],
            "vulnerabilities": [
                {"id": "GHSA-x", "cve": "CVE-2021-23337", "summary": "cmd inj"}
            ],
            "packages": ["lodash"],
            "pkg_cves": {"lodash": ["CVE-2021-23337"]},
            "sbom_available": True,
            "sbom_path": str(sbom),
            "sbom_dir": str(tmp_path),
            "secrets": [{"file": "app.py", "line": 3, "kind": "generic-secret"}],
            "licenses": [{"package": "lodash", "licenses": [{"Name": "MIT"}]}],
        },
    )
    return sbom


# --- SAST scan by git -------------------------------------------------------


def test_scan_requires_git_url(client):
    r = client.post("/api/source/scan", json={"name": "x"})
    assert r.status_code == 400
    assert "git_url" in r.json()["detail"]


def test_scan_reports_findings_with_sanitizer_plans(client, fake_ingest):
    r = client.post("/api/source/scan", json={"git_url": "https://x/y", "name": "demo"})
    assert r.status_code == 200
    d = r.json()
    assert d["files_scanned"] >= 1
    assert d["findings"]
    cwe = {f["cwe"] for f in d["findings"]}
    assert "CWE-120" in cwe  # strcpy hit
    # sanitizer-first: every finding carries a plan
    for f in d["findings"]:
        assert "sanitizer" in f
        assert "relevant" in f["sanitizer"]
    mem = next(f for f in d["findings"] if f["cwe"] == "CWE-120")
    assert mem["sanitizer"]["relevant"] is True
    assert "stack-buffer-overflow" in mem["sanitizer"]["expect"]


def test_scan_ingest_error_is_400(client, monkeypatch):
    import services.ingest as ingest

    def boom(url, dest):
        raise ingest.IngestError("clone failed")

    monkeypatch.setattr(ingest, "clone_git", boom)
    r = client.post("/api/source/scan", json={"git_url": "https://x/y"})
    assert r.status_code == 400
    assert "clone failed" in r.json()["detail"]


# --- upload -----------------------------------------------------------------


def test_scan_upload_rejects_non_archive(client):
    r = client.post(
        "/api/source/scan/upload",
        files={"file": ("evil.sh", b"rm -rf /", "text/plain")},
    )
    assert r.status_code == 400
    assert "zip" in r.json()["detail"]


def test_scan_upload_scans_archive(client, tmp_path, monkeypatch):
    import io
    import tarfile

    import services.ingest as ingest

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        data = b"int main(){return 0;}\n"
        info = tarfile.TarInfo("proj/a.c")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))

    monkeypatch.setattr(ingest, "extract_archive", lambda d, n, w: None)
    monkeypatch.setattr(ingest, "find_source_root", lambda w: tmp_path)
    r = client.post(
        "/api/source/scan/upload",
        files={"file": ("proj.tar.gz", buf.getvalue(), "application/gzip")},
    )
    assert r.status_code == 200
    assert r.json()["name"]


# --- PoC / exploit ----------------------------------------------------------


def test_exploit_returns_text(client):
    r = client.post(
        "/api/source/exploit",
        json={
            "rule_id": "sast-buffer-copy",
            "finding": {
                "rule_id": "sast-buffer-copy",
                "name": "Unchecked buffer copy",
                "severity": "high",
                "cwe": "CWE-120",
                "file": "a.c",
                "line": 5,
                "code": "strcpy(b, in);",
                "description": "overflow",
            },
        },
    )
    assert r.status_code == 200
    assert "strcpy" in r.text


def test_exploit_download_sets_attachment(client):
    r = client.post(
        "/api/source/exploit/download",
        json={
            "rule_id": "sast-buffer-copy",
            "finding": {
                "rule_id": "sast-buffer-copy",
                "name": "Unchecked buffer copy",
                "severity": "high",
                "cwe": "CWE-120",
                "file": "a.c",
                "line": 5,
            },
        },
    )
    assert r.status_code == 200, r.text
    assert "attachment" in r.headers["content-disposition"]
    assert "h4k-poc-sast-buffer-copy" in r.headers["content-disposition"]


def test_exploit_unknown_rule_still_answers(client):
    r = client.post("/api/source/exploit", json={"rule_id": "nope-unknown"})
    assert r.status_code == 200
    assert r.text


# --- SCA --------------------------------------------------------------------


def test_sca_requires_git_url(client):
    r = client.post("/api/source/sca", json={"name": "x"})
    assert r.status_code == 400


def test_sca_returns_cves_and_extras(client, fake_ingest, fake_sca):
    r = client.post("/api/source/sca", json={"git_url": "https://x/y"})
    assert r.status_code == 200
    d = r.json()
    assert d["cves"] == ["CVE-2021-23337"]
    assert d["sbom_available"] is True
    # schema must tolerate the extra scanner dicts
    assert d["secrets"][0]["kind"] == "generic-secret"
    assert d["licenses"][0]["package"] == "lodash"


def test_sca_by_git_url_get(client, fake_ingest, fake_sca):
    r = client.get("/api/source/sca/git", params={"git_url": "https://x/y"})
    assert r.status_code == 200
    assert r.json()["packages"] == ["lodash"]


def test_sbom_download(client, fake_ingest, fake_sca):
    r = client.get("/api/source/sca/sbom", params={"git_url": "https://x/y"})
    assert r.status_code == 200
    assert "attachment" in r.headers["content-disposition"]
    assert r.json()["bomFormat"] == "CycloneDX"


def test_sbom_download_failure_is_400(client, fake_ingest, monkeypatch):
    import services.sca as sca_service

    monkeypatch.setattr(sca_service, "generate_sbom", lambda root: None)
    r = client.get("/api/source/sca/sbom", params={"git_url": "https://x/y"})
    assert r.status_code == 400
    assert "SBOM" in r.json()["detail"]


def test_supply_chain_map_marks_reachable_vulns(client, fake_ingest, fake_sca):
    r = client.get("/api/source/sca/map", params={"git_url": "https://x/y"})
    assert r.status_code == 200
    d = r.json()
    assert d["summary"]["components"] == 2
    assert d["summary"]["vulnerable_reachable"] == 1
    node = next(n for n in d["graph"]["nodes"] if n["label"].startswith("lodash"))
    assert node["reachable"] is True
    assert node["reachable_cves"] == ["CVE-2021-23337"]


def test_supply_chain_map_without_sbom(client, fake_ingest, monkeypatch):
    import services.sca as sca_service

    monkeypatch.setattr(
        sca_service,
        "sca_scan",
        lambda root, with_sbom=True: {"sbom_path": None, "pkg_cves": {}},
    )
    r = client.get("/api/source/sca/map", params={"git_url": "https://x/y"})
    assert r.status_code == 200
    assert "no SBOM" in r.json()["error"]


# --- triage / minimize ------------------------------------------------------


def test_triage_returns_plan(client):
    r = client.post("/api/source/triage", json={"candidate": "AAAA" * 10})
    assert r.status_code == 200
    d = r.json()
    assert d["bug_class"]
    assert d["cwe"].startswith("CWE-")
    assert isinstance(d["steps"], list) and d["steps"]


def test_triage_minimize(client):
    r = client.post("/api/source/triage/minimize", json={"candidate": "A" * 50})
    assert r.status_code == 200
    assert "minimized" in r.json()


# --- AI ---------------------------------------------------------------------


def test_ai_endpoint_returns_result(client, monkeypatch):
    import services.ai as ai_service

    monkeypatch.setattr(
        ai_service,
        "ai_analyze",
        lambda text, model_override=None: {"ok": True, "raw": "root cause: overflow"},
    )
    r = client.post("/api/source/ai", json={"text": "crash log"})
    assert r.status_code == 200
    assert r.json()["ok"] is True


def test_ai_loop_endpoint(client, monkeypatch):
    import services.ai_loop as ai_loop

    monkeypatch.setattr(
        ai_loop,
        "ai_full_loop",
        lambda text, model_override=None: {
            "ok": True,
            "root_cause": "unbounded copy",
        },
    )
    r = client.post("/api/source/ai/loop", json={"text": "crash"})
    assert r.status_code == 200
    assert r.json()["ok"] is True


def test_ai_models_lists_provider(client):
    r = client.get("/api/source/ai/models")
    assert r.status_code == 200
    assert "provider" in r.json()


# --- custom rules -----------------------------------------------------------


def test_rules_crud_roundtrip(client, monkeypatch, tmp_path):
    import services.rules as rules_service

    monkeypatch.setattr(rules_service, "RULES_FILE", tmp_path / "rules.json")
    save = client.post(
        "/api/source/rules/save",
        json={
            "rule_id": "my-rule",
            "name": "My rule",
            "pattern": "eval\\(",
            "severity": "high",
            "message": "eval!",
        },
    )
    assert save.status_code == 200
    listed = client.get("/api/source/rules")
    assert any(r["rule_id"] == "my-rule" for r in listed.json()["rules"])
    deleted = client.delete("/api/source/rules/my-rule")
    assert deleted.status_code == 200
    assert not any(
        r["rule_id"] == "my-rule"
        for r in client.get("/api/source/rules").json()["rules"]
    )


def test_rules_test_validates_pattern(client):
    r = client.post(
        "/api/source/rules/test",
        json={
            "rule_id": "t",
            "name": "t",
            "pattern": "eval\\(",
            "severity": "high",
            "message": "m",
            "code": "eval(x)",
        },
    )
    assert r.status_code == 200
    assert "matched" in r.json()


# --- merged report ----------------------------------------------------------


def test_report_merge_combines_sections(client):
    r = client.post(
        "/api/source/report/merge",
        json={
            "scan": [{"address": "10.0.0.1", "os": "Linux", "services": []}],
            "sast": [
                {
                    "rule_id": "r",
                    "name": "buffer copy",
                    "severity": "high",
                    "cwe": "CWE-120",
                    "file": "a.c",
                    "line": 5,
                }
            ],
            "sca": {"cves": ["CVE-2021-23337"], "packages": ["lodash"]},
        },
    )
    assert r.status_code == 200
    d = r.json()
    assert "scan" in d and "sast" in d
    assert d["summary"]["sast_findings"] == 1


def test_report_md_returns_markdown(client):
    r = client.post(
        "/api/source/report/md",
        json={"scan": [{"address": "10.0.0.1", "os": "Linux", "services": []}]},
    )
    assert r.status_code == 200
    assert "10.0.0.1" in r.text
    assert "#" in r.text
