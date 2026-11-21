# BloodHound CE wrapper (#92). The REST transport is faked; collection is faked
# by replacing ADToolsService so no bloodhound-python install is required.
from contextlib import asynccontextmanager
from pathlib import Path

import main as main_module
import pytest
from fastapi.testclient import TestClient
from services import bloodhound_ce
from services.bloodhound_ce import BloodHoundClient, BloodHoundError


class FakeClient(BloodHoundClient):
    def __init__(self, responses=None, status_sequence=None):
        super().__init__(base_url="http://bh.test", username="u", password="p")
        self.responses = responses or {}
        self.calls: list[tuple] = []
        self.status_sequence = list(status_sequence or [])
        self.token = "tok"

    def _request(self, method, path, payload=None, **kwargs):
        self.calls.append((method, path, payload, kwargs))
        key = f"{method} {path}"
        if key in self.responses:
            value = self.responses[key]
            if isinstance(value, Exception):
                raise value
            return value
        if path == "/api/v2/analysis/status" and method == "GET":
            if self.status_sequence:
                value = self.status_sequence.pop(0)
                if value == "failed":
                    return {"data": {"request_type": "analysis", "status": "failed"}}
                if value in {"complete", "completed", "idle"}:
                    return {"data": {"request_type": ""}}
                return {"data": {"request_type": "analysis"}}
            return {"data": {"request_type": "analysis"}}
        return {}


@pytest.fixture()
def client(monkeypatch):
    import app_state

    class _CveStub:
        cves: tuple = ()
        path = "stub.json"

        def refresh(self) -> bool:
            return False

    app_state.msf_client = None
    app_state.cve_db = _CveStub()  # type: ignore[assignment]
    app_state.active_engagement_id = None

    @asynccontextmanager
    async def _noop(_app):
        yield

    main_module.app.router.lifespan_context = _noop
    main_module.reset_auth_cache()
    monkeypatch.delenv("H4K_AUTH_ENABLED", raising=False)
    main_module.reset_auth_cache()
    import routers.bloodhound as bh_router

    bh_router.reset_client()
    yield TestClient(main_module.app)
    bh_router.reset_client()
    main_module.reset_auth_cache()


def test_login_stores_token_and_status_reports_identity():
    fake = FakeClient(
        {
            "POST /api/v2/login": {"data": {"session_token": "tok-123456789"}},
            "GET /api/v2/self": {
                "data": {"Principal": "u", "Roles": ["Administrator"]}
            },
        }
    )
    login = fake.login()
    assert login["ok"] is True
    assert fake.token == "tok-123456789"
    assert login["token"].endswith("…")
    status = fake.status()
    assert status["reachable"] is True
    assert status["identity"]["Principal"] == "u"


def test_login_requires_credentials_and_token():
    fake = FakeClient()
    fake.username = fake.password = ""
    with pytest.raises(BloodHoundError):
        fake.login()
    fake = FakeClient({"POST /api/v2/login": {"data": {}}})
    with pytest.raises(BloodHoundError):
        fake.login()


def test_status_is_graceful_when_unreachable():
    fake = FakeClient({"GET /api/v2/self": BloodHoundError("down")})
    fake.token = "tok"
    status = fake.status()
    assert status["reachable"] is False
    assert "down" in status["error"]


def test_upload_zip_three_step_protocol(tmp_path):
    archive = tmp_path / "bh.zip"
    archive.write_bytes(b"PK\x03\x04demo")
    fake = FakeClient({"POST /api/v2/file-upload/start": {"data": {"id": "job1"}}})
    result = fake.upload_zip(archive)
    assert result == {"ok": True, "job_id": "job1", "file": "bh.zip", "bytes": 8}
    paths = [c[1] for c in fake.calls]
    assert paths == [
        "/api/v2/file-upload/start",
        "/api/v2/file-upload/job1",
        "/api/v2/file-upload/job1/end",
    ]
    upload_call = fake.calls[1]
    assert upload_call[3]["raw"] == b"PK\x03\x04demo"
    assert upload_call[3]["content_type"] == "application/zip"


def test_upload_missing_file_and_missing_job(tmp_path):
    fake = FakeClient()
    with pytest.raises(BloodHoundError):
        fake.upload_zip(tmp_path / "nope.zip")
    archive = tmp_path / "bh.zip"
    archive.write_bytes(b"x")
    with pytest.raises(BloodHoundError, match="upload job id"):
        fake.upload_zip(archive)


def test_analysis_polling_reaches_complete():
    fake = FakeClient(status_sequence=["running", "running", "complete"])
    fake.token = "tok"
    result = fake.wait_for_analysis(timeout=5, interval=0.01)
    assert result["ok"] is True
    assert result["status"] == "idle"


def test_analysis_polling_reports_failure_and_timeout(monkeypatch):
    fake = FakeClient(status_sequence=["failed"])
    fake.token = "tok"
    assert fake.wait_for_analysis(timeout=5, interval=0.01)["ok"] is False

    fake = FakeClient()
    fake.token = "tok"
    assert fake.wait_for_analysis(timeout=0.1, interval=0.05)["ok"] is False


def test_cypher_query_and_shortest_path_escaping():
    fake = FakeClient({"POST /api/v2/graphs/cypher": {"data": {"nodes": []}}})
    fake.token = "tok"
    result = fake.cypher("MATCH (n) RETURN n")
    assert result["result"] == {"nodes": []}
    payload = fake.calls[-1][2]
    assert payload == {"query": "MATCH (n) RETURN n", "include_properties": False}

    fake.shortest_path("DOMAIN USERS@LAB.LOCAL", "ADMIN@LAB.LOCAL'")
    query = fake.calls[-1][2]["query"]
    assert "shortestPath" in query
    assert "ADMIN@LAB.LOCAL\\'" in query

    named = fake.named_query("kerberoastable")
    assert "hasspn" in named["query"]
    with pytest.raises(BloodHoundError):
        fake.named_query("nope")


def test_collect_uses_bloodhound_python(monkeypatch, tmp_path):
    out_dir = tmp_path / "out"

    def _fake_collect(self, domain, username, password, **kwargs):
        Path(kwargs["output_dir"]).mkdir(parents=True, exist_ok=True)
        (Path(kwargs["output_dir"]) / "lab.zip").write_bytes(b"PK")
        return {"success": True, "stdout": "done", "stderr": "", "rc": 0}

    monkeypatch.setattr(
        "services.ad_tools.ADToolsService.bloodhound_collect", _fake_collect
    )
    client = BloodHoundClient(base_url="http://bh.test")
    result = client.collect("LAB.LOCAL", "u", "p", out_dir=str(out_dir))
    assert result["ok"] is True
    assert result["zip"].endswith("lab.zip")


def test_collect_upload_analyze_short_circuits_on_failure(monkeypatch, tmp_path):
    client = BloodHoundClient(base_url="http://bh.test")
    monkeypatch.setattr(
        client, "collect", lambda *a, **k: {"ok": False, "error": "collect failed"}
    )
    result = client.collect_upload_analyze("LAB.LOCAL", "u", "p")
    assert result["ok"] is False
    assert result["collect"]["error"] == "collect failed"


def test_collect_upload_analyze_full_loop(monkeypatch, tmp_path):
    archive = tmp_path / "lab.zip"
    archive.write_bytes(b"PK")
    fake = FakeClient(
        {
            "POST /api/v2/file-upload/start": {"data": {"id": "j1"}},
            "PUT /api/v2/analysis": {"data": {"id": "a1"}},
        }
    )
    monkeypatch.setattr(
        fake, "collect", lambda *a, **k: {"ok": True, "zip": str(archive)}
    )
    result = fake.collect_upload_analyze("LAB.LOCAL", "u", "p")
    assert result["ok"] is True
    assert result["upload"]["job_id"] == "j1"
    assert result["analysis"]["job"] == {"id": "a1"}


def test_queries_and_deeplink_helpers():
    assert "Domain Admins" not in bloodhound_ce.QUERIES["kerberoastable"]
    assert "hasspn" in bloodhound_ce.QUERIES["kerberoastable"]
    assert "search=MATCH" in bloodhound_ce.query_url("http://bh/", "MATCH (n)")


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------
def test_api_status_and_queries(client, monkeypatch):
    fake = FakeClient({"GET /api/v2/self": {"data": {"Principal": "u"}}})
    fake.token = "tok"
    import routers.bloodhound as bh_router

    monkeypatch.setattr(bh_router, "get_client", lambda body=None: fake)
    status = client.get("/api/bloodhound/status")
    assert status.status_code == 200
    assert status.json()["reachable"] is True
    queries = client.get("/api/bloodhound/queries").json()["queries"]
    assert "kerberoastable" in queries
    assert "cypher" in queries["kerberoastable"]


def test_api_login_query_and_validation(client, monkeypatch):
    fake = FakeClient(
        {
            "POST /api/v2/login": {"data": {"session_token": "tok"}},
            "POST /api/v2/graphs/cypher": {"data": {"nodes": []}},
        }
    )
    import routers.bloodhound as bh_router

    monkeypatch.setattr(bh_router, "get_client", lambda body=None: fake)
    login = client.post("/api/bloodhound/login", json={})
    assert login.status_code == 200
    assert login.json()["ok"] is True
    assert client.post("/api/bloodhound/query", json={}).status_code == 400
    query = client.post("/api/bloodhound/query", json={"query": "MATCH (n) RETURN n"})
    assert query.status_code == 200
    assert query.json()["ok"] is True
    assert (
        client.post("/api/bloodhound/query", json={"name": "nope"}).status_code == 400
    )
    assert (
        client.post("/api/bloodhound/shortest-path", json={"from": "a"}).status_code
        == 400
    )
    path = client.post("/api/bloodhound/shortest-path", json={"from": "a", "to": "b"})
    assert path.status_code == 200


def test_api_collect_validates_credentials(client, monkeypatch):
    import routers.bloodhound as bh_router

    fake = FakeClient()
    fake.username = fake.password = ""
    monkeypatch.setattr(bh_router, "get_client", lambda body=None: fake)
    r = client.post("/api/bloodhound/collect", json={"domain": "LAB.LOCAL"})
    assert r.status_code == 400


def test_api_maps_client_errors(client, monkeypatch):
    import routers.bloodhound as bh_router

    class _Broken(FakeClient):
        def login(self):
            raise BloodHoundError("nope", status_code=502)

    monkeypatch.setattr(bh_router, "get_client", lambda body=None: _Broken())
    r = client.post("/api/bloodhound/login", json={})
    assert r.status_code == 502
    assert "nope" in r.json()["detail"]


def test_default_transport_parses_json_and_errors(monkeypatch):
    class _Resp:
        def __init__(self, body):
            self.body = body

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self):
            return self.body

    client = BloodHoundClient(base_url="http://bh.test", token="tok")
    monkeypatch.setattr(
        bloodhound_ce.urllib.request,
        "urlopen",
        lambda req, timeout=0: _Resp(b'{"data": {"Principal": "u"}}'),
    )
    assert client.self()["Principal"] == "u"
    monkeypatch.setattr(
        bloodhound_ce.urllib.request,
        "urlopen",
        lambda req, timeout=0: _Resp(b""),
    )
    assert client._request("DELETE", "/x") == {}

    monkeypatch.setattr(
        bloodhound_ce.urllib.request,
        "urlopen",
        lambda req, timeout=0: _Resp(b"not json"),
    )
    assert "raw" in client._request("GET", "/x")

    monkeypatch.setattr(
        bloodhound_ce.urllib.request,
        "urlopen",
        lambda req, timeout=0: _Resp(b"[1, 2]"),
    )
    assert client._request("GET", "/x") == {"data": [1, 2]}


def test_default_transport_http_and_url_errors(monkeypatch):
    import urllib.error

    def _http(req, timeout=0):
        raise urllib.error.HTTPError(req.full_url, 401, "denied", {}, None)

    monkeypatch.setattr(bloodhound_ce.urllib.request, "urlopen", _http)
    client = BloodHoundClient(base_url="http://bh.test", token="tok")
    with pytest.raises(BloodHoundError) as exc:
        client.self()
    assert exc.value.status_code == 502

    def _down(req, timeout=0):
        raise urllib.error.URLError("down")

    monkeypatch.setattr(bloodhound_ce.urllib.request, "urlopen", _down)
    with pytest.raises(BloodHoundError, match="unreachable"):
        client.self()


def test_self_logs_in_when_no_token(monkeypatch):
    client = BloodHoundClient(base_url="http://bh.test", username="u", password="p")

    def _login():
        client.token = "t"
        return {"ok": True}

    monkeypatch.setattr(client, "login", _login)
    monkeypatch.setattr(
        client, "_request", lambda *a, **k: {"data": {"Principal": "u"}}
    )
    assert client.self()["Principal"] == "u"


def test_api_collect_requires_engagement(client, monkeypatch):
    import routers.bloodhound as bh_router
    import routers.scan as scan

    fake = FakeClient()
    fake.username = "u"
    fake.password = "p"
    monkeypatch.setattr(bh_router, "get_client", lambda body=None: fake)
    monkeypatch.setattr(scan, "_active_scope", lambda: (None, None))
    r = client.post(
        "/api/bloodhound/collect",
        json={"domain": "LAB.LOCAL", "username": "u", "password": "p"},
    )
    assert r.status_code == 403
    assert "engagement" in r.json()["detail"]


def test_login_uses_secret_method_and_analysis_contract():
    fake = FakeClient({"POST /api/v2/login": {"data": {"session_token": "tok"}}})
    fake.login()
    payload = fake.calls[0][2]
    assert payload["login_method"] == "secret"
    assert payload["username"] == "u"
    assert "secret" in payload
