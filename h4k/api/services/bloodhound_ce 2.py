# BloodHound CE wrapper (#92).
#
# Collection and graph analysis are two halves of the same job. bloodhound-python
# produces a zip of JSON; BloodHound CE ingests that zip, runs its own analysis,
# and exposes Cypher over REST. This client covers the whole loop — login,
# upload, analysis polling, Cypher, and the handful of questions an operator
# actually asks ("who can reach Domain Admins?", "shortest path from this user")
# — with no browser and no Neo4j driver.
#
# Every network call is bounded and errors are translated into BloodHoundError;
# a missing CE instance must never take the rest of the console down.
import json
import logging
import os
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

logger = logging.getLogger("h4k.bloodhound")

DEFAULT_TIMEOUT = 20.0

QUERIES = {
    "domain_admins": (
        "MATCH p=(u:User)-[:MemberOf*1..]->(g:Group) "
        "WHERE g.objectid ENDS WITH '-512' RETURN p LIMIT 100"
    ),
    "kerberoastable": (
        "MATCH (u:User) WHERE u.hasspn = true AND u.enabled = true "
        "RETURN u.name, u.serviceprincipalnames ORDER BY u.name LIMIT 200"
    ),
    "asrep_roastable": (
        "MATCH (u:User) WHERE u.dontreqpreauth = true AND u.enabled = true "
        "RETURN u.name LIMIT 200"
    ),
    "unconstrained_delegation": (
        "MATCH (c) WHERE c.unconstraineddelegation = true "
        "RETURN c.name, labels(c) LIMIT 200"
    ),
    "high_value_hosts": (
        "MATCH (c:Computer) WHERE c.systemtags CONTAINS 'admin_tier_0' "
        "RETURN c.name LIMIT 200"
    ),
    "sessions_to_domain_admins": (
        "MATCH (u:User)-[:MemberOf*1..]->(g:Group) "
        "WHERE g.objectid ENDS WITH '-512' "
        "MATCH (c:Computer)-[:HasSession]->(u) RETURN c.name, u.name LIMIT 200"
    ),
}


class BloodHoundError(Exception):
    def __init__(self, message: str, *, status_code: int = 502) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code


class BloodHoundClient:
    """Small REST client for BloodHound Community Edition's v2 API."""

    def __init__(
        self,
        base_url: str = "",
        username: str = "",
        password: str = "",  # nosec B107 - empty default; env/request supplies it
        token: str = "",  # nosec B105 - empty placeholder, not a credential
        *,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self.base_url = (
            base_url or os.environ.get("H4K_BLOODHOUND_URL", "http://127.0.0.1:8080")
        ).rstrip("/")
        self.username = username or os.environ.get("H4K_BLOODHOUND_USER", "")
        self.password = password or os.environ.get("H4K_BLOODHOUND_PASS", "")
        self.token = token or os.environ.get("H4K_BLOODHOUND_TOKEN", "")
        self.timeout = timeout

    # -- transport ----------------------------------------------------------
    def _request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        *,
        raw: bytes | None = None,
        content_type: str = "application/json",
        timeout: float | None = None,
    ) -> dict[str, Any]:
        url = f"{self.base_url}{path}"
        data = raw
        headers = {"Accept": "application/json"}
        if payload is not None:
            data = json.dumps(payload).encode()
        if data is not None:
            headers["Content-Type"] = content_type
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(  # nosec B310 - configured CE endpoint
                req, timeout=timeout or self.timeout
            ) as resp:
                body = resp.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:500]
            raise BloodHoundError(
                f"BloodHound {method} {path} failed ({exc.code}): {detail}",
                status_code=502,
            ) from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            raise BloodHoundError(
                f"BloodHound unreachable at {self.base_url}: {exc}"
            ) from exc
        if not body:
            return {}
        try:
            parsed = json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return {"raw": body[:2000].decode("utf-8", errors="replace")}
        return parsed if isinstance(parsed, dict) else {"data": parsed}

    def _data(self, response: dict[str, Any]) -> Any:
        if isinstance(response, dict) and "data" in response:
            return response["data"]
        return response

    # -- auth ---------------------------------------------------------------
    def login(self) -> dict[str, Any]:
        if not self.username or not self.password:
            raise BloodHoundError(
                "BloodHound credentials are not configured "
                "(set H4K_BLOODHOUND_USER/H4K_BLOODHOUND_PASS or pass them)",
                status_code=400,
            )
        response = self._request(
            "POST",
            "/api/v2/login",
            {
                "login_method": "secret",
                "username": self.username,
                "secret": self.password,
            },
        )
        data = self._data(response)
        token = ""  # nosec B105 - populated from the login response
        if isinstance(data, dict):
            token = str(
                data.get("session_token")
                or data.get("token")
                or data.get("accessToken")
                or ""
            )
        if not token:
            raise BloodHoundError("BloodHound login returned no session token")
        self.token = token
        return {"ok": True, "token": f"{token[:8]}…", "base_url": self.base_url}

    def ensure_token(self) -> None:
        if not self.token:
            self.login()

    def self(self) -> dict[str, Any]:
        self.ensure_token()
        return {"ok": True, **self._data(self._request("GET", "/api/v2/self"))}

    def status(self) -> dict[str, Any]:
        try:
            me = self.self()
            return {
                "reachable": True,
                "base_url": self.base_url,
                "identity": me,
            }
        except BloodHoundError as exc:
            return {
                "reachable": False,
                "base_url": self.base_url,
                "error": exc.message,
            }

    # -- collection + upload ------------------------------------------------
    def collect(
        self,
        domain: str,
        username: str,
        password: str,
        *,
        dc_ip: str = "",
        method: str = "All",
        out_dir: str = "",
    ) -> dict[str, Any]:
        """Run bloodhound-python and return the zip path (never uploads)."""
        from services.ad_tools import ADToolsService

        target_dir = out_dir or tempfile.mkdtemp(prefix="h4k-bh-")
        Path(target_dir).mkdir(parents=True, exist_ok=True)
        result = ADToolsService().bloodhound_collect(
            domain,
            username,
            password,
            dc_ip=dc_ip or None,
            collection_method=method,
            output_dir=target_dir,
            zip_output=True,
        )
        zips = sorted(Path(target_dir).glob("*.zip"))
        return {
            "ok": bool(zips) and result.get("success", False),
            "zip": str(zips[-1]) if zips else "",
            "output_dir": target_dir,
            "stdout": (result.get("stdout") or "")[-4000:],
            "stderr": (result.get("stderr") or "")[-2000:],
            "rc": result.get("rc"),
        }

    def upload_zip(self, path: str | Path) -> dict[str, Any]:
        self.ensure_token()
        file_path = Path(path)
        if not file_path.is_file():
            raise BloodHoundError(
                f"upload file not found: {file_path}", status_code=400
            )
        started = self._data(self._request("POST", "/api/v2/file-upload/start"))
        job_id = str(started.get("id") or "") if isinstance(started, dict) else ""
        if not job_id:
            raise BloodHoundError("BloodHound did not return an upload job id")
        self._request(
            "POST",
            f"/api/v2/file-upload/{job_id}",
            raw=file_path.read_bytes(),
            content_type="application/zip",
            timeout=max(self.timeout, 120),
        )
        self._request("POST", f"/api/v2/file-upload/{job_id}/end")
        return {
            "ok": True,
            "job_id": job_id,
            "file": file_path.name,
            "bytes": file_path.stat().st_size,
        }

    def start_analysis(self) -> dict[str, Any]:
        self.ensure_token()
        # BloodHound CE v9 uses PUT for the analysis request and returns 202.
        data = self._data(self._request("PUT", "/api/v2/analysis", {}))
        return {"ok": True, "job": data}

    def analysis_status(self) -> dict[str, Any]:
        self.ensure_token()
        data = self._data(self._request("GET", "/api/v2/analysis/status"))
        status = ""
        if isinstance(data, dict):
            # CE clears request_type when the request has been consumed. There is
            # no separate status enum; "running while queued, idle when done" is
            # the observable contract.
            request_type = str(data.get("request_type") or "")
            status = str(data.get("status") or data.get("state") or "") or (
                "running" if request_type else "idle"
            )
        return {"ok": True, "status": status, "data": data}

    def wait_for_analysis(self, *, timeout: float = 120, interval: float = 3) -> dict:
        deadline = time.monotonic() + max(5, timeout)
        last: dict[str, Any] = {}
        while time.monotonic() < deadline:
            last = self.analysis_status()
            status = str(last.get("status", "")).lower()
            if status in {"complete", "completed", "idle", "finished"}:
                return {**last, "ok": True}
            if status in {"failed", "error", "cancelled"}:
                return {**last, "ok": False}
            time.sleep(max(0.2, interval))
        return {**last, "ok": False, "error": "analysis timed out"}

    # -- graph queries ------------------------------------------------------
    def cypher(self, query: str, *, include_properties: bool = False) -> dict[str, Any]:
        self.ensure_token()
        payload = {"query": query, "include_properties": include_properties}
        try:
            data = self._data(self._request("POST", "/api/v2/graphs/cypher", payload))
        except BloodHoundError as exc:
            # CE returns 404 "resource not found" when a label/property does not
            # exist yet (e.g. an empty graph). That is an empty result, not a
            # transport failure.
            if "404" in exc.message and "resource not found" in exc.message.lower():
                return {
                    "ok": True,
                    "query": query,
                    "result": {"nodes": {}, "edges": [], "literals": []},
                    "empty": True,
                }
            raise
        return {"ok": True, "query": query, "result": data}

    def named_query(self, name: str) -> dict[str, Any]:
        query = QUERIES.get(name)
        if query is None:
            raise BloodHoundError(
                f"unknown query: {name} (choices: {', '.join(sorted(QUERIES))})",
                status_code=400,
            )
        return self.cypher(query)

    def shortest_path(self, source: str, target: str) -> dict[str, Any]:
        def _literal(value: str) -> str:
            # Cypher string literal: escape backslash and single quote.
            return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"

        query = (
            f"MATCH p=shortestPath((a {{name: {_literal(source)}}})"
            f"-[*1..]->(b {{name: {_literal(target)}}})) RETURN p LIMIT 5"
        )
        return self.cypher(query)

    def upload_and_analyze(self, path: str | Path) -> dict[str, Any]:
        uploaded = self.upload_zip(path)
        analysis = self.start_analysis()
        return {**uploaded, "analysis": analysis}

    def collect_upload_analyze(
        self,
        domain: str,
        username: str,
        password: str,
        *,
        dc_ip: str = "",
        method: str = "All",
    ) -> dict[str, Any]:
        collected = self.collect(domain, username, password, dc_ip=dc_ip, method=method)
        if not collected.get("ok"):
            return {"ok": False, "collect": collected}
        uploaded = self.upload_zip(collected["zip"])
        analysis = self.start_analysis()
        return {
            "ok": True,
            "collect": collected,
            "upload": uploaded,
            "analysis": analysis,
        }


def client_from_env() -> BloodHoundClient:
    return BloodHoundClient()


def query_url(base_url: str, query: str) -> str:
    """Build a deep-link into the BloodHound CE UI for a saved query."""
    return f"{base_url.rstrip('/')}/ui/explore?search={urllib.parse.quote(query)}"
