# Tests for the opt-in attack service and module mapping.
from schemas import AttackRequest
from services.attack import AttackService


def test_module_for_service_mapping():
    assert AttackService._module_for_service("ssh") == "exploit/multi/ssh/sshexec"
    assert (
        AttackService._module_for_service("microsoft-ds")
        == "exploit/windows/smb/ms17_010_eternalblue"
    )
    assert (
        AttackService._module_for_service("rdp")
        == "exploit/windows/rdp/cve_2019_0708_bluekeep_rce"
    )
    assert (
        AttackService._module_for_service("ftp")
        == "exploit/unix/ftp/vsftpd_234_backdoor"
    )
    assert AttackService._module_for_service("weird") is None


class _RecordingMsf:
    """Records what was executed so we can assert on the module/port chosen.

    Behaves like a real backend: execute() launches a job, and a session
    appears in sessions() only afterwards — never the job id itself.
    """

    def __init__(self):
        self.calls = []
        self._sessions: dict = {}

    def execute(self, mtype, mname, opts):
        self.calls.append((mtype, mname, opts))
        self._sessions = {"7": {"target_host": "10.0.0.5"}}
        return {"job_id": 7}

    def sessions(self):
        return dict(self._sessions)

    @property
    def client(self):
        class _Mod:
            options = ("RHOSTS", "RPORT", "USERNAME", "PASSWORD", "LHOST", "LPORT")

        class _Modules:
            def use(self, mtype, mname):
                return _Mod()

        return type("C", (), {"modules": _Modules()})()


def test_pinned_module_from_finding_is_used():
    # the triage drawer names the module; the heuristic must not override it
    msf = _RecordingMsf()
    svc = AttackService(msf)
    req = AttackRequest(
        target="10.0.0.5",
        host="10.0.0.5",
        module="exploit/multi/http/struts_code_exec",
        port=8080,
    )
    attacks = svc.run(req, [])
    assert [a["module"] for a in attacks] == ["exploit/multi/http/struts_code_exec"]
    assert msf.calls[0][1] == "exploit/multi/http/struts_code_exec"
    # the operator's port beats the service-name guess
    assert msf.calls[0][2]["RPORT"] == 8080
    assert attacks[0]["result"] == "success"


def test_pinned_module_runs_once_without_services():
    # no services and no msf db lookup: the named module is the whole job
    svc = AttackService(_RecordingMsf())
    req = AttackRequest(
        target="10.0.0.5", host="10.0.0.5", module="exploit/multi/handler"
    )
    assert svc._resolve_services(req, "10.0.0.5") == [""]


def test_module_must_look_like_a_module_path():
    svc = AttackService(_RecordingMsf())
    req = AttackRequest(target="10.0.0.5", host="10.0.0.5", module="rm -rf /")
    try:
        svc.run(req, [])
    except ValueError as exc:
        assert "refusing to run" in str(exc)
    else:  # pragma: no cover - the guard must fire
        raise AssertionError("a non-module string was accepted")


def test_heuristic_module_still_used_when_none_pinned():
    msf = _RecordingMsf()
    svc = AttackService(msf)
    req = AttackRequest(
        target="10.0.0.5",
        host="10.0.0.5",
        services=["ssh"],
        open_sessions=True,
    )
    attacks = svc.run(
        req,
        [
            {
                "host": "10.0.0.5",
                "service": "ssh",
                "user": "root",
                "password": "toor",
                "verified": True,
            }
        ],
    )
    assert attacks[0]["module"] == "exploit/multi/ssh/sshexec"
    assert msf.calls[0][2]["RPORT"] == 22


class _FakeMsf:
    def __init__(self):
        self._sessions: dict = {}

    def execute(self, mtype, mname, opts):
        self._sessions = {"5": {"target_host": "10.0.0.5"}}
        return {"job_id": 5}

    def sessions(self):
        return dict(self._sessions)

    @property
    def client(self):
        class _Mod:
            options = ("RHOSTS", "RPORT", "USERNAME", "PASSWORD", "LHOST", "LPORT")

        class _Modules:
            def use(self, mtype, mname):
                return _Mod()

        return type("C", (), {"modules": _Modules()})()


def test_try_exploit_success_with_cred():
    svc = AttackService(_FakeMsf())
    cred = {"user": "root", "password": "toor"}
    res = svc._try_exploit(
        "exploit/multi/ssh/sshexec", "10.0.0.5", "ssh", True, cred=cred
    )
    assert res["ok"] is True
    # a real session id, not the launch job id
    assert res["session_id"] == "5"


def test_try_exploit_job_id_is_never_reported_as_session():
    """Regression: {"job_id": N} means launched, not shelled. With no new
    session appearing, the result must say so instead of reporting success."""

    class _NoSessionMsf:
        def execute(self, mtype, mname, opts):
            return {"job_id": 9}

        def sessions(self):
            return {}

    svc = AttackService(_NoSessionMsf())
    res = svc._try_exploit(
        "exploit/unix/webapp/zoneminder_lang_exec",
        "192.168.1.84",
        "http",
        False,
        extra_opts={"USERNAME": "admin", "PASSWORD": "admin"},
        session_timeout=0,
    )
    assert res["ok"] is False
    assert res["session_id"] is None
    assert "no session" in res["detail"]


def test_framework_opts_pass_through_even_when_undeclared():
    """PAYLOAD/LHOST/LPORT are framework datastore keys: the operator must be
    able to set a bind payload and a routable LHOST from a container, even
    though module-option discovery never lists them. Unknown keys still drop."""

    class _StrictMsf:
        def __init__(self):
            self.seen: dict = {}
            self._sessions: dict = {}

        def execute(self, mtype, mname, opts):
            self.seen = dict(opts)
            self._sessions = {"3": {}}
            return {"job_id": 3}

        def sessions(self):
            return dict(self._sessions)

    msf = _StrictMsf()
    svc = AttackService(msf)
    res = svc._try_exploit(
        "exploit/unix/webapp/zoneminder_lang_exec",
        "192.168.1.84",
        "http",
        False,
        extra_opts={
            "USERNAME": "admin",
            "PAYLOAD": "php/bind_perl",
            "LHOST": "192.168.1.13",
            "LPORT": 4445,
            "BOGUS_OPT": "x",
        },
    )
    assert res["ok"] is True
    assert msf.seen["PAYLOAD"] == "php/bind_perl"
    assert msf.seen["LHOST"] == "192.168.1.13"
    assert msf.seen["LPORT"] == 4445
    assert "BOGUS_OPT" not in msf.seen


def test_auxiliary_modules_succeed_without_a_session():
    """Scanners never open shells: launching is the success criterion."""

    class _AuxMsf:
        def execute(self, mtype, mname, opts):
            assert mtype == "auxiliary"
            return {"job_id": 11}

        def sessions(self):
            return {}

    svc = AttackService(_AuxMsf())
    res = svc._try_exploit(
        "auxiliary/scanner/http/zoneminder_login",
        "192.168.1.84",
        "http",
        False,
        session_timeout=0,
    )
    assert res["ok"] is True
    assert res["session_id"] is None


def test_try_exploit_requires_cred():
    # credential-driven module with no verified cred -> refused
    svc = AttackService(_FakeMsf())
    res = svc._try_exploit("exploit/multi/ssh/sshexec", "10.0.0.5", "ssh", False)
    assert res["ok"] is False
    assert "credential" in res["detail"].lower()


class _FakeMsfFail:
    def execute(self, mtype, mname, opts):
        raise RuntimeError("boom")

    @property
    def client(self):
        raise RuntimeError("boom")


def test_try_exploit_error_reported_failure():
    svc = AttackService(_FakeMsfFail())
    res = svc._try_exploit("exploit/x", "10.0.0.5", "ssh", False)
    assert res["ok"] is False
    assert "boom" in res["detail"]


class _CheckMsf:
    def __init__(self, result):
        self.result = result
        self.seen: dict = {}

    def check(self, mtype, mname, opts):
        self.seen = dict(opts)
        return self.result

    def sessions(self):
        return {}


def _check_req(**kw):
    from schemas import AttackRequest

    base = {
        "target": "192.168.1.84",
        "host": "192.168.1.84",
        "module": "exploit/unix/webapp/zoneminder_lang_exec",
        "port": 80,
        "check_only": True,
        "options": {"USERNAME": "admin", "PASSWORD": "admin", "TARGETURI": "/"},
    }
    base.update(kw)
    return AttackRequest(**base)


def test_check_only_reports_vulnerable():
    svc = AttackService(_CheckMsf({"code": "Vulnerable"}))
    (attack,) = svc.run(_check_req(), [])
    assert attack["result"] == "vulnerable"
    assert attack["session_id"] is None
    assert attack["module"].endswith("zoneminder_lang_exec")


def test_check_only_reports_safe():
    svc = AttackService(_CheckMsf({"code": "Safe"}))
    (attack,) = svc.run(_check_req(), [])
    assert attack["result"] == "safe"


def test_check_only_passes_options_and_needs_a_module():
    msf = _CheckMsf({"code": "Appears"})
    svc = AttackService(msf)
    (attack,) = svc.run(_check_req(), [])
    assert attack["result"] == "likely_vulnerable"
    assert msf.seen["USERNAME"] == "admin"
    assert msf.seen["RHOSTS"] == "192.168.1.84"
    from schemas import AttackRequest

    (attack,) = svc.run(
        AttackRequest(target="h", check_only=True),
        [],
    )
    assert attack["result"] == "check_failed"


def test_check_only_reads_nested_msf_verdict():
    """Live shape is {status, result: {code, message}} — the top-level status
    word ('completed') must never shadow the nested check code."""

    class _NestedMsf:
        def check(self, mtype, mname, opts):
            return {
                "status": "completed",
                "result": {
                    "code": "appears",
                    "message": "The target appears to be vulnerable.",
                },
            }

        def sessions(self):
            return {}

    svc = AttackService(_NestedMsf())
    (attack,) = svc.run(_check_req(), [])
    assert attack["result"] == "likely_vulnerable"
    assert "appears to be vulnerable" in attack["detail"]
