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
    """Records what was executed so we can assert on the module/port chosen."""

    def __init__(self):
        self.calls = []

    def execute(self, mtype, mname, opts):
        self.calls.append((mtype, mname, opts))
        return {"job_id": 7}

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
    def execute(self, mtype, mname, opts):
        return {"job_id": 5}

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
    assert res["session_id"] is not None


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
