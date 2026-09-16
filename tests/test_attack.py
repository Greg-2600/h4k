# Tests for the opt-in attack service and module mapping.
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


class _FakeMsf:
    def execute(self, mtype, mname, opts):
        return {"job_id": 5}


def test_try_exploit_success_returns_session():
    svc = AttackService(_FakeMsf())
    res = svc._try_exploit("exploit/multi/ssh/sshexec", "10.0.0.5", "ssh", True)
    assert res["ok"] is True
    assert res["session_id"] is not None


class _FakeMsfFail:
    def execute(self, mtype, mname, opts):
        raise RuntimeError("boom")


def test_try_exploit_error_reported_failure():
    svc = AttackService(_FakeMsfFail())
    res = svc._try_exploit("exploit/x", "10.0.0.5", "ssh", False)
    assert res["ok"] is False
    assert "boom" in res["detail"]
