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
