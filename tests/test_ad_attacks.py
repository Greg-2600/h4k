# AD credential attacks (#91) and domain audit (#93). The LDAP/impacket boundary
# is faked at the runner function; no network, no domain controller required.
from contextlib import asynccontextmanager
from pathlib import Path

import main as main_module
import pytest
from fastapi.testclient import TestClient
from services import ad_attacks, ad_audit

POLICY_LDIF = """
dn: DC=LAB,DC=LOCAL
minPwdLength: 7
pwdProperties: 0
pwdHistoryLength: 24
lockoutThreshold: 5
lockoutDuration: -18000000000
lockoutObservationWindow: -18000000000
maxPwdAge: -36288000000000
ms-DS-MachineAccountQuota: 10
"""

KERB_LDIF = """
dn: CN=svc_sql,CN=Users,DC=LAB,DC=LOCAL
sAMAccountName: svc_sql
servicePrincipalName: MSSQLSvc/db.lab.local:1433
pwdLastSet: 132000000000000000
adminCount: 0

dn: CN=svc_web,CN=Users,DC=LAB,DC=LOCAL
sAMAccountName: svc_web
servicePrincipalName: HTTP/web.lab.local
pwdLastSet: 132000000000000000
adminCount: 0
"""

ASREP_LDIF = """
dn: CN=jdoe,CN=Users,DC=LAB,DC=LOCAL
sAMAccountName: jdoe
"""

UNC_USER_LDIF = """
dn: CN=helpdesk,CN=Users,DC=LAB,DC=LOCAL
sAMAccountName: helpdesk
distinguishedName: CN=helpdesk,CN=Users,DC=LAB,DC=LOCAL
"""

UNC_COMPUTER_LDIF = """
dn: CN=APP01,CN=Computers,DC=LAB,DC=LOCAL
sAMAccountName: APP01$
distinguishedName: CN=APP01,CN=Computers,DC=LAB,DC=LOCAL
"""

CONSTRAINED_LDIF = """
dn: CN=svc_app,CN=Users,DC=LAB,DC=LOCAL
sAMAccountName: svc_app
msDS-AllowedToDelegateTo: HTTP/app.lab.local
"""

ADMINCOUNT_LDIF = "\n\n".join(
    f"dn: CN=admin{i},CN=Users,DC=LAB,DC=LOCAL\nsAMAccountName: admin{i}\n"
    f"distinguishedName: CN=admin{i},CN=Users,DC=LAB,DC=LOCAL"
    for i in range(12)
)

NEVER_EXPIRES_LDIF = """
dn: CN=svc_old,CN=Users,DC=LAB,DC=LOCAL
sAMAccountName: svc_old
"""

TRUST_LDIF = """
dn: CN=partner.lab,CN=System,DC=LAB,DC=LOCAL
trustPartner: partner.lab
trustDirection: 3
trustAttributes: 8
"""

TEMPLATE_LDIF = """
dn: CN=ESC1-Template,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=LAB,DC=LOCAL
name: ESC1-Template
msPKI-Certificate-Name-Flag: 0x00000001
msPKI-Enrollment-Flag: 0x00000000
pKIExtendedKeyUsage: 1.3.6.1.5.5.7.3.2

dn: CN=AnyPurpose,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=LAB,DC=LOCAL
name: AnyPurpose
msPKI-Certificate-Name-Flag: 0
msPKI-Enrollment-Flag: 0
pKIExtendedKeyUsage: 2.5.29.37.0

dn: CN=EnrollAgent,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=LAB,DC=LOCAL
name: EnrollAgent
msPKI-Certificate-Name-Flag: 0
msPKI-Enrollment-Flag: 0
pKIExtendedKeyUsage: 1.3.6.1.5.5.7.3.1
"""

USERS_LDIF = """
dn: CN=alice,CN=Users,DC=LAB,DC=LOCAL
sAMAccountName: alice
userAccountControl: 512
memberOf: CN=Domain Users,CN=Users,DC=LAB,DC=LOCAL

dn: CN=bob,CN=Users,DC=LAB,DC=LOCAL
sAMAccountName: bob
userAccountControl: 66048
servicePrincipalName: HTTP/bob.lab.local
"""

GROUP_MEMBERS = "\n".join(
    f"member: CN=user{i},CN=Users,DC=LAB,DC=LOCAL" for i in range(25)
)


def fake_runner(argv, timeout):
    joined = " ".join(argv)
    if argv and argv[0] == "nmap":
        return {
            "rc": 0,
            "ok": True,
            "stdout": (
                "<nmaprun><host><ports><port><script id='smb2-security-mode'>"
                "SMB2 Security Mode: Message signing enabled but not required"
                "</script></port></ports></host></nmaprun>"
            ),
            "stderr": "",
            "timed_out": False,
        }
    if argv and argv[0] == "ldapwhoami":
        password = ""
        if "-y" in argv:
            password = Path(argv[argv.index("-y") + 1]).read_text(encoding="utf-8")
        ok = password == "Spring2026!" and "admin@" in joined
        return {
            "rc": 0 if ok else 49,
            "ok": ok,
            "stdout": "u:LAB\\admin" if ok else "",
            "stderr": "" if ok else "Invalid credentials",
            "timed_out": False,
        }
    if argv and argv[0] == "GetNPUsers.py":
        return {
            "rc": 0,
            "ok": True,
            "stdout": "$krb5asrep$23$jdoe@LAB.LOCAL:abcdef0123456789\n",
            "stderr": "",
            "timed_out": False,
        }
    if argv and argv[0] == "GetUserSPNs.py":
        out = ""
        if "-outputfile" in argv:
            out = argv[argv.index("-outputfile") + 1]
            Path(out).write_text(
                "$krb5tgs$23$*svc_sql$LAB.LOCAL$MSSQLSvc/db*$deadbeef\n",
                encoding="utf-8",
            )
        return {
            "rc": 0,
            "ok": True,
            "stdout": "ServicePrincipalName  Name     PasswordLastSet\n",
            "stderr": "",
            "timed_out": False,
        }
    if argv and argv[0] == "ldapsearch":
        argv[argv.index("-b") + 1] if "-b" in argv else ""
        filt = next((arg for arg in argv if str(arg).startswith("(")), joined)
        if "(objectClass=domainDNS)" in filt:
            return _ok(POLICY_LDIF)
        if "servicePrincipalName=*" in filt:
            return _ok(KERB_LDIF)
        if "4194304" in filt:
            return _ok(ASREP_LDIF)
        if "524288" in filt and "computer" in filt:
            return _ok(UNC_COMPUTER_LDIF)
        if "524288" in filt:
            return _ok(UNC_USER_LDIF)
        if "msDS-AllowedToDelegateTo" in filt:
            return _ok(CONSTRAINED_LDIF)
        if "adminCount=1" in filt:
            return _ok(ADMINCOUNT_LDIF)
        if "65536" in filt:
            return _ok(NEVER_EXPIRES_LDIF)
        if "(objectClass=trustedDomain)" in filt:
            return _ok(TRUST_LDIF)
        if "pKICertificateTemplate" in filt:
            return _ok(TEMPLATE_LDIF)
        if "(objectClass=group)" in filt:
            return _ok(
                "dn: CN=Group,CN=Users,DC=LAB,DC=LOCAL\n"
                f"{GROUP_MEMBERS}\ndistinguishedName: CN=Group,CN=Users,DC=LAB,DC=LOCAL"
            )
        if "objectCategory=person" in filt:
            return _ok(USERS_LDIF)
    return {
        "rc": 1,
        "ok": False,
        "stdout": "",
        "stderr": "unexpected call",
        "timed_out": False,
    }


def _ok(stdout):
    return {"rc": 0, "ok": True, "stdout": stdout, "stderr": "", "timed_out": False}


def _target(**overrides):
    values = {
        "domain": "LAB.LOCAL",
        "dc_ip": "192.168.56.10",
        "username": "alice",
        "password": "Password1",
    }
    values.update(overrides)
    return ad_attacks.ADTarget(**values)


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
    yield TestClient(main_module.app)
    main_module.reset_auth_cache()


# ---------------------------------------------------------------------------
# LDAP parsing / policy
# ---------------------------------------------------------------------------
def test_parse_ldif_handles_folded_and_base64_values():
    text = (
        "dn: CN=a,DC=x\n"
        "sAMAccountName: alice\n"
        "description: long value that\n"
        "  continues here\n"
        "jpegPhoto:: aGVsbG8=\n\n"
        "dn: CN=b,DC=x\n"
        "sAMAccountName: bob\n"
    )
    entries = ad_attacks.parse_ldif(text)
    assert entries[0]["dn"] == "CN=a,DC=x"
    assert entries[0]["description"] == "long value thatcontinues here"
    assert entries[0]["jpegPhoto"] == "hello"
    assert entries[1]["sAMAccountName"] == "bob"


def test_password_policy_parses_lockout_and_durations():
    result = ad_attacks.ADCredentialAttacks(fake_runner).password_policy(_target())
    assert result["ok"] is True
    policy = result["policy"]
    assert policy["lockout_threshold"] == 5
    assert policy["lockout_duration_minutes"] == 30
    assert policy["min_password_length"] == 7
    assert policy["machine_account_quota"] == 10
    assert result["attempts_per_user"] == 4
    assert result["spray_safe"] is True


def test_password_policy_failure_is_honest():
    def failing(argv, timeout):
        return {"rc": 49, "ok": False, "stdout": "", "stderr": "Bind failed"}

    result = ad_attacks.ADCredentialAttacks(failing).password_policy(_target())
    assert result["ok"] is False
    assert "Bind failed" in result["error"]


def test_target_validation_and_base_dn():
    target = _target(username="alice")
    assert target.base_dn == "DC=LAB,DC=LOCAL"
    assert target.upn() == "alice@LAB.LOCAL"
    with pytest.raises(ValueError):
        ad_attacks.ADTarget(domain="", dc_ip="1.2.3.4")


def test_users_enumeration():
    result = ad_attacks.ADCredentialAttacks(fake_runner).users(_target())
    assert result["ok"] is True
    assert [u["user"] for u in result["users"]] == ["alice", "bob"]
    assert result["users"][1]["password_never_expires"] is True
    assert result["users"][1]["kerberoastable"] is True


def test_asrep_plan_and_execution():
    service = ad_attacks.ADCredentialAttacks(fake_runner)
    plan = service.asrep_roast(_target(), ["jdoe"])
    assert plan["executed"] is False
    assert plan["plan"]["candidate_count"] == 1
    result = service.asrep_roast(_target(), ["jdoe"], execute=True)
    assert result["executed"] is True
    assert result["hash_count"] == 1
    assert result["hashes"][0].startswith("$krb5asrep$")


def test_kerberoast_needs_creds_and_parses_hashes():
    service = ad_attacks.ADCredentialAttacks(fake_runner)
    assert service.kerberoast(_target(password=""))["executed"] is False
    result = service.kerberoast(_target(), execute=True)
    assert result["executed"] is True
    assert result["hash_count"] == 1
    assert result["hashes"][0].startswith("$krb5tgs$")


def test_spray_refuses_lockout_unsafe_plan_and_executes_when_forced():
    service = ad_attacks.ADCredentialAttacks(fake_runner)
    target = _target(username="admin")
    users = ["admin", "bob"]
    unsafe = service.spray(target, users, ["a", "b", "c", "d", "e"])
    assert unsafe["executed"] is False
    assert unsafe["refused"] is True
    assert "lockoutThreshold=5" in unsafe["reason"]

    dry = service.spray(target, users, ["Spring2026!"])
    assert dry["executed"] is False
    assert dry["plan"]["attempts"] == 2

    result = service.spray(
        target, users, ["Spring2026!"], execute=True, delay=0, force=True
    )
    assert result["executed"] is True
    assert result["attempt_count"] == 2
    assert result["found"] == [{"user": "admin", "password": "Spring2026!"}]


def test_spray_stops_on_success():
    service = ad_attacks.ADCredentialAttacks(fake_runner)
    result = service.spray(
        _target(username="admin"),
        ["admin", "bob"],
        ["Spring2026!"],
        execute=True,
        delay=0,
        stop_on_success=True,
    )
    assert result["attempt_count"] == 1


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------
def test_domain_audit_finds_the_expected_issues():
    audit = ad_audit.ADDomainAudit(fake_runner)
    result = audit.audit(_target(), include_smb=True)
    assert result["ok"] is True
    ids = {f["id"] for f in result["findings"]}
    assert {
        "AD-POLICY-SHORTPW",
        "AD-POLICY-NOCOMPLEXITY",
        "AD-MACHINEQUOTA",
        "AD-KERBEROASTABLE",
        "AD-ASREP",
        "AD-UNCONSTRAINED",
        "AD-CONSTRAINED",
        "AD-ADMINCOUNT-BLOAT",
        "AD-GROUP-BLOAT",
        "AD-PW-NEVEREXPIRES",
        "AD-TRUSTS",
        "ADCS-ESC1",
        "ADCS-ESC2",
        "ADCS-ESC3",
        "AD-SMB-SIGNING",
    } <= ids
    assert "AD-POLICY-NOLOCKOUT" not in ids  # threshold is 5
    assert result["counts"]["critical"] >= 2
    assert result["risk"] in {"high", "critical"}
    assert result["read_only"] is True
    assert result["samples"]["kerberoastable"] == ["svc_sql", "svc_web"]
    assert result["errors"] == []


def test_domain_audit_fails_cleanly_when_bind_fails():
    def failing(argv, timeout):
        return {"rc": 49, "ok": False, "stdout": "", "stderr": "Bind failed"}

    result = ad_audit.ADDomainAudit(failing).audit(_target(), include_smb=False)
    assert result["ok"] is False
    assert "Bind failed" in result["error"]


def test_audit_helpers():
    assert ad_audit.ADDomainAudit.config_dn("DC=L,DC=X") == "CN=Configuration,DC=L,DC=X"
    assert "Certificate Templates" in ad_audit.ADDomainAudit.templates_dn("DC=L,DC=X")
    assert ad_audit._flag_int("0x00000001") == 1
    assert ad_audit._flag_int("524288") == 524288
    assert ad_audit._flag_int("nope") == 0
    assert ad_audit.parse_severity("This is HIGH risk") == "high"
    assert ad_audit.parse_severity("nothing") == "info"


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------
def test_api_validation(client):
    assert client.post("/api/ad/policy", json={}).status_code == 400
    assert client.post("/api/ad/audit", json={"domain": "LAB"}).status_code == 400
    assert (
        client.post(
            "/api/ad/spray", json={"domain": "LAB.LOCAL", "dc_ip": "1.2.3.4"}
        ).status_code
        == 400
    )


def test_api_policy_and_audit_with_injected_service(client, monkeypatch):
    monkeypatch.setattr(
        "routers.ad.password_policy",
        lambda target: {
            "ok": True,
            "policy": {"lockout_threshold": 0},
            "spray_safe": False,
        },
    )

    class _FakeAudit:
        def audit(self, target, **kwargs):
            return {"ok": False, "error": "stubbed", "findings": [], "queries": {}}

    monkeypatch.setattr("routers.ad.ADDomainAudit", _FakeAudit)
    audit = client.post(
        "/api/ad/audit", json={"domain": "LAB.LOCAL", "dc_ip": "127.0.0.1"}
    )
    assert audit.status_code == 200
    assert audit.json()["ok"] is False

    policy = client.post(
        "/api/ad/policy", json={"domain": "LAB.LOCAL", "dc_ip": "127.0.0.1"}
    )
    assert policy.status_code == 200
    assert policy.json()["policy"]["lockout_threshold"] == 0


def test_module_level_wrappers_and_subprocess_runner(monkeypatch, tmp_path):
    target = _target()
    assert ad_attacks.password_policy(target, runner=fake_runner)["ok"] is True
    assert (
        ad_attacks.asrep_roast(target, ["jdoe"], runner=fake_runner, execute=True)[
            "hash_count"
        ]
        == 1
    )
    assert (
        ad_attacks.kerberoast(target, runner=fake_runner, execute=True)["hash_count"]
        == 1
    )
    assert ad_attacks.spray(
        target,
        ["admin"],
        ["Spring2026!"],
        runner=fake_runner,
        execute=True,
        delay=0,
    )["found"]

    class _Proc:
        returncode = 0
        stdout = "ok"
        stderr = ""

    monkeypatch.setattr(ad_attacks.subprocess, "run", lambda *a, **k: _Proc())
    assert ad_attacks._subprocess_runner(["echo"], 1)["ok"] is True

    class _Timeout:
        stdout = b"partial"
        stderr = None

    def _timeout(*a, **k):
        raise ad_attacks.subprocess.TimeoutExpired(["echo"], 1, output=b"x")

    monkeypatch.setattr(ad_attacks.subprocess, "run", _timeout)
    out = ad_attacks._subprocess_runner(["echo"], 1)
    assert out["timed_out"] is True and out["stdout"] == "x"

    def _missing(*a, **k):
        raise FileNotFoundError(2, "missing", "nope")

    monkeypatch.setattr(ad_attacks.subprocess, "run", _missing)
    assert "not installed" in ad_attacks._subprocess_runner(["nope"], 1)["stderr"]

    def _oserror(*a, **k):
        raise OSError("nope")

    monkeypatch.setattr(ad_attacks.subprocess, "run", _oserror)
    assert "nope" in ad_attacks._subprocess_runner(["nope"], 1)["stderr"]


def test_ad_attack_edge_branches():
    service = ad_attacks.ADCredentialAttacks(fake_runner)
    with pytest.raises(ValueError):
        ad_attacks.ADTarget(domain="LAB.LOCAL", dc_ip="")
    assert ad_attacks._duration_minutes(0) == 0
    service.users = lambda target, limit=500: {"users": [], "count": 0}  # type: ignore[assignment]
    assert service.asrep_roast(_target(), [], execute=True).get("error")
    assert service.kerberoast(_target(username=""), execute=True).get("error")
    assert service.spray(_target(), [], [], execute=True).get("error")
    # no password argument -> ldapsearch uses -w ''
    result = service.ldapsearch(_target(password=""), "(objectClass=domainDNS)", ["x"])
    assert result["ok"] is True


def test_ldif_blank_entry_and_bad_base64():
    entries = ad_attacks.parse_ldif(
        "dn: CN=a\ndescription:: !!!notbase64\n\n" "dn: CN=b\nsAMAccountName: bob\n"
    )
    assert entries[0]["description"] == "!!!notbase64"
    assert entries[1]["sAMAccountName"] == "bob"


def test_execute_requires_engagement_scope(client, monkeypatch):
    import routers.scan as scan

    monkeypatch.setattr(scan, "_active_scope", lambda: (None, None))
    r = client.post(
        "/api/ad/spray",
        json={
            "domain": "LAB.LOCAL",
            "dc_ip": "127.0.0.1",
            "users": ["alice"],
            "passwords": ["x"],
            "execute": True,
        },
    )
    assert r.status_code == 403
    assert "engagement" in r.json()["detail"]


def test_parse_ldif_ignores_referrals_and_search_footer():
    text = (
        "# extended LDIF\n\n"
        "# jdoe, Users, lab.h4k\n"
        "dn: CN=jdoe,CN=Users,DC=lab,DC=h4k\n"
        "sAMAccountName: jdoe\n\n"
        "# search reference\n"
        "ref: ldap://lab.h4k/CN=Configuration,DC=lab,DC=h4k\n\n"
        "search: 2\n"
        "result: 0 Success\n"
        "numResponses: 3\n"
    )
    entries = ad_attacks.parse_ldif(text)
    assert entries == [
        {"dn": "CN=jdoe,CN=Users,DC=lab,DC=h4k", "sAMAccountName": "jdoe"}
    ]
