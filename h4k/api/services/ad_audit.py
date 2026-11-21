# AD domain audit (#93): read-only assessment of the identity plane.
#
# This is the defender-facing half of the AD work: it asks the domain about its
# own hygiene instead of attacking it. Every query is a plain LDAP read; the
# optional SMB check is an nmap script that negotiates and reports signing, not
# an exploit. Findings are mapped to ATT&CK where an adversary would use the
# weakness, and each one carries concrete remediation so the output is usable as
# an assessment appendix, not just a list of scary words.
import logging
import re
from typing import Any

from services.ad_attacks import (
    ADCredentialAttacks,
    ADTarget,
    Runner,
    _as_list,
    _int,
    parse_ldif,
)

logger = logging.getLogger("h4k.ad_audit")

EKU_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
EKU_ANY_PURPOSE = "2.5.29.37.0"
EKU_ENROLLMENT_AGENT = "1.3.6.1.5.5.7.3.1"
CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
CT_FLAG_PEND_ALL_REQUESTS = 0x00000002
CA_FLAG_EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x00040000

PRIVILEGED_GROUPS = (
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "Account Operators",
    "Backup Operators",
    "Server Operators",
    "Group Policy Creator Owners",
)


def _flag_int(value: Any) -> int:
    """LDAP flags arrive as decimal or ``0x...`` strings."""
    text = str(value or "0").strip()
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    except ValueError:
        return 0


SEVERITY_WEIGHT = {"critical": 25, "high": 15, "medium": 7, "low": 2, "info": 0}


def _finding(
    fid: str,
    title: str,
    severity: str,
    category: str,
    detail: str,
    *,
    evidence: Any = None,
    technique: str = "",
    remediation: str = "",
    references: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "id": fid,
        "title": title,
        "severity": severity,
        "category": category,
        "detail": detail,
        "evidence": evidence if evidence is not None else {},
        "attack_technique": technique,
        "remediation": remediation,
        "references": references or [],
    }


class ADDomainAudit:
    """Read-only domain assessment built on ldapsearch + an optional nmap check."""

    def __init__(
        self, runner: Runner | None = None, attacks: ADCredentialAttacks | None = None
    ):
        self.attacks = attacks or ADCredentialAttacks(runner)
        self._runner = runner

    # -- query helpers ------------------------------------------------------
    def _entries(
        self,
        target: ADTarget,
        filt: str,
        attrs: list[str],
        *,
        base: str | None = None,
        scope: str = "sub",
        size_limit: int = 1000,
    ) -> tuple[list[dict[str, Any]], str]:
        result = self.attacks.ldapsearch(
            target, filt, attrs, base=base, scope=scope, size_limit=size_limit
        )
        entries = parse_ldif(result.get("stdout", ""))
        error = "" if result.get("rc") == 0 or entries else (result.get("stderr") or "")
        return entries, error

    @staticmethod
    def config_dn(base_dn: str) -> str:
        return f"CN=Configuration,{base_dn}"

    @staticmethod
    def templates_dn(base_dn: str) -> str:
        return (
            "CN=Certificate Templates,CN=Public Key Services,CN=Services,"
            f"CN=Configuration,{base_dn}"
        )

    # -- main entry point ---------------------------------------------------
    def audit(
        self,
        target: ADTarget,
        *,
        include_smb: bool = True,
        max_samples: int = 10,
    ) -> dict[str, Any]:
        findings: list[dict[str, Any]] = []
        errors: list[str] = []
        samples: dict[str, Any] = {}
        queries: dict[str, int] = {}

        policy_result = self.attacks.password_policy(target)
        policy = policy_result.get("policy", {})
        if not policy_result.get("ok"):
            return {
                "ok": False,
                "error": policy_result.get("error") or "LDAP bind/read failed",
                "domain": target.domain,
                "dc_ip": target.dc_ip,
                "findings": [],
                "queries": {},
            }

        def _count(name: str, entries: list[dict[str, Any]], error: str) -> int:
            queries[name] = len(entries)
            if error:
                errors.append(f"{name}: {error}")
            return len(entries)

        # ---- password / lockout policy -----------------------------------
        threshold = _int(policy.get("lockout_threshold"))
        if threshold == 0:
            findings.append(
                _finding(
                    "AD-POLICY-NOLOCKOUT",
                    "No account lockout threshold",
                    "high",
                    "password-policy",
                    "The domain never locks accounts, so online password guessing "
                    "is limited only by network speed.",
                    evidence={"lockout_threshold": 0},
                    technique="T1110.003",
                    remediation="Set a lockout threshold (5-10) with a 15+ minute "
                    "observation window, and monitor 4740 events.",
                    references=["https://attack.mitre.org/techniques/T1110/003/"],
                )
            )
        elif threshold <= 3:
            findings.append(
                _finding(
                    "AD-POLICY-LOWLOCKOUT",
                    "Very low lockout threshold",
                    "low",
                    "password-policy",
                    f"lockoutThreshold={threshold} makes accidental lockouts likely; "
                    "spraying must be tightly bounded.",
                    evidence={"lockout_threshold": threshold},
                    remediation="Raise the threshold to 5-10 or deploy fine-grained "
                    "password policies for privileged accounts.",
                )
            )
        if _int(policy.get("min_password_length")) < 8:
            findings.append(
                _finding(
                    "AD-POLICY-SHORTPW",
                    "Minimum password length below 8",
                    "medium",
                    "password-policy",
                    f"minPwdLength={policy.get('min_password_length')} allows short, "
                    "guessable passwords.",
                    evidence={"min_password_length": policy.get("min_password_length")},
                    technique="T1110.001",
                    remediation="Require 14+ characters for privileged accounts; "
                    "length beats composition rules.",
                )
            )
        if not policy.get("password_complexity"):
            findings.append(
                _finding(
                    "AD-POLICY-NOCOMPLEXITY",
                    "Password complexity disabled",
                    "medium",
                    "password-policy",
                    "pwdProperties does not require complexity.",
                    evidence={"pwd_properties": policy.get("password_complexity")},
                    remediation="Enable complexity or, preferably, a banned-password "
                    "list and MFA for privileged access.",
                )
            )
        quota = _int(policy.get("machine_account_quota"))
        if quota > 0:
            findings.append(
                _finding(
                    "AD-MACHINEQUOTA",
                    "Authenticated users may join computers",
                    "high",
                    "delegation",
                    f"ms-DS-MachineAccountQuota={quota}: any authenticated user can "
                    "create machine accounts, enabling resource-based constrained "
                    "delegation attacks.",
                    evidence={"machine_account_quota": quota},
                    technique="T1136.002",
                    remediation="Set ms-DS-MachineAccountQuota to 0 and delegate "
                    "joins to a controlled group.",
                    references=[
                        "https://attack.mitre.org/techniques/T1136/002/",
                    ],
                )
            )

        # ---- roastable accounts ------------------------------------------
        kerb_entries, kerb_error = self._entries(
            target,
            "(&(objectClass=user)(servicePrincipalName=*)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
            ["sAMAccountName", "servicePrincipalName", "pwdLastSet", "adminCount"],
        )
        # Machine accounts and krbtgt carry SPNs by design; they are not useful
        # kerberoast candidates and reporting them drowns out the real ones.
        kerb_entries = [
            e
            for e in kerb_entries
            if str(e.get("sAMAccountName") or "").lower() != "krbtgt"
            and not str(e.get("sAMAccountName") or "").endswith("$")
        ]
        kerb_count = _count("kerberoastable", kerb_entries, kerb_error)
        if kerb_count:
            names = [
                str(e.get("sAMAccountName"))
                for e in kerb_entries
                if e.get("sAMAccountName")
            ]
            samples["kerberoastable"] = names[:max_samples]
            findings.append(
                _finding(
                    "AD-KERBEROASTABLE",
                    f"{kerb_count} enabled account(s) with an SPN",
                    "high",
                    "credentials",
                    "Any domain user can request a service ticket for these accounts "
                    "and crack it offline if the password is weak.",
                    evidence={"count": kerb_count, "sample": names[:max_samples]},
                    technique="T1558.003",
                    remediation="Use managed service accounts (gMSA) or 30+ character "
                    "random service passwords; monitor 4769 with RC4 encryption.",
                    references=["https://attack.mitre.org/techniques/T1558/003/"],
                )
            )

        asrep_entries, asrep_error = self._entries(
            target,
            "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
            ["sAMAccountName"],
        )
        asrep_entries = [
            e
            for e in asrep_entries
            if not str(e.get("sAMAccountName") or "").endswith("$")
        ]
        asrep_count = _count("asrep_roastable", asrep_entries, asrep_error)
        if asrep_count:
            names = [
                str(e.get("sAMAccountName"))
                for e in asrep_entries
                if e.get("sAMAccountName")
            ]
            samples["asrep_roastable"] = names[:max_samples]
            findings.append(
                _finding(
                    "AD-ASREP",
                    f"{asrep_count} AS-REP roastable account(s)",
                    "high",
                    "credentials",
                    "These accounts do not require Kerberos pre-authentication; an "
                    "unauthenticated attacker can request and crack an AS-REP.",
                    evidence={"count": asrep_count, "sample": names[:max_samples]},
                    technique="T1558.004",
                    remediation="Clear 'Do not require Kerberos preauthentication' on "
                    "all accounts; monitor 4768 with pre-auth disabled.",
                    references=["https://attack.mitre.org/techniques/T1558/004/"],
                )
            )

        # ---- delegation ---------------------------------------------------
        unc_users, unc_u_err = self._entries(
            target,
            "(&(objectClass=user)"
            "(userAccountControl:1.2.840.113556.1.4.803:=524288))",
            ["sAMAccountName", "distinguishedName"],
        )
        unc_users = [
            e for e in unc_users if not str(e.get("sAMAccountName") or "").endswith("$")
        ]
        unc_computers, unc_c_err = self._entries(
            target,
            "(&(objectClass=computer)"
            "(userAccountControl:1.2.840.113556.1.4.803:=524288))",
            ["sAMAccountName", "distinguishedName"],
        )
        # Domain controllers are trusted for delegation by design; only
        # non-DC computers are a finding.
        unc_computers = [
            e
            for e in unc_computers
            if "OU=Domain Controllers" not in str(e.get("dn") or "")
        ]
        unc_count = _count("unconstrained_users", unc_users, unc_u_err) + _count(
            "unconstrained_computers", unc_computers, unc_c_err
        )
        if unc_count:
            names = [
                str(e.get("sAMAccountName"))
                for e in (unc_users + unc_computers)
                if e.get("sAMAccountName")
            ]
            samples["unconstrained_delegation"] = names[:max_samples]
            findings.append(
                _finding(
                    "AD-UNCONSTRAINED",
                    f"{unc_count} account(s) with unconstrained delegation",
                    "critical",
                    "delegation",
                    "A compromised account with unconstrained delegation can collect "
                    "the TGT of any user who authenticates to it, including Domain "
                    "Admins.",
                    evidence={"count": unc_count, "sample": names[:max_samples]},
                    technique="T1558.001",
                    remediation="Remove unconstrained delegation; migrate to "
                    "constrained or resource-based constrained delegation and mark "
                    "tier-0 accounts 'sensitive and cannot be delegated'.",
                    references=["https://attack.mitre.org/techniques/T1558/001/"],
                )
            )

        cons_entries, cons_error = self._entries(
            target,
            "(msDS-AllowedToDelegateTo=*)",
            ["sAMAccountName", "msDS-AllowedToDelegateTo"],
        )
        cons_count = _count("constrained_delegation", cons_entries, cons_error)
        if cons_count:
            findings.append(
                _finding(
                    "AD-CONSTRAINED",
                    f"{cons_count} constrained-delegation account(s)",
                    "medium",
                    "delegation",
                    "Constrained delegation is intentionally scoped, but a "
                    "compromise of these accounts can reach the listed services.",
                    evidence={
                        "count": cons_count,
                        "sample": [
                            str(e.get("sAMAccountName"))
                            for e in cons_entries[:max_samples]
                        ],
                    },
                    technique="T1558",
                    remediation="Review each msDS-AllowedToDelegateTo target; prefer "
                    "resource-based constrained delegation with protocol transition "
                    "disabled.",
                )
            )

        # ---- privileged / adminCount -------------------------------------
        admin_entries, admin_error = self._entries(
            target,
            "(&(objectClass=user)(adminCount=1))",
            ["sAMAccountName", "distinguishedName"],
        )
        admin_count = _count("admin_count", admin_entries, admin_error)
        if admin_count > 10:
            findings.append(
                _finding(
                    "AD-ADMINCOUNT-BLOAT",
                    f"{admin_count} accounts carry adminCount=1",
                    "medium",
                    "privilege",
                    "A large adminCount population usually means inherited ACEs from "
                    "a privileged group were never cleaned up, widening the tier-0 "
                    "blast radius.",
                    evidence={
                        "count": admin_count,
                        "sample": [
                            str(e.get("sAMAccountName"))
                            for e in admin_entries[:max_samples]
                        ],
                    },
                    remediation="Audit AdminSDHolder and remove unnecessary privileged "
                    "group membership; re-run and confirm adminCount drops.",
                )
            )

        group_counts: dict[str, int] = {}
        group_samples: dict[str, list[str]] = {}
        for group in PRIVILEGED_GROUPS:
            base = f"CN={group},CN=Users,{target.base_dn}"
            entries, error = self._entries(
                target,
                "(objectClass=group)",
                ["member", "distinguishedName"],
                base=base,
                scope="base",
            )
            queries[f"group:{group}"] = len(entries)
            if error:
                errors.append(f"group {group}: {error}")
            if entries:
                members = _as_list(entries[0].get("member"))
                group_counts[group] = len(members)
                group_samples[group] = [m.split(",")[0] for m in members[:max_samples]]
        samples["privileged_groups"] = group_samples
        overfull = {g: n for g, n in group_counts.items() if n > 20}
        if overfull:
            findings.append(
                _finding(
                    "AD-GROUP-BLOAT",
                    "Privileged groups are unusually large",
                    "medium",
                    "privilege",
                    "Large built-in privileged groups increase the chance that a "
                    "single phished account is tier-0.",
                    evidence={"groups": overfull},
                    remediation="Move day-to-day admin into dedicated, time-bound "
                    "groups and keep Domain/Enterprise Admins near-empty.",
                )
            )

        # ---- password age / never expires --------------------------------
        never_entries, never_error = self._entries(
            target,
            "(&(objectClass=user)"
            "(userAccountControl:1.2.840.113556.1.4.803:=65536)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
            ["sAMAccountName"],
        )
        never_count = _count("password_never_expires", never_entries, never_error)
        if never_count:
            findings.append(
                _finding(
                    "AD-PW-NEVEREXPIRES",
                    f"{never_count} enabled account(s) with non-expiring passwords",
                    "medium",
                    "password-policy",
                    "Non-expiring passwords are acceptable only with compensating "
                    "controls (MFA, long random secrets); otherwise they age into "
                    "credential-stuffing material.",
                    evidence={"count": never_count},
                    technique="T1078",
                    remediation="Prefer long random passwords + MFA over rotation; "
                    "for accounts that must not expire, document the exception.",
                )
            )

        # ---- trusts -------------------------------------------------------
        trust_entries, trust_error = self._entries(
            target,
            "(objectClass=trustedDomain)",
            ["trustPartner", "trustDirection", "trustAttributes"],
            base=f"CN=System,{target.base_dn}",
        )
        trust_count = _count("trusts", trust_entries, trust_error)
        if trust_count:
            samples["trusts"] = [
                {
                    "partner": e.get("trustPartner"),
                    "direction": e.get("trustDirection"),
                    "attributes": e.get("trustAttributes"),
                }
                for e in trust_entries[:max_samples]
            ]
            findings.append(
                _finding(
                    "AD-TRUSTS",
                    f"{trust_count} domain trust(s) present",
                    "info",
                    "trust",
                    "Trusts widen the identity boundary; each one needs an owner and "
                    "a review cadence.",
                    evidence={"count": trust_count},
                    remediation="Review trust direction, SID filtering and selective "
                    "authentication; remove trusts that no longer serve a purpose.",
                )
            )

        # ---- AD CS --------------------------------------------------------
        templates, tpl_error = self._entries(
            target,
            "(objectClass=pKICertificateTemplate)",
            [
                "name",
                "msPKI-Certificate-Name-Flag",
                "msPKI-Enrollment-Flag",
                "msPKI-RA-Signature",
                "pKIExtendedKeyUsage",
            ],
            base=self.templates_dn(target.base_dn),
        )
        _count("adcs_templates", templates, tpl_error)
        esc1 = []
        esc2 = []
        esc3 = []
        for entry in templates:
            name_flags = _flag_int(entry.get("msPKI-Certificate-Name-Flag"))
            enroll_flags = _flag_int(entry.get("msPKI-Enrollment-Flag"))
            eku = _as_list(entry.get("pKIExtendedKeyUsage"))
            if (
                name_flags & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
                and not enroll_flags & CT_FLAG_PEND_ALL_REQUESTS
                and (not eku or EKU_CLIENT_AUTH in eku)
            ):
                esc1.append(str(entry.get("name") or "?"))
            if EKU_ANY_PURPOSE in eku:
                esc2.append(str(entry.get("name") or "?"))
            if EKU_ENROLLMENT_AGENT in eku:
                esc3.append(str(entry.get("name") or "?"))
        if esc1:
            findings.append(
                _finding(
                    "ADCS-ESC1",
                    f"{len(esc1)} template(s) look ESC1-vulnerable",
                    "critical",
                    "adcs",
                    "The template lets the enrollee supply the subject and does not "
                    "require manager approval, with a client-auth EKU. A low-privileged "
                    "user can request a certificate for an admin.",
                    evidence={"templates": esc1[:max_samples]},
                    technique="T1649",
                    remediation="Require manager approval, remove "
                    "ENROLLEE_SUPPLIES_SUBJECT, and restrict enrollment permissions.",
                    references=["https://attack.mitre.org/techniques/T1649/"],
                )
            )
        if esc2:
            findings.append(
                _finding(
                    "ADCS-ESC2",
                    f"{len(esc2)} template(s) have Any Purpose EKU",
                    "high",
                    "adcs",
                    "Any Purpose certificates can be used for client authentication "
                    "and code signing.",
                    evidence={"templates": esc2[:max_samples]},
                    technique="T1649",
                    remediation="Replace Any Purpose with the minimum required EKUs.",
                )
            )
        if esc3:
            findings.append(
                _finding(
                    "ADCS-ESC3",
                    f"{len(esc3)} template(s) grant enrollment-agent EKU",
                    "high",
                    "adcs",
                    "Enrollment-agent certificates can request certificates on behalf "
                    "of other users.",
                    evidence={"templates": esc3[:max_samples]},
                    technique="T1649",
                    remediation="Remove enrollment-agent EKU unless the workflow is "
                    "genuinely required; require approval and audit requests.",
                )
            )

        # ---- SMB signing (optional active check) --------------------------
        if include_smb:
            signing = self._check_smb_signing(target)
            queries["smb_signing"] = 1 if signing.get("checked") else 0
            if signing.get("checked") and not signing.get("required"):
                findings.append(
                    _finding(
                        "AD-SMB-SIGNING",
                        "SMB signing is not required on the DC",
                        "high",
                        "network",
                        "Without required signing, NTLM relay against SMB is viable.",
                        evidence=signing,
                        technique="T1557.001",
                        remediation="Require SMB signing on domain controllers via GPO "
                        "('Microsoft network server: Digitally sign communications').",
                        references=["https://attack.mitre.org/techniques/T1557/001/"],
                    )
                )
            elif signing.get("error"):
                errors.append(f"smb signing: {signing['error']}")

        # ---- score ---------------------------------------------------------
        score = min(
            100,
            sum(SEVERITY_WEIGHT.get(f["severity"], 0) for f in findings),
        )
        counts: dict[str, int] = {}
        for finding in findings:
            counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1
        return {
            "ok": True,
            "domain": target.domain,
            "dc_ip": target.dc_ip,
            "policy": policy,
            "findings": findings,
            "counts": counts,
            "samples": samples,
            "queries": queries,
            "errors": errors,
            "risk_score": score,
            "risk": (
                "critical"
                if score >= 60
                else "high" if score >= 35 else "medium" if score >= 15 else "low"
            ),
            "read_only": True,
        }

    # -- optional SMB signing check ----------------------------------------
    def _check_smb_signing(self, target: ADTarget) -> dict[str, Any]:
        argv = [
            "nmap",
            "-Pn",
            "-p445",
            "--script",
            "smb2-security-mode",
            "-oX",
            "-",
            target.dc_ip,
        ]
        try:
            result = self.attacks._run(argv, 60)
        except Exception as exc:  # pragma: no cover - defensive
            return {"checked": False, "error": str(exc)}
        if not result.get("ok") and not result.get("stdout"):
            return {"checked": False, "error": result.get("stderr", "nmap failed")}
        xml = result.get("stdout", "")
        required = "signing is required" in xml.lower() or "required" in xml.lower()
        enabled_but_not_required = "enabled but not required" in xml.lower()
        return {
            "checked": bool(xml.strip()),
            "required": bool(required and not enabled_but_not_required),
            "raw": xml[:2000],
            "error": "",
        }


def parse_severity(text: str) -> str:
    lowered = text.lower()
    for level in ("critical", "high", "medium", "low", "info"):
        if re.search(rf"\b{level}\b", lowered):
            return level
    return "info"


def audit_domain(
    target: ADTarget, *, runner: Runner | None = None, **kwargs: Any
) -> dict[str, Any]:
    return ADDomainAudit(runner).audit(target, **kwargs)
