# h4k AD lab — a throw-away Samba Active Directory domain controller.
#
# It exists so the AD audit/credential features have a real directory to talk to
# without touching production. The seed deliberately includes the misconfigurations
# the audit looks for: weak password policy, machine-account quota > 0, an
# AS-REP-roastable user, two SPN accounts, unconstrained delegation, constrained
# delegation, and an oversized privileged group.
FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive \
    REALM=LAB.H4K \
    DOMAIN=LAB \
    ADMIN_PASS=H4kLab!2026

RUN apt-get update && apt-get install -y --no-install-recommends \
      samba samba-ad-dc samba-ad-provision smbclient ldap-utils krb5-user ldb-tools tdb-tools \
      procps ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY provision.sh /usr/local/bin/provision.sh
RUN chmod 0755 /usr/local/bin/provision.sh

EXPOSE 53/tcp 53/udp 88/tcp 88/udp 135/tcp 139/tcp 389/tcp 389/udp \
       445/tcp 464/tcp 464/udp 636/tcp 3268/tcp 3269/tcp

HEALTHCHECK --interval=20s --timeout=5s --retries=6 --start-period=40s \
  CMD ldapsearch -x -H ldap://127.0.0.1 -s base -b "" namingContexts >/dev/null || exit 1

ENTRYPOINT ["/usr/local/bin/provision.sh"]
