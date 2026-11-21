#!/usr/bin/env bash
# Provision an intentionally-misconfigured Samba AD domain, once per volume.
set -euo pipefail

REALM="${REALM:-LAB.H4K}"
DOMAIN="${DOMAIN:-LAB}"
ADMIN_PASS="${ADMIN_PASS:-H4kLab!2026}"
LDB="/var/lib/samba/private/sam.ldb"
BASE_DN="DC=${DOMAIN,,},DC=${REALM#*.}"

log() { echo "[adlab] $*"; }

user_exists() {
  samba-tool user list 2>/dev/null | grep -qix "$1"
}

create_user() {
  local name="$1" pass="$2"
  if user_exists "$name"; then
    log "user $name already exists"
    return 0
  fi
  log "creating user $name"
  samba-tool user create "$name" "$pass" --given-name="$name" >/dev/null
}

if [[ ! -f "$LDB" ]]; then
  log "provisioning ${REALM} (${DOMAIN})"
  rm -f /etc/samba/smb.conf
  samba-tool domain provision \
    --use-rfc2307 \
    --realm="$REALM" \
    --domain="$DOMAIN" \
    --adminpass="$ADMIN_PASS" \
    --dns-backend=SAMBA_INTERNAL \
    --server-role=dc \
    --option="ldap server require strong auth=no"
  cp -f /var/lib/samba/private/krb5.conf /etc/krb5.conf
  # /etc/samba is not on the data volume; keep the provisioned config there.
  cp -f /etc/samba/smb.conf /var/lib/samba/smb.conf
fi

# Restore the provisioned config after a container rebuild. The default Debian
# smb.conf has no 'server role', so samba refuses to start as an AD DC.
if ! grep -q "server role = active directory domain controller" /etc/samba/smb.conf 2>/dev/null; then
  if [ -f /var/lib/samba/smb.conf ]; then
    cp -f /var/lib/samba/smb.conf /etc/samba/smb.conf
  fi
fi

# Lab only: allow simple LDAP binds so h4k's ldapsearch-based audit works over
# plain 389. Production AD should require signing/channel binding.
if ! grep -q "ldap server require strong auth" /etc/samba/smb.conf 2>/dev/null; then
  sed -i '/^\[global\]/a ldap server require strong auth = no' /etc/samba/smb.conf
fi
# DNS records are seeded once; on restart Samba's dnsupdate only logs duplicate
# record errors. The lab does not need dynamic DNS, so make it a no-op.
if ! grep -q "dns update command" /etc/samba/smb.conf 2>/dev/null; then
  sed -i '\|^\[global\]|a dns update command = /bin/true' /etc/samba/smb.conf
fi

log "starting samba for seeding"
samba -i >/tmp/samba-seed.log 2>&1 &
SAMBA_PID=$!
trap 'kill "$SAMBA_PID" 2>/dev/null || true' EXIT

for _ in $(seq 1 40); do
  if ldapsearch -x -H ldap://127.0.0.1 -s base -b "" namingContexts >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

# ---- weak policy (intentional) --------------------------------------------
log "setting weak password policy"
samba-tool domain passwordsettings set \
  --min-pwd-length=7 \
  --complexity=off \
  --history-length=24 \
  --account-lockout-threshold=5 \
  --account-lockout-duration=30 \
  --reset-account-lockout-after=30 >/dev/null || log "passwordsettings failed (non-fatal)"

# ---- users ----------------------------------------------------------------
create_user alice 'Passw0rd!2026'
create_user bob 'Passw0rd!2026'
create_user jdoe 'Jdoe!2026'
create_user helpdesk 'Helpdesk!2026'
create_user svc_sql 'SvcSql!2026'
create_user svc_web 'SvcWeb!2026'
create_user svc_app 'SvcApp!2026'
for n in 2 3 4 5 6; do create_user "admin$n" 'Adm1n!2026'; done

# ---- SPNs (kerberoastable) ------------------------------------------------
if ! samba-tool spn list svc_sql 2>/dev/null | grep -q MSSQLSvc; then
  samba-tool spn add "MSSQLSvc/db.${DOMAIN,,}.${REALM#*.}:1433" svc_sql >/dev/null || true
fi
if ! samba-tool spn list svc_web 2>/dev/null | grep -q HTTP; then
  samba-tool spn add "HTTP/web.${DOMAIN,,}.${REALM#*.}" svc_web >/dev/null || true
fi

# ---- delegation + AS-REP + adminCount (ldbmodify) -------------------------
USER_DN="CN=%s,CN=Users,$BASE_DN"
ldbmodify -H "$LDB" <<EOF || log "ldbmodify seed failed (non-fatal)"
dn: ${USER_DN//%s/jdoe}
changetype: modify
replace: userAccountControl
userAccountControl: 4194816

dn: ${USER_DN//%s/helpdesk}
changetype: modify
replace: userAccountControl
userAccountControl: 524800

dn: ${USER_DN//%s/svc_app}
changetype: modify
replace: msDS-AllowedToDelegateTo
msDS-AllowedToDelegateTo: HTTP/app.${DOMAIN,,}.${REALM#*.}

dn: ${USER_DN//%s/admin2}
changetype: modify
replace: adminCount
adminCount: 1

dn: ${USER_DN//%s/admin3}
changetype: modify
replace: adminCount
adminCount: 1

dn: ${USER_DN//%s/admin4}
changetype: modify
replace: adminCount
adminCount: 1

dn: ${USER_DN//%s/admin5}
changetype: modify
replace: adminCount
adminCount: 1

dn: ${USER_DN//%s/admin6}
changetype: modify
replace: adminCount
adminCount: 1

dn: ${BASE_DN}
changetype: modify
replace: ms-DS-MachineAccountQuota
ms-DS-MachineAccountQuota: 10
EOF

# ---- groups ---------------------------------------------------------------
for group in "Tier0 Operators" "Helpdesk Team"; do
  if ! samba-tool group list 2>/dev/null | grep -qix "$group"; then
    samba-tool group add "$group" >/dev/null || true
  fi
done
for n in 2 3 4 5 6; do
  samba-tool group addmembers "Tier0 Operators" "admin$n" >/dev/null 2>&1 || true
done
samba-tool group addmembers "Domain Admins" admin2 >/dev/null 2>&1 || true
samba-tool group addmembers "Helpdesk Team" helpdesk >/dev/null 2>&1 || true

log "seed complete"
trap - EXIT
kill "$SAMBA_PID" 2>/dev/null || true
wait "$SAMBA_PID" 2>/dev/null || true

log "starting samba in the foreground"
exec samba -i
