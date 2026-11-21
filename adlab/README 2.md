# h4k AD lab

A disposable Samba Active Directory domain controller with the misconfigurations
the audit is designed to find. It is a **lab fixture**: never join it to a real
domain, never reuse these passwords.

| Setting | Value |
|---|---|
| Realm | `LAB.H4K` |
| NetBIOS domain | `LAB` |
| Base DN | `DC=lab,DC=h4k` |
| DC IP (compose) | `172.30.0.10` |
| Admin | `Administrator` / `H4kLab!2026` |
| Users | `alice`, `bob`, `jdoe`, `helpdesk`, `svc_sql`, `svc_web`, `svc_app`, `admin2`–`admin6` |
| User password | `Passw0rd!2026` unless listed below |

Intentional findings:

- password policy: 7 chars, complexity off, lockout threshold 5;
- machine-account quota 10 (any authenticated user can join a computer);
- `jdoe` is AS-REP roastable (pre-auth disabled);
- `svc_sql` and `svc_web` have SPNs (kerberoastable);
- `helpdesk` has unconstrained delegation;
- `svc_app` has constrained delegation to `HTTP/app.lab.h4k`;
- `admin2`–`admin6` carry `adminCount=1` and sit in `Tier0 Operators`;
- `admin2` is a Domain Admin, `helpdesk` is in Helpdesk.

## Run

```sh
docker compose -f h4k/docker-compose.yml --profile adlab up -d adlab
```

The compose service adds `CAP_SYS_ADMIN` because Samba stores NT ACLs in
`security.*` extended attributes; without it provisioning fails at
`setsysvolacl`. The image installs `samba-ad-dc` (which provides the
`samba_secrets` LDB module) and `samba-ad-provision` (the AD schema files).
The lab config sets `ldap server require strong auth = no` so h4k's
`ldapsearch`-based audit works over plain 389; production AD should require
signing and channel binding.

The container is on an isolated bridge (`172.30.0.0/24`) so its Samba DNS does
not fight the host resolver. The h4k container uses host networking and can
reach `172.30.0.10` directly.

## Use it from h4k

```sh
curl -s -X POST localhost:3137/api/ad/audit \
  -H 'Content-Type: application/json' \
  -d '{"domain":"LAB.H4K","dc_ip":"172.30.0.10","username":"alice","password":"Passw0rd!2026"}'
```

LDAP from the host:

```sh
ldapsearch -x -H ldap://172.30.0.10 -D alice@LAB.H4K -w 'Passw0rd!2026' \
  -b 'DC=lab,DC=h4k' '(objectClass=user)' sAMAccountName
```

## Verified

Built and run against `h4k-adlab:latest`: Samba provisions `LAB.H4K`, the seed
creates the users/SPNs/delegation/AS-REP/adminCount state, `alice` binds over
LDAP, and `POST /api/ad/audit` returns the expected findings (weak policy,
machine quota, kerberoastable/AS-REP accounts, unconstrained/constrained
delegation). A fresh volume is required after changing the seed.

## Teardown

```sh
docker compose -f h4k/docker-compose.yml --profile adlab down -v
```

The volume holds the domain database; removing it lets the seed run again.
