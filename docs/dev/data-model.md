# Data model

Two SQLite databases plus a couple of JSON archives, all under
`H4K_DATA_DIR` (default `/opt/h4k/data` in the container, `h4k/data/` on a
host checkout).

---

## `neighbors.db` — the session store

Session-scoped: what the current run discovered.

| Table | Key columns | Purpose |
|---|---|---|
| `discovered_hosts` | `ip` (PK), `mac`, `vendor`, `hostname`, `os_guess`, `discovered_at` | Hosts seen this session |
| `discovered_services` | `ip`, `port`, `proto`, `service`, `product`, `version`, `state` | Open services + banners |
| `discovered_service_vulns` | `ip`, `port`, `kind`, `vid`, `severity`, `detail` | CVE hits per service |
| `found_creds` | `host`, `port`, `service`, `user`, `password`, `found_at` | Credentials found this session |
| `exploit_sessions` | `msf_session_id`, `host`, `port`, `module`, `opened_at` | Captured shells |
| `session_recon` | `msf_session_id`, `command`, `output` | Post-exploitation recon |
| `session_meta` | `key`, `value` | Session id, timestamps, `active_engagement_id` |
| `autopilot_runs` | `run_id`, `created_at`, `scope`, `message`, `log` | Autopilot history |

---

## `engagements.db` — the engagement store

Persistent, scope-enforced. Owned by `services/engagement.py`.

| Table | Key columns | Notes |
|---|---|---|
| `engagements` | `id`, `name`, `scope` (JSON CIDR list), `notes`, `created_at`, `updated_at` | The engagement itself |
| `assets` | `(engagement_id, host)`, `os`, `vendor`, `technology` | Hosts in scope |
| `services` | `(engagement_id, host, port, service)` | Per-host services |
| `credentials` | `(engagement_id, user, password, service)` | One row per credential, **not** per host |
| `cred_access` | `(engagement_id, user, password, service, host, port)`, `verified` | Where each credential works |
| `vulns` | `(engagement_id, host, name)` | Findings |
| `attempts` | `(engagement_id, host, port, service, user, password)`, `result` | Attempt ledger — a miss is **not** a credential |
| `crown_jewels` | `id`, `engagement_id`, `host`, `label`, `value`, `created_at` | Objectives |

### Why `credentials` and `cred_access` are separate

One credential usually works on many hosts. If the credential row carried the
host, the second host would overwrite the first and the lateral-movement
picture would be lost. Separating them lets `graph()` report *real* fan-out,
and lets `propagate` know which (credential, host) pairs were already tried.

### Scope enforcement

`EngagementStore._require_scope()` is called by every write path:

```python
def _require_scope(self, engagement_id: str, host: str) -> None:
    if not self.in_scope(engagement_id, host):
        raise ScopeError(
            f"{host} is outside the authorized scope of engagement {engagement_id}"
        )
```

Out-of-scope hosts are **skipped and reported**, never recorded. The database
file is chmod'ed `0600` — it holds verified credentials in the clear.

---

## `flags.db` — captured flags

Owned by `services/flags.py`. One row per distinct flag value:

| Column | Purpose |
|---|---|
| `engagement_id`, `value` | unique key — the same flag is never stored twice |
| `host`, `path`, `method` | where it was found (host may be empty = unplaced) |
| `note`, `auto`, `created_at` | analyst note, auto-detected or manual, timestamp |

---

## JSON archives (`h4k/data/`)

| File | Contents |
|---|---|
| `cves.json` | Curated CVE archive (banner-aware matching) |
| `creds.json` | Default-credential archive |
| `custom_rules.json` | User's custom Semgrep rules |
| `users.txt`, `passwords.txt`, `web-words.txt` | Small wordlists for the toolkit |

---

## Migrations

There is no migration runner yet — the schema is created with
`CREATE TABLE IF NOT EXISTS`, so new tables are added by extending
`SCHEMA` in `services/engagement.py`. Changing an existing table's columns
still needs a manual migration; that is a known gap (see ROADMAP).

---

## Backup

```sh
docker run --rm -v h4k_data:/data -v "$PWD":/backup alpine \
  tar czf /backup/h4k-data-$(date +%F).tgz -C /data .
```

Restoring is the same command with `tar xzf`. The database holds verified
credentials in plaintext — treat the archive as a secret.
