# Scope enforcement spec

Scope is the authorization boundary of h4k. This page describes exactly how
it is parsed, stored and enforced — and how to verify it.

---

## 1. What scope is

A list of CIDRs/IPs that the operator is authorized to test. It belongs to
an **engagement**.

```json
{"name": "acme red", "scope": ["10.0.0.0/24", "192.168.5.7"], "notes": "SOW-2026-14"}
```

Accepted forms: bare IPs (`10.0.0.5` → `10.0.0.5/32`), CIDRs, and mixed
lists. Both IPv4 and IPv6 are supported.

Validation happens at creation time (`create_engagement` raises `ValueError`
for a non-IP entry) and can be pre-checked:

```sh
curl -X POST http://127.0.0.1:3137/api/engagement/parse-scope \
  -H 'Content-Type: application/json' -d '{"text":"10.0.0.0/24, 192.168.5.7"}'
# -> {"scope": ["10.0.0.0/24", "192.168.5.7/32"]}
```

## 2. Where it lives

| Where | Form |
|---|---|
| `engagements.scope` | JSON list of normalized CIDRs |
| `session_meta.active_engagement_id` | The *active* engagement (persisted across restarts) |
| `app_state.active_engagement_id` | In-memory pointer to the active engagement |

## 3. Enforcement points

Scope is enforced **in the store**, not in the UI. Every write path calls
`EngagementStore._require_scope()`:

```python
def _require_scope(self, engagement_id: str, host: str) -> None:
    if not self.in_scope(engagement_id, host):
        raise ScopeError(
            f"{host} is outside the authorized scope of engagement {engagement_id}"
        )
```

Enforced on:

| Path | Behaviour on violation |
|---|---|
| `ingest_scan` | The out-of-scope host is **skipped and reported** (`skipped_hosts`), not recorded |
| `add_crown_jewel` | `400` — *"… is outside the authorized scope …"* |
| `record_credential` | `ScopeError` |
| `propagate` | The target service is skipped before any login attempt |
| `attack_paths` | Out-of-scope hosts never become nodes |
| `_host_in_scope` (scan router) | The host is skipped and the skip is logged |

Reads of already-in-scope data are not filtered — the store cannot hold
out-of-scope hosts in the first place.

## 4. Active scope semantics

| State | Behaviour |
|---|---|
| No active engagement | **Read-only posture.** Recon is allowed; every aggressive action is refused with a clear error. |
| Active engagement | Aggressive actions are allowed **only inside** the scope. |

```sh
curl -X POST http://127.0.0.1:3137/api/session/scope \
  -H 'Content-Type: application/json' -d '{"engagement_id":"b2ac8ca2ebfa"}'
# -> {"status":"scoped","name":"acme red","scope":["10.0.0.0/24"]}

curl -X POST http://127.0.0.1:3137/api/session/scope \
  -H 'Content-Type: application/json' -d '{"engagement_id":null}'
# -> {"status":"unscoped"}
```

The active choice is persisted in `session_meta`, so a restart does not
silently re-arm a stale scope — and clearing it also clears the persisted
value.

## 5. Verifying enforcement yourself

```sh
# a host outside the scope must be refused
curl -X POST http://127.0.0.1:3137/api/engagement/$ID/crown-jewels \
  -H 'Content-Type: application/json' -d '{"host":"8.8.8.8"}'
# -> 400 {"detail":"8.8.8.8 is outside the authorized scope of engagement ..."}
```

The test suite pins this behaviour:

* `tests/test_engagement.py` — scope errors on ingest and credentials.
* `tests/test_engagement_api.py` — HTTP-level 400/404 contract.
* `tests/e2e/test_crown_jewels_attack_paths.py` — the UI refuses and says so.

## 6. Known gaps

* Scope matching is by IP only. A host that changes address mid-engagement
  can fall outside the scope — re-check before an active window.
* There is no notion of "excluded" hosts inside a CIDR. Use a tighter CIDR.
* Service-level exclusions (e.g. "never touch port 22 on X") are not modelled;
  the `attempts` ledger prevents *repeat* attempts but not the first one.
