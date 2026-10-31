# Threat model

What h4k is, what it protects, and what it deliberately does not protect.

---

## 1. What h4k is

A **single-operator offensive-security analysis console** for authorized lab
work. It runs on the operator's own machine or on a host the operator
controls, drives recon/attack tooling against systems the operator owns or has
written permission to test, and stores the results locally.

It is **not** a multi-tenant service, not a web-facing scanner, and not a
platform for third parties.

## 2. Assets

| Asset | Why it matters |
|---|---|
| **Verified credentials** | Stored in plaintext in `engagements.db`; they are the crown jewels of the engagement |
| **Scope definitions** | They are the authorization boundary — a wrong scope enables real attacks |
| **The API** | It can execute exploits and brute-force attacks on the operator's behalf |
| **Scan data** | Contains the shape of the target estate (valuable to an attacker) |
| **The host itself** | h4k usually runs with root (raw sockets for SYN scans, ARP) |

## 3. Trust boundaries

```
┌───────────────────────────────┐
│ operator workstation           │  ← trusted
│  ├─ h4k API (often as root)   │
│  ├─ h4k_data volume (creds)   │
└──────────────┬────────────────┘
               │ ← the only untrusted boundary
┌──────────────▼────────────────┐
│ target estate (in scope)      │
└───────────────────────────────┘
```

Everything *inside* the top box is trusted. The target estate is untrusted
input: banners, service responses and crafted payloads are attacker-controlled
data that h4k parses.

## 4. Threats and mitigations

| # | Threat | Mitigation |
|---|---|---|
| T1 | **Scope bypass** — a mistyped target widens the engagement | Scope is enforced in `EngagementStore`, on every write path; out-of-scope hosts are skipped *and reported* |
| T2 | **Accidental attack on a third party** | Aggressive actions require an active scope; the UI shows the scope in the header; every action is logged |
| T3 | **Credential exposure** | DB file mode `0600`; data dir outside the repo; excluded from git; reports redact nothing, so **treat exports as secrets** |
| T4 | **Host compromise via h4k itself** | The API is a local tool; bind to `127.0.0.1`; do not expose it to a network. There is **no authentication** — that is the main caveat (see below) |
| T5 | **Malicious scan data** (banner injection, crafted XML) | Parsers are regex-based and defensive; untrusted strings are escaped in the UI (`escHtml`); the API never `eval`s scan output |
| T6 | **Subprocess injection** | Every external call uses an argv list, never `shell=True`; bandit enforces it |
| T7 | **Zip-slip in uploads** | `ingest.py` validates extracted paths |
| T8 | **Log/credential leakage** | `docker logs` may contain banners and findings; do not paste logs publicly without review |
| T9 | **Unintended Metasploit execution** | Module execution is opt-in, per-action, and every attempt is logged |
| T10 | **Rate-limit abuse / accidental DoS** | Per-IP sliding window (600 req/min) |

## 5. Accepted risks (deliberate)

* **No authentication on the API.** h4k binds to localhost and assumes a
  single trusted operator. Do not expose it.
* **Plaintext credentials in the store.** Required to replay what was found.
  The DB is `0600`; the volume is the sensitive part.
* **Running as root.** Raw sockets and ARP need it. Use a dedicated lab host
  or a container with minimal capabilities.
* **The tool executes real attacks when told to.** That is the product. The
  mitigations are the scope, the opt-in switches and the audit log.

## 6. Abuse cases

| Abuse | Mitigation |
|---|---|
| Someone points h4k at a third-party network | Legal framing + scope enforcement + the fact that a scope must be declared by the operator |
| A shared demo instance is abused | Demo instances run in **sandbox mode** (`H4K_SANDBOX=1`), which cannot touch the network at all |
| A leaked report discloses credentials | Reports are secrets; redact before sharing. h4k prints a warning in the UI when exporting |
| The tool is repurposed as a worm | Propagation replays **only already-verified** credentials, never invents candidates, and is capped (`MAX_ATTEMPTS=500`) |

## 7. Review checklist for new features

- [ ] Does it widen what h4k can do without an explicit opt-in?
- [ ] Does it bypass the scope check?
- [ ] Does it turn untrusted scan data into execution (shell, SQL, template)?
- [ ] Does it write secrets somewhere less protected than `0600`?
- [ ] Does it make the API reachable from a network it was not before?
