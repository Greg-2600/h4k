# Concepts

The vocabulary of h4k, and the mental model behind it.

---

## Engagement

An **engagement** is a named, scoped unit of work: *"acme red, 10.0.0.0/24,
Q3 window"*. It owns:

* a **scope** (a list of CIDRs/IPs you are authorized for),
* an **asset graph** (hosts, services, credentials, vulns, attempts),
* **crown jewels** (the objectives that matter),
* an **attempt ledger** (every login that was tried, hit or miss).

Engagements persist in SQLite (`engagements.db`) across restarts, so a
multi-hour engagement accumulates instead of dying with the process.

```sh
curl -X POST http://127.0.0.1:3137/api/engagement \
  -H 'Content-Type: application/json' \
  -d '{"name":"acme red","scope":["10.0.0.0/24"],"notes":"Q3 window"}'
```

## Scope

Scope is **enforced in the data layer**, not in the UI. Every write path —
ingest, crown jewels, credential replay, attack-path computation — re-checks
the CIDR list. Out-of-scope hosts are *skipped and reported*, never silently
recorded.

```sh
curl -X POST http://127.0.0.1:3137/api/engagement/parse-scope \
  -H 'Content-Type: application/json' -d '{"text":"10.0.0.0/24, 192.168.5.7"}'
```

| Scope state | Effect |
|---|---|
| No active engagement | Recon-only posture: reads are allowed, aggressive actions are refused |
| Active engagement | Actions are allowed **inside** the scope only |

## OPSEC modes

`mode` controls how noisy the recon is.

| Mode | Behaviour | Use when |
|---|---|---|
| `stealth` | Slow, low-rate, no service probes beyond the minimum | You do not want to be noticed |
| `tor` | Traffic routed through the local Tor SOCKS proxy | You need to avoid source attribution |
| `overt` | Fast, full port breadth | Your own lab |

```sh
curl -X POST http://127.0.0.1:3137/api/scan \
  -H 'Content-Type: application/json' \
  -d '{"target":"10.0.0.0/24","mode":"stealth"}'
```

## Depth (port breadth)

Depth and OPSEC mode are **separate axes**. `depth` decides how many ports
are swept.

| Depth | Ports |
|---|---|
| `quick` | ~10 common ports |
| `standard` | ~40 ports |
| `full` | all 65535 |

A partial sweep is honest about it: the report carries a `Coverage` block and
emits a `[coverage] PARTIAL SCAN` note rather than pretending it was complete.

## Credentials and lateral movement

* A **credential** is `(user, password, service)` — one row even if it works
  on fifty hosts.
* An **access** row records *where* it works: `(credential, host, port)`.
* Only **verified** logins create access rows, so the graph shows real
  reachability — never "these hosts both run SSH, so maybe".

**Propagation** replays already-verified credentials across the in-scope
estate. It never invents or sprays new candidates, and it has a dry-run plan:

```sh
curl http://127.0.0.1:3137/api/engagement/<id>/propagate/plan   # dry run
curl -X POST http://127.0.0.1:3137/api/engagement/<id>/propagate -d '{}'
```

## Crown jewels and attack paths

A **crown jewel** is an objective: a domain controller, a file server, a
database holding the thing you actually want. Each has a business **value**
(1–100).

**Attack paths** are computed from the engagement graph: every path from a
plausible foothold (a host with known vulns) to a crown jewel, using only
edges backed by *verified* credential logins. Paths are scored:

```
score = crown_value + Σ(vuln severity weight) + 25·hops − 12·(hops−1) + foothold bonus
```

The point is ranking: a 2.0 info-leak that pivots three hops into the DC
outranks a 9.8 on an isolated box.

## ATT&CK and detection guidance

Every finding h4k can produce is mapped to MITRE ATT&CK techniques, and every
technique carries **defender telemetry**: log sources, event IDs, and what to
look for. h4k speaks the attacker's language; this makes the output speak the
defender's.

## Aggressive actions are opt-in

| Action | Default | How to enable |
|---|---|---|
| Recon / fingerprint / CVE correlation | **on** | — |
| Default-credential testing | off | `try_default_creds: true` / Exploit-tab password attacks |
| Exploit execution | off | `do_attack: true` / Attack-queue fire buttons |
| Deep toolkit (hydra/nikto/sqlmap/NSE) | off | `/api/deepattack` (or the standalone nikto/gobuster/sqlmap endpoints) |
| Credential propagation | off | `POST /api/engagement/{id}/propagate` (or the Pivot-tab Execute button) |
| Fuzzing | off | the Exploit-tab Fuzz lab card |
| Container escape helpers | off | the Pivot-tab Escape check / `POST /api/container_escape` |

Everything aggressive is logged verbatim — in the UI activity pane, in the
session report, and in `docker logs`.

## Sandbox mode

`H4K_SANDBOX=1` replaces the three external dependencies (nmap, hydra,
Metasploit) with deterministic stand-ins. The API, parsers, scoring and UI are
the real thing; only the leaves are fake. It exists for class demos, CI and
the Selenium suite, and it never touches a network.

```sh
H4K_SANDBOX=1 python3 -m uvicorn main:app --port 3137
```

See the [testing guide](../dev/testing.md#sandbox-mode).
