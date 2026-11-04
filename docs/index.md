# h4k documentation

**h4k** is a containerized offensive-security analysis platform for **authorized
lab work only**: your own VMs, a test router, a deliberately vulnerable box.

Everything below is written for people running h4k against systems they own
or have written permission to test. See [safety](user/safety.md) first if you
are new.

## Start here

| I want to… | Read |
|---|---|
| Run it for the first time | [Quickstart](user/quickstart.md) |
| Understand scope, modes, depth | [Concepts](user/concepts.md) |
| Do a full recon → exploit walk | [Workflows](user/workflows.md) |
| Understand every button | [UI guide](user/ui.md) |
| Know what is safe to click | [Safety & authorization](user/safety.md) |
| Fix a broken scan | [Troubleshooting](user/troubleshooting.md) |
| Read a real engagement write-up | [Finding: pi.hole 192.168.1.26](examples/finding-pi-hole-192-168-1-26.md) |
| See the tech-debt & feature backlog | [Tech debt & features](dev/tech-debt-and-features.md) |
| Write code against h4k | [API reference](dev/api.md) |
| Understand the internals | [Architecture](dev/architecture.md) |
| Run the tests | [Testing guide](dev/testing.md) |
| Review before shipping | [Threat model](security/threat-model.md) |

## The 30-second summary

```
docker compose up --build          # platform on http://localhost:3137
```

Then, in the browser:

1. **Set the scope** — header scope picker → pick an engagement.
2. **Discover** — Workflow strip (Scope → Scan → Fingerprint → Win), target + **Scan**.
3. **Judge** — **Recon** tab: *Services* and *Likely Vulnerable* findings.
4. **Act** — every aggressive action is opt-in and named in the log.
5. **Report** — **Score** tab → **Report** → Download MD.

## Two modes of operation

| Mode | What it is | How to run it |
|---|---|---|
| **Real** | Scans, brute-forces and exploits real hosts you own | `docker compose up --build` |
| **Sandbox** | Deterministic fake lab estate — no network, no daemon | `H4K_SANDBOX=1 python3 -m uvicorn main:app` |

Sandbox mode exists for demos, CI and the Selenium suite. See
[testing guide](dev/testing.md#sandbox-mode).

## Repository map

```
h4k/
├── api/          FastAPI app (routers + ~65 services)
├── web/          the console (index.html + app.js + style.css)
├── data/         CVE archive, credential archive, wordlists
├── scripts/      DNS recon helpers
├── docs/         this documentation set
├── tests/        pytest suite (unit + API) and tests/e2e (Selenium)
└── vulnlab/      deliberately vulnerable fuzzing target (separate image)
```
