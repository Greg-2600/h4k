# Safety & authorization

**h4k is a tool for systems you own or have written permission to test.**

Scanning, brute-forcing, or exploiting systems you do not own is illegal in
most jurisdictions (e.g. CFAA in the US, Computer Misuse Act in the UK,
§202a StGB in Germany) and can carry serious civil and criminal liability.
"I was only testing" is not a defence without written authorization.

---

## What h4k refuses to do by default

* **No credential testing** until you opt in.
* **No exploit execution** until you opt in.
* **No brute forcing, directory brute forcing, SQL injection, NSE scripting,
  container escape helpers, lateral movement, or packet capture** until you
  explicitly call them.
* A plain scan only **reconnoiters and advises**.

## What h4k never does

* It never attacks a host outside the active engagement scope. Scope is
  checked in the data layer, so a mistyped target in the UI cannot widen the
  engagement.
* It never fabricates findings. If a scanner did not report something, h4k
  does not print it. The CVE archive is banner-aware (a "CherryPy" banner is
  not a Log4Shell), SCA needs a real lockfile, and SBOM reachability is
  labelled honestly as a dependency-graph claim, not a call-graph claim.
* It does not distribute weapons. Generated PoCs are **disclosure
  skeletons** — a reproduction recipe and a patch direction, not a payload.
* It does not exfiltrate anything. Data stays in your `h4k_data` volume.

## Before you scan

1. **Get authorization in writing.** A ticket, an email, a signed scope
   document. Note the exact hosts and the window.
2. **Define the scope in h4k**, not in your head:
   ```sh
   curl -X POST http://127.0.0.1:3137/api/engagement \
     -H 'Content-Type: application/json' \
     -d '{"name":"acme red","scope":["10.0.0.0/24"],"notes":"signed SOW-2026-14"}'
   ```
3. **Set the active scope** (header 🔒 picker or
   `POST /api/session/scope`). With no scope, aggressive actions are refused.
4. **Know the blast radius of the action you are about to click.** Password
   attacks lock accounts; exploit attempts crash services; propagation tries
   logins across the estate.

## Credential handling

* Verified credentials are stored **in the clear** inside `engagements.db`
  (mode `0600`). That is a deliberate trade-off: the tool must be able to
  replay what it found. Protect the volume like a password manager.
* The credential store is excluded from git, and the data directory is
  mounted as a volume, not committed.
* Never paste real credentials into a shared h4k instance, a demo box, or a
  GitHub issue.
* If a host may be monitored, prefer `stealth` mode and understand that even
  "stealth" traffic is traffic.

## Data handling and disclosure

* Reports contain **verified credentials in plaintext**. Redact before
  sharing.
* A responsible disclosure report should contain: what you found, how you
  found it, the impact, and a **reproduction that is safe for the vendor to
  run**. h4k's PoC skeleton is designed for that.
* Delete `h4k_data` when the engagement closes if the credentials are no
  longer needed:
  ```sh
  docker volume rm h4k_data
  ```

## Red-team and CTF work

h4k is explicitly built for **labs**: your own VMs, a test router, a
deliberately vulnerable box, or the bundled `vulnlab` target. Running it
against infrastructure you do not own — including third-party SaaS, CDNs or
"random IPs on the internet" — is out of scope and out of bounds.

## Reporting a problem

If you find a bug in h4k that could lead to unintended attacks (for example a
scope check that can be bypassed), report it privately to the maintainer
rather than exploiting it.
