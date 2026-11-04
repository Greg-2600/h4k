# Examples

Runnable, copy-pasteable snippets for the h4k API.

---

## 1. A complete engagement, end to end

```sh
BASE=http://127.0.0.1:3137

# 1. declare the authorized scope
ENG=$(curl -s -X POST $BASE/api/engagement \
  -H 'Content-Type: application/json' \
  -d '{"name":"lab","scope":["192.168.1.0/24"],"notes":"demo"}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])')

# 2. arm it
curl -s -X POST $BASE/api/session/scope \
  -H 'Content-Type: application/json' -d "{\"engagement_id\":\"$ENG\"}"

# 3. scan
JOB=$(curl -s -X POST $BASE/api/scan \
  -H 'Content-Type: application/json' \
  -d '{"target":"192.168.1.0/24","mode":"overt","depth":"standard"}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])')

# 4. wait for it
until [ "$(curl -s $BASE/api/jobs/$JOB | python3 -c 'import sys,json;print(json.load(sys.stdin)["status"])')" = "done" ]; do sleep 5; done

# 5. fold the result into the engagement graph
curl -s -X POST $BASE/api/engagement/$ENG/ingest \
  -H 'Content-Type: application/json' -d "{\"job_id\":\"$JOB\"}"

# 6. declare the objective and compute the paths to it
curl -s -X POST $BASE/api/engagement/$ENG/crown-jewels \
  -H 'Content-Type: application/json' \
  -d '{"host":"192.168.1.1","label":"router","value":90}'

curl -s $BASE/api/engagement/$ENG/attack-paths | python3 -m json.tool | head -40

# 7. ATT&CK view
curl -s $BASE/api/engagement/$ENG/attck | python3 -m json.tool | head -30
```

---

## 2. Attack-path output

```json
{
  "crown_jewel_id": "109b37a6ab80",
  "crown_jewel_host": "10.10.10.42",
  "crown_jewel_label": "Domain controller",
  "entry": "10.10.10.5",
  "nodes": ["10.10.10.5", "10.10.10.9", "10.10.10.42"],
  "edges": [
    {"type": "pivot", "user": "admin", "service": "ssh", "technique": "T1021"},
    {"type": "pivot", "user": "backup", "service": "ssh", "technique": "T1021"}
  ],
  "hops": 2,
  "vulns": [
    {"host": "10.10.10.5", "name": "OpenSSH outdated (CVE-2021-41617)", "severity": "high"}
  ],
  "techniques": ["T1021"],
  "score": 131
}
```

Read it as: *from the foothold at 10.10.10.5, the `admin` account reaches the
jump host, and from there the `backup` account reaches the domain
controller — two hops, one high-severity CVE on the way in.*

---

## 3. ATT&CK entry

```json
{
  "id": "T1110",
  "name": "Brute Force",
  "tactic": "Credential Access",
  "description": "Adversaries try many passwords until one works.",
  "detection": {
    "log_sources": ["authentication logs", "SSH/auth.log", "Windows 4625"],
    "event_ids": ["Linux auth.log failed password", "Windows 4625", "4771"],
    "notes": "Many failed logins from one source, then a success; lockout thresholds."
  }
}
```

---

## 4. Sandbox demo (no network, no daemon)

```sh
cd h4k/h4k/api
H4K_SANDBOX=1 H4K_DATA_DIR=/tmp/h4k-demo \
  python3 -m uvicorn main:app --port 3137

# seed a demo engagement with hosts, a pivot credential and a crown jewel
curl -s -X POST http://127.0.0.1:3137/api/engagement/sandbox-seed | python3 -m json.tool
```

Then open <http://127.0.0.1:3137> — the header scope picker shows
`scope: sandbox lab`.

---

## 5. Fuzzing your own service

```sh
# the bundled lab
cd vulnlab && docker build -t vulnlab . && \
  docker run --rm --name vulnlab -p 127.0.0.1:8080:8080 vulnlab

# fuzz it
curl -s -X POST http://127.0.0.1:3137/api/fuzz \
  -H 'Content-Type: application/json' \
  -d '{"target":"127.0.0.1","port":8080,"iterations":2000,"timeout":60}' \
  | python3 -m json.tool
```

---

## 6. Selenium against the sandbox

```sh
pip install selenium
sudo pacman -S chromium chromedriver      # Arch
H4K_E2E=1 pytest tests/e2e -v
```

The suite starts its own API on a free port, seeds the lab estate, and drives
the console. It fails the test if the browser logs an uncaught JavaScript
error — which is how the missing `renderReportPreview()` bug was found.
