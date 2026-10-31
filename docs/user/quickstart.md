# Quickstart

Get h4k running and get your first result — about ten minutes.

## 0. The one rule

**Only point h4k at systems you own or have written permission to test.**
Scanning, brute-forcing and exploiting someone else's network without
authorization is illegal in most jurisdictions. See [safety](safety.md).

---

## 1. Run the platform (Docker)

```sh
git clone https://github.com/Greg-2600/h4k.git
cd h4k/h4k
docker compose up --build -d
```

* Web UI: <http://localhost:3137>
* API docs: <http://localhost:3137/docs>
* Fuzzing lab: <http://localhost:3138>

> **Networking.** The default compose file uses a bridge network, so the
> container gets its own network stack and its postgres/Metasploit ports
> cannot collide with services already running on your host. If you need
> LAN-wide ARP discovery (arp-scan only sees the real LAN in host mode),
> use the host-network override:
>
> ```sh
> docker compose -f docker-compose.yml -f docker-compose.host.yml up -d
> ```
>
> In host mode the container shares your host's ports, so something already
> listening on 5432/5433/55553 will break the Metasploit database.

The `h4k_data` volume keeps your session (discovered hosts, services,
findings, verified credentials) across container rebuilds, and your chosen
scope persists too.

> `docker build` alone does **not** start anything. Use `docker compose up`.

### Optional: AI triage (keyless)

h4k can hand crashes to a local model for root-cause analysis:

```sh
# on the host, before the container
OPENCODE_MODEL=opencode/beam-free python3 h4k/scripts/opencode_relay.py
```

Then run the container with:

```sh
-e H4K_AI_PROVIDER=openai_compatible -e H4K_AI_KEYLESS=1 \
-e H4K_AI_URL=http://127.0.0.1:3777/v1/chat/completions \
-e H4K_AI_MODEL=opencode/beam-free
```

Any OpenAI-compatible gateway works — h4k never requires a key.

---

## 2. Run without Docker (host install)

Useful on a workstation you control (Arch/Ubuntu/macOS).

```sh
cd h4k/h4k/api
python3 -m venv .venv && source .venv/bin/activate
pip install -r ../../requirements.txt

# tools the platform shells out to
sudo apt install nmap arp-scan hydra nikto gobuster        # Debian/Ubuntu
sudo pacman -S nmap arp-scan hydra nikto gobuster           # Arch

MSF_HOST=127.0.0.1 MSF_PORT=55553 MSF_PASSWORD=h4k_msf_rocks \
  python3 -m uvicorn main:app --host 127.0.0.1 --port 3137
```

Metasploit is optional on a host install: without it, recon, fingerprinting,
CVE correlation, the toolkit and the whole analysis stack still work — only
module execution is unavailable.

---

## 3. Set your scope (mandatory for aggressive actions)

The scope is not a suggestion: it is stored with the engagement and enforced
in the data layer, not in the UI.

```sh
curl -X POST http://127.0.0.1:3137/api/engagement \
  -H 'Content-Type: application/json' \
  -d '{"name":"my lab","scope":["192.168.1.0/24"],"notes":"home lab"}'
```

Then activate it (or use the header 🔒 picker in the UI):

```sh
curl -X POST http://127.0.0.1:3137/api/session/scope \
  -H 'Content-Type: application/json' \
  -d '{"engagement_id":"<id from above>"}'
```

---

## 4. First recon

**In the UI:** the **Discover** tab walks you through Scope → Scan →
Fingerprint → Win (click any step to jump there). Enter a target, pick a
mode, hit **Scan**; results flow into the **Recon** tab — **Fingerprint
services**, then review **Likely vulnerable**.

**From the API:**

```sh
curl -X POST http://127.0.0.1:3137/api/scan \
  -H 'Content-Type: application/json' \
  -d '{"target":"192.168.1.0/24","mode":"overt","do_dns_recon":true}'
```

Poll `GET /api/jobs/{id}` until `status` is `done`, then read
`GET /api/report/{id}`.

---

## 5. The one-button walk

**Exploit** tab → **Autopilot** card → **Start full attack** does the whole
flow: discovery → fingerprinting → CVE correlation → password attacks →
exploit attempts. It requires an active scope and logs every named action
as it goes.

```sh
curl -X POST http://127.0.0.1:3137/api/autopilot/start -d '{}' \
  -H 'Content-Type: application/json'
curl -s http://127.0.0.1:3137/api/autopilot/status | jq
```

---

## 6. Read the report

**Score** tab → **Report** card → **Download MD**: scope, hosts, services,
findings, verified credentials, sessions and every action attempted.

---

## 7. (Optional) The fuzzing lab

`vulnlab` is a deliberately vulnerable HTTP server used as a fuzzing target.

```sh
cd vulnlab
docker build -t vulnlab .
docker run --rm --name vulnlab -p 127.0.0.1:8080:8080 vulnlab
```

Point the **Exploit** tab's **Fuzz lab** card at `127.0.0.1:8080` (or try
the **Container surfaces** card for Docker/kubelet/gRPC targets).

---

## Next

- [Concepts](concepts.md) — scope, OPSEC modes, depth, coverage
- [Workflows](workflows.md) — the full playbooks
- [Troubleshooting](troubleshooting.md) — when it does not work
