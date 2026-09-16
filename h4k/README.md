# h4k — Metasploit Recon & Advisory Toolkit

School cybersecurity project: a **web UI → FastAPI → Metasploit RPC** pipeline that
takes a target (IP or domain), runs recon + vulnerability scanning in one of three
OPSEC modes, produces a vulnerability report, and lists prioritized attack
recommendations. **This version stops short of auto-exploitation** — it advises,
it does not attack.

> **Authorization required.** Use only against systems you own or have written
> authorization to test (e.g. your school lab range, your own VMs).

## What it does

1. **Target input** — IP, hostname, or CIDR.
2. **Mode**
   - `stealth` — slow, non-invasive probes (`-T2`, low version intensity, no OS detect).
   - `tor` — routes module traffic through Tor SOCKS (`Proxies socks5:127.0.0.1:9050`)
     and wraps the whole pipeline in `proxychains`.
   - `overt` — fast, full scan (`-T4 -sV -O`, top 1000 ports).
3. **Optional DNS recon** — wraps your `dns_dumpster.sh`, `sub_domain_lookup.sh`,
   `reverse_dns_lookup.sh` tools to enrich the footprint.
4. **Vuln scan** — `db_nmap` imports discovered hosts/services into the Metasploit DB;
   then built-in `auxiliary/scanner/*` modules run per detected service
   (http, smb, ftp, ssh, rdp, mysql, mssql, postgres, telnet).
5. **Recommendations** — findings are scored/ranked into "what to attack" cards with
   suggested Metasploit module names, difficulty, and rationale. **Nothing is launched.**

## Reuse philosophy

Metasploit's native RPC (`msfrpcd`), its `db_nmap` + auxiliary scanner library, and
`analyze` already cover most scanning. Your GitHub bash tools add DNS footprinting on
top; they are invoked as subprocesses and their text output surfaced in the report notes.

## Build & run

```sh
# build
docker build -t h4k .

# run (binds web/API). --network host so the container can reach local lab hosts
docker run --rm --network host \
  -e API_PORT=3137 \
  -e MSF_PASSWORD=h4k_msf_rocks \
  h4k

# or via compose
docker compose up --build
```

Then open the web UI:

```
http://localhost:3137
```

The entrypoint starts PostgreSQL, initializes the Metasploit DB, starts Tor,
launches `msfrpcd` (MessagePack RPC on `:55553`), and serves the FastAPI app
+ static UI on **0.0.0.0:3137**.

### Health check

```sh
curl http://localhost:3137/api/health
```

### REST endpoints

| Method | Path                | Purpose                                    |
|--------|---------------------|--------------------------------------------|
| POST   | `/api/scan`         | Start a scan job `{target, mode, ...}`     |
| GET    | `/api/jobs/{id}`    | Poll job status/progress                   |
| GET    | `/api/report/{id}`  | Fetch the finished report                  |
| GET    | `/api/health`       | Health + msfrpcd reachability              |

## Layout

```
Dockerfile          container: postgres + tor + proxychains + metasploit + api
docker-compose.yml  single-service compose
entrypoint.sh       starts db, msfdb, tor, msfrpcd, uvicorn
api/
  main.py           FastAPI app (serves UI + API)
  routers/scan.py   REST endpoints + job tracking
  services/
    msfrpc.py       pymetasploit3 wrapper
    scan_pipeline.py orchestrator (recon -> scan -> analyze)
    modes.py        stealth / tor / overt configuration
    report.py       scoring + attack recommendations
web/                plain HTML/JS/CSS frontend
scripts/            your GitHub recon tools + scan.sh
```

## Safety / scope note

- **No auto-exploitation.** The tool reports and recommends only.
- **OPSEC/anonymity** (Tor/proxychains) is a valid defense-in-depth exercise in a
  sanctioned lab, but does *not* make unauthorized scanning legal or ethical.
  Confirm written authorization before every run.
