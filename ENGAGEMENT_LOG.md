# CTF Engagement Log - 192.168.1.13 (zhc3 stack)

## Target
- **Host**: 192.168.1.13 (greg-ThinkPad-T530)
- **Stack**: zhc3 orchestrator + CAD worker + Ollama
- **Network**: 192.168.1.13/24 (local LAN)

## Timeline
- **Start**: Full-depth scan (-p-) revealed 5 ports: 22, 1716, 4546, 11435, 18799
- **Foothold**: Root RCE on CAD worker (port 18799) via `/render/cadquery` exec()
- **Escalation**: Unauthenticated config write on orchestrator (PUT /system/config/{key})

## Current State (2026-10-01)

| Service | Port | Status |
|---------|------|--------|
| SSH | 22 | ✅ UP |
| Port 1716 | 1716 | ✅ UP (tcpwrapped) |
| Orchestrator | 4546 | ❌ DOWN |
| CAD Worker | 18799 | ❌ DOWN |
| Ollama | 11435 | ❌ DOWN |
| Port 1716 | 1716 | ✅ UP (tcpwrapped) |

## Achievements
✅ **Root RCE on CAD worker** (port 18799) via `/render/cadquery` exec()
- `uid=0(root)` in container `acab630979d5`
- Host PID namespace shared → `/proc/1/root` = host filesystem root

✅ **Unauthenticated config write** on orchestrator
- `PUT /system/config/{key}` flips `ZHC3_MIN_DESIRABILITY_SCORE` source `registry`→`db`
- `set_by=h4k` confirms write succeeded

## Flag Status
| Location | Status |
|----------|--------|
| `/shared-work/user/flag.txt` | **EMPTY** (0 bytes) |
| `/proc/1/root` (host FS) | No flag files |
| Orchestrator API | No flag in listings, config, or DB |
| Orchestrator DB | Not accessible (5432 closed, container localhost-only) |
| CAD worker `/shared-work` | Only empty flag.txt + old RCE artifacts |

## Container Status (via host Docker)

| Container | Port | Status |
|-----------|------|--------|
| zhc3-cad-worker | 18799 | DOWN |
| zhc3-orchestrator | 4546 | DOWN |
| ollama | 11435 | DOWN |
| Port 1716 | 1716 | tcpwrapped (unknown) |

## Host Access (via container)
- PID namespace shared: `/proc/1/root` = host root FS
- Host `/etc/passwd` readable via `/proc/1/root/etc/passwd`
- Host `/home/greg/projects/zhc3/` accessible via `/proc/1/root/home/greg/projects/zhc3/`
- No SSH keys, no flag files found in host FS

## Next Pivots (require host access)
1. **Restart containers** via host Docker: `docker start zhc3-orchestrator zhc3-cad-worker ollama`
2. **SSRF via config write** → set `CAD_WORKER_URL` to attacker, trigger pipeline
3. **Orchestrator pipeline RCE** - debug 500 on `/run_pipeline`
3. **Port 1716** - protocol analysis needed
4. **SSH brute** - host SSH (port 22) password auth enabled

## Repo State
- **Commits**: 4 new commits this session
- **Tests**: 531 passing
- **Lint**: Green (ruff, black, isort, flake8, mypy, pylint, bandit)
- **Coverage**: 79% (gate 70%)
- **Container**: `h4k:latest` rebuilt with all tools

## Next Steps
1. Need host access to restart containers: `docker start zhc3-orchestrator zhc3-cad-worker ollama`
2. Then re-engage orchestrator API + CAD worker
3. Exploit pipeline RCE or SSRF via config write
4. Flag likely in orchestrator DB or host filesystem
