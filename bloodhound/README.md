# BloodHound CE sidecar (#92)

The wrapper in `h4k/api/services/bloodhound_ce.py` talks to BloodHound Community
Edition over its v2 REST API. This compose profile runs the CE stack locally:
the application, PostgreSQL, and Neo4j.

```sh
# from the repo root
BH_PORT=8081 docker compose -f h4k/docker-compose.yml --profile bloodhound up -d bloodhound
# UI: http://127.0.0.1:8081/ui
```

`BH_PORT` defaults to `8080`; use another port if something else owns it (an SSH
tunnel, another lab UI). The CE container creates a default `admin` account on
first boot and prints the generated password:

```sh
docker logs h4k-bloodhound-1 2>&1 | grep "Initial Password"
```

Then point h4k at it (use the same port and the password printed above):

```sh
-e H4K_BLOODHOUND_URL=http://127.0.0.1:8081 \
-e H4K_BLOODHOUND_USER=admin \
-e H4K_BLOODHOUND_PASS='<Initial Password from docker logs>'
```

## What the wrapper covers

| Endpoint | Purpose |
|---|---|
| `GET /api/bloodhound/status` | reachability + authenticated identity |
| `POST /api/bloodhound/login` | exchange username/secret for a session token |
| `POST /api/bloodhound/collect` | run `bloodhound-python` into a temp dir (no upload) |
| `POST /api/bloodhound/upload` | upload a collected zip via the 3-step CE upload API |
| `POST /api/bloodhound/collect-upload-analyze` | the whole loop |
| `POST /api/bloodhound/analyze` | start analysis or wait for completion |
| `POST /api/bloodhound/query` | run a saved query (`name`) or raw Cypher |
| `POST /api/bloodhound/shortest-path` | shortest path between two principals |

Saved queries: `kerberoastable`, `asrep_roastable`, `domain_admins`,
`unconstrained_delegation`, `high_value_hosts`, `sessions_to_domain_admins`.

## Notes

- Verified against `specterops/bloodhound:latest` in November 2026: the app
  starts, creates the default admin, exposes `GET /api/v2/self`,
  `POST /api/v2/login` (with `login_method: secret`), the 3-step upload API,
  `PUT /api/v2/analysis`, `GET /api/v2/analysis/status` and
  `POST /api/v2/graphs/cypher`.
- CE returns `404 resource not found` for a Cypher query on a label that does not
  exist yet; the wrapper turns that into an empty result.
- CE image/env names change between releases. If the app container exits, check
  the CE release notes and adjust `bhe_database_connection` /
  `bhe_neo4j_connection` in `docker-compose.yml`.
- Neo4j 4.4 is intentional: CE's graph schema is built for it. Do not bump to 5
  without checking CE compatibility.
- This is a lab stack. It holds the full identity graph of the lab domain; keep
  it on loopback and never reuse the default passwords outside the lab.
