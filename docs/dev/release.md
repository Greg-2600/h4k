# Release process

## Versioning

Semantic versioning, `MAJOR.MINOR.PATCH`:

* **MAJOR** — API/CLI breaking changes.
* **MINOR** — new features, new endpoints.
* **PATCH** — fixes.

The version lives in `h4k/api/main.py` (`FastAPI(version=...)`) and in the
release script.

## Cutting a release

```sh
# 1. make sure the tree is green
make lint && make test && make e2e

# 2. bump the version + changelog
#    h4k/api/main.py -> version="1.1.0"
#    RELEASE_NOTES.md -> new section

# 3. build, tag, push the image
./scripts/release.sh 1.1.0
```

`scripts/release.sh` builds `h4k:latest` and `h4k:1.1.0`, tags the git
commit, pushes the image, and prints the one-line `docker run` for the
release notes.

## Checklist

- [ ] `make lint` green
- [ ] `make test` green (coverage ≥ 90%)
- [ ] `make e2e` green (Selenium)
- [ ] Version bumped in `h4k/api/main.py`
- [ ] `RELEASE_NOTES.md` updated (features + design decisions)
- [ ] `ROADMAP.md` updated (ticks for what shipped)
- [ ] `docs/` updated where behaviour changed
- [ ] `AGENTS.md` updated if structure changed
- [ ] Git tag pushed

## Image notes

* The image is `debian:12-slim` based and installs the offensive toolchain
  (nmap, hydra, nikto, sqlmap, gobuster, semgrep, trivy, osv-scanner,
  ZAP, Nuclei, impacket, chisel, Metasploit).
* `docker build` alone does **not** start the platform — you must
  `docker run` or `docker compose up`.
* Runtime data lives in the `h4k_data` volume so sessions survive rebuilds.

## Post-release

* Tag the release on GitHub with the changelog section.
* Announce the one-liner:

```sh
docker run -d --name h4k --network host -p 3137:3137 \
  -v h4k_data:/opt/h4k/data \
  -e API_PORT=3137 -e MSF_PASSWORD=h4k_msf_rocks \
  h4k:1.1.0
```

## Rolling back

```sh
docker compose down
docker run -d --name h4k --network host -p 3137:3137 \
  -v h4k_data:/opt/h4k/data h4k:1.0.0
```

The data volume is schema-additive, so an older image can usually read a
newer database. Back up `h4k_data` first anyway — see
[data-model.md](data-model.md#backup).
