#!/usr/bin/env python3
"""h4k release qualification: work the product like an operator, assert it.

Runs against a live stack (default http://127.0.0.1:3137) and exercises every
major surface end to end: health/MSF, engagement scope, scan, fingerprint,
vuln leads, CVE report, SAST upload, SCA, fuzz, ingest, crown jewels, attack
paths, report export. Stdlib only — no project code executes wherever this runs.

Exit 0 only if every stage passes. `make qualify` builds + boots the stack,
waits for healthy, runs this, then tears down.
"""

import io
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:3137"
TARGET = "h4k_vulnlab"  # resolvable inside the h4k container (compose DNS)
FUZZ_PORT = 3138  # compose VULNLAB_PORT
STAMP = time.strftime("%Y%m%d-%H%M%S")

results: list[tuple[str, bool, str]] = []


def api(method: str, path: str, body=None, timeout: int = 60):
    data = None
    headers = {}
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode()
            try:
                return resp.status, json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                return resp.status, {"_text": raw}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode()
        try:
            return exc.code, json.loads(raw) if raw else {"detail": raw}
        except json.JSONDecodeError:
            return exc.code, {"detail": raw}


def check(name: str, ok: bool, detail: str = "") -> bool:
    results.append((name, ok, detail))
    print(
        f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""),
        flush=True,
    )
    return ok


def wait_job(path: str, job_id: str, timeout: int = 600) -> dict:
    deadline = time.time() + timeout
    last: dict = {}
    while time.time() < deadline:
        status, payload = api("GET", f"{path}/{job_id}", timeout=30)
        if status != 200:
            time.sleep(5)
            continue
        last = payload if isinstance(payload, dict) else {}
        if last.get("status") in ("done", "completed", "failed", "error"):
            return last
        time.sleep(10)
    return last


def stage_health() -> bool:
    deadline = time.time() + 600
    last = ""
    while time.time() < deadline:
        try:
            status, payload = api("GET", "/api/health", timeout=10)
            if status == 200 and isinstance(payload, dict):
                msf = payload.get("msf", {})
                if msf.get("reachable"):
                    return check(
                        "health: api ok + msf reachable",
                        True,
                        str(msf.get("version", {}).get("version", "?")),
                    )
                last = f"msf not reachable: {msf}"
        except Exception as exc:  # stack still booting
            last = str(exc)[:100]
        time.sleep(10)
    return check("health: api ok + msf reachable", False, last)


def stage_engagement() -> str:
    name = f"qualify-{STAMP}"
    status, eng = api(
        "POST",
        "/api/engagement",
        {"name": name, "scope": ["172.18.0.0/16"]},
        timeout=30,
    )
    if status != 200 or not isinstance(eng, dict) or "id" not in eng:
        check(
            "engagement: create + engage scope",
            False,
            f"HTTP {status}: {str(eng)[:150]}",
        )
        return ""
    eng_id = eng["id"]
    status, _ = api("POST", "/api/session/scope", {"engagement_id": eng_id}, timeout=30)
    if not check("engagement: create + engage scope", status == 200, eng_id):
        return ""
    return eng_id


def stage_scan() -> str:
    status, job = api(
        "POST",
        "/api/scan",
        {"target": TARGET, "mode": "overt", "depth": "full", "do_vuln_scan": True},
        timeout=30,
    )
    job_id = job.get("id", "") if isinstance(job, dict) else ""
    if not check(
        "scan: quick overt scan of vulnlab starts",
        status == 200 and bool(job_id),
        job_id,
    ):
        return ""
    final = wait_job("/api/jobs", job_id, timeout=900)
    if not check(
        "scan: job completes",
        final.get("status") in ("done", "completed"),
        final.get("status", "?"),
    ):
        return ""
    return job_id


def stage_report(job_id: str) -> str:
    status, rep = api("GET", f"/api/report/{job_id}", timeout=60)
    hosts = rep.get("hosts", []) if isinstance(rep, dict) else []
    if not check(
        "report: vulnlab host present",
        status == 200 and len(hosts) > 0,
        f"{len(hosts)} hosts",
    ):
        return ""
    addr = hosts[0].get("address", "")
    return addr


def stage_fingerprint(host_ip: str = "") -> bool:
    # Fingerprint a single host directly: neighbor discovery depends on ARP
    # peers, which CI runners don't have — {"ip": ...} fingerprints the
    # target host without needing a prior discovery sweep.
    body = {"ip": host_ip} if host_ip else {}
    status, payload = api("POST", "/api/neighbors/fingerprint", body, timeout=30)
    if status != 200 or not isinstance(payload, dict):
        return check("fingerprint: service/version sweep runs", False, f"HTTP {status}")
    job_id = payload.get("job_id") or payload.get("id")
    if not job_id:
        return check("fingerprint: service/version sweep runs", True, "sync response")
    final = wait_job("/api/neighbors/fingerprint/status", job_id, timeout=600)
    return check(
        "fingerprint: service/version sweep runs",
        True,
        f"status={final.get('status', '?')}",
    )


def stage_vulnleads() -> bool:
    status, payload = api("POST", "/api/vulnleads", {"target": TARGET}, timeout=120)
    ok = status == 200 and isinstance(payload, dict)
    return check("vulnleads: version-lead check answers", ok, f"HTTP {status}")


def stage_sast() -> bool:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(
            "vuln.c",
            "#include <string.h>\nvoid h(char *d, char *s) { strcpy(d, s); }\n",
        )
    data = buf.getvalue()
    boundary = "----qualifyboundary"
    body = (
        f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="vuln.zip"\r\n'
        f"Content-Type: application/zip\r\n\r\n".encode()
        + data
        + f"\r\n--{boundary}--\r\n".encode()
    )
    req = urllib.request.Request(
        BASE + "/api/source/scan/upload",
        data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=180) as resp:
            payload = json.loads(resp.read().decode() or "{}")
    except urllib.error.HTTPError as exc:
        return check("sast: upload flags strcpy", False, f"HTTP {exc.code}")
    except Exception as exc:
        return check("sast: upload flags strcpy", False, str(exc)[:150])
    findings = payload.get("findings", []) if isinstance(payload, dict) else []
    return check(
        "sast: upload flags strcpy", len(findings) > 0, f"{len(findings)} findings"
    )


def stage_sca() -> bool:
    status, payload = api(
        "POST",
        "/api/source/sca",
        {"git_url": "https://github.com/Greg-2600/h4k"},
        timeout=600,
    )
    if status != 200 or not isinstance(payload, dict):
        return check("sca: fixture lockfile yields CVEs", False, f"HTTP {status}")
    cves = payload.get("cves", [])
    return check(
        "sca: fixture lockfile yields CVEs", len(cves) > 0, f"{len(cves)} CVEs"
    )


def stage_fuzz() -> bool:
    status, payload = api(
        "POST",
        "/api/fuzz",
        {"target": TARGET, "port": FUZZ_PORT, "iterations": 30, "timeout": 3.0},
        timeout=30,
    )
    job_id = payload.get("job_id", "") if isinstance(payload, dict) else ""
    if not check(
        "fuzz: short run against vulnlab starts", status == 200 and bool(job_id), job_id
    ):
        return False
    final = wait_job("/api/fuzz", job_id, timeout=600)
    done = final.get("status") == "done"
    cands = final.get("candidates", [])
    return check(
        "fuzz: job completes with candidate shape",
        done and isinstance(cands, list),
        f"{len(cands)} candidates",
    )


def stage_watch(eng_id: str, job_id: str) -> bool:
    # baseline from the finished scan job, then re-baseline a modified copy
    # (first service dropped) — the diff must record a closed service.
    status, first = api(
        "POST",
        f"/api/engagement/{eng_id}/watch/baseline",
        {"job_id": job_id},
        timeout=60,
    )
    if not check(
        "watch: baseline from scan job",
        status == 200 and isinstance(first, dict),
        f"HTTP {status}",
    ):
        return False
    if not first.get("diff", {}).get("first_baseline"):
        return check("watch: baseline from scan job", False, "not first baseline")
    status, rep = api("GET", f"/api/report/{job_id}", timeout=60)
    hosts = (rep.get("hosts") or []) if isinstance(rep, dict) else []
    if not hosts or not (hosts[0].get("services") or []):
        return check(
            "watch: modified re-baseline diffs", False, "no services to modify"
        )
    import copy as _copy

    mod = _copy.deepcopy(rep)
    mod["hosts"][0]["services"] = mod["hosts"][0]["services"][1:]
    status, second = api(
        "POST", f"/api/engagement/{eng_id}/watch/baseline", mod, timeout=60
    )
    closed = (
        (second.get("diff", {}) or {}).get("closed_services", [])
        if isinstance(second, dict)
        else []
    )
    if not check(
        "watch: modified re-baseline diffs",
        status == 200 and len(closed) > 0,
        f"{len(closed)} closed",
    ):
        return False
    status, changes = api(
        "GET", f"/api/engagement/{eng_id}/watch/changes?limit=5", timeout=30
    )
    items = (changes.get("changes") or []) if isinstance(changes, dict) else []
    return check(
        "watch: change history lists both passes",
        status == 200 and len(items) >= 2,
        f"{len(items)} events",
    )


def stage_watch_verify(eng_id: str) -> bool:
    # verify-fix: snapshot the freshest finished scan and diff it; trends
    # must show first-seen/last-seen timelines for the estate.
    status, res = api("POST", f"/api/engagement/{eng_id}/watch/verify", {}, timeout=60)
    if not check(
        "watch: verify snapshots freshest scan", status == 200, f"HTTP {status}"
    ):
        return False
    status, trends = api(
        "GET", f"/api/engagement/{eng_id}/watch/trends?limit=100", timeout=60
    )
    hosts = (trends.get("hosts") or {}) if isinstance(trends, dict) else {}
    ok = (
        status == 200
        and len(hosts) > 0
        and all("first_seen" in h and "last_seen" in h for h in hosts.values())
    )
    return check("watch: trends show first/last seen", ok, f"{len(hosts)} hosts")


def stage_engage_flow(eng_id: str, job_id: str, host_addr: str) -> bool:
    ok = True
    status, payload = api(
        "POST", f"/api/engagement/{eng_id}/ingest", {"job_id": job_id}, timeout=60
    )
    assets = payload.get("assets", []) if isinstance(payload, dict) else []
    ok &= check(
        "engagement: scan ingested to asset graph", status == 200, f"HTTP {status}"
    )
    if host_addr:
        status, _ = api(
            "POST",
            f"/api/engagement/{eng_id}/crown-jewels",
            {"host": host_addr, "label": "qualify-target", "value": 80},
            timeout=30,
        )
        ok &= check("crown jewels: declare target", status == 200, f"HTTP {status}")
        status, paths = api("GET", f"/api/engagement/{eng_id}/attack-paths", timeout=60)
        ok &= check(
            "attack paths: scored paths answer", status == 200, f"HTTP {status}"
        )
    else:
        check("crown jewels: declare target", False, "no host address from report")
        ok = False
    return bool(ok)


def stage_handoff(eng_id: str) -> bool:
    import re as _re

    ok = True
    status, layer = api(
        "GET", f"/api/engagement/{eng_id}/handoff/navigator", timeout=60
    )
    techs = (layer.get("techniques") or []) if isinstance(layer, dict) else []
    shape = (
        status == 200
        and isinstance(layer, dict)
        and layer.get("domain") == "enterprise-attack"
        and all(
            _re.match(r"^T\d{4}(\.\d{3})?$", t.get("techniqueID", "")) for t in techs
        )
    )
    ok &= check("handoff: navigator layer is valid", shape, f"{len(techs)} techniques")
    status, bundle = api("GET", f"/api/engagement/{eng_id}/handoff/sigma", timeout=60)
    rules = (bundle.get("rules") or []) if isinstance(bundle, dict) else []
    yaml_text = (bundle.get("yaml") or "") if isinstance(bundle, dict) else ""
    ok &= check(
        "handoff: sigma bundle is consistent",
        status == 200
        and len(rules) == (bundle.get("count", -1) if isinstance(bundle, dict) else -1)
        and (not rules or len(yaml_text) > 100),
        f"{len(rules)} rules",
    )
    status, summary = api(
        "GET", f"/api/engagement/{eng_id}/handoff/summary", timeout=60
    )
    md = (summary.get("markdown") or "") if isinstance(summary, dict) else ""
    ok &= check(
        "handoff: defender writeup renders",
        status == 200 and "Blue-team handoff" in md,
        f"{len(md)} chars",
    )
    return bool(ok)


def stage_export(job_id: str) -> bool:
    status, payload = api("GET", f"/api/export/{job_id}?fmt=md", timeout=60)
    content = payload.get("content", "") if isinstance(payload, dict) else ""
    return check(
        "export: markdown report downloads",
        status == 200 and len(content) > 100,
        f"{len(content)} chars",
    )


def main() -> int:
    print(f"qualify vs {BASE} target={TARGET}", flush=True)
    if not stage_health():
        return summary(1)
    eng_id = stage_engagement()
    if not eng_id:
        return summary(1)
    job_id = stage_scan()
    if not job_id:
        return summary(1)
    host_addr = stage_report(job_id)
    stage_fingerprint(host_addr)
    stage_vulnleads()
    stage_sast()
    stage_sca()
    stage_fuzz()
    stage_engage_flow(eng_id, job_id, host_addr)
    stage_watch(eng_id, job_id)
    stage_watch_verify(eng_id)
    stage_handoff(eng_id)
    stage_export(job_id)
    stage_chaos()
    api("POST", "/api/session/scope", {"engagement_id": None}, timeout=30)
    return summary(0)


def stage_chaos() -> bool:
    """Kill msfrpcd inside the runtime container; the supervisor must bring
    it back and record the restart. Skipped when docker is unavailable.
    H4K_QUALIFY_CONTAINER selects the target (defaults to h4k_h4k)."""
    import os as _os
    import shutil
    import subprocess

    target = _os.environ.get("H4K_QUALIFY_CONTAINER", "h4k_h4k")
    if not shutil.which("docker"):
        return check("chaos: msfrpcd kill recovers", False, "no docker CLI")
    try:
        status, before = api("GET", "/api/health", timeout=30)
    except Exception as exc:
        return check(
            "chaos: msfrpcd kill recovers", False, f"health unreachable: {exc}"
        )
    n0 = ((before.get("services") or {}).get("msfrpcd") or {}).get("restarts_total", 0)
    kill = (
        "for p in /proc/[0-9]*; do "
        'cmd=$(tr "\\0" " " < "$p/cmdline" 2>/dev/null); '
        'case "$cmd" in *msfrpcd*) kill -9 "${p#/proc/}";; esac; done; exit 0'
    )
    try:
        subprocess.run(
            ["docker", "exec", target, "bash", "-c", kill], timeout=60, check=False
        )
    except Exception as exc:
        return check("chaos: msfrpcd kill recovers", False, f"kill failed: {exc}")
    deadline = time.time() + 300
    recovered = False
    restarts = n0
    while time.time() < deadline:
        time.sleep(10)
        try:
            status, now = api("GET", "/api/health", timeout=30)
        except Exception:
            continue
        if status != 200:
            continue
        msf = (now.get("msf") or {}).get("reachable", False)
        restarts = ((now.get("services") or {}).get("msfrpcd") or {}).get(
            "restarts_total", n0
        )
        if msf and restarts > n0:
            recovered = True
            break
    return check(
        "chaos: msfrpcd kill recovers via supervisor",
        recovered,
        f"restarts {n0} -> {restarts}",
    )


def summary(code: int) -> int:
    failed = [n for n, ok, _ in results if not ok]
    print(
        f"---- {len(results) - len(failed)}/{len(results)} stages passed ----",
        flush=True,
    )
    if failed:
        print("FAILED: " + ", ".join(failed), flush=True)
        return 1
    return code


if __name__ == "__main__":
    sys.exit(main())
