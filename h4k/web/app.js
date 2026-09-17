/* ============================================================
   h4k — terminal UI (zsh/opencode-style)
   ============================================================ */
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
}[c]));

/* ---------- clock / status ---------- */
function tick() {
  $("clock").textContent = new Date().toLocaleTimeString("en-GB", { hour12: false });
}
tick();
setInterval(tick, 1000);

/* ---------- console ---------- */
const consoleEl = $("console");
function log(msg, cls = "") {
  const ln = document.createElement("div");
  ln.className = "ln " + cls;
  ln.textContent = msg;
  consoleEl.appendChild(ln);
  // keep a bounded scrollback so the TUI stays tight
  while (consoleEl.childElementCount > 800) consoleEl.removeChild(consoleEl.firstChild);
  consoleEl.scrollTop = consoleEl.scrollHeight;
}
function boot() {
  log("h4k terminal · metasploit recon suite", "sys");
  log("choose a stage · authorized scope only", "sys");
}
boot();

/* ---------- pipeline stage routing ---------- */
function setStage(name) {
  document.querySelectorAll(".stage-btn").forEach((b) => {
    b.classList.toggle("active", b.dataset.stage === name);
  });
  document.querySelectorAll(".stage").forEach((p) => {
    p.hidden = p.dataset.stage !== name;
  });
}
document.querySelectorAll(".stage-btn").forEach((b) => {
  b.addEventListener("click", () => setStage(b.dataset.stage));
});

/* ---------- target banner ---------- */
const targetBanner = $("target-banner");
function setTargetBanner(target, mode) {
  if (!target) { targetBanner.hidden = true; return; }
  $("tb-value").textContent = target;
  $("tb-mode").textContent = mode || "";
  targetBanner.hidden = false;
}
$("tb-clear").addEventListener("click", () => setTargetBanner("", ""));

/* ---------- action button busy state ---------- */
function busy(btn, on) {
  if (!btn) return;
  btn.classList.toggle("busy", !!on);
  btn.disabled = !!on;
}

/* ---------- scan form ---------- */
const form = $("scan-form"), scanBtn = $("scan-btn");
const statusPane = $("status-pane"), results = $("results");
const prog = $("prog"), pctEl = $("pct"), statusMsg = $("status-msg");
let pollTimer = null;
let currentJob = null;
// capture each source's results so the consolidated report can merge them all
let lastScanReport = null;   // host scan render() payload
let lastSast = null;         // SAST findings
let lastSca = null;          // SCA result
let lastFuzz = null;         // lab-fuzz candidates
let lastMergedReport = null; // last consolidated report (JSON)
// last SAST scan result (findings); AI button refuses to run without real data
// last OSS-Fuzz minimized crash so the AI loop can reason about a real trigger
let lastMinimized = null;
// last OSS-Fuzz auto-run result (crashes carry server-side minimized inputs)
let lastOssFuzz = null;

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  const target = $("target").value.trim();
  const mode = document.querySelector('input[name="mode"]:checked').value;
  const useCve = $("cve-toggle").checked;
  const tryCreds = $("creds-toggle").checked;
  const doAttack = $("attack-toggle").checked;
  if ((tryCreds || doAttack) && !window.confirm(
    "You are about to run an ACTIVE action against " + target +
    " (default-cred test / exploit attempt).\n\n" +
    "Only proceed if you own this system or have WRITTEN permission to test it.\n\nProceed?"
  )) {
    log("scan cancelled — active action not confirmed", "err");
    return;
  }
  setTargetBanner(target, "mode:" + mode);
  $("target").value = "";
  busy(scanBtn, true);
  $("stop-btn").disabled = false;
  $("neighbors-panel").hidden = true;
  statusPane.hidden = false;
  results.hidden = true;
  prog.style.width = "0%"; pctEl.textContent = "0";
  $("status-msg").textContent = "queued…";
  $("status-tag").textContent = "queued";
    log(`scan ${target} · mode=${mode}` + (useCve ? " · cve-db" : "")
      + (tryCreds ? " · creds" : "") + (doAttack ? " · attack" : ""), "info");
    setStage("recon");
    try {
    const resp = await fetch("/api/scan", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target, mode, do_dns_recon: true, do_vuln_scan: true,
        try_default_creds: tryCreds, open_sessions: tryCreds, do_attack: doAttack }),
    });
    if (!resp.ok) throw new Error("http " + resp.status);
    const job = await resp.json();
    currentJob = job.id;
    log(`[tracking] job ${job.id}` + (job.cached ? " (cached)" : ""), "ok");
    $("job-ind").textContent = "job:" + job.id;
    poll(job.id);
  } catch (err) {
    log("error " + err.message, "err");
    busy(scanBtn, false);
  }
});

$("stop-btn").addEventListener("click", async () => {
  if (!currentJob) return;
  log("[!] requesting abort of job " + currentJob + "…", "err");
  try {
    await fetch("/api/scan/" + currentJob + "/abort", { method: "POST" });
  } catch (err) { log("abort error " + err.message, "err"); }
});

async function doExport(fmt) {
  if (!currentJob) { log("[!] no job to export", "err"); return; }
  try {
    const resp = await fetch(`/api/export/${currentJob}?fmt=${fmt}`);
    if (!resp.ok) throw new Error("http " + resp.status);
    const data = await resp.json();
    const blob = new Blob([data.content], { type: "text/plain" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = data.filename;
    a.click();
    log(`[+] exported ${data.filename} (${fmt})`, "ok");
  } catch (err) { log("export error " + err.message, "err"); }
}
$("export-json").addEventListener("click", () => doExport("json"));
$("export-md").addEventListener("click", () => doExport("md"));

$("neighbors-btn").addEventListener("click", async () => {
  $("neighbors-panel").hidden = false;
  $("tab-neighbors").innerHTML = "sweeping local net (arp)…";
  log("[*] discovering neighbors via arp…", "info");
  try {
    const resp = await fetch("/api/neighbors");
    if (!resp.ok) throw new Error("http " + resp.status);
    const data = await resp.json();
    const nbs = data.neighbors || [];
    if (!nbs.length) { $("tab-neighbors").innerHTML = "<p class='msg'>no neighbors found via arp</p>"; return; }
    let h = "<table><tr><th>ip</th><th>mac</th><th>vendor</th><th>hostname</th></tr>";
    for (const n of nbs) {
      h += `<tr><td>${esc(n.ip)}</td><td>${esc(n.mac || "—")}</td>` +
        `<td>${esc(n.vendor || "—")}</td><td>${esc(n.hostname || "—")}</td></tr>`;
    }
    $("tab-neighbors").innerHTML = h + "</table>";
    log(`[+] ${nbs.length} neighbor(s) found`, "ok");
  } catch (err) { log("neighbors error " + err.message, "err"); $("tab-neighbors").innerHTML = "<p class='msg'>error: " + esc(err.message) + "</p>"; }
});

function poll(id) {
  clearInterval(pollTimer);
  let last = -1;
  let logCursor = 0;
  pollTimer = setInterval(async () => {
    try {
      const resp = await fetch("/api/jobs/" + id);
      if (!resp.ok) throw new Error("http " + resp.status);
      const j = await resp.json();
      const pct = Math.round(j.progress || 0);
      prog.style.width = pct + "%";
      pctEl.textContent = String(pct);
      $("status-msg").textContent = j.message || "";
      $("status-tag").textContent = j.status;
      if (pct !== last) { last = pct; log(`[${pct}%] ${j.message}`, "info"); }
      if (j.log && j.log.length > logCursor) {
        for (const line of j.log.slice(logCursor)) log(line);
        logCursor = j.log.length;
      }
      if (j.status === "done") {
        clearInterval(pollTimer);
        log("scan complete", "ok");
        $("job-ind").textContent = "idle";
        $("stop-btn").disabled = true;
        render(j.report);
        busy(scanBtn, false);
      } else if (j.status === "aborted") {
        clearInterval(pollTimer);
        log("scan aborted by operator", "err");
        $("job-ind").textContent = "idle";
        $("stop-btn").disabled = true;
        busy(scanBtn, false);
      } else if (j.status === "error") {
        clearInterval(pollTimer);
        log("error: " + (j.error || "unknown"), "err");
        $("job-ind").textContent = "idle";
        $("stop-btn").disabled = true;
        busy(scanBtn, false);
      }
    } catch (err) {
      clearInterval(pollTimer);
      $("job-ind").textContent = "idle";
      $("stop-btn").disabled = true;
      busy(scanBtn, false);
    }
  }, 1000);
}

/* ---------- rendering ---------- */
function render(r) {
  results.hidden = false;
  lastScanReport = r;
  $("report-meta").textContent =
    `${r.target} · ${r.mode} · ${(r.created_at || "").slice(11, 19)}`;
  renderHosts(r.hosts);
  renderFingerprints(r.fingerprints);
  renderVulns(r.vulns, r.mode);
  renderCreds(r.credentials);
  renderAttacks(r.attacks);
  renderSecurity(r.security);
  renderRecs(r.recommendations);
  renderNotes(r.notes);
  log(`report: ${r.hosts.length} host(s) · ${r.vulns.length} vuln(s) · ${r.recommendations.length} vector(s)`, "ok");
}

function renderFingerprints(fps) {
  const el = $("tab-fp");
  const has = fps && fps.length;
  $("box-fp").hidden = !has;
  if (!has) { el.innerHTML = "<p class='msg'>no fingerprint data</p>"; return; }
  let h = "<table><tr><th>host</th><th>vendor</th><th>model</th><th>os</th><th>technology</th><th>source</th></tr>";
  for (const f of fps) {
    h += `<tr><td>${esc(f.host)}</td><td>${esc(f.vendor || "?")}</td>` +
      `<td>${esc(f.model || "—")}</td><td>${esc(f.os || "—")}</td>` +
      `<td>${esc((f.technology || []).join(", ") || "—")}</td>` +
      `<td>${esc((f.source || []).join(", "))}</td></tr>`;
  }
  el.innerHTML = h + "</table>";
}

function renderAttacks(attacks) {
  const el = $("tab-attacks");
  const has = attacks && attacks.length;
  $("box-attacks").hidden = !has;
  if (!has) { el.innerHTML = "<p class='msg'>no attack attempts (opt-in exploit).</p>"; return; }
  let h = "<table><tr><th>host</th><th>service</th><th>module</th><th>result</th><th>session</th><th>detail</th></tr>";
  for (const a of attacks) {
    const ok = a.result === "success";
    h += `<tr><td>${esc(a.host)}</td><td>${esc(a.service)}:${esc(a.port ?? "?")}</td>` +
      `<td>${esc(a.module)}</td>` +
      `<td>${ok ? '<span class="ok">success</span>' : '<span class="err">' + esc(a.result) + '</span>'}</td>` +
      `<td>${esc(a.session_id != null ? "s" + a.session_id : "—")}</td>` +
      `<td>${esc((a.detail || "").slice(0, 80))}</td></tr>`;
  }
  el.innerHTML = h + "</table>";
}

function renderCreds(creds) {
  const el = $("tab-creds");
  const has = creds && creds.length;
  $("box-creds").hidden = !has;
  if (!has) { el.innerHTML = "<p class='msg'>no credentials tested (opt-in default).</p>"; return; }
  let h = "<table><tr><th>host</th><th>service</th><th>user</th><th>password</th><th>vendor</th><th>status</th></tr>";
  for (const c of creds) {
    h += `<tr><td>${esc(c.host)}</td><td>${esc(c.service)}:${esc(c.port ?? "?")}</td>` +
      `<td>${esc(c.user)}</td><td>${esc(c.password)}</td>` +
      `<td>${esc(c.vendor || "common")}</td>` +
      `<td>${c.verified ? '<span class="ok">verified</span>' : '<span>tested</span>'}</td></tr>`;
  }
  el.innerHTML = h + "</table>";
}

function renderSecurity(sec) {
  const el = $("tab-sec");
  const has = sec && sec.length;
  $("box-sec").hidden = !has;
  if (!has) { el.innerHTML = "<p class='msg'>no security assessment (traceroute)</p>"; return; }
  let h = "";
  for (const s of sec) {
    const cls = s.level === "low" ? "badge-critical" : (s.level === "medium" ? "badge-high" : "badge-sec");
    h += '<div class="rec-card"><span class="rec-rank">◉</span>' +
      '<span class="rec-title">' + esc(s.host) + '</span> ' +
      '<span class="' + cls + '">' + esc(s.level.toUpperCase()) + ' posture</span>' +
      ' <span class="rec-diff">score ' + esc(Math.round(s.score || 0)) + '/100 · confidence ' + esc(s.confidence || "low") + '</span><br/>' +
      '<div class="rec-why">';
    for (const r of (s.rationale || [])) h += '<div>· ' + esc(r) + '</div>';
    h += "</div></div>";
  }
  el.innerHTML = h;
}

function renderHosts(hosts) {
  const el = $("tab-hosts");
  const has = hosts && hosts.length;
  $("box-hosts").hidden = !has;
  if (!has) { el.innerHTML = "<p class='msg'>no hosts responding</p>"; return; }
  let h = "<table><tr><th>host</th><th>os</th><th>state</th></tr>";
  for (const hd of hosts) {
    h += `<tr><td>${esc(hd.address)}</td><td>${esc(hd.os || "—")}</td>` +
         `<td>${esc(hd.state || "—")}</td></tr>`;
    // per-service detail rows: port/proto, service, version banner (info), state
    for (const s of (hd.services || [])) {
      h += `<tr class="svc-row"><td> </td>` +
        `<td colspan="2"><span class="svc-port">${esc(s.port)}/${esc(s.proto||"tcp")}</span> ` +
        `<span class="svc-name">${esc(s.service || "?")}</span>` +
        (s.info ? ` <span class="svc-info">${esc(s.info)}</span>` : "") +
        ` <span class="svc-state">${esc(s.state || "")}</span></td></tr>`;
    }
  }
  el.innerHTML = h + "</table>";
}

function renderVulns(vulns, mode) {
  const el = $("tab-vulns");
  const has = vulns && vulns.length;
  $("box-vulns").hidden = !has;
  if (!has) { el.innerHTML = "<p class='msg'>no logged findings</p>"; return; }
  let h = "<table><tr><th>finding</th><th>port</th><th>refs</th></tr>";
  for (const v of vulns) {
    const refs = (v.refs || []).map(esc).join(" · ") || "—";
    h += `<tr><td>${esc(v.name || "unknown")}</td><td>${esc(v.port ?? "—")}</td><td>${refs}</td></tr>`;
  }
  el.innerHTML = h + "</table>";
}

function renderRecs(recs) {
  const el = $("tab-recs");
  const has = recs && recs.length;
  $("box-recs").hidden = !has;
  if (!has) { el.innerHTML = "<p class='msg'>no vectors prioritized</p>"; return; }
  el.innerHTML = recs.map((r) => {
    const cve = (r.refs || []).find((x) => /CVE-\d/.test(x)) || "";
    return `<div class="rec-card">
      <span class="rec-rank">${r.rank}.</span>
      <span class="rec-title">${esc(r.title)}</span>
      ${cve ? ` <span class="cvss ${r.difficulty==="easy"?"max":""}">${esc(cve)}</span>` : ""}
      ${r.difficulty ? ` <span class="rec-diff">// ${esc(r.difficulty)}</span>` : ""}<br/>
      ${r.module ? `<span class="rec-modal">${esc(r.module)}</span><br/>` : ""}
      <span class="rec-why">${esc(r.why)}</span>
    </div>`;
  }).join("");
}

function renderNotes(notes) {
  const el = $("tab-notes");
  const has = notes && notes.length;
  $("box-notes").hidden = !has;
  if (!has) { el.innerHTML = "<p class='msg'>no notes</p>"; return; }
  el.innerHTML = "<pre class='notes'>" + esc(notes.join("\n\n")) + "</pre>";
}

/* ---------- command input ---------- */
const cmd = $("cmd");
cmd.addEventListener("keydown", async (e) => {
  if (e.key !== "Enter") return;
  const raw = cmd.value.trim();
  cmd.value = "";
  if (!raw) return;
  log(raw, "ok");
  if (raw === "help" || raw === "?") {
    log("commands:  help · status · clear · scan <target> [stealth|tor|overt]");
  } else if (raw === "clear") {
    consoleEl.innerHTML = "";
  } else if (raw === "status") {
    try {
      const r = await (await fetch("/api/health")).json();
      log(`msf: ${r.msf.reachable ? "up" : "down"} · v${r.msf.version ? r.msf.version.version.trim() : "?"} · ${r.jobs} jobs`, "info");
    } catch (err) { log("error " + err.message, "err"); }
  } else if (raw.startsWith("scan ")) {
    const parts = raw.slice(5).trim().split(/\s+/);
    $("target").value = parts[0] || "";
    const m = parts[1];
    if (["stealth", "tor", "overt"].includes(m))
      document.querySelector(`input[value="${m}"]`).checked = true;
    form.requestSubmit();
  } else {
    log("unknown: '" + raw + "' — try 'help'", "err");
  }
});

/* ---------- deep toolkit attack ---------- */
let deepTimer = null;
$("deep-attack-btn").addEventListener("click", async () => {
  const target = $("target").value.trim();
  if (!target) { log("[!] enter a target first for deep attack", "err"); return; }  if (!window.confirm(
    "DEEP TOOLKIT attack on " + target + "\n" +
    "Runs brute-force (hydra), web vuln (nikto/sqlmap), smb & dns tools.\n\n" +
    "Only proceed if you own this system or have WRITTEN permission to test it.\n\nProceed?"
  )) { log("deep toolkit attack cancelled — not confirmed", "err"); return; }
  const services = [];
  if ($("deep-ssh").checked) services.push("ssh");
  if ($("deep-http").checked) services.push("http");
  if ($("deep-smb").checked) services.push("smb");
  if ($("deep-dns").checked) services.push("dns");
  $("deep-panel").hidden = false;
  $("deep-status").textContent = "queued";
  $("tab-deep").innerHTML = "<p class='msg'>launching deep toolkit sweep…</p>";
  log(`[!] deep toolkit attack on ${target} :: ${services.join(",")}`, "err");
  busy($("deep-attack-btn"), true);
  try {
    const resp = await fetch("/api/deepattack", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target, host: target, services }),
    });
    if (!resp.ok) throw new Error("http " + resp.status);
    const job = await resp.json();
    pollDeep(job.job_id);
  } catch (err) { log("deep attack error " + err.message, "err"); }
});

function pollDeep(jobId) {
  clearInterval(deepTimer);
  deepTimer = setInterval(async () => {
    try {
      const resp = await fetch("/api/deepattack/" + jobId);
      if (!resp.ok) { clearInterval(deepTimer); return; }
      const job = await resp.json();
      $("deep-status").textContent = job.status;
      if (job.results && job.results.length) renderDeep(job.results);
      if (job.status === "done" || job.status === "error") {
        clearInterval(deepTimer);
        busy($("deep-attack-btn"), false);
        log("[+] deep toolkit attack complete", "ok");
      }
    } catch (err) { clearInterval(deepTimer); }
  }, 1500);
}

function renderDeep(results) {
  const el = $("tab-deep");
  let h = "<table><tr><th>tool</th><th>service</th><th>rc</th><th>output</th></tr>";
  for (const r of results) {
    const out = (r.stdout || "").trim();
    const shown = out ? out.slice(0, 140) : (r.stderr || "").slice(0, 100) || "—";
    h += `<tr><td>${esc(r.tool)}</td><td>${esc(r.service || "—")}</td>` +
      `<td>${esc(r.rc)}</td><td>${esc(shown)}</td></tr>`;
  }
  el.innerHTML = h + "</table>";
}

/* ---------- version-lead scan ---------- */
$("vulnleads-btn").addEventListener("click", async () => {
  const target = $("target").value.trim();
  if (!target) { log("[!] enter a target first for version-lead scan", "err"); return; }
  $("vulnleads-panel").hidden = false;
  $("tab-vulnleads").innerHTML = "<p class='msg'>scanning for EOL/beta/old versions…</p>";
  log(`[*] version-lead scan on ${target}`, "info");
  try {
    const resp = await fetch("/api/vulnleads", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target }),
    });
    if (!resp.ok) throw new Error("http " + resp.status);
    const d = await resp.json();
    const leads = d.leads || [];
    if (!leads.length) { $("tab-vulnleads").innerHTML = "<p class='msg'>no outdated/EOL/beta version leads found</p>"; return; }
    let h = "<table><tr><th>host</th><th>service</th><th>product</th><th>version</th><th>lead</th><th>why</th></tr>";
    for (const l of leads) {
      h += `<tr><td>${esc(l.host)}</td><td>${esc(l.service)}</td><td>${esc(l.product)}</td>` +
        `<td>${esc(l.version)}</td><td>${esc(l.level)}</td><td>${esc(l.reason)} <a href="${esc(l.cve_link || "#")}" target="_blank">[ref]</a></td></tr>`;
    }
    $("tab-vulnleads").innerHTML = h + "</table>";
    log(`[+] ${leads.length} version lead(s)`, "ok");
  } catch (err) { log("version-lead error " + err.message, "err"); $("tab-vulnleads").innerHTML = "<p class='msg'>error: " + esc(err.message) + "</p>"; }
});

/* ---------- lab fuzzer ---------- */
let fuzzTimer = null;
$("fuzz-btn").addEventListener("click", async () => {
  const target = $("target").value.trim();
  if (!target) { log("[!] enter a lab target you OWN to fuzz", "err"); return; }
  if (!window.confirm(
    "LAB FUZZ " + target + "\n" +
    "Mutates HTTP inputs toward this service to trip crashes/anomalies.\n\n" +
    "This must be a system YOU OWN (it may crash or hang during fuzzing). Proceed?"
  )) { log("fuzz cancelled — not confirmed", "err"); return; }
  const portText = $("fuzz-port").value.trim();
  const port = portText ? parseInt(portText, 10) : null;
  const body = { target, host: target, service: "http" };
  if (port) body.port = port;
  $("fuzz-panel").hidden = false;
  $("fuzz-status").textContent = "running";
  $("tab-fuzz").innerHTML = "<p class='msg'>fuzzing…</p>";
  log(`[!] lab fuzz on ${target}` + (port ? ":" + port : ""), "err");
  busy($("fuzz-btn"), true);
  try {
    const resp = await fetch("/api/fuzz", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!resp.ok) throw new Error("http " + resp.status);
    const job = await resp.json();
    pollFuzz(job.job_id);
  } catch (err) { log("fuzz error " + err.message, "err"); }
});

function pollFuzz(jobId) {
  clearInterval(fuzzTimer);
  fuzzTimer = setInterval(async () => {
    try {
      const resp = await fetch("/api/fuzz/" + jobId);
      if (!resp.ok) { clearInterval(fuzzTimer); return; }
      const job = await resp.json();
      $("fuzz-status").textContent = job.status;
      if (job.candidates && job.candidates.length) { renderFuzz(job.candidates); lastFuzz = job.candidates; }
      if (job.status === "done" || job.status === "error") {
        clearInterval(fuzzTimer);
        if (job.candidates && job.candidates.length) lastFuzz = job.candidates;
        busy($("fuzz-btn"), false);
        log("[+] fuzz complete — " + (job.count || 0) + " candidate(s)", "ok");
      }
    } catch (err) { clearInterval(fuzzTimer); }
  }, 1600);
}

function renderFuzz(cands) {
  const el = $("tab-fuzz");
  if (!cands.length) { el.innerHTML = "<p class='msg'>no anomalies detected (clean)</p>"; return; }
  let h = "<p class='msg'>Potential bug candidates — reproduce on a lab box, then disclose responsibly.</p><table><tr><th>vector</th><th>signal</th><th>evidence</th></tr>";
  for (const c of cands) {
    h += `<tr><td>${esc(c.vector)}</td><td><span class="${c.signal === "teardown" || c.signal === "resource" ? "err" : ""}">${esc(c.signal)}</span></td>` +
      `<td>${esc((c.evidence || "").slice(0, 80))}</td></tr>`;
  }
  el.innerHTML = h + "</table>";
}

/* ---------- source analysis (SAST) ---------- */
$("source-run").addEventListener("click", async () => {
  const file = $("source-file").files[0];
  const gitUrl = $("source-url").value.trim();
  if (!file && !gitUrl) { log("[!] provide a file or git URL to analyze", "err"); return; }
  $("source-panel").hidden = false;
  $("exploit-panel").hidden = true;
  $("source-status").textContent = "running";
  $("tab-source").innerHTML = "<p class='msg'>analyzing source…</p>";
  try {
    let resp;
    if (file) {
      const fd = new FormData();
      fd.append("file", file);
      resp = await fetch("/api/source/scan/upload", { method: "POST", body: fd });
    } else {
      resp = await fetch("/api/source/scan", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ git_url: gitUrl }),
      });
    }
    if (!resp.ok) throw new Error("http " + resp.status);
    const result = await resp.json();
    $("source-status").textContent = "done";
    renderSource(result);
  } catch (err) {
    $("source-status").textContent = "error";
    $("tab-source").innerHTML = "<p class='err'>" + esc(err.message) + "</p>";
    log("source analysis error " + err.message, "err");
  }
});

function renderSource(result) {
  lastSast = result; // keep for AI analysis
  const el = $("tab-source");
  let html = `<p class='msg'>source: ${esc(result.name)} · files scanned: ${esc(result.files_scanned)} · findings: ${esc(result.findings.length)}</p>`;
  if (!result.findings.length) { html += "<p class='ok'>no risky patterns found</p>"; el.innerHTML = html; return; }
  html += "<table><tr><th>sev</th><th>cwe</th><th>file</th><th>line</th><th>issue</th><th></th></tr>";
  for (const f of result.findings) {
    const sev = f.severity === "critical" || f.severity === "high" ? "err" : "";
    html += `<tr><td class="${sev}">${esc(f.severity)}</td><td>${esc(f.cwe)}</td>` +
      `<td>${esc(f.file)}:${esc(f.line)}</td><td>${esc(f.code || "—").slice(0, 40)}</td>` +
      `<td>${esc(f.name)}</td>` +
      `<td>` +
      `<button class="btn-sub" onclick="genExploit(${JSON.stringify(f)})">poc</button> ` +
      `<button class="btn-sub" onclick="downloadExploit(${JSON.stringify(f)})">dl</button>` +
      `</td></tr>`;
  }
  el.innerHTML = html + "</table>";
}

async function genExploit(finding) {
  $("exploit-panel").hidden = false;
  $("tab-exploit").textContent = "generating disclosure PoC…";
  try {
    const resp = await fetch("/api/source/exploit", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ rule_id: finding.rule_id, finding }),
    });
    if (!resp.ok) throw new Error("http " + resp.status);
    const poc = await resp.text();
    $("tab-exploit").textContent = poc;
    log("[+] PoC skeleton generated for " + finding.rule_id, "ok");
  } catch (err) { $("tab-exploit").textContent = "error: " + err.message; }
}

async function downloadExploit(finding) {
  try {
    const resp = await fetch("/api/source/exploit/download", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ rule_id: finding.rule_id, finding }),
    });
    if (!resp.ok) throw new Error("http " + resp.status);
    const blob = await resp.blob();
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "h4k-poc-" + (finding.rule_id || "finding") + ".txt";
    a.click();
    URL.revokeObjectURL(a.href);
    log("[+] PoC downloaded for " + finding.rule_id, "ok");
  } catch (err) { log("PoC download error " + err.message, "err"); }
}

/* ---------- SCA / SBOM ---------- */
$("sca-btn").addEventListener("click", async () => {
  const url = $("source-url").value.trim();
  if (!url) { log("[!] enter a git URL for SCA", "err"); return; }
  $("sca-panel").hidden = false;
  $("tab-sca").innerHTML = "<p class='msg'>building SBOM + checking dependencies…</p>";
  log(`[*] SCA on ${url}`, "info");
  try {
    const resp = await fetch("/api/source/sca/git?git_url=" + encodeURIComponent(url));
    if (!resp.ok) throw new Error("http " + resp.status);
    const d = await resp.json();
    renderSca(d);
  } catch (err) { $("tab-sca").innerHTML = "<p class='err'>" + esc(err.message) + "</p>"; log("SCA error " + err.message, "err"); }
});

function renderSca(d) {
  const el = $("tab-sca");
  lastSca = d;
  const cves = d.cves || [];
  const pkgs = d.packages || [];
  let h = `<p class='msg'>SBOM available: ${esc(d.sbom_available ? "yes" : "no")} · packages: ${esc(pkgs.length)} · known CVEs: ${esc(cves.length)}</p>`;
  if (cves.length) {
    h += "<table><tr><th>CVE</th></tr>";
    for (const c of cves) h += `<tr><td>${esc(c)}</td></tr>`;
    h += "</table>";
  } else if (pkgs.length) {
    h += "<p class='ok'>no known CVEs across " + esc(pkgs.length) + " package(s)</p>";
  } else {
    h += "<p class='msg'>no lockfiles/manifests found to scan</p>";
  }
  el.innerHTML = h;
  log("[+] SCA done", "ok");
}

/* ---------- AI root-cause + patch ---------- */
/* ---------- AI model picker + reachability ---------- */
async function refreshAiModels() {
  try {
    const resp = await fetch("/api/source/ai/models");
    const d = await resp.json();
    const reach = $("ai-reach");
    if (d.ollama_reachable) {
      reach.textContent = "ai: online (" + (d.model || "?") + ")";
      reach.classList.add("ok");
    } else {
      reach.textContent = "ai: offline — no local ollama";
      reach.classList.remove("ok");
    }
    const sel = $("ai-model");
    sel.innerHTML = "";
    for (const m of (d.models || [])) {
      const opt = document.createElement("option");
      opt.value = m; opt.textContent = m;
      sel.appendChild(opt);
    }
    // pre-select configured model if present
    if (d.model && (d.models || []).includes(d.model)) sel.value = d.model;
    sel.hidden = !(d.models || []).length;
  } catch (e) {
    $("ai-reach").textContent = "ai: unreachable";
    $("ai-model").hidden = true;
    log("AI health check failed: " + e.message, "err");
  }
}
refreshAiModels();

function buildAiInput(fromFindings) {
  // For the one-click full-loop demo, prefer a real minimized crash trigger
  // (that's the actual "crash -> patch -> verify" story).
  if (!fromFindings && lastMinimized) {
    return {
      source: "minimized crash (" + (lastMinimized.source || "OSS-Fuzz") + ")",
      text: "Analyze this minimized crash repro from a fuzzer the user owns:\n" +
        "file: " + (lastMinimized.file || "—") + "\ninput:\n" +
        (lastMinimized.input || "—") +
        "\n\nPlease give ROOT_CAUSE, PATCH_CANDIDATE, VERIFY.",
    };
  }
  // Prefer real SAST findings; else fall back to the last minimized crash.
  if (fromFindings && lastSast && lastSast.findings && lastSast.findings.length) {
    const f = lastSast.findings.slice(0, 10).map((x) =>
      (x.severity || "?") + " " + (x.cwe || "") + " " + (x.name || "") +
      " @ " + (x.file || "?") + ":" + (x.line || "?"));
    return {
      source: "SAST findings",
      text: "Analyze these SAST findings in source code the user owns:\n" +
        "Target: " + (lastSast.name || "project") + "\n" + f.join("\n") +
        "\n\nPlease give ROOT_CAUSE, PATCH_CANDIDATE, VERIFY.",
    };
  }
  return null;
}

async function runAi(endpoint, label, useFindings) {
  const prompt = buildAiInput(useFindings) || buildAiInput(!useFindings);
  if (!prompt) {
    $("ai-panel").hidden = false;
    $("ai-prompt").textContent = "";
    $("ai-model-used").textContent = "";
    $("tab-ai").textContent =
      "No source analysis yet. Run a SAST scan (upload zip/tar or clone a git URL) or an OSS-Fuzz run + minimize so the AI has a real finding/minimized crash to reason about.";
    log("[!] AI skipped: nothing to analyze", "err");
    return;
  }
  const model = ($("ai-model").value || "").trim() || null;
  const payload = prompt.text + "\n(analyzed from: " + prompt.source + ")";
  $("ai-panel").hidden = false;
  $("ai-prompt").textContent = payload;
  $("ai-model-used").textContent = model ? "model: " + model + " · " + prompt.source : "source: " + prompt.source;
  $("tab-ai").textContent = "asking model…";
  try {
    const resp = await fetch(endpoint, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text: payload, model }),
    });
    const d = await resp.json();
    if (d.ok) {
      $("tab-ai").textContent = (d.parsed && (d.parsed.patch_candidate || d.parsed.verify || d.parsed.root_cause))
        ? renderAiParsed(d.parsed, d.raw)
        : d.raw;
      log("[+] AI " + label + " returned", "ok");
    } else {
      $("tab-ai").textContent = "AI unavailable: " + (d.error || "no provider").replace(/^"|"$/g, "");
      log("[!] AI: " + d.error, "err");
    }
  } catch (err) { $("tab-ai").textContent = "error: " + err.message; }
}

function renderAiParsed(parsed, raw) {
  let h = "";
  if (parsed.root_cause) h += "ROOT_CAUSE:\n" + parsed.root_cause + "\n\n";
  if (parsed.patch_candidate) h += "PATCH_CANDIDATE:\n" + parsed.patch_candidate + "\n\n";
  if (parsed.verify) h += "VERIFY:\n" + parsed.verify + "\n\n";
  return (h || raw || "").trim();
}

$("ai-btn").addEventListener("click", () => { setStage("fix"); runAi("/api/source/ai", "analysis", true); });
$("ai-loop-btn").addEventListener("click", () => { setStage("fix"); runAi("/api/source/ai/loop", "full-loop", false); });

/* ---------- OSS-Fuzz auto-run + crash minimization ---------- */
$("ossfuzz-btn").addEventListener("click", () => {
  setStage("fix");
  $("ossfuzz-panel").hidden = false;
  $("ossfuzz-status").textContent = "ready";
  $("ossfuzz-url").focus();
  log("[*] open OSS-Fuzz auto-runner — paste a git URL to a fuzz harness you own", "info");
});

$("ossfuzz-run").addEventListener("click", async () => {
  const url = $("ossfuzz-url").value.trim();
  if (!url) { log("[!] enter a git URL to the fuzz-harness repo you own", "err"); return; }
  if (!window.confirm(
    "OSS-FUZZ AUTO-RUN on " + url + "\n\n" +
    "Clones the repo, builds with AddressSanitizer/UBSan, and runs libFuzzer for a short window. " +
    "This compiles and executes code and may crash — only on a repo YOU OWN. Proceed?"
  )) { log("OSS-Fuzz cancelled", "err"); return; }
  $("ossfuzz-status").textContent = "running";
  $("tab-ossfuzz").innerHTML = "<p class='msg'>building with ASan + fuzzing…</p>";
  log("[!] OSS-Fuzz auto-run on " + url, "err");
  busy($("ossfuzz-run"), true);
  try {
    const resp = await fetch("/api/source/ossfuzz", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ git_url: url, seconds: 10 }),
    });
    if (!resp.ok) { const e = await resp.json().catch(() => ({})); throw new Error(e.detail || "http " + resp.status); }
    const d = await resp.json();
    busy($("ossfuzz-run"), false);
    renderOssFuzz(d);
  } catch (err) {
    busy($("ossfuzz-run"), false);
    $("ossfuzz-status").textContent = "error";
    $("tab-ossfuzz").innerHTML = "<p class='err'>" + esc(err.message) + "</p>";
    log("OSS-Fuzz error: " + err.message, "err");
  }
});

function renderOssFuzz(d) {
  const el = $("tab-ossfuzz");
  lastOssFuzz = d;
  $("ossfuzz-status").textContent = d.ok ? "done" : "error";
  if (!d.ok) { el.innerHTML = "<p class='err'>" + esc(d.error || "run failed") + "</p>"; return; }
  const crashes = (d.crashes || []).filter((c) => c.exists || c.summary);
  let h = `<p class='msg'>built: ${esc(d.built)} · fuzz bin: ${esc(d.fuzz_bin)} · fuzzed ${esc(d.seconds)}s · crashes: ${crashes.length}</p>`;
  if (!crashes.length) {
    h += "<p class='ok'>no crashes in this window — try more seconds or richer seed data.</p>";
  } else {
    h += "<table><tr><th>crash/artifact</th><th>path</th><th>summary</th><th>minimized input</th></tr>";
    for (const c of crashes) {
      h += `<tr><td>${esc(c.name)}</td><td>${esc(c.path || "—")}</td><td>${esc((c.summary || "").slice(0, 80))}</td>` +
        `<td>${esc((c.minimized || "—").slice(0, 80))}</td></tr>`;
    }
    h += "</table>";
    h += "<p class='msg'>hint: use “minimize crash(s)” to reduce to the smallest repro, then “AI full-loop” for root-cause → patch → verify.</p>";
  }
  if (d.steps && d.steps.length) h += "<p class='notes'>" + esc(d.steps.join(" · ")) + "</p>";
  if (d.log_tail) h += "<pre class='notes'>" + esc(d.log_tail.slice(-600)) + "</pre>";
  el.innerHTML = h;
  log("[+] OSS-Fuzz run complete — " + crashes.length + " crash lead(s)", crashes.length ? "err" : "ok");
}

$("minimize-btn").addEventListener("click", () => {
  const minimized = (lastOssFuzz || {}).crashes || [];
  const have = minimized.filter((c) => c.minimized && c.minimized.length);
  if (!have.length) {
    $("ossfuzz-status").textContent = "no-op";
    $("tab-ossfuzz").innerHTML = "<p class='msg'>No minimized crash artifacts from the last OSS-Fuzz run. Run a build+fuzz first on a harness that trips a crash, and minimization will be reported per-crash above.</p>";
    log("[!] minimize: no crash artifacts to reduce", "err");
    return;
  }
  if (have[0]) lastMinimized = { source: "OSS-Fuzz", input: have[0].minimized, file: have[0].name };
  $("ossfuzz-status").textContent = "done";
  $("tab-ossfuzz").innerHTML =
    "<p class='ok'>Minimization done for " + have.length + " crash(s). Reduced repro ready — run “AI full-loop” in the Fix stage for root-cause → patch → verify.</p>";
  log("[+] minimize: reduced repro ready for AI full-loop", "ok");
  setStage("fix");
});

/* ---------- consolidated one-click report ---------- */
function mergePayload() {
  // scan: map hosts/services into the merged_report schema
  const scanHosts = (lastScanReport && lastScanReport.hosts) || [];
  const scan = scanHosts.map((hd) => ({
    address: hd.address, os: hd.os, state: hd.state,
    services: (hd.services || []).map((s) => ({
      port: s.port, service: s.service, proto: s.proto, info: s.info, state: s.state,
    })),
  }));
  // sast: keep the fields the renderer/markdown need
  const sast = (lastSast && lastSast.findings) || [];
  return {
    scan,
    sast,
    sca: lastSca || {},
    fuzz: lastFuzz || [],
    triage: [],
  };
}

function mergedCounts() {
  const p = mergePayload();
  const hosts = p.scan.length;
  const sast = p.sast.length;
  const cves = ((p.sca && p.sca.cves) || []).length;
  const fuzz = p.fuzz.length;
  return { hosts, sast, cves, fuzz };
}

function refreshMergedSummary() {
  const c = mergedCounts();
  $("merged-meta").textContent =
    `hosts ${c.hosts} · SAST ${c.sast} · SCA CVEs ${c.cves} · fuzz ${c.fuzz}`;
  $("merged-summary").innerHTML =
    `<p class="msg">Collects everything from this session: ` +
    `<b>${c.hosts}</b> host(s), <b>${c.sast}</b> SAST finding(s), ` +
    `<b>${c.cves}</b> known dependency CVE(s), <b>${c.fuzz}</b> fuzz candidate(s). ` +
    `Run an analysis first so the report is populated.</p>`;
}

$("merged-run").addEventListener("click", async () => {
  busy($("merged-run"), true);
  try {
    const resp = await fetch("/api/source/report/merge", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(mergePayload()),
    });
    if (!resp.ok) throw new Error("http " + resp.status);
    const rep = await resp.json();
    lastMergedReport = rep;
    const s = rep.summary || {};
    $("merged-meta").textContent =
      `generated ${(rep.generated || "").slice(0, 19).replace("T", " ")} · ` +
      `hosts ${s.hosts_scanned} · SAST ${s.sast_findings} · SCA ${s.sca_cves} · fuzz ${s.fuzz_candidates}`;
    $("merged-summary").innerHTML =
      `<p class='ok'>Report built. Download as .md or .json.</p>`;
    log("[+] consolidated report built", "ok");
  } catch (err) {
    $("merged-summary").innerHTML = "<p class='err'>" + esc(err.message) + "</p>";
    log("merged report error " + err.message, "err");
  } finally {
    busy($("merged-run"), false);
  }
});

async function mergedDownload(btn, endpoint, filename) {
  busy(btn, true);
  try {
    const resp = await fetch(endpoint, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(mergePayload()),
    });
    if (!resp.ok) throw new Error("http " + resp.status);
    const text = await resp.text();
    const isJson = endpoint.endsWith("merge");
    // /report/merge returns JSON; /report/md returns a JSON-encoded string of markdown.
    let finalText = text;
    if (isJson) {
      finalText = JSON.stringify(JSON.parse(text), null, 2);
    } else {
      try { finalText = JSON.parse(text); } catch (_) { /* already plain */ }
    }
    const finalBlob = new Blob([finalText], { type: "text/plain" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(finalBlob);
    a.download = filename;
    a.click();
    URL.revokeObjectURL(a.href);
    log("[+] report downloaded: " + filename, "ok");
  } catch (err) {
    log("report download error " + err.message, "err");
  } finally {
    busy(btn, false);
  }
}
$("merged-md").addEventListener("click", () => mergedDownload($("merged-md"), "/api/source/report/md", "h4k-assessment.md"));
$("merged-json").addEventListener("click", () => mergedDownload($("merged-json"), "/api/source/report/merge", "h4k-assessment.json"));
refreshMergedSummary();

/* ---------- supply-chain map ---------- */
$("sca-map-btn").addEventListener("click", async () => {
  const url = $("source-url").value.trim();
  if (!url) { log("[!] enter a git URL for the supply-chain map", "err"); return; }
  $("sca-panel").hidden = false;
  $("tab-sca").innerHTML = "<p class='msg'>building dependency graph + reachability…</p>";
  log("[*] supply-chain map on " + url, "info");
  try {
    const resp = await fetch("/api/source/sca/map?git_url=" + encodeURIComponent(url));
    if (!resp.ok) { const e = await resp.json().catch(()=>({})); throw new Error(e.detail || "http " + resp.status); }
    const d = await resp.json();
    if (d.error) throw new Error(d.error);
    renderSupplyChainMap(d);
  } catch (err) { $("tab-sca").innerHTML = "<p class='err'>" + esc(err.message) + "</p>"; log("map error " + err.message, "err"); }
});

function renderSupplyChainMap(d) {
  const el = $("tab-sca");
  const gr = d.graph || {};
  const nodes = gr.nodes || [];
  const edits = gr.edges || [];
  const cveMap = {};
  for (const n of nodes) if (n.cves && n.cves.length) cveMap[n.label] = n.cves;
  let h = `<p class='msg'>components: ${(d.summary||{}).components||0} · edges: ${edits.length} · known CVEs: ${(d.summary||{}).cves||0}</p>`;
  h += "<h3>Dependency graph (nodes → edges)</h3><table><tr><th>node</th><th>type</th><th>dependencies</th><th>known CVEs</th></tr>";
  const childByParent = {};
  for (const e of edits) (childByParent[e.from] = childByParent[e.from]||[]).push(e.to);
  for (const n of nodes) {
    const kids = (childByParent[n.id]||[]).map(x=>esc(x)).join(", ")||"—";
    const cves = (n.cves||[]).map(esc).join(", ")||"—";
    h += `<tr><td>${esc(n.label)}</td><td>${esc(n.type||"—")}</td><td>${kids}</td><td>${cves}</td></tr>`;
  }
  h += "</table>";
  h += "<p class='msg'>reachability: any node with a listed CVE is a reachable-vulnerable component.</p>";
  el.innerHTML = h;
  log("[+] supply-chain map built (" + nodes.length + " nodes, " + (d.summary||{}).cves + " CVEs)", "ok");
}

/* ---------- network layer (sniff / arp / mitm / wifi) ---------- */
const netIf = () => ($("net-iface").value.trim() || "eth0");
const netOut = (d) => {
  $("net-status").textContent = "done";
  $("tab-net").textContent = (d.stdout || d.error || d.stderr || JSON.stringify(d, null, 2)).slice(0, 3000);
};

$("iface-btn").addEventListener("click", async () => {
  try { const d = await (await fetch("/api/net/interfaces")).json();
    $("net-panel").hidden = false; $("tab-net").textContent = JSON.stringify(d.interfaces, null, 2);
    log("[+] interfaces listed", "ok"); } catch (e) { log("interfaces error " + e.message, "err"); }
});

$("sniff-btn").addEventListener("click", async () => {
  $("net-panel").hidden = false; $("net-status").textContent = "running"; $("tab-net").textContent = "sniffing…";
  try { const r = await (await fetch("/api/net/sniff", { method: "POST", headers: {"Content-Type":"application/json"}, body: JSON.stringify({interface: netIf()})})).json(); netOut(r); log("[+] sniff done", "ok"); }
  catch (e) { $("tab-net").textContent = "error: " + e.message; }
});

$("arp-btn").addEventListener("click", async () => {
  $("net-panel").hidden = false; $("net-status").textContent = "running";
  try { const r = await (await fetch("/api/net/arp", { method: "POST", headers: {"Content-Type":"application/json"}, body: JSON.stringify({interface: netIf()})})).json(); netOut(r); log("[+] arp done", "ok"); }
  catch (e) { $("tab-net").textContent = "error: " + e.message; }
});

$("mitm-btn").addEventListener("click", async () => {
  if (!window.confirm("bettercap ARP-spoof MITM on " + netIf() + " — only on a lab interface/net you control. Continue?")) { log("mitm cancelled", "err"); return; }
  $("net-panel").hidden = false; $("net-status").textContent = "running";
  // target the gateway? We let the user pass any single host; default to the local subnet broadcast-ish target note.
  const target = window.prompt("ARP-spoof target IP (lab only):", "") || "";
  if (!target) { log("mitm cancelled — no target", "err"); return; }
  try { const r = await (await fetch("/api/net/mitm", { method: "POST", headers: {"Content-Type":"application/json"}, body: JSON.stringify({interface: netIf(), target})})).json(); netOut(r); log("[+] mitm done", "ok"); }
  catch (e) { $("tab-net").textContent = "error: " + e.message; }
});

$("wifi-scan-btn").addEventListener("click", async () => {
  $("net-panel").hidden = false; $("net-status").textContent = "running"; $("tab-net").textContent = "scanning (need monitor interface)…";
  try { const r = await (await fetch("/api/net/wifi/scan", { method: "POST", headers: {"Content-Type":"application/json"}, body: JSON.stringify({interface: netIf()})})).json(); netOut(r); log("[+] wifi scan done", "ok"); }
  catch (e) { $("tab-net").textContent = "error: " + e.message; }
});

$("wifi-cap-btn").addEventListener("click", async () => {
  $("net-panel").hidden = false; $("net-status").textContent = "running"; $("tab-net").textContent = "capturing frames (offline crack later)…";
  try { const r = await (await fetch("/api/net/wifi/capture", { method: "POST", headers: {"Content-Type":"application/json"}, body: JSON.stringify({interface: netIf()})})).json(); netOut(r); log("[+] wifi capture done — feed .cap to aircrack-ng", "ok"); }
  catch (e) { $("tab-net").textContent = "error: " + e.message; }
});

/* ---------- custom rule test ---------- */
$("rule-test").addEventListener("click", async () => {
  const pattern = $("rule-pattern").value.trim();
  if (!pattern) { log("[!] enter a semgrep pattern to test", "err"); return; }
  try {
    const resp = await fetch("/api/source/rules/test", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        rule_id: "custom-rule-" + Math.random().toString(36).slice(2, 6),
        name: "Custom rule", severity: "medium", languages: ["python"],
        pattern, message: "custom rule hit", test_code: "exec('id')",
      }),
    });
    if (!resp.ok) throw new Error("http " + resp.status);
    const d = await resp.json();
    if (d.ok) log("[+] custom rule " + (d.matched ? "matched (vuln found)" : "did not match") + " sample code", d.matched ? "err" : "ok");
    else log("[!] rule test error: " + (d.error || "").slice(0, 120), "err");
  } catch (err) { log("rule test error " + err.message, "err"); }
});

/* ---------- session indicator toggling ---------- */
(async () => {
  try {
    const r = await (await fetch("/api/health")).json();
    if (r.msf.reachable) {
      const m = $("msf-state");
      m.classList.add("on");
      m.textContent = "msf: up · v" + (r.msf.version ? r.msf.version.version.trim() : "?");
    }
  } catch (_) {}
})();
