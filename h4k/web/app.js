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
  log("type 'help' for commands · authorized scope only", "sys");
}
boot();

/* ---------- scan form ---------- */
const form = $("scan-form"), scanBtn = $("scan-btn");
const statusPane = $("status-pane"), results = $("results");
const prog = $("prog"), pctEl = $("pct"), statusMsg = $("status-msg");
let pollTimer = null;

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  const target = $("target").value.trim();
  const mode = document.querySelector('input[name="mode"]:checked').value;
  const useCve = $("cve-toggle").checked;
  const tryCreds = $("creds-toggle").checked;
  $("target").value = "";
  scanBtn.disabled = true;
  statusPane.hidden = false;
  results.hidden = true;
  prog.style.width = "0%"; pctEl.textContent = "0";
  $("status-msg").textContent = "queued…";
  $("status-tag").textContent = "queued";
  log(`scan ${target} · mode=${mode}` + (useCve ? " · cve-db" : "")
    + (tryCreds ? " · creds=ON" : ""), "info");
  try {
    const resp = await fetch("/api/scan", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target, mode, do_dns_recon: true, do_vuln_scan: true,
        try_default_creds: tryCreds, open_sessions: tryCreds }),
    });
    if (!resp.ok) throw new Error("http " + resp.status);
    const job = await resp.json();
    log(`[tracking] job ${job.id}`, "ok");
    $("job-ind").textContent = "job:" + job.id;
    poll(job.id);
  } catch (err) {
    log("error " + err.message, "err");
    scanBtn.disabled = false;
  }
});

function poll(id) {
  clearInterval(pollTimer);
  let last = -1;
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
      if (j.status === "done") {
        clearInterval(pollTimer);
        log("scan complete", "ok");
        $("job-ind").textContent = "idle";
        render(j.report);
        scanBtn.disabled = false;
      } else if (j.status === "error") {
        clearInterval(pollTimer);
        log("error: " + (j.error || "unknown"), "err");
        $("job-ind").textContent = "idle";
        scanBtn.disabled = false;
      }
    } catch (err) {
      clearInterval(pollTimer);
      $("job-ind").textContent = "idle";
      scanBtn.disabled = false;
    }
  }, 1400);
}

/* ---------- rendering ---------- */
function render(r) {
  results.hidden = false;
  $("report-meta").textContent =
    `${r.target} · ${r.mode} · ${(r.created_at || "").slice(11, 19)}`;
  renderHosts(r.hosts);
  renderFingerprints(r.fingerprints);
  renderVulns(r.vulns, r.mode);
  renderCreds(r.credentials);
  renderRecs(r.recommendations);
  renderNotes(r.notes);

  document.querySelectorAll(".tab").forEach((t) =>
    t.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach((x) => x.classList.remove("active"));
      document.querySelectorAll(".tab-panel").forEach((x) => x.classList.remove("active"));
      t.classList.add("active");
      $("tab-" + t.dataset.tab).classList.add("active");
    }));
  log(`report: ${r.hosts.length} host(s) · ${r.vulns.length} vuln(s) · ${r.recommendations.length} vector(s)`, "ok");
}

function renderFingerprints(fps) {
  const el = $("tab-fp");
  if (!fps || !fps.length) { el.innerHTML = "<p class='msg'>no fingerprint data</p>"; return; }
  let h = "<table><tr><th>host</th><th>vendor</th><th>model</th><th>os</th><th>technology</th><th>source</th></tr>";
  for (const f of fps) {
    h += `<tr><td>${esc(f.host)}</td><td>${esc(f.vendor || "?")}</td>` +
      `<td>${esc(f.model || "—")}</td><td>${esc(f.os || "—")}</td>` +
      `<td>${esc((f.technology || []).join(", ") || "—")}</td>` +
      `<td>${esc((f.source || []).join(", "))}</td></tr>`;
  }
  el.innerHTML = h + "</table>";
}

function renderCreds(creds) {
  const el = $("tab-creds");
  if (!creds || !creds.length) { el.innerHTML = "<p class='msg'>no credentials tested (opt-in default).</p>"; return; }
  let h = "<table><tr><th>host</th><th>service</th><th>user</th><th>password</th><th>vendor</th><th>status</th></tr>";
  for (const c of creds) {
    h += `<tr><td>${esc(c.host)}</td><td>${esc(c.service)}:${esc(c.port ?? "?")}</td>` +
      `<td>${esc(c.user)}</td><td>${esc(c.password)}</td>` +
      `<td>${esc(c.vendor || "common")}</td>` +
      `<td>${c.verified ? '<span class="ok">verified</span>' : '<span>tested</span>'}</td></tr>`;
  }
  el.innerHTML = h + "</table>";
}

function renderHosts(hosts) {
  const el = $("tab-hosts");
  if (!hosts || !hosts.length) { el.innerHTML = "<p class='msg'>no hosts responding</p>"; return; }
  let h = "<table><tr><th>host</th><th>os</th><th>state</th><th>services</th></tr>";
  for (const hd of hosts) {
    const sv = (hd.services || []).map((s) => s.port + "/" + (s.service || "?")).join(", ") || "—";
    h += `<tr><td>${esc(hd.address)}</td><td>${esc(hd.os || "—")}</td>` +
         `<td>${esc(hd.state || "—")}</td><td>${esc(sv)}</td></tr>`;
  }
  el.innerHTML = h + "</table>";
}

function renderVulns(vulns, mode) {
  const el = $("tab-vulns");
  if (!vulns || !vulns.length) { el.innerHTML = "<p class='msg'>no logged findings</p>"; return; }
  let h = "<table><tr><th>finding</th><th>port</th><th>refs</th></tr>";
  for (const v of vulns) {
    const refs = (v.refs || []).map(esc).join(" · ") || "—";
    h += `<tr><td>${esc(v.name || "unknown")}</td><td>${esc(v.port ?? "—")}</td><td>${refs}</td></tr>`;
  }
  el.innerHTML = h + "</table>";
}

function renderRecs(recs) {
  const el = $("tab-recs");
  if (!recs || !recs.length) { el.innerHTML = "<p class='msg'>no vectors prioritized</p>"; return; }
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
  if (!notes || !notes.length) { el.innerHTML = "<p class='msg'>no notes</p>"; return; }
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
