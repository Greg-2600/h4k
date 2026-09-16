/* ============================================================
   H4K // INTRUSION-SUITE frontend
   ============================================================ */
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
}[c]));

/* ---------- matrix rain backdrop ---------- */
const canvas = $("bg"), ctx = canvas.getContext("2d");
let cols, drops, glyphs = "01アイウエオカキクケコサシスセソタチツテト01<>/$#%";
const resize = () => {
  canvas.width = innerWidth; canvas.height = innerHeight;
  cols = Math.floor(innerWidth / 18);
  drops = Array(cols).fill(0).map(() => Math.random() * innerHeight / 20);
};
resize();
addEventListener("resize", resize);
function rain() {
  ctx.fillStyle = "rgba(3, 9, 13, 0.12)";
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.fillStyle = "#0f0";
  ctx.font = "16px monospace";
  for (let i = 0; i < cols; i++) {
    const ch = glyphs[(Math.random() * glyphs.length) | 0];
    const y = drops[i] * 18;
    ctx.fillText(ch, i * 18, y);
    if (y > canvas.height && Math.random() > 0.975) drops[i] = 0;
    drops[i]++;
  }
}
setInterval(rain, 50);

/* ---------- boot sequence ---------- */
const BOOT_LINES = [
  "[ OK ] INITIALIZING NEURO-STACK .............. DONE",
  "[ OK ] MOUNTING /dev/msfrpc ................. 55553",
  "[ OK ] HANDSHAKE WITH MSFROUTER .............. ACCEPTED",
  "[ OK ] LOADING CVE-ARCHIVE .................. 31 RECORDS",
  "[ OK ] SPINNING TOR CIRCUITS ..... (if routed) STANDBY",
  "[ OK ] UPLINK BONDED 0.0.0.0:3137 ............... LIVE",
  ">_ SYSTEM READY. ROUTE INPUT TO BEGIN."
];
const boot = $("boot"), bootText = $("boot-text");
(async function runBoot() {
  for (const l of BOOT_LINES) {
    for (const ch of l) {
      bootText.textContent += ch;
      await new Promise(r => setTimeout(r, 12));
    }
    bootText.textContent += "\n";
  }
  boot.classList.add("done");
})();

/* ---------- clock ---------- */
setInterval(() => {
  $("clock").textContent = new Date().toLocaleTimeString("en-GB");
}, 1000);

/* ---------- console ---------- */
const consoleEl = $("console");
function log(msg, cls = "") {
  const ln = document.createElement("div");
  ln.className = "ln " + cls;
  ln.textContent = msg;
  consoleEl.appendChild(ln);
  consoleEl.scrollTop = consoleEl.scrollHeight;
}
log("h4k :: intrusion-suite v1.0 booted", "sys");

/* ---------- form submit -> scan job ---------- */
const form = $("scan-form"), scanBtn = $("scan-btn");
const statusPanel = $("status-panel"), reportPanel = $("report-panel");
const progressBar = $("progress-bar"), statusMsg = $("status-msg");
let pollTimer = null;

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  const target = $("target").value.trim();
  const mode = document.querySelector('input[name="mode"]:checked').value;
  const useCve = $("cve-toggle").checked;
  $("target").value = "";
  scanBtn.disabled = true;
  statusPanel.hidden = false;
  reportPanel.hidden = true;
  resetProgress();
  log(`[>] DEPLOY_SIGNAL to ${target} :: protocol=${mode.toUpperCase()}` + (useCve ? " :: CVE-ON" : ""), "info");
  try {
    const resp = await fetch("/api/scan", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target, mode, do_dns_recon: true, do_vuln_scan: true }),
    });
    if (!resp.ok) throw new Error("uplink rejected (HTTP " + resp.status + ")");
    const job = await resp.json();
    log(`[+] job ${job.id} accepted — tracking`, "ok");
    poll(job.id);
  } catch (err) {
    log("[!] ERROR " + err.message, "err");
    scanBtn.disabled = false;
  }
});

function resetProgress() {
  progressBar.style.width = "0%";
  $("progress-pct").textContent = "0%";
  $("status-msg").textContent = "uplink in progress…";
}

function poll(jobId) {
  clearInterval(pollTimer);
  let lastPct = -1;
  pollTimer = setInterval(async () => {
    try {
      const resp = await fetch("/api/jobs/" + jobId);
      if (!resp.ok) { clearInterval(pollTimer); fail("job lookup failed"); return; }
      const job = await resp.json();
      const pct = Math.round(job.progress || 0);
      progressBar.style.width = pct + "%";
      $("progress-pct").textContent = pct + "%";
      if (pct !== lastPct) {
        lastPct = pct;
        log(`[*] ${job.status.toUpperCase()} :: ${job.message} (${pct}%)`, "info");
      }
      if (job.status === "done") {
        clearInterval(pollTimer);
        $("status-tag").textContent = "✓";
        log("[+] SIGINT COMPLETE — decrypting report", "ok");
        renderReport(job.report);
        scanBtn.disabled = false;
      } else if (job.status === "error") {
        clearInterval(pollTimer);
        fail(job.error || "unknown fault");
      }
    } catch (err) {
      clearInterval(pollTimer); fail(err.message);
    }
  }, 1300);
}
function fail(msg) {
  $("status-tag").textContent = "✗";
  $("status-msg").textContent = "ERROR: " + msg;
  log("[!] ERROR " + msg, "err");
  scanBtn.disabled = false;
}

/* ---------- report rendering ---------- */
function renderReport(report) {
  reportPanel.hidden = false;
  const mode = (report.mode || "overt").toUpperCase();
  $("report-meta").innerHTML =
    "TARGET: <code>" + esc(report.target) + "</code> " +
    '<span class="badge ' + esc(report.mode || "overt") + '">' + esc(mode) + "</span> " +
    "&nbsp; T+<code>" + esc((report.created_at || "").slice(11, 19)) + "</code>";
  renderHosts(report.hosts);
  renderVulns(report.vulns);
  renderRecs(report.recommendations);
  renderNotes(report.notes);

  document.querySelectorAll(".tab").forEach((t) => t.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((x) => x.classList.remove("active"));
    document.querySelectorAll(".tab-panel").forEach((x) => x.classList.remove("active"));
    t.classList.add("active");
    $("tab-" + t.dataset.tab).classList.add("active");
  }));

  log("[+] REPORT parsed: " + report.hosts.length + " host(s), "
    + report.vulns.length + " vuln(s), "
    + report.recommendations.length + " recommendation(s)", "ok");
}

function renderHosts(hosts) {
  const el = $("tab-hosts");
  if (!hosts || !hosts.length) { el.innerHTML = "<p class='status-msg danger'>NO HOSTS RESPONDING</p>"; return; }
  let h = "<table><tr><th>#</th><th>ADDRESS</th><th>OS</th><th>STATE</th><th>OPEN SERVICES</th></tr>";
  hosts.forEach((hd, i) => {
    const svcs = (hd.services || []).map((s) => s.port + "/" + (s.service || "?")).join(", ") || "—";
    h += "<tr><td>" + (i + 1) + "</td><td>" + esc(hd.address) + "</td><td>" + esc(hd.os || "—")
      + "</td><td>" + esc(hd.state || "—") + "</td><td>" + esc(svcs) + "</td></tr>";
  });
  el.innerHTML = h + "</table>";
}

function renderVulns(vulns) {
  const el = $("tab-vulns");
  if (!vulns || !vulns.length) { el.innerHTML = "<p class='status-msg'>NO EXPLOITABLE FINDINGS LOGGED</p>"; return; }
  let h = "<table><tr><th>SIGNATURE</th><th>PORT</th><th>REFS</th></tr>";
  for (const v of vulns) {
    const crit = /(eternal|critical|rce|bluekeep)/i.test(v.name || "");
    const refs = (v.refs || []).map(esc).join(" · ") || "—";
    h += "<tr><td>" + (crit ? '<span class="badge badge-critical">' : "") + esc(v.name || "unknown")
      + (crit ? "</span>" : "") + "</td><td>" + esc(v.port ?? "—") + "</td><td>" + refs + "</td></tr>";
  }
  el.innerHTML = h + "</table>";
}

function renderRecs(recs) {
  const el = $("tab-recs");
  if (!recs || !recs.length) { el.innerHTML = "<p class='status-msg'>NO ATTACK VECTORS PRIORITIZED</p>"; return; }
  let h = "";
  for (const r of recs) {
    const cve = (r.refs || []).find((x) => /CVE-\d/.test(x)) || "";
    h += '<div class="rec-card"><span class="rec-rank">' + r.rank + '</span>' +
      '<span class="rec-title">' + esc(r.title) + "</span>" +
      (cve ? ' <code class="cvss">' + esc(cve) + "</code>" : "") +
      ' <span class="rec-diff">// difficulty: ' + esc(r.difficulty || "hard") + "</span><br/>" +
      (r.module ? '<span class="rec-modal">◈ ' + esc(r.module) + "</span><br/>" : "") +
      '<div class="rec-why">' + esc(r.why) + "</div></div>";
  }
  el.innerHTML = h;
}

function renderNotes(notes) {
  const el = $("tab-notes");
  if (!notes || !notes.length) { el.innerHTML = "<p class='status-msg'>NO RAW NOTATIONS</p>"; return; }
  el.innerHTML = "<pre class='notes'>" + esc(notes.join("\n\n")) + "</pre>";
}

/* ---------- console command input ---------- */
const cmdInput = $("console-cmd");
cmdInput.addEventListener("keydown", async (e) => {
  if (e.key !== "Enter") return;
  const raw = cmdInput.value.trim();
  cmdInput.value = "";
  if (!raw) return;
  log("h4k:~$ " + raw);
  if (raw === "help" || raw === "?") {
    log("[?] commands: help · status · scan <target> [mode] · clear", "info");
  } else if (raw === "clear") {
    consoleEl.innerHTML = "";
  } else if (raw === "status") {
    try {
      const r = await (await fetch("/api/health")).json();
      log("[*] MSF reachable: " + r.msf.reachable + " | v" + (r.msf.version ? r.msf.version.version.trim() : "?") + " | jobs: " + r.jobs, "info");
    } catch (err) { log("[!] " + err.message, "err"); }
  } else if (raw.startsWith("scan ")) {
    $("target").value = raw.slice(5).trim().split(/\s+/)[0] || "";
    document.querySelector('input[name="mode"]:checked').checked = false;
    const m = raw.replace("scan", "").trim().split(/\s+/)[1];
    if (["stealth", "tor", "overt"].includes(m)) {
      document.querySelector('input[value="' + m + '"]').checked = true;
    }
    form.requestSubmit();
  } else {
    log("[!] unknown directive '" + raw + "'. type 'help'", "err");
  }
});
