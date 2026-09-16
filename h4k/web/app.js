const form = document.getElementById("scan-form");
const scanBtn = document.getElementById("scan-btn");
const statusPanel = document.getElementById("status-panel");
const progressBar = document.getElementById("progress-bar");
const statusMsg = document.getElementById("status-msg");
const statusTitle = document.getElementById("status-title");
const reportPanel = document.getElementById("report-panel");
const reportMeta = document.getElementById("report-meta");

let pollTimer = null;

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  const target = document.getElementById("target").value.trim();
  const mode = document.querySelector('input[name="mode"]:checked').value;

  scanBtn.disabled = true;
  statusPanel.hidden = false;
  reportPanel.hidden = true;
  setProgress(0, "Submitting scan request...");

  try {
    const resp = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target, mode, do_dns_recon: true, do_vuln_scan: true }),
    });
    if (!resp.ok) throw new Error("scan request failed (HTTP " + resp.status + ")");
    const job = await resp.json();
    poll(job.id);
  } catch (err) {
    setProgress(0, "Error: " + err.message);
    scanBtn.disabled = false;
  }
});

function poll(jobId) {
  clearInterval(pollTimer);
  pollTimer = setInterval(async () => {
    try {
      const resp = await fetch("/api/jobs/" + jobId);
      if (!resp.ok) { clearInterval(pollTimer); setProgress(0, "Job lookup failed"); scanBtn.disabled = false; return; }
      const job = await resp.json();

      setProgress(job.progress, job.status + " — " + job.message);

      if (job.status === "done") {
        clearInterval(pollTimer);
        renderReport(job.report);
        scanBtn.disabled = false;
      } else if (job.status === "error") {
        clearInterval(pollTimer);
        setProgress(0, "Scan error: " + (job.error || "unknown"));
        scanBtn.disabled = false;
      }
    } catch (err) {
      clearInterval(pollTimer);
      scanBtn.disabled = false;
    }
  }, 1500);
}

function setProgress(pct, msg) {
  progressBar.style.width = String(pct) + "%";
  statusMsg.textContent = msg;
  statusTitle.textContent = "Job status";
}

/* ---- report rendering --------------------------------------------------- */

function renderReport(report) {
  reportPanel.hidden = false;
  const mode = String(report.mode || "").toUpperCase();
  reportMeta.innerHTML =
    "Target: <code>" + esc(report.target) + "</code> &nbsp; Mode: " +
    '<span class="badge ' + esc(report.mode || "overt") + '">' + esc(mode) + "</span>" +
    " &nbsp; Generated: " + esc((report.created_at || "").replace("T", " ").slice(0, 19));

  renderHosts(report.hosts);
  renderVulns(report.vulns);
  renderRecs(report.recommendations);
  renderNotes(report.notes);

  document.querySelectorAll(".tab").forEach((t) => {
    t.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach((x) => x.classList.remove("active"));
      document.querySelectorAll(".tab-panel").forEach((x) => x.classList.remove("active"));
      t.classList.add("active");
      document.getElementById("tab-" + t.dataset.tab).classList.add("active");
    });
  });
}

function renderHosts(hosts) {
  const el = document.getElementById("tab-hosts");
  if (!hosts || !hosts.length) { el.innerHTML = "<p class='status-msg'>No hosts found.</p>"; return; }
  let html = "<table><tr><th>IP</th><th>Hostname</th><th>OS</th><th>State</th><th>Services</th></tr>";
  for (const h of hosts) {
    const svcs = (h.services || []).map((s) => s.port + "/" + (s.service || "?"))
      .join(", ") || "none";
    html += "<tr><td>" + esc(h.address) + "</td><td>" + esc(h.hostname || "-") +
      "</td><td>" + esc(h.os || "-") + "</td><td>" + esc(h.state || "-") +
      "</td><td>" + esc(svcs) + "</td></tr>";
  }
  html += "</table>";
  el.innerHTML = html;
}

function renderVulns(vulns) {
  const el = document.getElementById("tab-vulns");
  if (!vulns || !vulns.length) { el.innerHTML = "<p class='status-msg'>No vulnerabilities reported.</p>"; return; }
  let html = "<table><tr><th>Vulnerability</th><th>Port</th><th>References</th></tr>";
  for (const v of vulns) {
    const refs = (v.refs || []).map((r) => esc(r)).join(", ") || "-";
    const critical = v.name && /(eternalblue|critical|rce)/i.test(v.name);
    html += "<tr><td>" + (critical ? '<span class="badge badge-critical">' : "") +
      esc(v.name || "unknown") + (critical ? "</span>" : "") +
      "</td><td>" + esc(v.port || "-") + "</td><td>" + refs + "</td></tr>";
  }
  html += "</table>";
  el.innerHTML = html;
}

function renderRecs(recs) {
  const el = document.getElementById("tab-recs");
  if (!recs || !recs.length) { el.innerHTML = "<p class='status-msg'>No recommendations generated.</p>"; return; }
  let html = "";
  for (const r of recs) {
    html += '<div class="rec-card">' +
      '<span class="rec-rank">' + r.rank + '</span>' +
      '<span class="rec-title">' + esc(r.title) + '</span>' +
      (r.difficulty ? ' <span class="rec-diff">(' + esc(r.difficulty) + ")</span>" : "") + "<br/>" +
      (r.module ? '<span class="rec-modal">' + esc(r.module) + "</span><br/>" : "") +
      '<div class="rec-why">' + esc(r.why) + "</div>" +
      "</div>";
  }
  el.innerHTML = html;
}

function renderNotes(notes) {
  const el = document.getElementById("tab-notes");
  if (!notes || !notes.length) { el.innerHTML = "<p class='status-msg'>No notes.</p>"; return; }
  el.innerHTML = "<pre class='notes'>" + esc(notes.join("\n\n")) + "</pre>";
}

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}
