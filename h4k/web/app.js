// h4k kill-chain console.
// Phases: Discover → Recon → Exploit → Pivot → Persist → Score.
// Every control calls a real endpoint; nothing is decorative.

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const escA = (s) => esc(s).replace(/"/g, '&quot;');

const state = {
  tab: 'discover',
  engagementId: null,
  moves: [],
  shells: [],
  activeSession: null,
  scanTimer: null,
  fpTimer: null,
  apTimer: null,
  fzTimer: null,
  paTimer: null,
  cfTimer: null,
  statusTimer: null,
};

const TABS = ['discover', 'recon', 'exploit', 'pivot', 'persist', 'score'];

/* ---------- http ---------- */

const api = async (url, opts = {}) => {
  const r = await fetch(url, {
    headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) },
    ...opts,
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  const text = await r.text();
  try { return JSON.parse(text); }
  catch { return { status: r.status, detail: `${r.status} ${r.statusText}` }; }
};

const apiOrThrow = async (url, opts = {}) => {
  const res = await api(url, opts);
  if (res && res.detail && !res.job_id && !res.id && !res.hosts && !res.moves && !res.flags) {
    const d = res.detail;
    throw new Error(typeof d === 'string' ? d : JSON.stringify(d));
  }
  return res;
};

// /api/scan returns {id}, everything else returns {job_id}.
// Terminal states disagree too (done vs completed).
const jobIdOf = (res) => res && (res.job_id || res.id);
const isDone = (s) => ['done', 'completed', 'failed', 'error', 'aborted'].includes(s);

/* ---------- activity log ---------- */

function log(msg, level = 'info') {
  const el = $('activity-log');
  if (!el) return;
  const ts = new Date().toLocaleTimeString('en-US', { hour12: false });
  const div = document.createElement('div');
  div.className = `log-${level}`;
  div.textContent = `${ts} ${msg}`;
  el.appendChild(div);
  while (el.children.length > 300) el.removeChild(el.firstChild);
  el.scrollTop = el.scrollHeight;
}

/* ---------- tabs + chain badges ---------- */

function setTab(tab) {
  if (!TABS.includes(tab)) return;
  state.tab = tab;
  document.querySelectorAll('.ws-panel').forEach((el) => el.classList.toggle('active', el.dataset.tab === tab));
  document.querySelectorAll('.ws-btn').forEach((el) => el.classList.toggle('active', el.dataset.tab === tab));
  if (tab === 'recon') { loadHosts(); loadVulns(); }
  if (tab === 'exploit') { refreshNextMove(); loadCredTargets(); }
  if (tab === 'pivot') { loadShells(); loadCredLedger(); }
  if (tab === 'persist') renderPersist();
  if (tab === 'score') { refreshFlags(); renderReportPreview(); }
}

function badge(id, n) {
  const el = $(id);
  if (el) el.textContent = n > 0 ? `· ${n}` : '';
}

/* ---------- scope + status ---------- */

async function currentEngagementId() {
  if (state.engagementId) return state.engagementId;
  try {
    const s = await api('/api/session');
    state.engagementId = (s.scope && s.scope.engagement_id) || null;
    return state.engagementId;
  } catch { return null; }
}

async function loadScopeSelect() {
  const sel = $('scope-select');
  if (!sel) return;
  try {
    const res = await api('/api/engagement');
    const s = await api('/api/session');
    const cur = (s.scope && s.scope.engagement_id) || '';
    state.engagementId = cur || null;
    sel.innerHTML = '';
    const none = document.createElement('option');
    none.value = ''; none.textContent = 'scope: none';
    sel.appendChild(none);
    (res.engagements || []).forEach((e) => {
      const o = document.createElement('option');
      o.value = e.id; o.textContent = `scope: ${e.name}`;
      sel.appendChild(o);
    });
    sel.value = cur;
    updateScopeSummary(res.engagements || [], cur);
  } catch { /* offline */ }
}

function updateScopeSummary(engs, cur) {
  const el = $('scope-summary');
  if (!el) return;
  const e = (engs || []).find((x) => x.id === cur);
  el.textContent = e ? `${e.name}: ${(e.scope || []).join(', ')}` : 'no scope — recon only, nothing recorded';
}

function setPill(id, text, level) {
  const el = $(id);
  if (!el) return;
  const dot = el.querySelector('.dot');
  if (dot) dot.className = `dot ${level}`;
  const span = el.querySelector('span:last-child');
  if (span) span.textContent = text;
}

async function refreshStatus() {
  try {
    const h = await api('/api/health');
    setPill('msf-status', h.msf === 'up' ? 'msf up' : 'msf down', h.msf === 'up' ? 'online' : 'offline');
  } catch { setPill('msf-status', 'msf ?', 'offline'); }
  try {
    const c = await api('/api/capabilities');
    const tools = c.tools ? Object.values(c.tools).filter((t) => t.installed).length : '?';
    setPill('cap-status', `caps: ${tools} tools`, 'online');
  } catch { setPill('cap-status', 'caps ?', 'offline'); }
  let hosts = 0, services = 0, vulns = 0;
  try {
    const m = await api('/api/map/status');
    const st = (m.status && (m.status.running ? 'running' : m.status.last_status)) || 'idle';
    setPill('autoscan-status', `scan ${st}`, m.status && m.status.running ? 'online' : 'offline');
    const ls = document.querySelector('[data-testid="live-map-state"]');
    if (ls) ls.textContent = `auto-scan: ${st}`;
    hosts = m.host_count || 0; services = m.service_count || 0; vulns = m.vuln_count || 0;
    const lc = document.querySelector('[data-testid="live-map-counts"]');
    if (lc) lc.textContent = `${hosts} hosts · ${services} services · ${vulns} vulns`;
  } catch { /* offline */ }
  try {
    const s = await api('/api/session');
    hosts = Math.max(hosts, s.hosts || 0);
    $('host-counter').textContent = `${hosts} hosts`;
  } catch { /* offline */ }
  badge('ws-count-discover', hosts);
  badge('ws-count-recon', vulns || services);
  const engId = await currentEngagementId();
  let flags = 0, shells = 0, creds = 0;
  if (engId) {
    try {
      const f = await api(`/api/engagement/${engId}/flags`);
      flags = f.count ?? (f.flags || []).length;
      $('flag-counter').textContent = `${flags} flag${flags === 1 ? '' : 's'}`;
    } catch { /* ignore */ }
    try {
      const c = await api(`/api/engagement/${engId}/credentials`);
      creds = (c.credentials || []).length;
    } catch { /* ignore */ }
  } else {
    $('flag-counter').textContent = '0 flags';
  }
  try {
    const s = await api('/api/sessions');
    shells = (s.sessions || []).length;
  } catch { /* ignore */ }
  badge('ws-count-exploit', state.moves.length);
  badge('ws-count-pivot', shells + creds);
  badge('ws-count-persist', shells);
  badge('ws-count-score', flags);
  renderSteps({
    scoped: !!engId,
    scanned: hosts > 0,
    fingerprinted: services > 0,
    won: flags > 0 || shells > 0,
  });
}

function renderSteps(st) {
  // Discover-tab stepper: where am I in scope → scan → fingerprint → win.
  const steps = [
    ['step-scope', st.scoped],
    ['step-scan', st.scanned],
    ['step-fingerprint', st.fingerprinted],
    ['step-win', st.won],
  ];
  steps.forEach(([id, done], i) => {
    const el = $(id);
    if (!el) return;
    el.classList.toggle('done', !!done);
    const label = ['Scope', 'Scan', 'Fingerprint', 'Win'][i];
    el.textContent = `${done ? '✓' : `${i + 1} ·`} ${label}`;
  });
}

/* ---------- 1. discover ---------- */

async function pollJob(jobId, onDone) {
  try {
    const j = await api(`/api/jobs/${jobId}`);
    const pct = j.progress || 0;
    $('scan-status').textContent = `${j.status || 'running'} ${pct}%${j.current_module ? ' · ' + j.current_module : ''}`;
    if (isDone(j.status)) {
      if (state.scanTimer) { clearInterval(state.scanTimer); state.scanTimer = null; }
      onDone(j);
    }
  } catch (e) { log(`job poll failed: ${e.message}`, 'error'); }
}

async function launchScan() {
  const target = $('target').value.trim();
  if (!target) { log('enter a target IP or CIDR first', 'error'); $('target').focus(); return; }
  $('scan-status').textContent = 'starting…';
  try {
    const res = await api('/api/scan', {
      method: 'POST',
      body: { target, mode: $('mode-select').value, depth: $('depth-select').value, do_dns_recon: false, do_vuln_scan: true, try_default_creds: false, open_sessions: false, do_attack: false },
    });
    if (!jobIdOf(res)) { log(`scan refused: ${res.detail || JSON.stringify(res)}`, 'error'); $('scan-status').textContent = 'idle'; return; }
    const scanId = jobIdOf(res);
    log(`scan ${scanId} → ${target}`, 'info');
    if (state.scanTimer) clearInterval(state.scanTimer);
    state.scanTimer = setInterval(() => pollJob(scanId, async () => {
      $('scan-status').textContent = 'done';
      refreshStatus(); refreshNextMove();
    }), 2000);
  } catch (e) { log(`scan failed: ${e.message}`, 'error'); }
}

async function launchNeighbors() {
  try {
    const res = await api('/api/neighbors/scan', { method: 'POST' });
    if (!jobIdOf(res)) { log(`neighbors refused: ${res.detail || 'error'}`, 'error'); return; }
    log(`neighbor discovery ${jobIdOf(res)}`, 'info');
    if (state.scanTimer) clearInterval(state.scanTimer);
    state.scanTimer = setInterval(() => pollJob(jobIdOf(res), async () => {
      $('scan-status').textContent = 'done';
      refreshStatus(); refreshNextMove();
    }), 2000);
  } catch (e) { log(`neighbors failed: ${e.message}`, 'error'); }
}

/* ---------- 2. recon ---------- */

function renderHosts(rows) {
  const tb = $('hosts-tbody');
  const empty = $('hosts-empty');
  const count = $('hosts-count');
  if (!tb) return;
  if (!rows.length) { tb.innerHTML = ''; if (empty) empty.hidden = false; if (count) count.textContent = '0 hosts'; return; }
  if (empty) empty.hidden = true;
  if (count) count.textContent = `${new Set(rows.map((r) => r.ip)).size} hosts · ${rows.length} services`;
  tb.innerHTML = rows.map((r) => `<tr><td>${esc(r.ip)}</td><td>${esc(r.port)}</td><td>${esc(r.service || '')}</td><td>${esc(r.product || '')}</td><td>${esc(r.version || '')}</td><td><button class="btn small" data-act="exploit" data-ip="${escA(r.ip)}" data-port="${escA(r.port)}" data-svc="${escA(r.service || '')}">exploit</button></td></tr>`).join('');
}

async function loadHosts() {
  try {
    const res = await api('/api/neighbors');
    const rows = [];
    (res.hosts || []).forEach((h) => {
      const ip = h.ip || h.address;
      (h.services || []).forEach((s) => {
        if (s.state && s.state !== 'open') return;
        rows.push({ ip, port: `${s.port}/${s.proto || 'tcp'}`, service: s.service, product: s.product, version: s.version });
      });
    });
    renderHosts(rows);
  } catch (e) { log(`hosts load failed: ${e.message}`, 'error'); }
}

function renderVulns(rows) {
  const tb = $('vulns-tbody');
  const empty = $('vulns-empty');
  const count = $('vulns-count');
  if (!tb) return;
  if (!rows.length) { tb.innerHTML = ''; if (empty) empty.hidden = false; if (count) count.textContent = '0 findings'; return; }
  if (empty) empty.hidden = true;
  if (count) count.textContent = `${rows.length} findings`;
  tb.innerHTML = rows.map((v) => `<tr><td>${esc(v.ip)}</td><td>${esc(v.port)}</td><td>${esc(v.id || v.name || '')}</td><td>${esc(v.severity || '')}</td><td><button class="btn small danger" data-act="exploit" data-ip="${escA(v.ip)}" data-port="${escA(v.port || '')}" data-module="${escA(v.module || '')}">fire</button></td></tr>`).join('');
}

async function loadVulns() {
  try {
    const res = await api('/api/neighbors/vulns');
    renderVulns(res.vulns || []);
    const cs = $('cve-status');
    if (cs) {
      const st = await api('/api/cves/status').catch(() => null);
      if (st) cs.textContent = `cve db: ${st.count || '?'} entries${st.stale ? ' (stale)' : ''}`;
      const rb = $('btn-cve-refresh');
      if (rb) rb.hidden = !(st && st.stale);
    }
  } catch (e) { log(`vulns load failed: ${e.message}`, 'error'); }
}

async function startFingerprint() {
  try {
    const res = await api('/api/neighbors/fingerprint', { method: 'POST' });
    if (!jobIdOf(res)) { log(`fingerprint refused: ${res.detail || 'error'}`, 'error'); return; }
    log(`fingerprint ${jobIdOf(res)}`, 'info');
    const jobId = jobIdOf(res);
    if (state.fpTimer) clearInterval(state.fpTimer);
    state.fpTimer = setInterval(async () => {
      try {
        const st = await api(`/api/neighbors/fingerprint/status/${jobId}`);
        if (isDone(st.status)) {
          clearInterval(state.fpTimer); state.fpTimer = null;
          await loadHosts(); await loadVulns(); refreshNextMove(); refreshStatus();
        }
      } catch (e) { log(`fingerprint poll: ${e.message}`, 'error'); }
    }, 2000);
  } catch (e) { log(`fingerprint failed: ${e.message}`, 'error'); }
}

/* ---------- 3. exploit ---------- */

async function refreshNextMove() {
  const list = $('next-move-list');
  const engId = await currentEngagementId();
  if (!engId) {
    if (list) list.innerHTML = '<span>no active scope</span>';
    const q = $('attack-queue');
    if (q) q.innerHTML = '';
    const e = $('attack-empty');
    if (e) e.hidden = false;
    const c = $('attack-queue-count');
    if (c) c.textContent = '0 moves';
    state.moves = [];
    badge('ws-count-exploit', 0);
    return;
  }
  try {
    const res = await api(`/api/engagement/${engId}/next-move`);
    const moves = res.moves || [];
    state.moves = moves;
    badge('ws-count-exploit', moves.length);
    if (list) list.innerHTML = moves.length ? `<b>${esc(moves[0].title)}</b><span>${esc(moves[0].rationale || '')}</span>` : '<span>queue clear</span>';
    const q = $('attack-queue');
    const empty = $('attack-empty');
    const cnt = $('attack-queue-count');
    if (cnt) cnt.textContent = `${moves.length} move${moves.length === 1 ? '' : 's'}`;
    if (!moves.length) { if (q) q.innerHTML = ''; if (empty) empty.hidden = false; return; }
    if (empty) empty.hidden = true;
    if (q) {
      q.innerHTML = moves.map((m, i) => `<div class="move${m.kind === 'attack_path' ? ' hot' : ''}"><span class="kind">${esc(m.kind)}</span><span><span class="title">${esc(m.title)}</span><br /><span class="why">${esc(m.rationale || '')}</span></span><button class="btn small danger" data-move="${i}">fire</button></div>`).join('');
    }
  } catch (e) { if (list) list.innerHTML = '<span>queue unavailable</span>'; }
}

async function fireMove(m) {
  if (!m) return;
  if (m.kind === 'exploit' && m.module) {
    setTab('exploit');
    try {
      const res = await api('/api/attack', { method: 'POST', body: { target: m.host, host: m.host, services: [], module: m.module, port: m.port || null, open_sessions: false } });
      log(jobIdOf(res) ? `exploit ${m.module} → ${m.host} (${jobIdOf(res)})` : `exploit refused: ${res.detail}`, jobIdOf(res) ? 'success' : 'error');
    } catch (e) { log(`exploit failed: ${e.message}`, 'error'); }
  } else if (m.kind === 'default_creds') {
    setTab('exploit');
    log(`try default creds on ${m.host}:${m.port} (${m.service})`, 'warn');
    launchPassAttack(m.host, m.port, m.service);
  } else if (m.kind === 'fuzz') {
    setTab('exploit');
    startFuzzing();
  } else {
    setTab('discover');
    if (m.host && $('target')) { $('target').value = m.host; launchScan(); }
  }
}

async function startAutopilot() {
  const btn = $('btn-ap-start');
  if (btn) btn.disabled = true;
  try {
    const res = await api('/api/autopilot/start', { method: 'POST' });
    if (!jobIdOf(res)) { log(`autopilot refused: ${res.detail || 'no scope?'}`, 'error'); if (btn) btn.disabled = false; return; }
    log('autopilot engaged', 'warn');
    $('btn-ap-stop').hidden = false;
    $('ap-log').textContent = '';
    if (state.apTimer) clearInterval(state.apTimer);
    state.apTimer = setInterval(pollAutopilot, 2000);
    pollAutopilot();
  } catch (e) { log(`autopilot failed: ${e.message}`, 'error'); if (btn) btn.disabled = false; }
}

async function stopAutopilot() {
  try { await api('/api/autopilot/stop', { method: 'POST' }); } catch { /* ignore */ }
  if (state.apTimer) { clearInterval(state.apTimer); state.apTimer = null; }
  $('btn-ap-start').disabled = false;
  $('btn-ap-stop').hidden = true;
  log('autopilot stopped', 'warn');
}

async function pollAutopilot() {
  try {
    const st = await api('/api/autopilot/status');
    if (st.status === 'idle') { $('ap-status').textContent = 'idle'; return; }
    $('ap-status').textContent = st.stage || st.status || 'running';
    if (Array.isArray(st.log)) {
      const box = $('ap-log');
      const fresh = st.log.slice(-120).join('\n');
      if (box.textContent !== fresh) { box.textContent = fresh; box.scrollTop = box.scrollHeight; }
    }
    const entries = Object.entries(st.hosts || {});
    if (entries.length) {
      $('ap-tbody').innerHTML = entries.map(([ip, h]) => `<tr><td>${esc(ip)}</td><td>${esc(h.stage || '')}${h.session_id ? ' 💀' : ''}</td><td>${esc((h.services || []).map((s) => s.port).join(', '))}</td><td>${esc((h.vulns || []).join(', '))}</td><td>${esc(h.creds || '')}</td></tr>`).join('');
    }
    if (st.done || (st.status && st.status !== 'running')) {
      if (state.apTimer) { clearInterval(state.apTimer); state.apTimer = null; }
      $('btn-ap-start').disabled = false;
      $('btn-ap-stop').hidden = true;
      const sum = $('ap-summary');
      if (sum) sum.hidden = false;
      const vals = entries.map(([, h]) => h);
      $('ap-chip-hosts').textContent = `${entries.length} hosts`;
      $('ap-chip-vulns').textContent = `${vals.filter((h) => (h.vulns || []).length).length} with vulns`;
      const m = String(st.message || '');
      $('ap-chip-creds').textContent = `${(m.match(/(\d+) cred/) || [0, 0])[1]} creds`;
      $('ap-chip-sessions').textContent = `${(m.match(/(\d+) session/) || [0, 0])[1]} sessions`;
      log(`autopilot complete: ${m}`, 'success');
      await loadHosts(); await loadVulns(); refreshNextMove(); refreshStatus();
    }
  } catch (e) { log(`autopilot poll: ${e.message}`, 'error'); }
}

async function loadCredTargets() {
  try {
    const res = await api('/api/passattack/targets');
    const targets = res.targets || [];
    $('cred-targets-count').textContent = `${targets.length} targets`;
    $('cred-targets-empty').hidden = targets.length > 0;
    $('cred-targets-tbody').innerHTML = targets.map((t, i) => `<tr><td>${esc(t.ip)}</td><td>${esc(String(t.port))}</td><td>${esc(t.service)}</td><td>${esc(t.product || '')}</td><td><button class="btn small danger" data-cred="${i}">attack</button></td></tr>`).join('');
    $('cred-targets-tbody').dataset.json = JSON.stringify(targets);
  } catch (e) { log(`cred targets failed: ${e.message}`, 'error'); }
}

async function launchPassAttack(host, port, service) {
  try {
    const res = await api('/api/passattack', { method: 'POST', body: { host: host || undefined, port: port ? parseInt(port, 10) : undefined, service: service || undefined } });
    if (!jobIdOf(res)) { log(`password attack refused: ${res.detail || 'error'}`, 'error'); return; }
    log(`password attack ${jobIdOf(res)}`, 'warn');
    const jobId = jobIdOf(res);
    if (state.paTimer) clearInterval(state.paTimer);
    state.paTimer = setInterval(async () => {
      try {
        const st = await api(`/api/passattack/${jobId}`);
        if (isDone(st.status)) {
          clearInterval(state.paTimer); state.paTimer = null;
          log(`password attack done: ${(st.creds || []).length} cred(s)`, 'success');
          loadCredTargets(); refreshNextMove(); refreshStatus();
        }
      } catch (e) { log(`password poll: ${e.message}`, 'error'); }
    }, 2000);
  } catch (e) { log(`password attack failed: ${e.message}`, 'error'); }
}

async function startFuzzing() {
  const btn = $('btn-fz-start');
  if (btn) btn.disabled = true;
  $('btn-fz-stop').hidden = false;
  $('fz-output').hidden = false;
  $('fz-output').textContent = 'fuzzing…';
  try {
    const res = await api('/api/fuzz', {
      method: 'POST',
      body: { host: $('fz-host').value.trim() || '127.0.0.1', port: parseInt($('fz-port').value, 10) || 3138, iterations: parseInt($('fz-iters').value, 10) || 2000, timeout: parseInt($('fz-timeout').value, 10) || 60 },
    });
    if (!jobIdOf(res)) { log(`fuzz refused: ${res.detail || 'error'}`, 'error'); if (btn) btn.disabled = false; return; }
    const jobId = jobIdOf(res);
    log(`fuzz ${jobId}`, 'info');
    if (state.fzTimer) clearInterval(state.fzTimer);
    state.fzTimer = setInterval(async () => {
      try {
        const st = await api(`/api/fuzz/${jobId}`);
        $('fz-live').textContent = `${st.status || 'running'} ${st.progress || 0}%`;
        if (st.output) $('fz-output').textContent = String(st.output).slice(-4000);
        if (isDone(st.status)) {
          clearInterval(state.fzTimer); state.fzTimer = null;
          if (btn) btn.disabled = false;
          $('btn-fz-stop').hidden = true;
          log('fuzz done', 'success');
          refreshNextMove();
        }
      } catch (e) { log(`fuzz poll: ${e.message}`, 'error'); }
    }, 2000);
  } catch (e) { log(`fuzz failed: ${e.message}`, 'error'); if (btn) btn.disabled = false; }
}

/* ---------- 4. pivot ---------- */

async function loadCredLedger() {
  const box = $('creds-ledger');
  const empty = $('creds-empty');
  const cnt = $('creds-ledger-count');
  const engId = await currentEngagementId();
  if (!engId) { if (box) box.innerHTML = ''; if (empty) empty.hidden = false; if (cnt) cnt.textContent = '0 creds'; return; }
  try {
    const res = await api(`/api/engagement/${engId}/credentials`);
    const creds = res.credentials || [];
    if (cnt) cnt.textContent = `${creds.length} cred${creds.length === 1 ? '' : 's'}`;
    if (!creds.length) { if (box) box.innerHTML = ''; if (empty) empty.hidden = false; return; }
    if (empty) empty.hidden = true;
    if (box) box.innerHTML = creds.map((c) => `<div class="credrow"><span class="mono">${esc(c.user || '?')}</span><span class="mono">${esc((((c.hosts || [])[0] || {}).host) || c.host || '')}</span><span class="muted">${esc(c.service || '')} · verified</span></div>`).join('');
  } catch { /* optional */ }
}

async function loadPropagationPlan() {
  const engId = await currentEngagementId();
  if (!engId) { log('set an active scope first', 'warn'); return; }
  try {
    const plan = await api(`/api/engagement/${engId}/propagate/plan`);
    const pairs = plan.pairs || [];
    $('prop-body').innerHTML = pairs.length ? pairs.map((p) => `<div>${esc(p.user)} @ ${esc(p.host)}:${esc(p.port)} (${esc(p.service)})</div>`).join('') : 'no replay pairs';
    $('btn-propagate-run').hidden = pairs.length === 0;
  } catch (e) { log(`propagation plan failed: ${e.message}`, 'error'); }
}

async function executePropagation() {
  const engId = await currentEngagementId();
  if (!engId) return;
  $('prop-results').hidden = false;
  $('prop-results').textContent = 'executing…';
  try {
    const res = await api(`/api/engagement/${engId}/propagate`, { method: 'POST', body: { open_sessions: false } });
    $('prop-results').textContent = JSON.stringify(res, null, 2).slice(0, 4000);
    log(`propagation: ${(res.logins || []).length} attempt(s)`, 'success');
    loadCredLedger(); loadShells(); refreshStatus();
  } catch (e) { log(`propagation failed: ${e.message}`, 'error'); }
}

async function loadShells() {
  const list = $('shells-list');
  const empty = $('shells-empty');
  const cnt = $('shells-count');
  try {
    const res = await api('/api/sessions');
    const sessions = res.sessions || [];
    state.shells = sessions;
    if (cnt) cnt.textContent = `${sessions.length} shell${sessions.length === 1 ? '' : 's'}`;
    if (!sessions.length) { list.innerHTML = ''; if (empty) empty.hidden = false; return; }
    if (empty) empty.hidden = true;
    list.innerHTML = sessions.map((s) => `<div class="shellrow"><span>💀</span><span class="mono">${esc(s.msf_session_id || s.id)}</span><span>${esc(s.host || '')}</span>${s.alive === false ? '<span class="muted">dead — re-enter via Persist</span>' : `<button class="btn small" data-shell="${escA(s.msf_session_id || s.id)}" data-host="${escA(s.host || '')}">open</button>`}</div>`).join('');
  } catch (e) { log(`sessions failed: ${e.message}`, 'error'); }
}

function openSessionConsole(sessionId, host) {
  state.activeSession = sessionId;
  $('ex-console').hidden = false;
  $('ex-console-target').textContent = `session ${sessionId} @ ${host}`;
  $('ex-console-output').textContent = '';
  $('ex-console').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

async function runSessionCmd(cmd) {
  const sid = state.activeSession;
  if (!sid) { log('no active session', 'warn'); return; }
  const out = $('ex-console-output');
  out.textContent += `> ${cmd}\n`;
  try {
    const res = await api(`/api/sessions/${sid}/cmd`, { method: 'POST', body: { command: cmd } });
    const text = res.output;
    out.textContent += text !== undefined ? `${text || '(no output)'}\n`.slice(0, 4000) : `error: ${res.detail || '?'}\n`;
    if (text) scanFlagsFor(text);
  } catch (e) { out.textContent += `error: ${e.message}\n`; }
  out.scrollTop = out.scrollHeight;
}

async function mapLateralRoutes() {
  const cidr = $('lateral-cidr').value.trim() || '192.168.1.0/24';
  $('lateral-body').textContent = 'mapping…';
  try {
    const res = await api('/api/lateral', { method: 'POST', body: { cidr } });
    const lines = [];
    (res.local_ips || []).forEach((ip) => lines.push(`local: ${ip}`));
    (res.routes || []).forEach((r) => lines.push(`route: ${typeof r === 'string' ? r : JSON.stringify(r)}`));
    $('lateral-body').innerHTML = lines.length
      ? `<div class="output">${esc(lines.join('\n')).slice(0, 3000)}</div>`
      : 'no routes returned';
    log('route map done', 'info');
  } catch (e) {
    $('lateral-body').textContent = `route map failed: ${e.message}`;
    log(`route map failed: ${e.message}`, 'error');
  }
}

async function runDbInterrogate() {
  const target = $('db-target').value.trim() || '127.0.0.1';
  $('db-body').textContent = 'enumerating…';
  try {
    const res = await api('/api/db_interrogate', { method: 'POST', body: { target } });
    const text = JSON.stringify(res, null, 2).slice(0, 4000);
    $('db-body').innerHTML = `<div class="output">${esc(text)}</div>`;
    await scanFlagsFor(text);
    log('interrogation done', 'success');
  } catch (e) {
    $('db-body').textContent = `interrogation failed: ${e.message}`;
    log(`interrogation failed: ${e.message}`, 'error');
  }
}

async function runTryLocalRoot() {
  $('trylocalroot-body').textContent = 'trying passwordless paths + auditing…';
  try {
    const res = await api('/api/tryLocalRoot_go_bro', { method: 'POST', body: {} });
    const rows = [];
    const u = res.userns || {};
    rows.push(`${u.success ? '✅' : '⬜'} userns uid 0 (no sudo, no docker)${u.stdout ? `: ${u.stdout.split('\n')[0]}` : ''}`);
    const d = res.docker_group || {};
    rows.push(`${d.success ? '✅' : '⬜'} docker-group host read${d.success ? '' : ' (needs docker group)'}${d.reason ? `: ${d.reason}` : ''}`);
    const a = res.host_audit || {};
    const vecs = a.vectors || [];
    rows.push(`${res.host_root_achieved ? '🚨 HOST ROOT VECTOR' : '✅ no host-root vector'} in automated scope (${a.suid_count ?? '?'} SUID, ${(a.risky_caps && Object.keys(a.risky_caps).length) ?? '?'} risky caps)`);
    vecs.slice(0, 5).forEach((v) => rows.push(`⚠ ${v.type}: ${v.name || ''}`));
    if (res.verdict) rows.push(`verdict: ${res.verdict}`);
    $('trylocalroot-body').innerHTML = rows.map((r) => `<div>${esc(r).slice(0, 300)}</div>`).join('');
    log('local-root assessment done', res.host_root_achieved ? 'warn' : 'success');
  } catch (e) {
    $('trylocalroot-body').textContent = `local-root assessment failed: ${e.message}`;
    log(`local-root assessment failed: ${e.message}`, 'error');
  }
}

async function runEscapeCheck() {
  $('escape-body').textContent = 'checking…';
  try {
    const res = await api('/api/container_escape', { method: 'POST', body: {} });
    const vecs = res.vectors || [];
    $('escape-body').innerHTML = vecs.length
      ? vecs.map((v) => `<div>⚠ ${esc(v.name || v.id || 'vector')}: ${esc(v.detail || v.description || '')}</div>`).join('')
      : 'no escape vectors detected';
    log('escape check done', 'info');
  } catch (e) {
    $('escape-body').textContent = `escape check failed: ${e.message}`;
    log(`escape check failed: ${e.message}`, 'error');
  }
}

/* ---------- recon: web assessment (nikto + gobuster) ---------- */

function renderToolResult(elId, res, label) {
  const tool = res.tool || {};
  const text = (tool.stdout || tool.stderr || JSON.stringify(res)).slice(0, 4000);
  $(elId).innerHTML = `<div class="output">${esc(text)}</div>`;
  log(`${label} done: ${tool.status || (res.success ? 'ok' : 'failed')}`, 'info');
}

async function runNikto() {
  const target = $('web-target').value.trim();
  if (!target) { log('nikto needs a target', 'warn'); return; }
  $('web-body').textContent = 'nikto scanning…';
  try {
    const res = await api('/api/nikto', { method: 'POST', body: { target } });
    renderToolResult('web-body', res, 'nikto');
  } catch (e) {
    $('web-body').textContent = `nikto failed: ${e.message}`;
    log(`nikto failed: ${e.message}`, 'error');
  }
}

async function runGobuster() {
  const target = $('web-target').value.trim();
  if (!target) { log('gobuster needs a target', 'warn'); return; }
  const extensions = $('webgob-ext').value.trim();
  $('web-body').textContent = 'gobuster enumerating…';
  try {
    const res = await api('/api/gobuster', { method: 'POST', body: { target, extensions: extensions || null } });
    renderToolResult('web-body', res, 'gobuster');
  } catch (e) {
    $('web-body').textContent = `gobuster failed: ${e.message}`;
    log(`gobuster failed: ${e.message}`, 'error');
  }
}

/* ---------- pivot: Fire TV via adb ---------- */

async function ftvRun(action, extra = {}) {
  const target = $('ftv-target').value.trim() || '127.0.0.1';
  $('ftv-body').textContent = `${action}…`;
  try {
    const res = await api(`/api/firetv/${action}`, { method: 'POST', body: { target, ...extra } });
    const detail = res.detail || {};
    const rows = [];
    if (res.output) rows.push(res.output.slice(0, 1500));
    if (detail.state) rows.push(`adb state: ${detail.state}`);
    if (detail.adb_state) rows.push(`adb state: ${detail.adb_state}`);
    if (detail.count !== undefined) rows.push(`packages: ${detail.count}`);
    if (detail.file) rows.push(`saved: ${detail.file}`);
    if (detail.ports) {
      const open = Object.entries(detail.ports).filter(([, v]) => v).map(([p]) => p);
      rows.push(`open tv ports: ${open.length ? open.join(', ') : 'none'}`);
    }
    if (detail.eureka && detail.eureka.model_name) rows.push(`model: ${detail.eureka.model_name}`);
    const text = rows.length ? rows.join('\n') : JSON.stringify(detail).slice(0, 1500) || '(empty)';
    $('ftv-body').innerHTML = `<div class="output">${esc(text)}</div>`;
    log(`firetv ${action}: ${res.success ? 'ok' : (res.error || 'failed')}`, res.success ? 'success' : 'warn');
  } catch (e) {
    $('ftv-body').textContent = `firetv ${action} failed: ${e.message}`;
    log(`firetv ${action} failed: ${e.message}`, 'error');
  }
}

/* ---------- exploit: container-surface recon + fuzz ---------- */

async function detectContainerSurfaces() {
  const target = $('cf-target').value.trim() || '127.0.0.1';
  $('cf-output').hidden = false;
  $('cf-output').textContent = 'inventorying runtimes…';
  try {
    const res = await api('/api/container_surfaces', { method: 'POST', body: { target } });
    const rows = [];
    const s = res.surfaces || {};
    if (s.docker) rows.push(`docker sock: ${s.docker.socket_present ? 'present' : 'absent'}${s.docker.api_version ? ` (API ${s.docker.api_version})` : ''}`);
    if (s.containerd) rows.push(`containerd sock: ${s.containerd.socket_present ? 'present' : 'absent'}`);
    if (s.kubelet && s.kubelet.ports) {
      const open = Object.entries(s.kubelet.ports).filter(([, p]) => p.open).map(([p]) => p);
      rows.push(`kubelet: ${open.length ? `open on ${open.join(', ')}` : 'no API ports open'}`);
    }
    $('cf-output').textContent = rows.length ? rows.join('\n') : 'no container runtimes found';
    log('surface inventory done', 'info');
  } catch (e) {
    $('cf-output').textContent = `inventory failed: ${e.message}`;
    log(`surface inventory failed: ${e.message}`, 'error');
  }
}

async function startContainerFuzz() {
  const btn = $('btn-cf-start');
  if (btn) btn.disabled = true;
  $('cf-output').hidden = false;
  $('cf-output').textContent = 'fuzzing container surface…';
  try {
    const res = await api('/api/container_fuzz', {
      method: 'POST',
      body: {
        surface: $('cf-surface').value,
        target: $('cf-target').value.trim() || '127.0.0.1',
        iterations: parseInt($('cf-iters').value, 10) || 200,
      },
    });
    if (!jobIdOf(res)) { log(`container fuzz refused: ${res.detail || 'error'}`, 'error'); if (btn) btn.disabled = false; return; }
    const jobId = jobIdOf(res);
    log(`container fuzz ${jobId}`, 'info');
    if (state.cfTimer) clearInterval(state.cfTimer);
    state.cfTimer = setInterval(async () => {
      try {
        const st = await api(`/api/container_fuzz/${jobId}`);
        $('cf-live').textContent = `${st.status || 'running'}`;
        const cands = st.candidates || [];
        if (cands.length) $('cf-output').textContent = cands.map((c) => `${c.signal || '?'} via ${c.vector || '?'} (${c.port || ''})`).join('\n').slice(0, 4000);
        if (isDone(st.status)) {
          clearInterval(state.cfTimer); state.cfTimer = null;
          if (btn) btn.disabled = false;
          if (!cands.length) $('cf-output').textContent += '\nno candidates — surface stayed quiet';
          log('container fuzz done', 'success');
        }
      } catch (e) { log(`container fuzz poll: ${e.message}`, 'error'); }
    }, 2000);
  } catch (e) { log(`container fuzz failed: ${e.message}`, 'error'); if (btn) btn.disabled = false; }
}

/* ---------- 5. persist: hold the win ---------- */

async function renderPersist() {
  const box = $('persist-checks');
  const sessBox = $('persist-sessions');
  const engId = await currentEngagementId();
  let sessions = [];
  let creds = 0, flags = 0;
  try { sessions = (await api('/api/sessions')).sessions || []; } catch { /* ignore */ }
  if (engId) {
    try { creds = ((await api(`/api/engagement/${engId}/credentials`)).credentials || []).length; } catch { /* ignore */ }
    try {
      const f = await api(`/api/engagement/${engId}/flags`);
      flags = f.count ?? (f.flags || []).length;
    } catch { /* ignore */ }
  }
  const rows = [
    [`${sessions.length} live session(s)`, sessions.length > 0],
    [`${creds} banked credential(s) — your re-entry keys`, creds > 0],
    [`${flags} flag(s) captured`, flags > 0],
  ];
  box.innerHTML = rows.map(([label, ok]) => `<div class="persistrow">${ok ? '✅' : '⬜'} ${esc(label)}</div>`).join('');
  sessBox.innerHTML = sessions.length
    ? sessions.map((s) => `<div class="shellrow"><span>💀</span><span class="mono">${esc(s.msf_session_id || s.id)}</span><span>${esc(s.host || '')}</span>${s.alive === false ? '<span class="muted">dead</span>' : '<span class="muted">alive</span>'}</div>`).join('')
    : 'no live sessions — re-enter below, then come back';
}

/* ---------- 6. score: flags, objective, report ---------- */

function toast(text) {
  const el = $('flag-toast');
  el.textContent = text;
  el.hidden = false;
  setTimeout(() => { el.hidden = true; }, 4500);
}

async function refreshFlags() {
  const grid = $('flags-grid');
  const empty = $('flags-empty');
  const engId = await currentEngagementId();
  if (!engId) {
    grid.innerHTML = ''; empty.hidden = false;
    $('flags-count').textContent = '0 captured';
    $('flag-counter').textContent = '0 flags';
    return;
  }
  try {
    const res = await api(`/api/engagement/${engId}/flags`);
    const flags = res.flags || [];
    const n = res.count ?? flags.length;
    $('flags-count').textContent = `${n} captured`;
    $('flag-counter').textContent = `${n} flag${n === 1 ? '' : 's'}`;
    if (!flags.length) { grid.innerHTML = ''; empty.hidden = false; return; }
    empty.hidden = true;
    grid.innerHTML = flags.map((f) => `<div class="flag"><span class="val">${esc(f.value)}</span><span class="meta">${esc(f.host || 'unknown')}${f.auto ? ' · auto' : ''}</span><span class="spacer"></span><button class="btn small" data-flagdel="${escA(f.id)}">✕</button></div>`).join('');
  } catch (e) { log(`flags failed: ${e.message}`, 'error'); }
}

async function addFlag() {
  const engId = await currentEngagementId();
  if (!engId) { log('set an active scope first', 'warn'); return; }
  const value = $('flag-value').value.trim();
  if (!value) { log('flag value required', 'error'); return; }
  try {
    await apiOrThrow(`/api/engagement/${engId}/flags`, { method: 'POST', body: { value, host: $('flag-host').value.trim() || null, note: $('flag-note').value.trim() } });
    log(`flag captured: ${value}`, 'success');
    toast(`FLAG: ${value}`);
    $('flag-value').value = ''; $('flag-host').value = ''; $('flag-note').value = '';
    refreshFlags(); refreshStatus();
  } catch (e) { log(`flag add failed: ${e.message}`, 'error'); }
}

async function detectFlags() {
  const engId = await currentEngagementId();
  if (!engId) { log('set an active scope first', 'warn'); return; }
  const text = $('ex-console-output') ? $('ex-console-output').textContent : '';
  try {
    const res = await api(`/api/engagement/${engId}/flags/detect`, { method: 'POST', body: { text } });
    const n = (res.detected || []).length;
    log(`auto-detect: ${n} new flag(s)`, n ? 'success' : 'info');
    if (n) { toast(`${n} flag(s) detected`); refreshFlags(); refreshStatus(); }
  } catch (e) { log(`detect failed: ${e.message}`, 'error'); }
}

async function scanFlagsFor(text) {
  const engId = await currentEngagementId();
  if (!engId) return;
  try {
    const res = await api(`/api/engagement/${engId}/flags/detect`, { method: 'POST', body: { text: String(text || '') } });
    if ((res.detected || []).length) { toast('flag detected in output'); refreshFlags(); refreshStatus(); }
  } catch { /* best-effort */ }
}

async function loadCrowns() {
  const engId = await currentEngagementId();
  if (!engId) return [];
  try {
    const res = await api(`/api/engagement/${engId}/crown-jewels`);
    const crowns = res.crowns || res.crown_jewels || [];
    $('crown-list').innerHTML = crowns.length
      ? crowns.map((c) => `<div>${esc(c.label || c.host)} — ${esc(c.host)} <button class="btn small" data-crowndel="${escA(c.id)}" data-testid="del-crown">✕</button></div>`).join('')
      : 'No crown jewels declared yet';
    return crowns;
  } catch (e) { log(`crowns failed: ${e.message}`, 'error'); return []; }
}

async function addCrownJewel() {
  const engId = await currentEngagementId();
  if (!engId) { log('set an active scope first', 'warn'); return; }
  const host = $('cj-host').value.trim();
  if (!host) { log('crown jewel host required', 'error'); return; }
  try {
    await apiOrThrow(`/api/engagement/${engId}/crown-jewels`, {
      method: 'POST',
      body: { host, label: $('cj-label').value.trim() || host, value: parseInt($('cj-value').value, 10) || 50 },
    });
    log(`crown jewel declared: ${host}`, 'success');
    $('cj-host').value = ''; $('cj-label').value = '';
    await loadAttackPaths();
  } catch (e) { log(`Add crown jewel failed: ${e.message}`, 'error'); }
}

async function loadAttackPaths() {
  const engId = await currentEngagementId();
  if (!engId) return;
  await loadCrowns();
  try {
    const res = await api(`/api/engagement/${engId}/attack-paths`);
    renderPathList(res.paths || [], `${(res.paths || []).length} path(s)`);
  } catch (e) { log(`attack paths failed: ${e.message}`, 'error'); }
}

function renderPathList(paths, summary) {
  $('attack-paths-body').innerHTML = paths.length
    ? paths.map((p) => {
      const flags = (p.flags || []).map((f) => esc(f.value || '')).join(', ');
      return `<div class="move hot" data-testid="path-item"><span class="kind">score <span data-testid="path-score">${esc(String(p.score ?? ''))}</span></span><span><span class="title" data-testid="path-nodes">${esc((p.nodes || []).join(' → '))}</span><br /><span class="why">${esc((p.vulns || []).join(', '))}${flags ? `<br />🏁 ${flags}` : ''}</span></span></div>`;
    }).join('')
    : 'no paths yet';
  const sum = $('attack-paths-summary');
  sum.hidden = false;
  sum.textContent = summary;
}

async function loadFlagPaths() {
  const engId = await currentEngagementId();
  if (!engId) return;
  await loadCrowns();
  try {
    const res = await api(`/api/engagement/${engId}/flag-paths`);
    renderPathList(res.paths || [], `${(res.paths || []).length} flag path(s) · ${(res.summary || {}).flags || 0} flag(s)`);
  } catch (e) { log(`flag paths failed: ${e.message}`, 'error'); }
}

async function loadAttck() {
  const engId = await currentEngagementId();
  if (!engId) { $('attck-body').textContent = 'No active engagement scope — declare one in the status bar first.'; return; }
  try {
    const res = await api(`/api/engagement/${engId}/attck`);
    const techs = res.techniques || [];
    $('attck-body').innerHTML = techs.length
      ? techs.map((t) => `<div data-testid="attck-technique"><b data-testid="attck-tech-id">${esc(t.id)}</b> ${esc(t.name || '')}<br /><span data-testid="attck-detection">${esc(t.detection || '')} sources: ${esc((t.data_sources || []).join(', '))} events: ${esc((t.events || []).join(', '))}</span></div>`).join('')
      : 'no findings mapped';
  } catch (e) { log(`attck failed: ${e.message}`, 'error'); }
}

async function renderReportPreview() {
  try {
    const res = await api('/api/session/report?fmt=md');
    const body = (res.content || 'empty — run a scan first').slice(0, 6000);
    $('report-preview').textContent = `h4k session report\n\n${body}`;
  } catch (e) { $('report-preview').textContent = `preview failed: ${e.message}`; }
}

async function downloadSessionReport() {
  try {
    const res = await api('/api/session/report?fmt=md');
    const blob = new Blob([res.content || ''], { type: 'text/markdown' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'h4k-session.md';
    a.click();
    URL.revokeObjectURL(a.href);
    log('session report downloaded', 'success');
  } catch (e) { log(`report failed: ${e.message}`, 'error'); }
}

/* ---------- palette + keyboard ---------- */

function togglePalette(show) {
  const el = $('cmd-palette');
  if (show === undefined) show = el.hidden;
  el.hidden = !show;
  if (!show) $('cmd-input').value = '';
  else setTimeout(() => $('cmd-input').focus(), 50);
}

function runCmd(cmd) {
  togglePalette(false);
  if (cmd === 'scan') { setTab('discover'); launchScan(); }
  else if (cmd === 'neighbors') { setTab('discover'); launchNeighbors(); }
  else if (cmd === 'fingerprint') { setTab('recon'); startFingerprint(); }
  else if (cmd === 'autopilot') { setTab('exploit'); startAutopilot(); }
  else if (cmd === 'nikto') { setTab('recon'); runNikto(); }
  else if (cmd === 'gobuster') { setTab('recon'); runGobuster(); }
  else if (cmd === 'firetv') setTab('pivot');
  else if (cmd === 'cfuzz') setTab('exploit');
  else if (cmd === 'persist') setTab('persist');
  else if (cmd === 'score') setTab('score');
  else if (cmd === 'theme') toggleTheme();
  else if (cmd === 'clear') { $('activity-log').innerHTML = ''; }
}

function toggleTheme() {
  const root = document.documentElement;
  root.dataset.theme = root.dataset.theme === 'light' ? 'dark' : 'light';
  try { localStorage.setItem('h4k-theme', root.dataset.theme); } catch { /* ignore */ }
}

/* ---------- boot ---------- */

document.addEventListener('DOMContentLoaded', () => {
  try {
    const saved = localStorage.getItem('h4k-theme');
    if (saved) document.documentElement.dataset.theme = saved;
  } catch { /* ignore */ }

  document.querySelectorAll('.ws-btn').forEach((b) => b.addEventListener('click', () => setTab(b.dataset.tab)));

  $('scope-select').addEventListener('change', async (e) => {
    const engId = e.target.value || null;
    try {
      const res = await api('/api/session/scope', { method: 'POST', body: { engagement_id: engId } });
      state.engagementId = engId;
      log(res.status === 'scoped' ? `scope engaged: ${res.name}` : 'scope cleared', 'warn');
      loadScopeSelect();
      refreshStatus(); refreshNextMove();
    } catch (err) { log(`scope change failed: ${err.message}`, 'error'); }
  });

  // discover stepper
  $('step-scope').addEventListener('click', () => { const s = $('scope-select'); if (s) s.focus(); });
  $('step-scan').addEventListener('click', () => { const t = $('target'); if (t) t.focus(); });
  $('step-fingerprint').addEventListener('click', () => setTab('recon'));
  $('step-win').addEventListener('click', () => setTab('exploit'));
  // next strip: run the top recommendation
  $('btn-next-go').addEventListener('click', () => {
    const top = state.moves && state.moves[0];
    if (!top) { log('queue clear — nothing to run', 'info'); return; }
    fireMove(top);
  });
  // discover
  $('btn-scan').addEventListener('click', launchScan);
  $('target').addEventListener('keydown', (e) => { if (e.key === 'Enter') launchScan(); });
  $('btn-neighbors').addEventListener('click', launchNeighbors);
  $('btn-live-map-toggle').addEventListener('click', async () => {
    try {
      const cur = await api('/api/map/status');
      const running = cur.status && cur.status.running;
      await api(running ? '/api/map/stop' : '/api/map/start', { method: 'POST' });
      refreshStatus();
    } catch (e) { log(`auto-scan toggle failed: ${e.message}`, 'error'); }
  });

  // recon
  $('btn-fingerprint').addEventListener('click', startFingerprint);
  $('btn-empty-fp').addEventListener('click', startFingerprint);
  $('btn-empty-fpv').addEventListener('click', startFingerprint);
  $('btn-empty-scope').addEventListener('click', () => setTab('discover'));
  $('btn-empty-exploit').addEventListener('click', () => setTab('exploit'));
  $('btn-full-scan').addEventListener('click', async () => {
    try {
      const res = await api('/api/neighbors/fingerprint', { method: 'POST', body: {} });
      log(jobIdOf(res) ? `full scan ${jobIdOf(res)}` : `full scan refused: ${res.detail}`, jobIdOf(res) ? 'info' : 'error');
    } catch (e) { log(`full scan failed: ${e.message}`, 'error'); }
  });
  $('btn-nikto').addEventListener('click', runNikto);
  $('btn-gobuster').addEventListener('click', runGobuster);
  $('btn-cf-detect').addEventListener('click', detectContainerSurfaces);
  $('btn-cf-start').addEventListener('click', startContainerFuzz);
  $('btn-cve-refresh').addEventListener('click', async () => {
    try { await api('/api/cves/refresh', { method: 'POST' }); log('cve refresh started', 'info'); loadVulns(); }
    catch (e) { log(`cve refresh failed: ${e.message}`, 'error'); }
  });

  // exploit
  $('btn-refresh-next').addEventListener('click', refreshNextMove);
  $('btn-ap-start').addEventListener('click', startAutopilot);
  $('btn-ap-stop').addEventListener('click', stopAutopilot);
  $('btn-fz-start').addEventListener('click', startFuzzing);
  $('btn-fz-stop').addEventListener('click', async () => { $('btn-fz-stop').hidden = true; $('btn-fz-start').disabled = false; });
  $('btn-cred-targets-refresh').addEventListener('click', loadCredTargets);
  $('btn-launch-passattack').addEventListener('click', () => launchPassAttack());

  // pivot
  $('shell-close').addEventListener('click', () => { $('ex-console').hidden = true; state.activeSession = null; });
  $('btn-ex-cmd').addEventListener('click', () => { const v = $('ex-cmd').value.trim(); if (v) { runSessionCmd(v); $('ex-cmd').value = ''; } });
  $('ex-cmd').addEventListener('keydown', (e) => { if (e.key === 'Enter') { const v = e.target.value.trim(); if (v) { runSessionCmd(v); e.target.value = ''; } } });
  $('btn-propagate-plan').addEventListener('click', loadPropagationPlan);
  $('btn-propagate-run').addEventListener('click', executePropagation);
  $('btn-lateral-map').addEventListener('click', mapLateralRoutes);
  $('btn-db-run').addEventListener('click', runDbInterrogate);
  $('btn-escape-run').addEventListener('click', runEscapeCheck);
  $('btn-trylocalroot-run').addEventListener('click', runTryLocalRoot);
  $('btn-ftv-recon').addEventListener('click', () => ftvRun('recon'));
  $('btn-ftv-pair').addEventListener('click', () => {
    const code = $('ftv-code').value.trim();
    if (!code) { log('pair needs the 6-digit on-screen code', 'warn'); return; }
    ftvRun('pair', { code });
  });
  $('btn-ftv-state').addEventListener('click', () => ftvRun('state'));
  $('btn-ftv-apps').addEventListener('click', () => ftvRun('apps'));
  $('btn-ftv-shot').addEventListener('click', () => ftvRun('screenshot'));

  // persist
  $('btn-reenter').addEventListener('click', async () => { setTab('pivot'); await loadPropagationPlan(); await executePropagation(); await renderPersist(); });
  $('btn-go-score').addEventListener('click', () => setTab('score'));

  // score
  $('btn-flag-add').addEventListener('click', addFlag);
  $('btn-flag-detect').addEventListener('click', detectFlags);
  $('btn-add-crown').addEventListener('click', addCrownJewel);
  $('btn-attack-paths').addEventListener('click', loadAttackPaths);
  $('btn-flag-paths').addEventListener('click', loadFlagPaths);
  $('btn-attck').addEventListener('click', loadAttck);
  $('btn-session-report').addEventListener('click', downloadSessionReport);

  // chrome
  $('activity-toggle').addEventListener('click', () => { $('activity-drawer').hidden = !$('activity-drawer').hidden; });
  $('activity-close').addEventListener('click', () => { $('activity-drawer').hidden = true; });
  $('cmd-palette-btn').addEventListener('click', () => togglePalette(true));
  $('cmd-palette').addEventListener('click', (e) => { if (e.target === $('cmd-palette')) togglePalette(false); });
  $('cmd-input').addEventListener('input', (e) => {
    const q = e.target.value.toLowerCase();
    document.querySelectorAll('.cmd-item').forEach((item) => {
      item.style.display = item.textContent.toLowerCase().includes(q) ? '' : 'none';
    });
  });
  $('cmd-input').addEventListener('keydown', (e) => {
    if (e.key === 'Escape') togglePalette(false);
    if (e.key === 'Enter') {
      const first = document.querySelector('.cmd-item:not([style*="none"])');
      if (first) runCmd(first.dataset.cmd);
    }
  });
  document.querySelectorAll('.cmd-item').forEach((item) => item.addEventListener('click', () => runCmd(item.dataset.cmd)));

  document.addEventListener('keydown', (e) => {
    if (e.ctrlKey && e.key === 'k') { e.preventDefault(); togglePalette(true); return; }
    if (e.key === 'Escape') { togglePalette(false); $('activity-drawer').hidden = true; return; }
    if (['INPUT', 'TEXTAREA', 'SELECT'].includes(e.target.tagName)) return;
    if (e.ctrlKey && e.key === 'Enter' && state.tab === 'discover') { launchScan(); return; }
    if (e.key >= '1' && e.key <= String(TABS.length)) setTab(TABS[parseInt(e.key, 10) - 1]);
    if (e.key === 't') toggleTheme();
    if (e.key === 'j' || e.key === 'l') {
      const i = TABS.indexOf(state.tab);
      setTab(TABS[(i + (e.key === 'j' ? 1 : TABS.length - 1)) % TABS.length]);
    }
    if (e.key === 'k' || e.key === 'h') {
      const i = TABS.indexOf(state.tab);
      setTab(TABS[(i + (e.key === 'k' ? TABS.length - 1 : 1)) % TABS.length]);
    }
  });

  document.addEventListener('click', (e) => {
    const mv = e.target.closest('[data-move]');
    if (mv) { const m = state.moves[parseInt(mv.dataset.move, 10)]; if (m) fireMove(m); return; }
    const fd = e.target.closest('[data-flagdel]');
    if (fd) {
      currentEngagementId().then(async (engId) => {
        if (!engId) return;
        await api(`/api/engagement/${engId}/flags/${fd.dataset.flagdel}`, { method: 'DELETE' });
        refreshFlags(); refreshStatus();
      });
      return;
    }
    const sh = e.target.closest('[data-shell]');
    if (sh) { setTab('pivot'); openSessionConsole(sh.dataset.shell, sh.dataset.host); return; }
    const cd = e.target.closest('[data-crowndel]');
    if (cd) {
      currentEngagementId().then(async (engId) => {
        if (!engId) return;
        await api(`/api/engagement/${engId}/crown-jewels/${cd.dataset.crowndel}`, { method: 'DELETE' });
        loadAttackPaths();
      });
      return;
    }
    const ct = e.target.closest('[data-cred]');
    if (ct) {
      try {
        const targets = JSON.parse($('cred-targets-tbody').dataset.json || '[]');
        const t = targets[parseInt(ct.dataset.cred, 10)];
        if (t) launchPassAttack(t.ip, t.port, t.service);
      } catch { /* ignore */ }
      return;
    }
    const ex = e.target.closest('[data-excmd]');
    if (ex) { runSessionCmd(ex.dataset.excmd); return; }
    const eb = e.target.closest('[data-act="exploit"]');
    if (eb) {
      setTab('exploit');
      refreshNextMove();
      log(`exploit candidate: ${eb.dataset.ip}:${eb.dataset.port || ''} ${eb.dataset.module || eb.dataset.svc || ''}`, 'info');
      return;
    }
  });

  $('theme-toggle').addEventListener('click', toggleTheme);
  $('btn-session-reset').addEventListener('click', async () => {
    if (!confirm('Reset session? Engagements are kept.')) return;
    try {
      await api('/api/session/reset?wipe_engagements=false', { method: 'POST' });
      log('session reset', 'warn');
      loadHosts(); loadVulns(); loadShells(); refreshStatus();
    } catch (e) { log(`reset failed: ${e.message}`, 'error'); }
  });

  loadScopeSelect().then(() => { refreshStatus(); refreshNextMove(); });
  state.statusTimer = setInterval(refreshStatus, 8000);
  log('h4k kill-chain console ready — discover → recon → exploit → pivot → persist → score', 'info');
  setTab('discover');
});
