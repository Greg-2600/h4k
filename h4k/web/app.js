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
  const rail = $('rail-log');
  if (rail) {
    rail.appendChild(div.cloneNode(true));
    while (rail.children.length > 40) rail.removeChild(rail.firstChild);
    rail.scrollTop = rail.scrollHeight;
  }
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
  if (tab === 'score') { refreshFlags(); renderReportPreview(); refreshWatch(); refreshHandoff(); }
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
  const form = $('scope-create');
  if (form) form.hidden = !!e;
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
  let daemonLine = '';
  try {
    const h = await api('/api/health');
    const msfUp = !!(h.msf && h.msf.reachable);
    setPill('msf-status', msfUp ? 'msf up' : 'msf down', msfUp ? 'online' : 'offline');
    const svc = (h.services) || {};
    const parts = Object.keys(svc).sort().map((n) => {
      const s = svc[n] || {};
      const mark = s.up ? '✓' : (s.degraded ? '!' : '✗');
      const rest = s.restarts_total ? ` (r${s.restarts_total})` : '';
      return `${esc(n)} ${mark}${rest}`;
    });
    if (parts.length) daemonLine = parts.join(' · ');
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
  const rs = $('rail-session');
  if (rs) {
    rs.innerHTML =
      `<div>scope <b>${esc(engId ? engId.slice(0, 8) : 'none')}</b></div>` +
      `<div>hosts <b>${hosts}</b> · services <b>${services}</b> · vulns <b>${vulns}</b></div>` +
      `<div>shells <b>${shells}</b> · creds <b>${creds}</b> · flags <b>${flags}</b></div>` +
      (daemonLine ? `<div data-testid="rail-services">daemons ${daemonLine}</div>` : '');
  }
  const rsc = $('rail-scope');
  if (rsc) rsc.textContent = engId ? engId.slice(0, 8) : 'no scope';
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
  const engId = await currentEngagementId();
  if (!engId) {
    log('no scope: create one above (name + authorized CIDRs) before scanning — scans stay read-only without it', 'error');
    const c = $('scope-cidrs'); if (c && !$('scope-create').hidden) c.focus();
    return;
  }
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

async function launchNeighbors6() {
  $('ipv6-body').textContent = 'discovering IPv6 neighbors…';
  try {
    const engId = await currentEngagementId();
    const target = $('target').value.trim();
    const cidr = /:/.test(target) ? target : null;
    const res = await api('/api/net/ipv6/discover', {
      method: 'POST', body: { cidr, engagement_id: engId || null },
    });
    const rows = (res.neighbors || []).map((n) => `<div data-testid="ipv6-neighbor">${esc(n.ip)} <span class="muted">${esc(n.dev || '')} ${esc(n.mac || '')} ${esc(n.state || '')}</span></div>`).join('');
    $('ipv6-body').innerHTML = rows || 'no IPv6 neighbors seen';
    if (res.recorded) log(`ipv6: ${res.recorded} in-scope host(s) recorded`, 'success');
    if ((res.skipped_out_of_scope || []).length) log(`ipv6: ${res.skipped_out_of_scope.length} out-of-scope skipped`, 'warn');
  } catch (e) { $('ipv6-body').textContent = `ipv6 failed: ${e.message}`; }
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
    // the endpoint returns {neighbors: [...]} (services merged from the
    // fingerprint store); older shapes used `hosts`.
    (res.neighbors || res.hosts || []).forEach((h) => {
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

function sprayPolicy() {
  const mu = parseInt((($('spray-max-user') || {}).value || '25'), 10) || 25;
  const ji = parseFloat((($('spray-jitter') || {}).value || '0')) || 0;
  return { max_per_user: mu, jitter_max: ji };
}

async function loadPropagationPlan() {
  const engId = await currentEngagementId();
  if (!engId) { log('set an active scope first', 'warn'); return; }
  try {
    const pol = sprayPolicy();
    const plan = await api(`/api/engagement/${engId}/propagate/plan?max_per_user=${pol.max_per_user}&jitter_max=${pol.jitter_max}`);
    const pairs = plan.pairs || [];
    const held = `held: ${plan.held_locked || 0} locked, ${plan.held_capped || 0} over cap`;
    $('prop-body').innerHTML = pairs.length ? pairs.map((p) => `<div>${esc(p.user)} @ ${esc(p.host)}:${esc(p.port)} (${esc(p.service)})</div>`).join('') + `<div class="muted">${esc(held)}</div>` : 'no replay pairs';
    $('btn-propagate-run').hidden = pairs.length === 0;
  } catch (e) { log(`propagation plan failed: ${e.message}`, 'error'); }
}

async function loadHygiene() {
  const engId = await currentEngagementId();
  if (!engId) { log('set an active scope first', 'warn'); return; }
  try {
    const res = await api(`/api/engagement/${engId}/hygiene`);
    const s = res.summary || {};
    const rows = (res.findings || []).map((f) => `<div data-testid="hygiene-finding"><b>${esc(f.kind)}</b> ${esc(f.user)} — ${esc(f.detail)} <span class="muted">${esc((f.hosts || []).join(', '))}</span></div>`).join('');
    $('hygiene-body').innerHTML = `<div data-testid="hygiene-summary">score ${s.score ?? '?'} · ${s.verified_credentials ?? 0} creds · reuse ${s.reuse ?? 0} · weak ${s.weak ?? 0} · default ${s.default ?? 0}</div>${rows || 'no hygiene findings'}`;
    log(`hygiene: score ${s.score}`, 'success');
  } catch (e) { log(`hygiene failed: ${e.message}`, 'error'); }
}

async function executePropagation() {
  const engId = await currentEngagementId();
  if (!engId) return;
  $('prop-results').hidden = false;
  $('prop-results').textContent = 'executing…';
  try {
    const pol = sprayPolicy();
    const res = await api(`/api/engagement/${engId}/propagate`, { method: 'POST', body: { open_sessions: false, max_per_user: pol.max_per_user, jitter_max: pol.jitter_max } });
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

async function runPrivescSuggest() {
  $('privesc-suggest-body').textContent = 'running read-only checklist…';
  try {
    const res = await api('/api/privesc/suggest', { method: 'POST', body: {} });
    const checks = res.checks || [];
    $('privesc-suggest-body').innerHTML = checks.map((c) => `<div data-testid="privesc-check">${c.status === 'fail' ? '🔴' : c.status === 'pass' ? '🟢' : '⚪'} <b>${esc(c.id)}</b> ${esc(c.title)} — ${esc(c.detail || '')}${c.fix ? `<br /><span class="muted">fix: ${esc(c.fix)}</span>` : ''}</div>`).join('') || 'no checks ran';
    log(`privesc checklist: ${res.fails || 0}/${res.count || 0} failing`, 'info');
  } catch (e) {
    $('privesc-suggest-body').textContent = `checklist failed: ${e.message}`;
    log(`checklist failed: ${e.message}`, 'error');
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

async function runNseSuggest() {
  const service = $('nse-service').value.trim();
  if (!service) { log('nse needs a service name', 'warn'); return; }
  try {
    const res = await api(`/api/nse/suggest?service=${encodeURIComponent(service)}&product=${encodeURIComponent($('nse-product').value.trim())}`);
    state.nseScripts = res.script_arg || '';
    $('nse-body').innerHTML = (res.scripts || []).map((s) => `<div data-testid="nse-suggestion"><b>${esc(s.script)}</b> [${esc(s.category)}] — ${esc(s.reason)}</div>`).join('') || 'no suggestions';
    $('btn-nse-run').hidden = !(res.scripts || []).length;
    log(`nse: ${res.count || 0} suggestion(s) for ${res.service}`, 'info');
  } catch (e) { $('nse-body').textContent = `nse suggest failed: ${e.message}`; }
}

async function runNse() {
  const target = $('nse-target').value.trim() || $('target').value.trim();
  if (!target) { log('nse needs a target', 'warn'); return; }
  if (!state.nseScripts) { log('suggest scripts first', 'warn'); return; }
  $('nse-body').textContent = 'nse running…';
  try {
    const res = await api('/api/nmap/nse', { method: 'POST', body: { target, scripts: state.nseScripts } });
    const tool = res.tool || {};
    $('nse-body').innerHTML = `<div data-testid="nse-result" class="output">${esc((tool.stdout || tool.stderr || JSON.stringify(res)).slice(0, 4000))}</div>`;
    log(`nse done: ${tool.status || res.target}`, 'info');
  } catch (e) { $('nse-body').textContent = `nse failed: ${e.message}`; }
}

async function krbRoast(kind) {
  const domain = $('krb-domain').value.trim();
  if (!domain) { log('kerberos needs a domain', 'warn'); return; }
  const body = { domain, dc_ip: $('krb-dc').value.trim() || null };
  if (kind === 'asrep') {
    const users = $('krb-users').value.split(',').map((s) => s.trim()).filter(Boolean);
    if (users.length) body.users = users;
  } else {
    if (!$('krb-user').value.trim()) { log('kerberoast needs a valid account', 'warn'); return; }
    body.user = $('krb-user').value.trim();
    body.password = $('krb-pass').value;
  }
  $('krb-body').textContent = `${kind} roasting…`;
  try {
    const res = await api(`/api/kerberos/${kind}`, { method: 'POST', body });
    const hashes = res.hashes || [];
    $('krb-body').innerHTML = `<div data-testid="krb-hashes">${esc(`${hashes.length} hash(es): ${hashes.slice(0, 3).join(' ').slice(0, 300) || 'none'}`)}</div>`;
    log(`${kind}: ${hashes.length} hash(es)`, 'success');
  } catch (e) { $('krb-body').textContent = `${kind} failed: ${e.message}`; }
}

async function runTlsFingerprint() {
  const target = $('tls-target').value.trim() || $('target').value.trim();
  if (!target) { log('tls needs a target', 'warn'); return; }
  const ports = $('tls-ports').value.split(',').map((s) => parseInt(s.trim(), 10)).filter((n) => n > 0 && n < 65536);
  $('tls-body').textContent = 'probing TLS…';
  $('tls-status').textContent = '';
  try {
    const res = await api('/api/tls/fingerprint', { method: 'POST', body: { target, ports: ports.length ? ports : null } });
    const rows = (res.probes || []).filter((p) => p.ok).map((p) => {
      const leads = (p.leads || []).map((l) => `[${l.level}] ${l.lead}`).join('; ');
      return `<div data-testid="tls-probe"><b>${esc(p.host)}:${p.port}</b> ${esc(p.version)} ${esc(p.cipher)} <span class="mono">${esc((p.fingerprint || '').slice(0, 16))}…</span>${leads ? `<br />⚠ ${esc(leads)}` : ''}</div>`;
    }).join('');
    $('tls-body').innerHTML = rows || 'no TLS services answered';
    $('tls-status').textContent = `${(res.ports || []).length} TLS port(s), ${res.lead_count || 0} lead(s)`;
    log(`tls fingerprint: ${(res.ports || []).length} port(s)`, 'success');
  } catch (e) { $('tls-body').textContent = `tls failed: ${e.message}`; }
}

async function runTlsInventory() {
  const raw = $('tls-inv-targets').value.trim() || $('tls-target').value.trim();
  if (!raw) { log('tls inventory needs targets', 'warn'); return; }
  $('tls-inv-body').textContent = 'inventorying certs…';
  try {
    const engId = await currentEngagementId();
    const res = await api('/api/tls/inventory', {
      method: 'POST',
      body: { targets: raw.split(',').map((s) => s.trim()).filter(Boolean), engagement_id: engId || null },
    });
    const rows = (res.entries || []).filter((e) => e.ok).map((e) => {
      const leads = (e.leads || []).map((l) => `[${l.level}] ${l.lead}`).join('; ');
      return `<div data-testid="tls-inv-entry"><b>${esc(e.host)}:${e.port}</b> ${esc(e.version || '?')} <span class="mono">${esc((e.fingerprint || '').slice(0, 16))}…</span>${leads ? `<br />⚠ ${esc(leads)}` : ''}</div>`;
    }).join('');
    $('tls-inv-body').innerHTML = rows || 'no TLS services answered';
    log(`tls inventory: ${res.count || 0} host(s), ${res.lead_count || 0} lead(s)${res.ingested ? `, ${res.ingested} ledgered` : ''}`, 'success');
  } catch (e) { $('tls-inv-body').textContent = `tls inventory failed: ${e.message}`; }
}

async function runKevCheck() {
  const raw = $('kev-cves').value.trim();
  if (!raw) { log('kev needs CVE ids', 'warn'); return; }
  const cves = raw.split(',').map((s) => s.trim()).filter(Boolean);
  $('kev-body').textContent = 'checking…';
  try {
    const res = await api('/api/kev/enrich', { method: 'POST', body: { cves } });
    $('kev-body').innerHTML = (res.results || []).map((r) => `<div data-testid="kev-result"><b>${esc(r.cve)}</b> ${r.kev ? '🔴 KEV' : '—'}${r.epss && r.epss.score ? ` EPSS ${esc(r.epss.score)}` : ''}<span class="muted"> due ${esc(r.due_date || '—')}</span></div>`).join('') || 'no results';
    log(`kev: ${res.kev_count || 0}/${res.count || 0} known-exploited`, 'success');
  } catch (e) { $('kev-body').textContent = `kev failed: ${e.message}`; }
}

async function runKevRefresh() {
  $('kev-body').textContent = 'refreshing KEV catalog…';
  try {
    const res = await api('/api/kev/refresh', { method: 'POST', body: {} });
    if (res.error) log(`kev refresh failed (kept bundled table): ${res.error}`, 'warn');
    else log(`kev refreshed: ${res.after} entries`, 'success');
    runKevCheck();
  } catch (e) { $('kev-body').textContent = `kev refresh failed: ${e.message}`; }
}

async function runSuppress() {
  const engId = await currentEngagementId();
  if (!engId) { log('set an active scope first', 'warn'); return; }
  const body = {
    host: $('sup-host').value.trim(), name: $('sup-name').value.trim(),
    reason: $('sup-reason').value.trim(),
    days: parseInt($('sup-days').value, 10) || 30,
  };
  if (!body.host || !body.name || !body.reason) { log('suppress needs host, name and reason', 'warn'); return; }
  try {
    const res = await apiOrThrow(`/api/engagement/${engId}/vulns/suppress`, { method: 'POST', body });
    $('sup-body').innerHTML = `<div data-testid="sup-done">suppressed <b>${esc(res.name)}</b> on ${esc(res.host)} until ${esc(res.expires_at || '')}</div>`;
    log(`suppressed ${res.name}`, 'success');
  } catch (e) { $('sup-body').textContent = `suppress failed: ${e.message}`; }
}

async function listSuppressions() {
  const engId = await currentEngagementId();
  if (!engId) return;
  try {
    const res = await api(`/api/engagement/${engId}/vulns/suppressions`);
    const items = res.suppressions || [];
    $('sup-body').innerHTML = items.length
      ? items.map((s) => `<div data-testid="sup-item"><b>${esc(s.name)}</b> on ${esc(s.host)} — ${esc(s.reason)} <span class="muted">until ${esc(s.expires_at || '—')}</span></div>`).join('')
      : 'no suppressions recorded';
  } catch (e) { $('sup-body').textContent = `list failed: ${e.message}`; }
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

async function runNuclei() {
  const target = $('web-target').value.trim();
  if (!target) { log('nuclei needs a target', 'warn'); return; }
  const sev = $('nuclei-sev').value.trim();
  const offline = $('nuclei-offline').checked;
  $('web-body').textContent = 'nuclei scanning…';
  $('nuclei-status').textContent = '';
  try {
    const engId = await currentEngagementId();
    const res = await api('/api/nuclei', {
      method: 'POST',
      body: { target, severity: sev || null, offline, engagement_id: engId || null },
    });
    const names = (res.findings || []).map((f) => ((f.info || {}).name || f.template || 'finding')).slice(0, 10).join(', ');
    $('web-body').innerHTML = `<div data-testid="nuclei-findings">${esc(`${res.finding_count || 0} finding(s)${res.offline ? ' (offline bundle)' : ''}${res.ingested ? ` · ${res.ingested} in ledger` : ''}: ${names || 'none'}`)}</div>`;
    $('nuclei-status').textContent = `${res.finding_count || 0} finding(s)`;
    log(`nuclei done: ${res.finding_count || 0} finding(s)`, 'success');
  } catch (e) {
    $('web-body').textContent = `nuclei failed: ${e.message}`;
    log(`nuclei failed: ${e.message}`, 'error');
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

async function auditKubelet() {
  const host = $('kube-host').value.trim() || '127.0.0.1';
  const port = parseInt($('kube-port').value, 10) || 10250;
  $('kube-body').textContent = 'auditing kubelet (read-only)…';
  $('kube-status').textContent = '';
  try {
    const engId = await currentEngagementId();
    const res = await api('/api/kubelet/audit', {
      method: 'POST',
      body: { host, port, engagement_id: engId || null },
    });
    const names = (res.findings || []).map((f) => `${f.check || 'finding'} (${f.severity || '?'})`).join(', ');
    const state = res.reachable ? (res.secure ? 'secure' : `${res.finding_count || 0} finding(s)`) : 'unreachable';
    $('kube-body').innerHTML = `<div data-testid="kube-findings">${esc(`${host}:${port} ${state}${res.ingested ? ` · ${res.ingested} in ledger` : ''}${(res.skipped_out_of_scope || []).length ? ' · out of scope (not stored)' : ''}${names ? `: ${names}` : ''}${res.note ? ` — ${res.note}` : ''}`)}</div>`;
    $('kube-status').textContent = state;
    log(`kubelet audit done: ${state}`, res.secure ? 'success' : 'warn');
  } catch (e) {
    $('kube-body').textContent = `kubelet audit failed: ${e.message}`;
    log(`kubelet audit failed: ${e.message}`, 'error');
  }
}

async function auditRbac() {
  const documents = [$('rbac-docs').value.trim()].filter(Boolean);
  if (!documents.length) { log('RBAC audit needs pasted YAML', 'warn'); return; }
  const host = $('rbac-host').value.trim() || '127.0.0.1';
  $('rbac-body').textContent = 'auditing RBAC (offline)…';
  $('rbac-status').textContent = '';
  try {
    const engId = await currentEngagementId();
    const res = await api('/api/rbac/audit', {
      method: 'POST',
      body: { documents, host, engagement_id: engId || null },
    });
    const names = (res.findings || []).map((f) => `${f.title || f.role || 'finding'} (${f.severity || '?'})`).slice(0, 8).join(', ');
    const state = res.risky ? 'no over-permissive grants' : `${res.finding_count || 0} finding(s)`;
    $('rbac-body').innerHTML = `<div data-testid="rbac-findings">${esc(`${state} across ${res.parsed || 0} manifest(s)${res.ingested ? ` · ${res.ingested} in ledger` : ''}${(res.skipped_out_of_scope || []).length ? ' · out of scope (not stored)' : ''}${(res.errors || []).length ? ` · ${res.errors.length} parse note(s)` : ''}${names ? `: ${names}` : ''}`)}</div>`;
    $('rbac-status').textContent = state;
    log(`RBAC audit done: ${state}`, res.risky ? 'success' : 'warn');
  } catch (e) {
    $('rbac-body').textContent = `RBAC audit failed: ${e.message}`;
    log(`RBAC audit failed: ${e.message}`, 'error');
  }
}

async function scanTerraform() {
  const bundle = $('tf-bundle').value.trim();
  if (!bundle) { log('IaC scan needs a pasted bundle', 'warn'); return; }
  const stack = $('tf-stack').value.trim() || 'stack';
  const host = $('tf-host').value.trim() || '127.0.0.1';
  $('tf-body').textContent = 'scanning IaC (offline)…';
  $('tf-status').textContent = '';
  try {
    const engId = await currentEngagementId();
    const res = await api('/api/source/terraform/scan', {
      method: 'POST',
      body: { stack, bundle, host, engagement_id: engId || null },
    });
    const names = (res.findings || []).map((f) => `${f.title || f.check || 'finding'} (${f.severity || '?'})`).slice(0, 8).join(', ');
    const state = res.clean ? 'clean' : `${res.finding_count || 0} finding(s)`;
    $('tf-body').innerHTML = `<div data-testid="tf-findings">${esc(`${stack} ${state} across ${res.resources || 0} resource(s)${res.ingested ? ` · ${res.ingested} in ledger` : ''}${(res.skipped_out_of_scope || []).length ? ' · out of scope (not stored)' : ''}${(res.errors || []).length ? ` · ${res.errors.length} parse note(s)` : ''}${names ? `: ${names}` : ''}`)}</div>`;
    $('tf-status').textContent = state;
    log(`IaC scan done: ${state}`, res.clean ? 'success' : 'warn');
  } catch (e) {
    $('tf-body').textContent = `IaC scan failed: ${e.message}`;
    log(`IaC scan failed: ${e.message}`, 'error');
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

async function refreshWatch() {
  const list = $('watch-list');
  const empty = $('watch-empty');
  const status = $('watch-status');
  const badge = $('watch-new');
  const engId = await currentEngagementId();
  if (!engId) {
    list.innerHTML = ''; empty.hidden = false; status.textContent = 'needs scope';
    badge.hidden = true;
    return;
  }
  try {
    const [st, ch, cfg] = await Promise.all([
      api(`/api/engagement/${engId}/watch/status`),
      api(`/api/engagement/${engId}/watch/changes?limit=10`),
      api(`/api/engagement/${engId}/watch/config`).catch(() => ({ mode: 'notable' })),
    ]);
    const sel = $('watch-mode');
    if (sel && cfg.mode) sel.value = cfg.mode;
    status.textContent = st.snapshots
      ? `${st.snapshots} snapshot(s)${st.last_change ? ` · last change: ${st.last_change.summary}` : ' · no changes yet'}`
      : 'no snapshots yet — auto-scan records them';
    const items = (ch.changes) || [];
    empty.hidden = items.length > 0;
    // digest: notable changes since this engagement was last viewed here
    const mode = (cfg.mode) || 'notable';
    let fresh = 0;
    if (mode !== 'off') {
      const seenKey = `h4k-watch-seen-${engId}`;
      const seenAt = localStorage.getItem(seenKey) || '';
      fresh = items.filter((c) => (c.created_at || '') > seenAt && (mode === 'all' || (c.diff && c.diff.notable))).length;
      localStorage.setItem(seenKey, new Date().toISOString());
    }
    if (fresh > 0) {
      badge.hidden = false;
      badge.textContent = `${fresh} new`;
      log(`watch: ${fresh} new notable change(s) since last visit`, 'warn');
    } else {
      badge.hidden = true;
    }
    list.innerHTML = items.map((c) => {
      const d = c.diff || {};
      const parts = [];
      for (const h of (d.appeared_hosts || [])) parts.push(`<div class="watch-line">+ host <b>${esc(h)}</b></div>`);
      for (const h of (d.vanished_hosts || [])) parts.push(`<div class="watch-line">− host <b>${esc(h)}</b></div>`);
      for (const s of (d.new_services || [])) parts.push(`<div class="watch-line">+ <b>${esc(s.host)}:${esc(String(s.port))}</b> ${esc(s.service || '')} ${esc(s.version || '')}</div>`);
      for (const s of (d.closed_services || [])) parts.push(`<div class="watch-line">− <b>${esc(s.host)}:${esc(String(s.port))}</b> ${esc(s.service || '')}</div>`);
      for (const v of (d.new_vulns || [])) parts.push(`<div class="watch-line">! <b>${esc(v.name)}</b> on ${esc(v.host)}${v.severity ? ` (${esc(v.severity)})` : ''}</div>`);
      for (const v of (d.cleared_vulns || [])) parts.push(`<div class="watch-line">✓ cleared <b>${esc(v.name)}</b> on ${esc(v.host)}</div>`);
      return `<div class="watch-item"><div class="watch-head"><span class="muted">${esc(c.created_at || '')} [${esc(c.source || '')}]</span><span>${esc(c.summary || '')}</span></div>${parts.join('')}</div>`;
    }).join('');
  } catch { status.textContent = 'unavailable'; }
}

async function refreshHandoff() {
  const list = $('handoff-list');
  const status = $('handoff-status');
  const engId = await currentEngagementId();
  if (!engId) { list.textContent = 'Navigator layer + Sigma skeletons + defender writeup for this engagement.'; status.textContent = 'no engagement'; return; }
  try {
    const layer = await api(`/api/engagement/${engId}/handoff/navigator`);
    const techs = layer.techniques || [];
    const rules = await api(`/api/engagement/${engId}/handoff/sigma`).catch(() => ({ count: 0 }));
    status.textContent = `${techs.length} technique(s) · ${rules.count || 0} rule(s) ready`;
    list.innerHTML = techs.length
      ? techs.map((t) => `<div class="watch-line"><b>${esc(t.techniqueID)}</b> ${esc(t.tactic || '')} <span class="muted">×${t.score}</span></div>`).join('')
      : '<span class="muted">No techniques observed yet — scan and ingest findings first.</span>';
  } catch { status.textContent = 'unavailable'; }
}

function downloadText(name, text, type) {
  const blob = new Blob([text], { type });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 5000);
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

async function loadVault() {
  const engId = await currentEngagementId();
  if (!engId) { log('set an active scope first', 'warn'); return; }
  const reveal = $('vault-reveal').checked;
  try {
    const res = await api(`/api/engagement/${engId}/vault?reveal=${reveal}`);
    const items = res.items || [];
    $('vault-body').innerHTML = items.length
      ? `<div data-testid="vault-count">${res.count} item(s)${res.revealed ? ' · UNMASKED' : ' · masked'}</div>` + items.map((item) => {
        if (item.type === 'credential') return `<div data-testid="vault-item">cred <b>${esc(item.user)}</b> (${esc(item.service || 'any')}) on ${esc((item.hosts || []).join(', '))} — <span class="mono">${esc(item.password)}</span></div>`;
        if (item.type === 'flag') return `<div data-testid="vault-item">flag <span class="mono">${esc(item.value)}</span> on ${esc(item.host || '?')}</div>`;
        return `<div data-testid="vault-item">share \\\\${esc(item.host)}\\${esc(item.share)} (${esc(item.access || '?')})</div>`;
      }).join('')
      : 'vault empty — verify a cred, capture a flag, enumerate shares';
    log(`vault: ${res.count || 0} item(s)${reveal ? ' UNMASKED' : ''}`, reveal ? 'warn' : 'success');
  } catch (e) { $('vault-body').textContent = `vault failed: ${e.message}`; }
}

async function downloadVaultMd() {
  const engId = await currentEngagementId();
  if (!engId) { log('set an active scope first', 'warn'); return; }
  const reveal = $('vault-reveal').checked;
  try {
    const res = await api(`/api/engagement/${engId}/vault/export?fmt=md&reveal=${reveal}`);
    downloadText('h4k-vault.md', res.content || '', 'text/markdown');
    log('vault export downloaded', 'success');
  } catch (e) { log(`vault export failed: ${e.message}`, 'error'); }
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

const canvasView = { x: 0, y: 0, w: 800, h: 600 };
let canvasData = null;

function canvasColor(type) {
  if (type === 'host') return '#4da3ff';
  if (type === 'service') return '#9fe870';
  if (type === 'pivot') return '#ef476f';
  return '#ffd166';
}

function applyCanvasView() {
  const svg = $('graph-canvas');
  if (svg) svg.setAttribute('viewBox', `${canvasView.x} ${canvasView.y} ${canvasView.w} ${canvasView.h}`);
}

function canvasZoom(factor) {
  const cx = canvasView.x + canvasView.w / 2;
  const cy = canvasView.y + canvasView.h / 2;
  canvasView.w = Math.min(2400, Math.max(200, canvasView.w * factor));
  canvasView.h = canvasView.w * 0.75;
  canvasView.x = cx - canvasView.w / 2;
  canvasView.y = cy - canvasView.h / 2;
  applyCanvasView();
}

function renderCanvasSvg(payload) {
  const svg = $('graph-canvas');
  if (!svg) return;
  canvasData = payload;
  const nodes = payload.nodes || [];
  const edges = payload.edges || [];
  const byId = {};
  nodes.forEach((n) => { byId[n.id] = n; });
  const edgeLines = edges.map((e) => {
    const a = byId[e.source];
    const b = byId[e.target];
    if (!a || !b) return '';
    const col = e.type === 'pivot' ? '#ef476f' : e.type === 'credential' ? '#ffd166' : '#3a4356';
    return `<line x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}" stroke="${col}" stroke-width="${e.type === 'service' ? 1 : 2}" opacity="0.8" />`;
  }).join('');
  const nodeEls = nodes.map((n) => {
    const col = canvasColor(n.type);
    const r = n.type === 'host' ? 16 : 10;
    return `<g data-canvas-node="${escA(n.id)}" class="canvas-node"><circle cx="${n.x}" cy="${n.y}" r="${r}" fill="${col}" fill-opacity="0.25" stroke="${col}" stroke-width="2" /><text x="${n.x}" y="${n.y + r + 12}" text-anchor="middle" font-size="11" fill="#c9d4e3">${esc(n.label || n.id)}</text></g>`;
  }).join('');
  svg.innerHTML = `${edgeLines}${nodeEls}`;
  const legend = $('canvas-legend');
  if (legend) legend.textContent = `legend: ${(payload.legend || []).map((l) => l.label).join(' · ')} — ${nodes.length} nodes, ${edges.length} edges. Drag to pan, wheel to zoom.`;
}

async function loadGraphCanvas() {
  const engId = await currentEngagementId();
  if (!engId) { log('set an active scope first', 'warn'); return; }
  try {
    const res = await api(`/api/engagement/${engId}/graph/canvas`);
    renderCanvasSvg(res);
    log(`canvas: ${(res.nodes || []).length} nodes`, 'success');
  } catch (e) { log(`canvas failed: ${e.message}`, 'error'); }
}

function exportCanvasPng() {
  const svg = $('graph-canvas');
  if (!svg) return;
  try {
    const data = new XMLSerializer().serializeToString(svg);
    const blob = new Blob([data], { type: 'image/svg+xml;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const img = new Image();
    img.onload = () => {
      const c = document.createElement('canvas');
      c.width = 800; c.height = 600;
      c.getContext('2d').drawImage(img, 0, 0, 800, 600);
      URL.revokeObjectURL(url);
      const a = document.createElement('a');
      a.download = 'h4k-graph.png';
      a.href = c.toDataURL('image/png');
      a.click();
      log('canvas PNG exported', 'success');
    };
    img.src = url;
  } catch (e) { log(`PNG export failed: ${e.message}`, 'error'); }
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

async function downloadSessionPdf() {
  try {
    const r = await fetch('/api/session/report?fmt=pdf');
    if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
    const blob = await r.blob();
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'h4k-session.pdf';
    a.click();
    URL.revokeObjectURL(a.href);
    log('session PDF downloaded', 'success');
  } catch (e) { log(`PDF failed: ${e.message}`, 'error'); }
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
  else if (cmd === 'neighbors6') { setTab('discover'); launchNeighbors6(); }
  else if (cmd === 'fingerprint') { setTab('recon'); startFingerprint(); }
  else if (cmd === 'autopilot') { setTab('exploit'); startAutopilot(); }
  else if (cmd === 'nikto') { setTab('recon'); runNikto(); }
  else if (cmd === 'gobuster') { setTab('recon'); runGobuster(); }
  else if (cmd === 'suppress') { setTab('recon'); }
  else if (cmd === 'kev') { setTab('recon'); runKevCheck(); }
  else if (cmd === 'tls') { setTab('recon'); runTlsFingerprint(); }
  else if (cmd === 'kerberos') { setTab('pivot'); }
  else if (cmd === 'nuclei') { setTab('recon'); runNuclei(); }
  else if (cmd === 'firetv') setTab('pivot');
  else if (cmd === 'cfuzz') setTab('exploit');
  else if (cmd === 'iacscan') setTab('exploit');
  else if (cmd === 'rbacaudit') setTab('exploit');
  else if (cmd === 'kubeaudit') setTab('exploit');
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

  // scope creator (Discover): validate CIDRs, create engagement, engage it
  $('btn-scope-create').addEventListener('click', async () => {
    const status = $('scope-create-status');
    const name = ($('scope-name').value || '').trim() || 'lab';
    const text = ($('scope-cidrs').value || '').trim();
    if (!text) { status.textContent = 'enter authorized CIDRs first'; $('scope-cidrs').focus(); return; }
    status.textContent = 'checking…';
    try {
      const parsed = await api('/api/engagement/parse-scope', { method: 'POST', body: { text } });
      if (!parsed.scope || !parsed.scope.length) { status.textContent = 'no valid IPs/CIDRs in that text'; return; }
      const eng = await api('/api/engagement', { method: 'POST', body: { name, scope: parsed.scope } });
      if (!eng.id) { status.textContent = `refused: ${eng.detail || 'error'}`; return; }
      await api('/api/session/scope', { method: 'POST', body: { engagement_id: eng.id } });
      state.engagementId = eng.id;
      status.textContent = '';
      log(`scope engaged: ${eng.name} (${parsed.scope.join(', ')})`, 'info');
      loadScopeSelect();
      refreshStatus(); refreshNextMove();
    } catch (e) { status.textContent = `failed: ${e.message}`; }
  });
  // blue-team handoff: defender exports for the active engagement
  $('btn-handoff-layer').addEventListener('click', async () => {
    const engId = await currentEngagementId();
    if (!engId) { log('engage a scope first', 'error'); return; }
    try {
      const layer = await api(`/api/engagement/${engId}/handoff/navigator`);
      downloadText('handoff-layer.json', JSON.stringify(layer, null, 2), 'application/json');
      log(`navigator layer: ${(layer.techniques || []).length} technique(s)`, 'success');
    } catch (e) { log(`layer failed: ${e.message}`, 'error'); }
  });
  $('btn-handoff-sigma').addEventListener('click', async () => {
    const engId = await currentEngagementId();
    if (!engId) { log('engage a scope first', 'error'); return; }
    try {
      const bundle = await api(`/api/engagement/${engId}/handoff/sigma`);
      downloadText('handoff-sigma.yml', bundle.yaml || '', 'text/yaml');
      log(`sigma bundle: ${bundle.count || 0} experimental rule(s) — tune before use`, 'success');
    } catch (e) { log(`sigma failed: ${e.message}`, 'error'); }
  });
  $('btn-handoff-summary').addEventListener('click', async () => {
    const engId = await currentEngagementId();
    if (!engId) { log('engage a scope first', 'error'); return; }
    try {
      const res = await api(`/api/engagement/${engId}/handoff/summary`);
      downloadText('handoff-writeup.md', res.markdown || '', 'text/markdown');
      log('defender writeup downloaded', 'success');
    } catch (e) { log(`writeup failed: ${e.message}`, 'error'); }
  });
  // lab watch: estate change history for the active engagement
  $('btn-watch-refresh').addEventListener('click', refreshWatch);
  $('btn-watch-verify').addEventListener('click', async () => {
    const engId = await currentEngagementId();
    if (!engId) { log('engage a scope first', 'error'); return; }
    try {
      const res = await api(`/api/engagement/${engId}/watch/verify`, { method: 'POST', body: {} });
      log(`watch verify: ${res.summary || res.snapshot_id}`, res.notable ? 'warn' : 'info');
      refreshWatch();
    } catch (e) { log(`verify failed: ${e.message}`, 'error'); }
  });
  $('btn-watch-trends').addEventListener('click', async () => {
    const engId = await currentEngagementId();
    if (!engId) { log('engage a scope first', 'error'); return; }
    const box = $('watch-trends');
    if (!box.hidden) { box.hidden = true; box.innerHTML = ''; return; }
    try {
      const t = await api(`/api/engagement/${engId}/watch/trends?limit=100`);
      const hosts = t.hosts || {};
      const rows = Object.keys(hosts).sort().map((addr) => {
        const h = hosts[addr];
        const svcs = Object.keys(h.services || {}).sort().map((k) => {
          const s = h.services[k];
          return `<div class="watch-line">· ${esc(k)} ${esc(s.service || '')} <span class="muted">${esc(s.first_seen || '')} → ${esc(s.last_seen || '')}</span></div>`;
        }).join('');
        return `<div class="watch-item"><div class="watch-head"><b>${esc(addr)}</b>${h.present ? '' : ' <span class="muted">(gone)</span>'}<span class="muted">${esc(h.first_seen || '')} → ${esc(h.last_seen || '')}</span></div>${svcs}</div>`;
      }).join('');
      box.innerHTML = rows || '<div class="muted">no snapshots yet</div>';
      box.hidden = false;
    } catch (e) { log(`trends failed: ${e.message}`, 'error'); }
  });
  $('watch-mode').addEventListener('change', async (e) => {
    const engId = await currentEngagementId();
    if (!engId) return;
    try {
      await api(`/api/engagement/${engId}/watch/config`, { method: 'POST', body: { mode: e.target.value } });
      refreshWatch();
    } catch (err) { log(`watch mode failed: ${err.message}`, 'error'); }
  });
  $('btn-watch-baseline').addEventListener('click', async () => {
    const engId = await currentEngagementId();
    if (!engId) { log('engage a scope first', 'error'); return; }
    try {
      const jobs = await api('/api/jobs?active=false');
      const scan = ((jobs.jobs) || []).find((j) => (j.status === 'done' || j.status === 'completed'));
      if (!scan) { log('run a scan first — nothing to snapshot yet', 'error'); return; }
      const res = await api(`/api/engagement/${engId}/watch/baseline`, { method: 'POST', body: { job_id: scan.id } });
      log(`watch snapshot: ${res.summary || res.snapshot_id}`, 'info');
      refreshWatch();
    } catch (e) { log(`baseline failed: ${e.message}`, 'error'); }
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
  $('btn-neighbors6').addEventListener('click', launchNeighbors6);
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
  $('btn-suppress').addEventListener('click', runSuppress);
  $('btn-sup-list').addEventListener('click', listSuppressions);
  $('btn-kev').addEventListener('click', runKevCheck);
  $('btn-kev-refresh').addEventListener('click', runKevRefresh);
  $('btn-tls-run').addEventListener('click', runTlsFingerprint);
  $('btn-tls-inv').addEventListener('click', runTlsInventory);
  $('btn-krb-asrep').addEventListener('click', () => krbRoast('asrep'));
  $('btn-krb-roast').addEventListener('click', () => krbRoast('kerberoast'));
  $('btn-nse-suggest').addEventListener('click', runNseSuggest);
  $('btn-nse-run').addEventListener('click', runNse);
  $('btn-gobuster').addEventListener('click', runGobuster);
  $('btn-nuclei').addEventListener('click', runNuclei);
  $('btn-cf-detect').addEventListener('click', detectContainerSurfaces);
  $('btn-cf-start').addEventListener('click', startContainerFuzz);
  $('btn-kube-audit').addEventListener('click', auditKubelet);
  $('btn-tf-scan').addEventListener('click', scanTerraform);
  $('btn-rbac-audit').addEventListener('click', auditRbac);
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
  $('btn-hygiene').addEventListener('click', loadHygiene);
  $('btn-propagate-run').addEventListener('click', executePropagation);
  $('btn-lateral-map').addEventListener('click', mapLateralRoutes);
  $('btn-db-run').addEventListener('click', runDbInterrogate);
  $('btn-escape-run').addEventListener('click', runEscapeCheck);
  $('btn-trylocalroot-run').addEventListener('click', runTryLocalRoot);
  $('btn-privesc-suggest').addEventListener('click', runPrivescSuggest);
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
  $('btn-vault').addEventListener('click', loadVault);
  $('btn-vault-md').addEventListener('click', downloadVaultMd);
  $('btn-flag-detect').addEventListener('click', detectFlags);
  $('btn-add-crown').addEventListener('click', addCrownJewel);
  $('btn-attack-paths').addEventListener('click', loadAttackPaths);
  $('btn-flag-paths').addEventListener('click', loadFlagPaths);
  $('btn-graph-canvas').addEventListener('click', loadGraphCanvas);
  $('btn-canvas-zoom-in').addEventListener('click', () => canvasZoom(0.8));
  $('btn-canvas-zoom-out').addEventListener('click', () => canvasZoom(1.25));
  $('btn-canvas-reset').addEventListener('click', () => { canvasView.x = 0; canvasView.y = 0; canvasView.w = 800; canvasView.h = 600; applyCanvasView(); });
  $('btn-canvas-png').addEventListener('click', exportCanvasPng);
  const _svg = $('graph-canvas');
  if (_svg) {
    let pan = null;
    _svg.addEventListener('pointerdown', (e) => { pan = { x: e.clientX, y: e.clientY, vx: canvasView.x, vy: canvasView.y }; _svg.setPointerCapture(e.pointerId); });
    _svg.addEventListener('pointermove', (e) => {
      if (!pan) return;
      const scale = canvasView.w / _svg.clientWidth;
      canvasView.x = pan.vx - (e.clientX - pan.x) * scale;
      canvasView.y = pan.vy - (e.clientY - pan.y) * scale;
      applyCanvasView();
    });
    _svg.addEventListener('pointerup', () => { pan = null; });
    _svg.addEventListener('wheel', (e) => { e.preventDefault(); canvasZoom(e.deltaY > 0 ? 1.1 : 0.9); }, { passive: false });
    _svg.addEventListener('click', (e) => {
      const g = e.target.closest('[data-canvas-node]');
      if (!g || !canvasData) return;
      const n = (canvasData.nodes || []).find((v) => v.id === g.dataset.canvasNode);
      if (n) $('canvas-detail').textContent = `${n.label || n.id} · type=${n.type}${n.parent ? ` · parent=${n.parent}` : ''}${n.os ? ` · os=${n.os}` : ''} @ (${n.x}, ${n.y})`;
    });
  }
  $('btn-attck').addEventListener('click', loadAttck);
  $('btn-session-report').addEventListener('click', downloadSessionReport);
  $('btn-session-pdf').addEventListener('click', downloadSessionPdf);

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
