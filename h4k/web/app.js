// h4k Operations Center - Full Game UI Logic

// ═══════════════════════════════════════════
// STATE
// ═══════════════════════════════════════════
const state = {
  currentPhase: 'recon',
  scanResults: null,
  selectedVuln: null,
  selectedExploit: null,
  selectedService: null,
  stats: { hosts: 0, services: 0, vulns: 0, pwned: 0 },
  logs: [],
  lastLogCount: 0,
  soundEnabled: true,
  vimIndex: 0,
  xp: 0,
  level: 1,
  xpToNext: 100,
  achievements: new Set(),
  missionComplete: false,
  graphData: null,
  selectedGraphNode: null,
  scanType: 'ip', // 'ip' or 'neighbors'
  discoveredTarget: null,
  fingerprintJobId: null,
  vulnRows: [],
  selectedVulnRow: null,
  exploitAlternatives: [],
};

// XP table: level -> XP required to reach it
const XP_LEVELS = [0, 100, 250, 500, 1000, 2000, 4000, 8000, 16000, 32000];

const ACHIEVEMENTS = [
  { id: 'first_host', name: 'First Blood', icon: '🎯', xp: 10 },
  { id: 'port_scanner', name: 'Port Scanner', icon: '🔍', xp: 15 },
  { id: 'vuln_finder', name: 'Vuln Hunter', icon: '⚠️', xp: 20 },
  { id: 'exploiter', name: 'Exploiter', icon: '💀', xp: 50 },
  { id: 'shell_stealer', name: 'Shell Stealer', icon: '🐚', xp: 75 },
  { id: 'port_knight', name: 'Port Knight', icon: '🏆', xp: 25 },
  { id: 'service_ enumerate', name: 'Service Spy', icon: '🕵️', xp: 15 },
  { id: 'os_intel', name: 'OS Intel', icon: '💻', xp: 10 },
];

const LEVEL_NAMES = ['Script Kiddie', 'Hacker', 'Elite', 'Master', 'Wizard', 'Sage', 'Overlord', 'God Mode'];

// ═══════════════════════════════════════════
// UTILS
// ═══════════════════════════════════════════
const $ = (id) => document.getElementById(id);
const api = (url, opts = {}) => fetch(url, {
  headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) },
  ...opts,
  body: opts.body ? JSON.stringify(opts.body) : undefined,
}).then(r => r.json());

function log(msg, level = 'info') {
  const ts = new Date().toLocaleTimeString('en-US', { hour12: false });
  state.logs.push({ ts, msg, level });
  appendActivityLog(ts, msg, level);
  playSound('log');
}

function logXp(amount, reason = '') {
  state.xp += amount;
  const oldLevel = state.level;
  while (state.level < XP_LEVELS.length && state.xp >= XP_LEVELS[state.level]) {
    state.level++;
  }
  if (state.level > oldLevel) {
    showAchievement(`LEVEL UP! ${LEVEL_NAMES[state.level - 1] || 'Level ' + state.level}`, '⬆️', 0);
  }
  updateXpDisplay();
  showXpPopup(`+${amount} XP${reason ? ' ' + reason : ''}`);
}

function unlockAchievement(id) {
  if (state.achievements.has(id)) return;
  state.achievements.add(id);
  const ach = ACHIEVEMENTS.find(a => a.id === id);
  if (ach) {
    showAchievement(ach.name, ach.icon, ach.xp);
    logXp(ach.xp, `(${ach.name})`);
  }
}

function playSound(type) {
  if (!state.soundEnabled) return;
  // Sound effects via Web Audio API - subtle beeps
  try {
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.connect(gain);
    gain.connect(ctx.destination);
    const sounds = {
      log: { freq: 800, dur: 0.05, type: 'sine' },
      success: { freq: 1200, dur: 0.15, type: 'sine' },
      error: { freq: 300, dur: 0.2, type: 'sawtooth' },
      xp: { freq: 600, dur: 0.1, type: 'triangle' },
      scan: { freq: 440, dur: 0.08, type: 'square' },
    };
    const s = sounds[type] || sounds.log;
    osc.type = s.type;
    osc.frequency.setValueAtTime(s.freq, ctx.currentTime);
    gain.gain.setValueAtTime(0.1, ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + s.dur);
    osc.start(ctx.currentTime);
    osc.stop(ctx.currentTime + s.dur);
  } catch (e) { /* audio not supported */ }
}

function glitchEffect() {
  const el = $('glitch-overlay');
  el.hidden = false;
  el.classList.add('active');
  playSound('success');
  setTimeout(() => { el.classList.remove('active'); el.hidden = true; }, 500);
}

function showXpPopup(text) {
  const el = $('xp-popup');
  $('xp-popup-text').textContent = text;
  el.hidden = false;
  setTimeout(() => { el.hidden = true; }, 1000);
}

function showAchievement(name, icon, xp) {
  const popup = $('ach-popup');
  $('ap-name').textContent = name;
  $('ap-icon').textContent = icon;
  popup.hidden = false;
  playSound('xp');
  setTimeout(() => { popup.hidden = true; }, 3000);
}

function updateXpDisplay() {
  const xpForCurrentLevel = XP_LEVELS[state.level - 1] || 0;
  const xpForNextLevel = XP_LEVELS[state.level] || XP_LEVELS[XP_LEVELS.length - 1];
  const progress = state.xp - xpForCurrentLevel;
  const needed = xpForNextLevel - xpForCurrentLevel;
  const pct = Math.min(100, (progress / needed) * 100);

  $('player-level').textContent = state.level;
  $('player-xp').textContent = state.xp;
  $('player-xp-next').textContent = xpForNextLevel;
  $('xp-bar').style.width = pct + '%';
}

// ═══════════════════════════════════════════
// PHASE MANAGEMENT
// ═══════════════════════════════════════════
function setPhase(phase) {
  state.currentPhase = phase;
  document.querySelectorAll('.phase').forEach(el => {
    el.hidden = el.dataset.phase !== phase;
  });
  document.querySelectorAll('.nav-btn').forEach(el => {
    el.classList.toggle('active', el.dataset.phase === phase);
  });
  updateHint();
}

function updateHint() {
  const hints = {
    recon: 'Enter target IP, configure options, and hit Launch Recon',
    prepare: 'Configure exploit options (LHOST is auto-detected)',
    execute: 'Execute the exploit and await session',
    pwned: 'Session established! Use Next Target or start New Mission',
    graph: 'Explore the discovered host graph — click nodes for details',
  };
  $('footer-hint').textContent = hints[state.currentPhase] || '';
}

function updateMissionObjective(obj, done = true) {
  const el = document.querySelector(`[data-obj="${obj}"]`);
  if (!el) return;
  el.classList.toggle('done', done);
  el.classList.remove('active');
  if (done) {
    el.querySelector('.obj-check').textContent = '✓';
    playSound('success');
  }
}

// ═══════════════════════════════════════════
// ACTIVITY LOG
// ═══════════════════════════════════════════
function appendActivityLog(ts, msg, level = 'info') {
  let el = $('activity-log');
  if (!el) return;
  const entry = document.createElement('div');
  entry.className = 'log-entry';
  entry.innerHTML = `<span class="log-time">${ts}</span><span class="log-msg ${level}">${escHtml(msg)}</span>`;
  el.appendChild(entry);
  el.scrollTop = el.scrollHeight;
  // keep max 200 entries
  while (el.children.length > 200) el.removeChild(el.firstChild);
}

function clearActivityLog() {
  const el = $('activity-log');
  if (el) while (el.firstChild) el.removeChild(el.firstChild);
}

function escHtml(s) {
  return String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

// ═══════════════════════════════════════════
// COMMAND PALETTE
// ═══════════════════════════════════════════
function toggleCmdPalette(show) {
  const el = $('cmd-palette');
  if (show === undefined) show = el.hidden;
  el.hidden = !show;
  if (!show) $('cmd-input').value = '';
  else setTimeout(() => $('cmd-input').focus(), 50);
}

function executeCmd(cmd) {
  toggleCmdPalette(false);
  switch (cmd) {
    case 'scan': launchScan(); break;
    case 'neighbors': findNeighbors(); break;
    case 'deep': deepAttack(); break;
    case 'theme': toggleTheme(); break;
    case 'clear': clearActivityLog(); break;
  }
}

// ═══════════════════════════════════════════
// THEME
// ═══════════════════════════════════════════
function toggleTheme() {
  const cur = document.documentElement.dataset.theme || 'light';
  setTheme(cur === 'light' ? 'dark' : 'light');
}

function setTheme(theme) {
  document.documentElement.dataset.theme = theme;
  localStorage.setItem('h4k-theme', theme);
}

// ═══════════════════════════════════════════
// SCAN LAUNCH
// ═══════════════════════════════════════════
let scanJobId = null;
let pollInterval = null;
let neighborJobId = null;
let neighborPollInterval = null;

async function launchScan() {
  const scanType = state.scanType;
  let target;

  if (scanType === 'neighbors') {
    const res = await api('/api/neighbors/scan', { method: 'POST' });
    if (res.job_id) {
      neighborJobId = res.job_id;
      startNeighborDiscovery();
    }
    return;
  } else {
    target = $('target').value.trim();
    if (!target) { alert('Enter a target IP or CIDR'); return; }
  }

  const btn = $('btn-launch-recon');
  btn.classList.add('loading');
  btn.disabled = true;

  $('brief-target').textContent = target;
  document.querySelector('[data-obj="host"]').classList.add('active');

  setPhase('recon');
  log(`Starting recon on ${target}...`, 'info');
  logXp(5, '(recon started)');

  try {
    const res = await api('/api/scan', {
      method: 'POST',
      body: {
        target,
        mode: $('mode-select').value,
        depth: $('depth-select').value,
        do_dns_recon: false,
        do_vuln_scan: true,
        try_default_creds: $('creds-toggle').checked,
        open_sessions: false,
        do_attack: false,
      }
    });

    if (res.job_id) {
      scanJobId = res.job_id;
      log(`Job ${scanJobId} created`, 'info');
      startScanPolling();
    } else {
      log('Scan failed: ' + JSON.stringify(res), 'error');
      btn.classList.remove('loading');
      btn.disabled = false;
    }
  } catch (e) {
    log('Scan error: ' + e.message, 'error');
    btn.classList.remove('loading');
    btn.disabled = false;
  }
}

function startScanPolling() {
  $('scan-progress-card').hidden = false;
  updateScanProgress({ stage: 'recon', pct: 0, status: 'Initializing...' });
  pollInterval = setInterval(pollScanProgress, 2000);
}

function startNeighborDiscovery() {
  $('neighbors-panel') || buildNeighborsPanel();
  $('neighbors-panel').hidden = false;
  $('neighbors-status').textContent = 'Discovering local network...';
  $('neighbors-list').innerHTML = '';
  $('neighbors-progress').style.width = '0%';
  $('neighbors-progress-wrap').hidden = false;
  $('btn-launch-recon').disabled = true;
  log('Local network discovery started', 'info');
  neighborPollInterval = setInterval(pollNeighborDiscovery, 1500);
}

async function pollNeighborDiscovery() {
  if (!neighborJobId) return;
  try {
    const res = await api(`/api/neighbors/status/${neighborJobId}`);
    updateNeighborProgress(res);
    if (res.status === 'done' || res.status === 'error') {
      clearInterval(neighborPollInterval);
      onNeighborDiscoveryDone(res);
    }
  } catch (e) { log('Neighbor poll error: ' + e.message, 'error'); }
}

function updateNeighborProgress(job) {
  const pct = job.progress || 0;
  $('neighbors-progress').style.width = pct + '%';
  $('neighbors-status').textContent = job.message || job.status;
  $('neighbors-progress-pct').textContent = Math.round(pct) + '%';

  const hosts = job.hosts || [];
  const list = $('neighbors-list');
  const existingIPs = new Set(Array.from(list.querySelectorAll('.neighbor-item')).map(el => el.dataset.ip));

  hosts.forEach(h => {
    if (!existingIPs.has(h.ip)) {
      existingIPs.add(h.ip);
      const el = document.createElement('div');
      el.className = 'neighbor-item';
      el.dataset.ip = h.ip;
      el.innerHTML = `
        <span class="ni-ip">${h.ip}</span>
        <span class="ni-vendor">${h.vendor || 'unknown'}</span>
        <span class="ni-hostname">${h.hostname || ''}</span>
        <span class="ni-status">discovered</span>
      `;
      list.appendChild(el);
      setTimeout(() => el.classList.add('pop'), 50);
    }
  });
}

async function onNeighborDiscoveryDone(job) {
  const hosts = job.hosts || [];
  clearInterval(neighborPollInterval);

  $('neighbors-progress').style.width = '100%';
  $('btn-launch-recon').disabled = false;

  if (job.status === 'error') {
    log('Neighbor discovery failed: ' + (job.error || 'unknown error'), 'error');
    $('neighbors-status').textContent = 'Discovery failed';
    return;
  }

  if (hosts.length === 0) {
    log('No neighbors found. Is arp-scan available?', 'warn');
    $('neighbors-status').textContent = 'No hosts found';
    return;
  }

  log(`Found ${hosts.length} neighbor(s) on local network`, 'success');
  $('neighbors-status').textContent = `${hosts.length} host(s) found — ready to scan`;

  unlockAchievement('first_host');
  logXp(10, '(neighbors found)');

  const cidrs = [];
  for (const h of hosts) {
    const parts = h.ip.split('.');
    cidrs.push(`${parts[0]}.${parts[1]}.${parts[2]}.0/24`);
  }
  const unique = [...new Set(cidrs)];
  const target = unique.join(',');
  $('brief-target').textContent = target;
  document.querySelector('[data-obj="host"]').classList.add('active');

  const btnArea = $('neighbors-btn-area');
  if (btnArea) btnArea.hidden = false;

  state.discoveredTarget = target;
}

function buildNeighborsPanel() {
  const card = document.createElement('div');
  card.className = 'card';
  card.id = 'neighbors-panel';
  card.hidden = true;
  card.innerHTML = `
    <div class="card-header">
      <h2>🌐 Local Network Discovery</h2>
      <span class="neighbors-status" id="neighbors-status">Initializing...</span>
    </div>
    <div class="card-body">
      <div class="neighbors-progress-wrap" id="neighbors-progress-wrap">
        <div class="progress-bar"><div class="progress-fill" id="neighbors-progress"></div></div>
        <span class="neighbors-progress-pct" id="neighbors-progress-pct">0%</span>
      </div>
      <div class="neighbors-list" id="neighbors-list"></div>
      <div class="neighbors-btn-area" id="neighbors-btn-area" hidden>
        <div class="btn-row neighbors-actions">
          <button class="btn btn-primary" id="btn-fingerprint">
            🔍 Scan Services &amp; Fingerprint
          </button>
          <button class="btn btn-outline" id="btn-full-scan">
            ⚡ Full Port Scan
          </button>
        </div>
      </div>
    </div>
  `;
  $('phase-recon').insertBefore(card, $('scan-progress-card'));
}

let fingerprintPollInterval = null;

async function startFingerprintScan() {
  const btn = $('btn-fingerprint');
  if (btn) { btn.disabled = true; btn.classList.add('loading'); }
  log('Starting service fingerprint scan...', 'info');

  try {
    const res = await api('/api/neighbors/fingerprint', { method: 'POST' });
    if (res.job_id) {
      state.fingerprintJobId = res.job_id;
      log(`Fingerprint job ${res.job_id} started`, 'info');
      startFingerprintPolling();
    } else {
      log('Fingerprint failed: ' + JSON.stringify(res), 'error');
      if (btn) { btn.disabled = false; btn.classList.remove('loading'); }
    }
  } catch (e) {
    log('Fingerprint error: ' + e.message, 'error');
    if (btn) { btn.disabled = false; btn.classList.remove('loading'); }
  }
}

function startFingerprintPolling() {
  const panel = $('fingerprint-panel');
  if (panel) panel.hidden = false;
  fingerprintPollInterval = setInterval(pollFingerprintProgress, 2000);
}

async function pollFingerprintProgress() {
  if (!state.fingerprintJobId) return;
  try {
    const res = await api(`/api/neighbors/fingerprint/status/${state.fingerprintJobId}`);
    updateFingerprintProgress(res);
    if (res.status === 'done' || res.status === 'error') {
      clearInterval(fingerprintPollInterval);
      onFingerprintDone(res);
    }
  } catch (e) { log('Fingerprint poll error: ' + e.message, 'error'); }
}

function updateFingerprintProgress(job) {
  const panel = $('fingerprint-panel');
  if (!panel) return;
  const pct = job.progress || 0;
  const statusEl = $('fp-status');
  const fillEl = $('fp-fill');
  const pctEl = $('fp-pct');
  if (statusEl) statusEl.textContent = job.message || job.status;
  if (fillEl) fillEl.style.width = pct + '%';
  if (pctEl) pctEl.textContent = Math.round(pct) + '%';

  renderFingerprintTable(job.results || []);
  renderVulnPanel(job.results || []);
}

async function loadCveStatus() {
  const el = $('cve-status');
  if (!el) return;
  try {
    const st = await api('/api/cves/status');
    const date = st.loaded_at ? st.loaded_at.slice(0, 10) : 'never';
    el.textContent = `CVE db: ${date} · ${st.count} entries · ${st.age_days}d old`;
    const btn = $('btn-cve-refresh');
    if (btn) btn.hidden = !st.stale;
  } catch { el.textContent = 'CVE db: unavailable'; }
}

let cveRefreshPoll = null;

async function refreshCveDb() {
  const btn = $('btn-cve-refresh');
  const el = $('cve-status');
  if (btn) { btn.disabled = true; }
  if (el) el.textContent = 'CVE db: updating…';
  log('Refreshing CVE database (deltas)...', 'info');
  try {
    await api('/api/cves/refresh', { method: 'POST' });
    if (cveRefreshPoll) clearInterval(cveRefreshPoll);
    let tries = 0;
    cveRefreshPoll = setInterval(async () => {
      tries++;
      if (tries > 30) {
        clearInterval(cveRefreshPoll);
        cveRefreshPoll = null;
        if (btn) btn.disabled = false;
        log('CVE refresh did not complete — source unreachable? Staying on local db.', 'warn');
        loadCveStatus();
        return;
      }
      try {
        const st = await api('/api/cves/status');
        if (!st.stale) {
          clearInterval(cveRefreshPoll);
          cveRefreshPoll = null;
          if (btn) { btn.disabled = false; btn.hidden = true; }
          loadCveStatus();
          log(`CVE db updated — ${st.count} entries`, 'success');
          logXp(10, '(cve refresh)');
        }
      } catch { /* keep polling */ }
    }, 4000);
  } catch (e) {
    log('CVE refresh failed: ' + e.message, 'error');
    if (btn) btn.disabled = false;
    loadCveStatus();
  }
}

function renderVulnPanel(results) {
  const tbody = $('vuln-tbody');
  const empty = $('vuln-empty');
  const panel = $('vulns-panel');
  if (!tbody) return;

  const rows = [];
  results.forEach(r => {
    (r.services || []).forEach(s => {
      (s.vulns || []).forEach(v => {
        rows.push({ ip: r.ip, port: s.port, proto: s.proto, service: s.service, product: s.product, ...v });
      });
    });
  });

  panel.hidden = rows.length === 0 ? panel.hidden : false;
  if (rows.length === 0) { if (empty) empty.hidden = false; return; }
  empty.hidden = true;
  const chip = $('vuln-chip-count');
  if (chip) chip.textContent = `${rows.length} findings`;
  loadCveStatus();

  const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  const severityKey = (d) => { const k = (d || '').split(':')[0]; return k in severityOrder ? severityOrder[k] : 9; };
  rows.sort((a, b) => severityKey(a.detail) - severityKey(b.detail));

  state.vulnRows = rows;
  tbody.innerHTML = rows.map(x => {
    const sev = (x.detail || '').split(':')[0];
    const sevCls = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(sev) ? sev.toLowerCase() : '';
    const i = rows.indexOf(x);
    return `
    <tr>
      <td class="fp-ip">${escHtml(x.ip)}</td>
      <td class="fp-port">${escHtml(x.port + '/' + x.proto)}</td>
      <td class="v-kind">${escHtml(x.vid)}</td>
      <td><span class="v-sev ${sevCls}">${escHtml(sev || 'INFO')}</span></td>
      <td class="v-detail">${escHtml((x.detail || '').split(': ').slice(1).join(': '))}</td>
      <td><button class="btn btn-danger v-exploit-btn" data-vuln-index="${i}" title="Prepare exploit">⚔</button></td>
    </tr>`;
  }).join('');
}

function openExploitPanel(idx) {
  const row = (state.vulnRows || [])[idx];
  if (!row) return;
  state.selectedVulnRow = row;

  const msfHint = (row.detail || '').match(/msf:\s*([^\s|]+)/);
  const module = msfHint ? msfHint[1] : '';
  $('ex-module').value = module;
  $('ex-rhost').value = row.ip;
  $('ex-rport').value = row.port;
  $('ex-find').textContent = row.vid || 'manual';
  $('ex-status').textContent = module
    ? 'Module suggested from CVE db — confirm then launch.'
    : 'No msf module hint — enter one or pick a heuristic.';
  $('ex-output').hidden = true;
  $('ex-output').innerHTML = '';
  $('exploit-panel').hidden = false;
  $('exploit-panel').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

async function launchExploit() {
  const row = state.selectedVulnRow;
  if (!row || !row.ip) { $('ex-status').textContent = 'Pick a finding first.'; return; }
  const module = $('ex-module').value.trim();
  if (!module) { $('ex-status').textContent = 'Module is required.'; return; }
  if (!module.startsWith('exploit/')) {
    $('ex-status').textContent = 'Only exploit/ modules launch here.';
    return;
  }

  const btn = $('btn-launch-exploit');
  btn.disabled = true;
  $('ex-status').textContent = 'Launching...';
  $('ex-output').hidden = false;
  appendExOutput(`> ${module} @ ${row.ip}:${row.port}`);

  try {
    const res = await api('/api/attack', {
      method: 'POST',
      body: {
        target: row.ip,
        host: row.ip,
        services: [],
        module,
        port: parseInt(row.port, 10) || null,
        open_sessions: false,
      }
    });
    if (!res.job_id) {
      $('ex-status').textContent = 'Launch failed: ' + (res.detail || JSON.stringify(res));
      btn.disabled = false;
      return;
    }
    pollExploitJob(res.job_id, btn);
  } catch (e) {
    $('ex-status').textContent = 'Launch error: ' + e.message;
    appendExOutput('launch error: ' + e.message);
    btn.disabled = false;
  }
}

let exploitPollTimer = null;

function pollExploitJob(jobId, btn) {
  if (exploitPollTimer) clearInterval(exploitPollTimer);
  let ticks = 0;
  exploitPollTimer = setInterval(async () => {
    ticks++;
    try {
      const job = await api(`/api/attack/${jobId}`);
      const atk = (job.attacks || [])[job.attacks?.length - 1] || null;
      const msg = job.message || job.status || 'working';
      $('ex-status').textContent = `Attack ${jobId}: ${msg}`;
      if (atk && !atk._shown) {
        atk._shown = true;
        appendExOutput(`[${atk.result}] ${atk.module} — ${atk.detail}`);
        if (atk.session_id) appendExOutput(`SESSION ESTABLISHED: ${atk.session_id}`);
      }
      if (['done', 'error'].includes(job.status) || ticks > 60) {
        clearInterval(exploitPollTimer);
        exploitPollTimer = null;
        btn.disabled = false;
        if (job.status === 'done' && atk?.session_id) {
          $('ex-status').textContent = `Pwned — session ${atk.session_id}`;
          glitchEffect();
          unlockAchievement('exploiter');
          logXp(50, '(exploit)');
          state.stats.pwned++;
        } else if (job.status === 'done') {
          $('ex-status').textContent = 'Exploit finished — no session opened.';
          appendExOutput('no session. escalation ladder:');
          showExploitAlternatives(row);
          appendLadderButtons();
        } else {
          $('ex-status').textContent = 'Attack failed or timed out.';
          appendExOutput('timed out. escalation ladder:');
          showExploitAlternatives(row);
          appendLadderButtons();
          playSound('error');
        }
      }
    } catch (e) {
      clearInterval(exploitPollTimer); exploitPollTimer = null;
      btn.disabled = false;
      $('ex-status').textContent = 'Poll error: ' + e.message;
    }
  }, 2500);
}

function appendLadderButtons() {
  const el = $('ex-output');
  const row = document.createElement('div');
  row.className = 'ladder-btns';
  row.innerHTML = `
    <button class="btn btn-secondary ladder-btn" id="ldr-creds">🔑 Try default creds sweep</button>
    <button class="btn btn-secondary ladder-btn" id="ldr-deep">⚔️ Deep attack (toolkit)</button>
  `;
  el.appendChild(row);
  row.querySelector('#ldr-creds')?.addEventListener('click', () => startLadderCreds());
  row.querySelector('#ldr-deep')?.addEventListener('click', () => startLadderDeep());
}

async function startLadderCreds() {
  const row = state.selectedVulnRow;
  if (!row) return;
  const svc = (row.service || '').toLowerCase();
  appendExOutput(`> default-cred sweep: ${row.ip}:${row.port} (${svc || 'known services'})`);
  try {
    const res = await api('/api/deepattack', {
      method: 'POST',
      body: { target: row.ip, host: row.ip, services: svc ? [svc] : [] }
    });
    if (res.job_id) {
      appendExOutput(`  toolkit job ${res.job_id} started — results appear when done (GET /api/deepattack/${res.job_id})`);
      log(`Default-cred sweep ${res.job_id} launched for ${row.ip}`, 'info');
    } else {
      appendExOutput('  sweep failed to start: ' + JSON.stringify(res));
    }
  } catch (e) { appendExOutput('  sweep error: ' + e.message); }
}

async function startLadderDeep() {
  const row = state.selectedVulnRow;
  if (!row) return;
  appendExOutput(`> deep toolkit sweep: ${row.ip}:${row.port}`);
  try {
    const res = await api('/api/deepattack', {
      method: 'POST',
      body: { target: row.ip, host: row.ip, services: [] }
    });
    if (res.job_id) {
      appendExOutput(`  toolkit job ${res.job_id} started`);
      log(`Deep attack ${res.job_id} launched for ${row.ip}`, 'info');
    } else {
      appendExOutput('  sweep failed to start');
    }
  } catch (e) { appendExOutput('  sweep error: ' + e.message); }
}

async function showExploitAlternatives(row) {
  const svc = row.service || row.vid?.split('@')[0] || '';
  if (!svc) return;
  try {
    const res = await api(`/api/exploit-candidates?service=${encodeURIComponent(svc)}&port=${row.port || ''}`);
    if (!res.candidates?.length) {
      appendExOutput('no alternative modules found — try default creds or deep attack.');
      return;
    }
    appendExOutput(`alternative modules for ${svc} (click to switch):`);
    res.candidates.slice(0, 6).forEach(m => appendExOutput(`  [module] ${m}`));
    state.exploitAlternatives = res.candidates.slice(0, 6);
  } catch (e) { /* soft-fail */ }
}

function appendExOutput(text) {
  const el = $('ex-output');
  const p = document.createElement('p');
  p.className = 't-line';
  const m = text.match(/^\s+\[module\] (.+)$/);
  if (m) {
    p.classList.add('ex-mod');
    p.textContent = m[1];
    p.title = 'Click to use this module';
    p.addEventListener('click', () => {
      $('ex-module').value = m[1];
      $('ex-status').textContent = 'Module switched — launch when ready.';
    });
  } else {
    p.textContent = text;
  }
  el.appendChild(p);
  el.scrollTop = el.scrollHeight;
}

function renderFingerprintTable(results) {
  const tbody = $('fp-tbody');
  const empty = $('fp-empty');
  if (!tbody) return;

  const rows = [];
  results.forEach(r => {
    const open = (r.services || []).filter(s => s.state === 'open');
    open.forEach(s => {
      rows.push({
        ip: r.ip,
        port: `${s.port}/${s.proto}`,
        service: s.service || '?',
        product: s.product || '',
        version: s.version || '',
        vendor: r.vendor || r.hostname || '',
      });
    });
  });

  empty.hidden = rows.length > 0;
  const hosts = new Set(rows.map(x => x.ip));

  const chipHosts = $('fp-chip-hosts');
  const chipPorts = $('fp-chip-ports');
  if (chipHosts) chipHosts.textContent = `${hosts.size} hosts`;
  if (chipPorts) chipPorts.textContent = `${rows.length} open ports`;

  // cheap diff: only rebuild if row count changed (poll is 2s, scan is slow)
  if (tbody.dataset.rowCount === String(rows.length)) return;
  tbody.dataset.rowCount = String(rows.length);
  tbody.innerHTML = rows.map(x => `
    <tr>
      <td class="fp-ip">${escHtml(x.ip)}</td>
      <td class="fp-port">${escHtml(x.port)}</td>
      <td>${escHtml(x.service)}</td>
      <td>${escHtml(x.product)}</td>
      <td>${escHtml(x.version)}</td>
      <td class="fp-vendor">${escHtml(x.vendor)}</td>
    </tr>
  `).join('');
}

async function onFingerprintDone(job) {
  const btn = $('btn-fingerprint');
  if (btn) { btn.disabled = false; btn.classList.remove('loading'); }

  if (job.status === 'error') {
    log('Fingerprint scan failed: ' + (job.error || 'unknown'), 'error');
    return;
  }

  const results = job.results || [];
  renderFingerprintTable(results);

  const statusEl = $('fp-status');
  if (statusEl) statusEl.textContent = 'Complete';
  const fillEl = $('fp-fill');
  if (fillEl) fillEl.style.width = '100%';
  const pctEl = $('fp-pct');
  if (pctEl) pctEl.textContent = '100%';

  const openPorts = results.reduce((n, r) => n + (r.services || []).filter(s => s.state === 'open').length, 0);
  const hosts = new Set(
    results.flatMap(r => (r.services || []).filter(s => s.state === 'open').length ? [r.ip] : [])
  );
  log(`Service map complete — ${hosts.size} hosts, ${openPorts} open ports`, 'success');
  logXp(15, '(fingerprint)');
  unlockAchievement('port_scanner');
  unlockAchievement('vuln_finder');
  // authoritative refresh: persisted vulns (covers earlier runs)
  api('/api/neighbors/vulns').then(res => {
    const rows = (res.vulns || []).map(v => ({ services: [{ port: v.port, proto: v.proto, vulns: [v] }], ip: v.ip }));
    renderVulnPanel(rows);
  }).catch(() => {});
}

async function startFullScan() {
  if (!state.discoveredTarget) {
    log('No target — run neighbor discovery first', 'warn');
    return;
  }
  log('Starting full port scan...', 'info');
  logXp(5, '(recon started)');

  const btn = $('btn-full-scan');
  if (btn) { btn.disabled = true; btn.classList.add('loading'); }

  $('btn-launch-recon').classList.add('loading');
  $('btn-launch-recon').disabled = true;

  setPhase('recon');

  try {
    const res = await api('/api/scan', {
      method: 'POST',
      body: {
        target: state.discoveredTarget,
        mode: $('mode-select').value,
        depth: $('depth-select').value,
        do_dns_recon: false,
        do_vuln_scan: false,
        try_default_creds: $('creds-toggle').checked,
        open_sessions: false,
        do_attack: false,
      }
    });

    if (res.job_id) {
      scanJobId = res.job_id;
      log(`Job ${scanJobId} created`, 'info');
      startScanPolling();
    } else {
      log('Scan failed: ' + JSON.stringify(res), 'error');
      if (btn) { btn.disabled = false; btn.classList.remove('loading'); }
      $('btn-launch-recon').classList.remove('loading');
      $('btn-launch-recon').disabled = false;
    }
  } catch (e) {
    log('Scan error: ' + e.message, 'error');
    if (btn) { btn.disabled = false; btn.classList.remove('loading'); }
    $('btn-launch-recon').classList.remove('loading');
    $('btn-launch-recon').disabled = false;
  }
}

async function pollScanProgress() {
  if (!scanJobId) return;
  try {
    const res = await api(`/api/jobs/${scanJobId}`);
    updateScanProgressFromJob(res);
    if (res.status === 'completed' || res.status === 'failed') {
      clearInterval(pollInterval);
      onScanComplete(res);
    }
  } catch (e) { log('Poll error: ' + e.message, 'error'); }
}

function updateScanProgress(data) {
  $('sp-pct').textContent = data.pct + '%';
  $('sp-fill').style.width = data.pct + '%';
  $('sp-status').textContent = data.status || '';

  const stages = ['recon', 'fingerprint', 'scan', 'creds', 'attack'];
  const stageEl = $('sp-stages');
  stageEl.innerHTML = stages.map(s => {
    const cls = s === data.stage ? 'active' : (data.pct > stages.indexOf(s) * 20 ? 'done' : '');
    return `<span class="scan-stage ${cls}">${s}</span>`;
  }).join('');
}

function updateScanProgressFromJob(job) {
  const stageMap = { running: 'scan', completed: 'attack', failed: 'scan' };
  const stage = job.current_module ? job.current_module.split('/').pop().split('_')[0] : 'scan';
  const pct = job.progress || 0;
  updateScanProgress({ stage, pct, status: job.status });

  // Poll server logs for cred attempts
  if (job.log && job.log.length > state.lastLogCount) {
    const newLogs = job.log.slice(state.lastLogCount);
    newLogs.forEach(line => {
      const credMatch = line.match(/\[creds\] try (.+?):(.+?) on (.+?):(.+?) \((.+?)\)/);
      if (credMatch) {
        log(`AUTH: ${credMatch[1]}:${credMatch[2]} → ${credMatch[3]}:${credMatch[4]}`, 'warn');
      } else if (line.includes('SUCCESS') || line.includes('success')) {
        log(`✓ ${line}`, 'success');
      } else if (line.startsWith('[+]')) {
        log(line, 'success');
      }
    });
    state.lastLogCount = job.log.length;
  }
}

async function onScanComplete(job) {
  log('Scan completed', 'success');
  unlockAchievement('first_host');
  logXp(20, '(host discovered)');

  $('btn-launch-recon').classList.remove('loading');
  $('btn-launch-recon').disabled = false;

  try {
    const report = await api(`/api/report/${scanJobId}`);
    if (report && report.hosts && report.hosts.length > 0) {
      displayScanResults(report.hosts[0]);
    }
  } catch (e) { log('Failed to fetch report: ' + e.message, 'error'); }
}

function displayScanResults(host) {
  state.scanResults = host;
  state.stats.hosts = 1;

  $('result-ip').textContent = host.address || 'Unknown';
  $('result-hostname').textContent = host.name || '';
  $('result-os').textContent = host.os_name || '';

  unlockAchievement('port_scanner');
  logXp(15, '(port scan)');

  if (host.services) {
    state.stats.services = host.services.length;
    const list = $('service-list');
    list.innerHTML = '';
    host.services.forEach((svc, i) => {
      const el = document.createElement('div');
      el.className = 'service-item';
      el.dataset.index = i;
      el.innerHTML = `
        <span class="svc-port">${svc.port}/${svc.proto}</span>
        <span class="svc-name">${svc.name} ${svc.product || ''}</span>
        <span class="svc-state ${svc.state}">${svc.state}</span>
      `;
      el.addEventListener('click', () => selectService(i));
      list.appendChild(el);
      // Pulse animation delay
      setTimeout(() => el.classList.add('pulse'), i * 100);
    });
  }

  updateMissionObjective('host');
  updateMissionObjective('services');
  document.querySelector('[data-obj="vuln"]').classList.add('active');

  $('target-results-card').hidden = false;
  log('Host discovered: ' + host.address, 'success');
  playSound('success');

  // vuln leads from the scan feed the Likely Vulnerable card (no phase jump)
  if (host.vulnerabilities && host.vulnerabilities.length > 0) {
    state.stats.vulns = host.vulnerabilities.length;
    unlockAchievement('vuln_finder');
    logXp(20, '(vuln found)');
  }
}

function selectService(idx) {
  document.querySelectorAll('.service-item').forEach((el, i) => {
    el.classList.toggle('selected', i === idx);
  });
  state.selectedService = state.scanResults.services[idx];
  log(`Selected: ${state.selectedService.port}/${state.selectedService.proto} (${state.selectedService.name})`, 'info');
}

// ═══════════════════════════════════════════
// TOOL ACTIONS
// ═══════════════════════════════════════════
async function findNeighbors() {
  log('Scanning neighbors...', 'info');
  try {
    const res = await api('/api/neighbors', { method: 'GET' });
    if (res.hosts) {
      log(`Found ${res.hosts.length} neighbors`, 'success');
      res.hosts.forEach(h => log(`  ${h.ip} (${h.mac})`, 'info'));
    }
  } catch (e) { log('Neighbors scan failed: ' + e.message, 'error'); }
}

async function deepAttack() {
  if (!state.scanResults) { alert('Run a scan first'); return; }
  log('Starting deep attack...', 'warn');
  try {
    const res = await api('/api/deepattack', {
      method: 'POST',
      body: { target: state.scanResults.address }
    });
    log('Deep attack job: ' + (res.job_id || res.attack_id || 'started'), 'info');
  } catch (e) { log('Deep attack failed: ' + e.message, 'error'); }
}

// ═══════════════════════════════════════════
// VIM NAVIGATION
// ═══════════════════════════════════════════
function vimNavigate(dir) {
  const phases = ['recon', 'prepare', 'execute', 'pwned', 'graph'];
  const idx = phases.indexOf(state.currentPhase);
  if (dir === 'j' && idx < phases.length - 1) setPhase(phases[idx + 1]);
  if (dir === 'k' && idx > 0) setPhase(phases[idx - 1]);
  if (dir === 'h') setPhase(phases[Math.max(0, idx - 1)]);
  if (dir === 'l') setPhase(phases[Math.min(phases.length - 1, idx + 1)]);
}

// ═══════════════════════════════════════════
// INIT
// ═══════════════════════════════════════════
document.addEventListener('DOMContentLoaded', () => {
  // Load saved theme
  const savedTheme = localStorage.getItem('h4k-theme') || 'light';
  setTheme(savedTheme);

  // Clock
  setInterval(() => {
    $('clock').textContent = new Date().toLocaleTimeString('en-US', { hour12: false });
  }, 1000);

  // MSF status check
  checkMsfStatus();
  setInterval(checkMsfStatus, 30000);

  // Scan button
  $('btn-launch-recon').addEventListener('click', launchScan);

  // Target input enter
  $('target').addEventListener('keydown', e => {
    if (e.key === 'Enter' && state.scanType === 'ip') launchScan();
  });

  // Scan type tabs
  document.querySelectorAll('.st-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      const type = tab.dataset.type;
      state.scanType = type;
      document.querySelectorAll('.st-tab').forEach(t => t.classList.toggle('active', t === tab));
      const targetInput = $('target');
      const hint = $('target-hint');
      if (type === 'neighbors') {
        targetInput.value = 'All local neighbors';
        targetInput.readOnly = true;
        targetInput.style.cursor = 'not-allowed';
        hint.textContent = 'Will scan all hosts found on your local network(s)';
        $('btn-launch-recon').disabled = false;
      } else {
        targetInput.value = '';
        targetInput.readOnly = false;
        targetInput.style.cursor = '';
        targetInput.placeholder = '192.168.1.13 or 192.168.1.0/24';
        hint.textContent = 'Enter a single IP or CIDR range (e.g. 192.168.1.0/24)';
        $('btn-launch-recon').disabled = false;
      }
    });
  });

  // Phase nav
  document.querySelectorAll('.nav-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      setPhase(btn.dataset.phase);
      if (btn.dataset.phase === 'graph') loadGraph();
    });
  });

  // Terminal clear
  $('terminal-clear')?.addEventListener('click', () => {
    const el = $('terminal-content');
    if (el) el.innerHTML = '';
  });

  // Sound toggle
  $('sound-toggle').addEventListener('click', () => {
    state.soundEnabled = !state.soundEnabled;
    $('sound-toggle').textContent = state.soundEnabled ? '🔊' : '🔇';
  });

  // Command palette
  $('cmd-palette-btn').addEventListener('click', () => toggleCmdPalette(true));
  $('cmd-input').addEventListener('input', e => {
    const q = e.target.value.toLowerCase();
    document.querySelectorAll('.cmd-item').forEach(item => {
      const match = item.dataset.cmd.includes(q) || item.querySelector('.cmd-label').textContent.toLowerCase().includes(q);
      item.style.display = match || !q ? 'flex' : 'none';
    });
  });
  $('cmd-input').addEventListener('keydown', e => {
    if (e.key === 'Enter') {
      const first = document.querySelector('.cmd-item:not([style*="none"])');
      if (first) executeCmd(first.dataset.cmd);
    }
    if (e.key === 'Escape') toggleCmdPalette(false);
  });

  // Cmd palette item clicks
  document.querySelectorAll('.cmd-item').forEach(item => {
    item.addEventListener('click', () => executeCmd(item.dataset.cmd));
  });

  // Keyboard shortcuts
  document.addEventListener('keydown', e => {
    // Ctrl+K = command palette
    if (e.ctrlKey && e.key === 'k') { e.preventDefault(); toggleCmdPalette(true); return; }
    // Don't handle if typing in input
    if (['INPUT', 'TEXTAREA'].includes(e.target.tagName)) return;

    // Vim keys
    if (['j', 'k', 'h', 'l'].includes(e.key)) vimNavigate(e.key);
    // Number phases
    if (e.key >= '1' && e.key <= '5') setPhase(['recon','prepare','execute','pwned','graph'][parseInt(e.key) - 1]);
    // T = theme
    if (e.key === 't') toggleTheme();
    // ? = help
    if (e.key === '?') log('Shortcuts: j/k/h/l=navigate, 1-5=phases, t=theme, Ctrl+K=palette, Esc=close', 'info');
    // Ctrl+Enter = scan
    if (e.ctrlKey && e.key === 'Enter' && state.currentPhase === 'recon') launchScan();
  });

  // Tool buttons
  $('tool-neighbors').addEventListener('click', findNeighbors);
  $('tool-deep').addEventListener('click', deepAttack);
  $('btn-graph-refresh').addEventListener('click', loadGraph);

  // Neighbor panel action buttons (delegated since panel is built dynamically)
  document.addEventListener('click', (e) => {
    if (e.target.closest('#btn-fingerprint')) startFingerprintScan();
    if (e.target.closest('#btn-full-scan')) startFullScan();
    const exBtn = e.target.closest('.v-exploit-btn');
    if (exBtn) openExploitPanel(parseInt(exBtn.dataset.vulnIndex, 10));
    if (e.target.closest('#btn-launch-exploit')) launchExploit();
    if (e.target.closest('#btn-cve-refresh')) refreshCveDb();
  });

  // Pwned buttons
  $('btn-next-target')?.addEventListener('click', () => {
    setPhase('recon');
    $('target').value = '';
    $('target').focus();
  });
  $('btn-new-mission')?.addEventListener('click', () => {
    state.scanResults = null;
    state.selectedVuln = null;
    state.selectedExploit = null;
    $('target-results-card').hidden = true;
    $('scan-progress-card').hidden = true;
    document.querySelectorAll('.obj').forEach(o => { o.classList.remove('done', 'active'); o.querySelector('.obj-check').textContent = '○'; });
    setPhase('recon');
  });

  // Theme toggle
  $('theme-toggle').addEventListener('click', toggleTheme);

  // Close cmd palette on backdrop click
  $('cmd-palette').addEventListener('click', e => {
    if (e.target === $('cmd-palette')) toggleCmdPalette(false);
  });

  updateXpDisplay();
  log('h4k operations center ready', 'system');
  log('Press Ctrl+K for command palette, ? for shortcuts', 'info');

  // repopulate persisted findings from previous fingerprint runs
  loadPersistedVulns();
  refreshSessionBadge();

  // Session reset: clears accumulated discovery/services/vulns + job history
  $('btn-session-reset')?.addEventListener('click', async () => {
    if (!confirm('Reset session? This clears all discovered hosts, services and vulnerability findings (engagements are kept).')) return;
    try {
      const res = await api('/api/session/reset?wipe_engagements=false', { method: 'POST' });
      log(`Session ${res.previous_session_id} reset → ${res.session_id}`, 'warn');
      // clear UI state
      state.vulnRows = [];
      state.selectedVulnRow = null;
      state.graphData = null;
      ['neighbors-panel', 'fingerprint-panel', 'vulns-panel', 'scan-progress-card', 'target-results-card', 'exploit-panel'].forEach(id => {
        const el = $(id);
        if (el) el.hidden = true;
      });
      const tb = $('vuln-tbody'); if (tb) tb.innerHTML = '';
      const fpt = $('fp-tbody'); if (fpt) fpt.innerHTML = '';
      const nl = $('neighbors-list'); if (nl) nl.innerHTML = '';
      refreshSessionBadge();
      loadGraph();
    } catch (e) { log('Session reset failed: ' + e.message, 'error'); }
  });
});

async function refreshSessionBadge() {
  const el = $('session-badge');
  if (!el) return;
  try {
    const s = await api('/api/session');
    el.textContent = `${s.id} · ${s.hosts}h ${s.services}s ${s.vulns}v`;
  } catch { el.textContent = 'session: unavailable'; }
}

async function loadPersistedVulns() {
  try {
    const res = await api('/api/neighbors/vulns');
    const vulns = res.vulns || [];
    if (vulns.length === 0) return;
    const rows = vulns.map(v => ({
      services: [{ port: v.port, proto: v.proto, vulns: [v] }],
      ip: v.ip,
    }));
    renderVulnPanel(rows);
    log(`Restored ${vulns.length} persisted vulnerability finding(s)`, 'info');
  } catch { /* first run or db empty */ }
}

async function checkMsfStatus() {
  try {
    const res = await fetch('/api/health').then(r => r.json()).catch(() => ({ status: 'unknown' }));
    const dot = document.querySelector('.status-dot');
    const text = dot?.nextElementSibling;
    if (res.status === 'ok' || res.msf === 'connected') {
      dot?.classList.replace('offline', 'online');
      if (text) text.textContent = 'MSF: online';
    } else {
      dot?.classList.replace('online', 'offline');
      if (text) text.textContent = 'MSF: offline';
    }
  } catch { /* ignore */ }
}

// ═══════════════════════════════════════════
// GRAPH
// ═══════════════════════════════════════════
let graphSimulation = null;

async function loadGraph() {
  try {
    const res = await api('/api/graph');
    state.graphData = res;
    renderGraph(res);
    $('graph-host-count').textContent = (res.nodes || []).length + ' hosts';
    $('graph-svc-count').textContent = (res.edges || []).length + ' services';
  } catch (e) {
    log('Graph load failed: ' + e.message, 'error');
  }
}

function renderGraph(data) {
  const svg = $('graph-svg');
  const empty = $('graph-empty');
  const nodes = data.nodes || [];
  const edges = data.edges || [];

  svg.innerHTML = '';
  empty.hidden = nodes.length > 0;
  if (nodes.length === 0) return;

  const W = svg.clientWidth || 800;
  const H = 600;

  // Build node map
  const nodeMap = {};
  nodes.forEach((n, i) => {
    nodeMap[n.id] = {
      ...n,
      x: W / 2 + (Math.random() - 0.5) * 400,
      y: H / 2 + (Math.random() - 0.5) * 300,
      vx: 0, vy: 0,
    };
  });

  // Force-directed simulation (simple link + charge + center)
  const nodes_list = Object.values(nodeMap);
  const edges_list = edges.map(e => ({
    ...e,
    source: nodeMap[e.source],
    target: nodeMap[e.target],
  })).filter(e => e.source && e.target);

  if (graphSimulation) graphSimulation.stop();

  // Run simulation ticks
  let tick = 0;
  const run = () => {
    for (let i = 0; i < 60; i++) tickSimulation(nodes_list, edges_list);
    renderGraphFrame(svg, nodes_list, edges_list);
    tick++;
    if (tick < 200) graphSimulation = setTimeout(run, 10);
    else renderGraphFrame(svg, nodes_list, edges_list);
  };
  graphSimulation = setTimeout(run, 10);
}

function tickSimulation(nodes, edges) {
  const W = 800, H = 600;
  const alpha = 0.3;
  // Center gravity
  nodes.forEach(n => {
    n.vx += (W / 2 - n.x) * 0.01 * alpha;
    n.vy += (H / 2 - n.y) * 0.01 * alpha;
  });
  // Charge (repulsion)
  for (let i = 0; i < nodes.length; i++) {
    for (let j = i + 1; j < nodes.length; j++) {
      const dx = nodes[j].x - nodes[i].x;
      const dy = nodes[j].y - nodes[i].y;
      const dist = Math.sqrt(dx * dx + dy * dy) || 1;
      const force = 2000 / (dist * dist);
      const fx = dx / dist * force * alpha;
      const fy = dy / dist * force * alpha;
      nodes[i].vx -= fx; nodes[i].vy -= fy;
      nodes[j].vx += fx; nodes[j].vy += fy;
    }
  }
  // Link (spring)
  edges.forEach(e => {
    if (!e.source || !e.target) return;
    const dx = e.target.x - e.source.x;
    const dy = e.target.y - e.source.y;
    const dist = Math.sqrt(dx * dx + dy * dy) || 1;
    const force = (dist - 80) * 0.05 * alpha;
    const fx = dx / dist * force;
    const fy = dy / dist * force;
    e.source.vx += fx; e.source.vy += fy;
    e.target.vx -= fx; e.target.vy -= fy;
  });
  // Apply velocity
  nodes.forEach(n => {
    n.x += n.vx; n.y += n.vy;
    n.x = Math.max(30, Math.min(W - 30, n.x));
    n.y = Math.max(30, Math.min(H - 30, n.y));
    n.vx *= 0.8; n.vy *= 0.8;
  });
}

function renderGraphFrame(svg, nodes, edges) {
  const selected = state.selectedGraphNode;
  let html = `<g class="edges">`;
  edges.forEach(e => {
    if (!e.source || !e.target) return;
    const cls = `edge edge-service edge-${e.proto || 'tcp'}`;
    html += `<line class="${cls}" x1="${e.source.x}" y1="${e.source.y}" x2="${e.target.x}" y2="${e.target.y}"/>`;
  });
  html += `</g>`;

  html += `<g class="nodes">`;
  // Service nodes
  const svcByHost = {};
  edges.forEach(e => {
    if (!e.source || !e.target) return;
    const hostId = e.source.id;
    if (!svcByHost[hostId]) svcByHost[hostId] = [];
    svcByHost[hostId].push(e);
  });
  nodes.forEach(n => {
    const isHost = n.type === 'host';
    const isSelected = selected && selected.id === n.id;
    const svcList = svcByHost[n.id] || [];
    // Service nodes cluster near host
    svcList.forEach((e, i) => {
      const angle = (i / svcList.length) * 2 * Math.PI;
      const r = 40 + svcList.length * 6;
      const sx = n.x + Math.cos(angle) * r;
      const sy = n.y + Math.sin(angle) * r;
      e.source.x = sx; e.source.y = sy;
      e.source.label = e.service || e.port;
      const scls = `node-service${isSelected ? ' selected' : ''}`;
      html += `<g class="${scls}" data-node-id="${e.target.id}" data-node-type="service" data-node-data="${escAttr(JSON.stringify(e))}">`;
      html += `<circle cx="${sx}" cy="${sy}" r="5"/>`;
      html += `<text x="${sx + 8}" y="${sy + 4}">${e.port}/${e.proto || 'tcp'}</text>`;
      html += `</g>`;
    });
    // Host node
    const hcls = `node-host${isSelected ? ' selected' : ''}${n.vuln_count > 0 ? ' has-vulns' : ''}${n.has_session ? ' pwned' : ''}`;
    html += `<g class="${hcls}" data-node-id="${n.id}" data-node-type="host" data-node-data="${escAttr(JSON.stringify(n))}">`;
    if (n.vuln_count > 0) {
      html += `<circle cx="${n.x}" cy="${n.y}" r="24" class="vuln-ring"/>`;
      html += `<text x="${n.x}" y="${n.y - 22}" text-anchor="middle" class="vuln-badge">⚠${n.vuln_count}</text>`;
    }
    if (n.has_session) {
      html += `<text x="${n.x}" y="${n.y - 26}" text-anchor="middle" class="pwned-badge">💀</text>`;
    }
    html += `<circle cx="${n.x}" cy="${n.y}" r="18"/>`;
    const shortLabel = n.label.length > 12 ? n.label.slice(0, 10) + '…' : n.label;
    html += `<text x="${n.x}" y="${n.y + 4}" text-anchor="middle">${shortLabel}</text>`;
    html += `</g>`;
  });
  html += `</g>`;
  svg.innerHTML = html;

  // Attach click events
  svg.querySelectorAll('.node-host, .node-service').forEach(el => {
    el.addEventListener('click', () => {
      const type = el.dataset.nodeType;
      const data = JSON.parse(el.dataset.nodeData);
      selectGraphNode(type, data);
    });
    el.addEventListener('mouseenter', (ev) => showGraphTooltip(ev, el));
    el.addEventListener('mouseleave', hideGraphTooltip);
  });
}

function selectGraphNode(type, data) {
  state.selectedGraphNode = data;
  const edges = (state.graphData?.edges || []).filter(e => {
    if (type === 'host') return e.source === data.id;
    return e.target === data.id;
  });
  const detailTitle = $('graph-detail-title');
  const detailBody = $('graph-detail-body');
  const detailCard = $('graph-detail-card');
  detailCard.hidden = false;
  if (type === 'host') {
    detailTitle.textContent = data.label || data.id;
    const svcList = edges.map(e => ({
      port: e.port, proto: e.proto, service: e.service, state: e.state, info: e.info
    }));
    detailBody.innerHTML = `
      <div class="graph-detail-row"><span class="graph-detail-label">Address</span><span class="graph-detail-value">${data.id}</span></div>
      <div class="graph-detail-row"><span class="graph-detail-label">OS</span><span class="graph-detail-value">${data.os || 'unknown'}</span></div>
      <div class="graph-detail-row"><span class="graph-detail-label">Vendor</span><span class="graph-detail-value">${data.vendor || '—'}</span></div>
      <div class="graph-detail-row"><span class="graph-detail-label">Status</span><span class="graph-detail-value">${data.has_session ? '💀 session' : '—'}</span></div>
      <div class="graph-detail-row"><span class="graph-detail-label">Services</span><span class="graph-detail-value">${svcList.length}</span></div>
      ${data.vuln_count ? `<div class="graph-detail-row"><span class="graph-detail-label">Vulns</span><span class="graph-detail-value">⚠ ${data.vuln_count} — see Likely Vulnerable card</span></div>` : ''}
      <div class="graph-detail-services">
        ${svcList.map(s => `<span class="graph-svc-chip ${s.state === 'open' ? 'open' : 'closed'}">${s.port}/${s.proto} ${s.service || ''}</span>`).join('')}
      </div>
    `;
  } else {
    const hostEdge = (state.graphData?.edges || []).find(e => e.target === data.id);
    detailTitle.textContent = `Port ${data.port}/${data.proto}`;
    detailBody.innerHTML = `
      <div class="graph-detail-row"><span class="graph-detail-label">Host</span><span class="graph-detail-value">${hostEdge?.source || '?'}</span></div>
      <div class="graph-detail-row"><span class="graph-detail-label">Port</span><span class="graph-detail-value">${data.port}</span></div>
      <div class="graph-detail-row"><span class="graph-detail-label">Proto</span><span class="graph-detail-value">${data.proto || 'tcp'}</span></div>
      <div class="graph-detail-row"><span class="graph-detail-label">Service</span><span class="graph-detail-value">${data.service || 'unknown'}</span></div>
      <div class="graph-detail-row"><span class="graph-detail-label">State</span><span class="graph-detail-value">${data.state || 'unknown'}</span></div>
      <div class="graph-detail-row"><span class="graph-detail-label">Info</span><span class="graph-detail-value">${data.info || '—'}</span></div>
    `;
  }
}

function showGraphTooltip(ev, el) {
  const type = el.dataset.nodeType;
  const data = JSON.parse(el.dataset.nodeData);
  const tip = $('graph-tooltip');
  if (type === 'host') {
    tip.innerHTML = `<div class="gt-host">${data.id}</div>
      <div class="gt-row"><span class="gt-label">OS</span><span class="gt-value">${data.os || '—'}</span></div>
      <div class="gt-row"><span class="gt-label">Vendor</span><span class="gt-value">${data.vendor || '—'}</span></div>
      ${data.vuln_count ? `<div class="gt-row"><span class="gt-label">Vulns</span><span class="gt-value">⚠ ${data.vuln_count}</span></div>` : ''}
      ${data.has_session ? `<div class="gt-row"><span class="gt-label">Status</span><span class="gt-value">💀 pwned</span></div>` : ''}`;
  } else {
    const edges = (state.graphData?.edges || []).filter(e => e.target === data.id);
    const host = edges[0]?.source || '?';
    tip.innerHTML = `<div class="gt-host">${data.service || data.port}</div>
      <div class="gt-row"><span class="gt-label">Host</span><span class="gt-value">${host}</span></div>
      <div class="gt-row"><span class="gt-label">Port</span><span class="gt-value">${data.port}/${data.proto}</span></div>
      <div class="gt-row"><span class="gt-label">State</span><span class="gt-value">${data.state || '—'}</span></div>`;
  }
  const rect = el.getBoundingClientRect();
  tip.style.left = (rect.right + 10) + 'px';
  tip.style.top = rect.top + 'px';
  tip.hidden = false;
}

function hideGraphTooltip() {
  $('graph-tooltip').hidden = true;
}

function escAttr(s) {
  return s.replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
