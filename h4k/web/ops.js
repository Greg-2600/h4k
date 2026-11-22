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
  credTargets: [],
  lastCredTargetsLoad: 0,
  activeSession: null,
  propEngagementId: null,
  propPairs: [],
  propPlan: null,
  overview: undefined,
  findings: [],
};

// XP table: level -> XP required to reach it
const XP_LEVELS = [0, 100, 250, 500, 1000, 2000, 4000, 8000, 16000, 32000];

// Every navigable view, in nav order. Keyboard shortcuts and the roving
// tabindex both derive from this list so they cannot drift from the markup.
const PHASES = ['assets', 'walk', 'fuzz', 'lab', 'ad', 'telemetry', 'nightly', 'report', 'settings'];
const PHASE_KEYS = { a: 'assets', w: 'walk', f: 'fuzz', l: 'lab', d: 'ad', t: 'telemetry', n: 'nightly', r: 'report', s: 'settings' };

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

// ═══════════════════════════════════════════
// ACCESSIBILITY (#83)
// ═══════════════════════════════════════════
// A single polite live region and one assertive alert region. Screen readers
// get every state change (phase switch, job start/finish, detections) without
// the visual log having to be a live region that re-reads 200 lines.
let _announceTimer = null;
function announce(message, assertive = false) {
  const el = $(assertive ? 'sr-alert' : 'sr-status');
  if (!el) return;
  el.textContent = '';
  clearTimeout(_announceTimer);
  _announceTimer = setTimeout(() => { el.textContent = String(message || ''); }, 30);
}

function setProgress(el, pct) {
  if (!el) return;
  const bar = el.closest('[role="progressbar"]') || (el.parentElement && el.parentElement.parentElement);
  if (bar && bar.getAttribute) {
    bar.setAttribute('aria-valuenow', String(Math.round(Number(pct) || 0)));
  }
}

function applyPrefs() {
  const reduce = localStorage.getItem('h4k-reduce-motion') === '1';
  document.documentElement.dataset.reduceMotion = reduce ? 'true' : 'false';
  const sound = localStorage.getItem('h4k-sound');
  state.soundEnabled = sound !== '0';
  const soundBtn = $('sound-toggle');
  if (soundBtn) {
    soundBtn.textContent = state.soundEnabled ? '🔊' : '🔇';
    soundBtn.setAttribute('aria-pressed', state.soundEnabled ? 'true' : 'false');
  }
  const setSound = $('set-sound');
  if (setSound) setSound.checked = state.soundEnabled;
  const setMotion = $('set-reduce-motion');
  if (setMotion) setMotion.checked = reduce;
  const setTheme = $('set-theme');
  if (setTheme) setTheme.value = document.documentElement.dataset.theme || 'light';
}

function apiKey() {
  return sessionStorage.getItem('h4k-api-key') || '';
}

function apiHeaders() {
  const headers = { 'Content-Type': 'application/json' };
  const key = apiKey();
  if (key) headers['X-API-Key'] = key;
  return headers;
}

const api = async (url, opts = {}) => {
  const r = await fetch(url, {
    ...opts,
    headers: { ...apiHeaders(), ...(opts.headers || {}) },
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  // non-JSON error bodies (e.g. middleware 429s) read as {detail: '...'}
  // instead of blowing up every poller with a JSON parse error
  const text = await r.text();
  let data;
  try { data = JSON.parse(text); }
  catch { data = { status: r.status, detail: `${r.status} ${r.statusText}` }; }
  if (r.status === 401 && !url.startsWith('/api/auth/')) {
    announce('Authentication required. Add an API key in Settings.', true);
    data = { ...data, auth_required: true };
  }
  return data;
};

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
  saveDefaultPanel();
  state.currentPhase = 'assets';
  updateXpDisplay();
  renderOverview();
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
  const target = document.getElementById('phase-' + phase);
  if (!target) return;
  state.currentPhase = phase;
  document.querySelectorAll('.phase, .console').forEach(el => {
    el.hidden = el.dataset.phase !== phase;
  });
  document.querySelectorAll('.nav-btn').forEach(el => {
    const active = el.dataset.phase === phase;
    el.classList.toggle('active', active);
    if (active) el.setAttribute('aria-current', 'page');
    else el.removeAttribute('aria-current');
  });
  updateHint();
  const heading = target.querySelector('h2');
  announce(`View: ${heading ? heading.textContent.trim() : phase}`);
  if (phase === 'assets') {
    loadGraph();
    loadCredTargets();
    loadCveStatus();
    refreshSessionBadge();
    restoreDefaultPanel();
  }
  if (phase === 'report') { renderReportPreview(); loadAttackPaths(); loadFindings(); }
  if (phase === 'telemetry') loadTelemetry();
  if (phase === 'nightly') loadSchedules();
  if (phase === 'settings') { loadAuthStatus(); loadApprovals(); loadLimits(); }
  if (phase === 'lab' || phase === 'ad') loadAuthStatus();
}

function updateHint() {
  const hints = {
    assets: 'Click a host/service/cred on the canvas — actions appear for that asset',
    walk: 'Requires an active scope — Start walks the entire local network',
    fuzz: 'Point at a service you own and start fuzzing',
    lab: 'Benign traffic generation and read-only IoT/OT discovery',
    ad: 'Read-only domain audit; credential operations are opt-in and lockout-aware',
    telemetry: 'Ingest sysmon/auditd/osquery events and see ATT&CK-mapped detections',
    nightly: 'Cron schedules for unattended autopilot runs (H4K_SCHEDULER=1)',
    report: '⇩ Report downloads the full writeup; 🧬 plans credential propagation',
    settings: 'API key, OIDC sign-in, theme and accessibility preferences',
  };
  $('footer-hint').textContent = hints[state.currentPhase] || '';
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
  // Safe for text nodes AND attribute values: quotes are escaped too, so a
  // hostname/service string cannot break out of data-* or title attributes.
  return String(s ?? '')
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;')
    .replace(/'/g,'&#39;');
}

// ═══════════════════════════════════════════
// COMMAND PALETTE
// ═══════════════════════════════════════════
function toggleCmdPalette(show) {
  const el = $('cmd-palette');
  if (!el) return;
  if (show === undefined) show = el.hidden;
  el.hidden = !show;
  const input = $('cmd-input');
  if (!show) {
    input.value = '';
    input.setAttribute('aria-expanded', 'false');
    if (_paletteReturn) { try { _paletteReturn.focus(); } catch (e) { /* gone */ } }
    return;
  }
  _paletteReturn = document.activeElement;
  input.setAttribute('aria-expanded', 'true');
  filterPalette('');
  setTimeout(() => input.focus(), 30);
}

let _paletteReturn = null;
let _paletteIndex = 0;

function paletteItems() {
  return Array.from(document.querySelectorAll('#cmd-results .cmd-item'))
    .filter(el => el.style.display !== 'none');
}

function selectPaletteItem(index) {
  const items = paletteItems();
  if (!items.length) return;
  _paletteIndex = Math.max(0, Math.min(index, items.length - 1));
  items.forEach((el, i) => {
    const active = i === _paletteIndex;
    el.classList.toggle('selected', active);
    el.setAttribute('aria-selected', active ? 'true' : 'false');
  });
  const active = items[_paletteIndex];
  const input = $('cmd-input');
  if (input) input.setAttribute('aria-activedescendant', active.id);
  active.scrollIntoView({ block: 'nearest' });
}

function filterPalette(query) {
  const q = String(query || '').toLowerCase();
  document.querySelectorAll('#cmd-results .cmd-item').forEach(item => {
    const label = item.querySelector('.cmd-label')?.textContent || '';
    const match = !q || item.dataset.cmd.includes(q) || label.toLowerCase().includes(q);
    item.style.display = match ? 'flex' : 'none';
  });
  selectPaletteItem(0);
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
  const select = document.getElementById('set-theme');
  if (select) select.value = theme;
}

// ═══════════════════════════════════════════
// SCAN LAUNCH
// ═══════════════════════════════════════════
let scanJobId = null;
let pollInterval = null;
let neighborJobId = null;
let neighborPollInterval = null;

function selectScanType(tab) {
  const type = tab.dataset.type;
  state.scanType = type;
  document.querySelectorAll('.st-tab[data-type]').forEach(t => t.classList.toggle('active', t === tab));
  const targetInput = $('target');
  const hint = $('target-hint');
  if (!targetInput) return;
  if (type === 'neighbors') {
    targetInput.value = 'All local neighbors';
    targetInput.readOnly = true;
    targetInput.style.cursor = 'not-allowed';
    if (hint) hint.textContent = 'Will scan all hosts found on your local network(s)';
  } else {
    targetInput.value = '';
    targetInput.readOnly = false;
    targetInput.style.cursor = '';
    targetInput.placeholder = '192.168.1.13 or 192.168.1.0/24';
    if (hint) hint.textContent = 'Enter a single IP or CIDR range (e.g. 192.168.1.0/24)';
  }
  const btn = $('btn-launch-recon');
  if (btn) btn.disabled = false;
}

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


  // Legacy nav highlight: the element was removed in the console redesign.
  const hostObj = document.querySelector('[data-obj="host"]');
  if (hostObj) hostObj.classList.add('active');


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
        try_default_creds: false,
        open_sessions: false,
        do_attack: false,
      }
    });

    const scanId = res.job_id || res.id;
    if (scanId) {
      scanJobId = scanId;
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
  if (state.panelMode !== 'default') restoreDefaultPanel();
  $('sp-strip').hidden = false;
  updateScanProgress({ stage: 'recon', pct: 0, status: 'Initializing...' });
  pollInterval = setInterval(pollScanProgress, 2000);
}

function startNeighborDiscovery() {
  if (state.panelMode !== 'default') restoreDefaultPanel();
  $('sp-strip').hidden = false;
  $('neighbors-list').innerHTML = '';
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
  const fill = $('sp-fill');
  const status = $('sp-status');
  if (fill) fill.style.width = pct + '%';
  setProgress(fill, pct);
  if (status) status.textContent = job.message || job.status;

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
  clearInterval(neighborPollInterval);
  const hosts = job.hosts || [];

  if (job.status === 'error') {
    log('Neighbor discovery failed: ' + (job.error || 'unknown error'), 'error');
    $('sp-strip').hidden = true;
    return;
  }
  if (hosts.length === 0) {
    log('No neighbors found. Is arp-scan available?', 'warn');
    $('sp-strip').hidden = true;
    return;
  }
  log(`Found ${hosts.length} neighbor(s) on local network`, 'success');
  renderOverview();
  unlockAchievement('first_host');
  logXp(10, '(neighbors found)');
  const cidrs = [];
  for (const h of hosts) {
    const parts = h.ip.split('.');
    cidrs.push(`${parts[0]}.${parts[1]}.${parts[2]}.0/24`);
  }
  state.discoveredTarget = [...new Set(cidrs)].join(',');
  state.panelTab = 'map';
  // discovery done -> fingerprint all (with MSF union) for the coherent flow
  startFingerprintScan();
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
  if (state.panelMode !== 'default') restoreDefaultPanel();
  state.panelTab = 'map';
  bindPanelTabs();
  // overlapping jobs create overlapping pollers; clear the old handle or one
  // orphaned interval will burn onFingerprintDone forever
  if (fingerprintPollInterval) clearInterval(fingerprintPollInterval);
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
  const panel = $('pane-map');
  if (!panel) restoreDefaultPanel();
  const pct = job.progress || 0;
  const statusEl = $('fp-status');
  const fillEl = $('fp-fill');
  const pctEl = $('fp-pct');
  if (statusEl) statusEl.textContent = job.message || job.status;
  if (fillEl) fillEl.style.width = pct + '%';
  setProgress(fillEl, pct);
  if (pctEl) pctEl.textContent = Math.round(pct) + '%';

  renderFingerprintTable(job.results || []);
  renderVulnPanel(job.results || []);
}

async function loadCveStatus() {
  if (typeof refreshOverview === 'function') refreshOverview();
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
  if (!tbody) return;

  const rows = [];
  results.forEach(r => {
    (r.services || []).forEach(s => {
      (s.vulns || []).forEach(v => {
        rows.push({ ip: r.ip, port: s.port, proto: s.proto, service: s.service, product: s.product, ...v });
      });
    });
  });

  const pane = $('pane-vulns');
  const vulnsVisible = !$('pane-vulns')?.hidden;
  if (rows.length === 0) { if (empty) empty.hidden = false; return; }
  empty.hidden = true;
  const chip = $('vuln-chip-count');
  if (chip) chip.textContent = `${rows.length} findings`;
  loadCveStatus();
  // Default-Cred Targets card rides along: populated once the vuln card is
  // live (throttled — polling fires every 2s, sqlite fetch is cheap but not free)
  if (!state.lastCredTargetsLoad || Date.now() - state.lastCredTargetsLoad > 10000) {
    state.lastCredTargetsLoad = Date.now();
    loadCredTargets();
  }

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
  renderActionPanel('vuln', row);
  $('ex-output').hidden = true;
  $('ex-output').innerHTML = '';
  hintVerifiedCreds(row);
}

let credsCache = null;
let credsCacheAt = 0;

async function hintVerifiedCreds(row) {
  try {
    if (!credsCache || Date.now() - credsCacheAt > 30000) {
      credsCache = await api('/api/passattack/creds/all');
      credsCacheAt = Date.now();
    }
    const c = (credsCache?.creds || []).find(c => c.host === row.ip);
    if (c) {
      appendExOutput(`verified creds for ${c.host}: ${c.user}:${c.password} (${c.service}) — login modules unlocked`);
      const loginMod = { ssh: 'exploit/multi/ssh/ssh_login', telnet: 'exploit/multi/telnet/telnet_rlogin' }[c.service];
      if (loginMod) appendExOutput(`  [module] ${loginMod}`);
    }
  } catch { /* soft fail */ }
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
          openSessionConsole(atk.session_id, row.ip);
          refreshSessionBadge();
          loadGraph();
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
  const svc = (row.service || '').split('/')[0];
  openPassAttackCard(row.ip, row.port, svc || 'ssh');
}

function openPassAttackCard(host, port, service) {
  renderActionPanel('passattack', { host, port, service });
  $('pa-host').value = host || '';
  $('pa-port').value = port || '';
  const sel = $('pa-service');
  if (sel) {
    const known = ['ssh', 'ftp', 'telnet', 'mysql', 'http-basic'].find(s => s === service);
    if (known) sel.value = known;
  }
}

let paPollTimer = null;

async function launchPassAttack() {
  const host = $('pa-host').value.trim();
  const port = parseInt($('pa-port').value, 10) || null;
  const service = $('pa-service').value;
  if (!host) { $('pa-live-status').textContent = 'Host is required.'; return; }

  const btn = $('btn-launch-passattack');
  btn.disabled = true;
  $('pa-live-status').textContent = 'Launching...';
  $('pa-progress').style.width = '0%';
  $('pa-output').hidden = false;
  $('pa-output').innerHTML = '';
  $('pa-found').hidden = true;
  appendPaOutput(`> ${service} password attack on ${host}:${port || 'default'}`);

  try {
    const res = await api('/api/passattack', {
      method: 'POST',
      body: { host, port, service }
    });
    if (!res.job_id) {
      $('pa-live-status').textContent = 'Failed: ' + (res.detail || JSON.stringify(res));
      btn.disabled = false;
      return;
    }
    if (paPollTimer) clearInterval(paPollTimer);
    paPollTimer = setInterval(async () => {
      try {
        const job = await api(`/api/passattack/${res.job_id}`);
        $('pa-live-status').textContent = job.message || job.status;
        $('pa-progress').style.width = (job.progress || 0) + '%';
        (job.log || []).forEach(l => {
          if (!$('pa-output').dataset[`seen_${btoa(l).slice(0, 8)}`]) {
            $('pa-output').dataset[`seen_${btoa(l).slice(0, 8)}`] = '1';
            appendPaOutput('  ' + l);
          }
        });
        if (job.found && job.found.length) renderPaFound(job.found);
        if (['done', 'error'].includes(job.status)) {
          clearInterval(paPollTimer);
          paPollTimer = null;
          btn.disabled = false;
          if (job.status === 'error') {
            $('pa-live-status').textContent = 'Error: ' + (job.error || 'unknown');
            playSound('error');
          } else if (job.found && job.found.length) {
            $('pa-live-status').textContent = `${job.found.length} credential(s) found!`;
            glitchEffect();
            unlockAchievement('exploiter');
            logXp(25, '(password attack)');
            loadCredTargets();
          } else {
            playSound('error');
          }
        }
      } catch (e) {
        clearInterval(paPollTimer); paPollTimer = null;
        btn.disabled = false;
        $('pa-live-status').textContent = 'Poll error: ' + e.message;
      }
    }, 2500);
  } catch (e) {
    $('pa-live-status').textContent = 'Launch error: ' + e.message;
    btn.disabled = false;
  }
}

function appendPaOutput(text) {
  const el = $('pa-output');
  if (el) {
    const p = document.createElement('p');
    p.className = 't-line';
    p.textContent = text;
    el.appendChild(p);
    el.scrollTop = el.scrollHeight;
  }
}

// ---- session console ----

function openSessionConsole(sessionId, host) {
  state.activeSession = sessionId;
  const con = $('ex-console');
  if (!con) return;
  con.hidden = false;
  $('ex-console-target').textContent = `session ${sessionId} @ ${host}`;
  $('ex-console-output').hidden = false;
  $('ex-console-output').innerHTML = '';
  appendConsoleLine(`session ${sessionId} opened on ${host} — try a quick action or type a command`);
  con.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function appendConsoleLine(text) {
  const el = $('ex-console-output');
  if (!el) return;
  const p = document.createElement('p');
  p.className = 't-line';
  p.textContent = text;
  el.appendChild(p);
  el.scrollTop = el.scrollHeight;
}

async function runSessionCmd(cmd) {
  const sid = state.activeSession;
  if (!sid) { log('No active session', 'warn'); return; }
  appendConsoleLine(`> ${cmd}`);
  try {
    const res = await api(`/api/sessions/${sid}/cmd`, { method: 'POST', body: { command: cmd } });
    if (res.output !== undefined) {
      (res.output || '(no output)').split('\n').slice(0, 40).forEach(l => appendConsoleLine('  ' + l));
    } else {
      appendConsoleLine('  error: ' + (res.detail || JSON.stringify(res)));
    }
  } catch (e) { appendConsoleLine('  error: ' + e.message); }
}

async function downloadSessionReport() {
  try {
    const fmt = 'md';
    const res = await api(`/api/session/report?fmt=${fmt}`);
    const blob = new Blob([res.content], { type: 'text/markdown' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    const s = await api('/api/session');
    a.download = `h4k-session-${s.session_id || 'report'}.md`;
    a.click();
    URL.revokeObjectURL(a.href);
    log(`Session report ${a.download} downloaded`, 'success');
    logXp(10, '(report)');
  } catch (e) { log('Report failed: ' + e.message, 'error'); }
}

async function renderReportPreview() {
  const el = $('report-preview');
  if (!el) return;
  el.textContent = 'loading session report…';
  try {
    const res = await api('/api/session/report?fmt=md');
    if (res && typeof res.content === 'string') {
      el.textContent = res.content.length > 20000
        ? res.content.slice(0, 20000) + '\n…[preview truncated — download for the full report]…'
        : res.content;
    } else {
      el.textContent = res?.detail || 'No report content yet — run a scan or autopilot first.';
    }
  } catch (e) {
    el.textContent = 'Report preview failed: ' + e.message;
  }
}

// ═══════════════════════════════════════════
// OBJECTIVES, ATTACK PATHS & COVERAGE
// ═══════════════════════════════════════════
async function activeEngagementId() {
  try {
    const session = await api('/api/session');
    const id = session?.scope?.engagement_id;
    if (id) return id;
  } catch (e) { /* fall through to the header selector */ }
  return $('scope-select')?.value || '';
}

async function loadAttackPaths() {
  const eid = await activeEngagementId();
  if (!eid) {
    setText('paths-summary', 'no engagement');
    setText('paths-status', 'select an engagement scope first');
    const tbody = $('obj-tbody');
    if (tbody) tbody.innerHTML = '';
    const empty = $('obj-empty');
    if (empty) empty.style.display = 'block';
    const out = $('paths-output');
    if (out) out.textContent = 'No active engagement — choose one in the header.';
    return;
  }
  const data = await api(`/api/engagement/${encodeURIComponent(eid)}/paths`);
  if (!data || data.detail) {
    setText('paths-summary', data?.detail || 'paths unavailable');
    setText('paths-status', data?.detail || 'paths unavailable');
    return;
  }
  renderObjectives(data);
  setText(
    'paths-summary',
    `${(data.objectives || []).length} objectives · ${(data.paths || []).length} paths · ${data.coverage?.gaps || 0} gaps`
  );
  renderPaths(data);
}

function renderObjectives(data) {
  const rows = data.objectives || [];
  const body = $('obj-tbody');
  if (body) {
    body.innerHTML = rows.map(o => `
      <tr>
        <td><code>${escHtml(o.host)}</code></td>
        <td>${escHtml(o.label || o.host)}</td>
        <td>${escHtml(o.kind || 'host')}</td>
        <td><span class="v-sev ${escHtml(o.criticality)}">${escHtml(o.criticality)}</span></td>
        <td><button class="btn btn-secondary btn-sm" data-obj-del="${escAttr(o.host)}" data-obj-label="${escAttr(o.label || '')}">Remove</button></td>
      </tr>`).join('');
  }
  const empty = $('obj-empty');
  if (empty) empty.style.display = rows.length ? 'none' : 'block';
}

function renderPaths(data) {
  const lines = [];
  (data.paths || []).forEach(p => {
    lines.push(`PATH #${p.rank} [${p.risk}] ${p.chain} → ${p.objective.host}`);
    lines.push(`  objective: ${p.objective.label || p.objective.host} (${p.objective_criticality}), cost ${p.cost}`);
    if (p.techniques?.length) lines.push(`  ATT&CK: ${p.techniques.join(', ')}`);
    if (p.findings?.length) {
      lines.push(`  findings: ${p.findings.map(f => `${f.id} ${f.severity} ${f.title}`).join(' | ')}`);
    }
    if (p.evidence?.length) lines.push(`  evidence: ${p.evidence.length} artifact(s)`);
    lines.push('');
  });
  if ((data.unreachable_objectives || []).length) {
    lines.push('UNREACHABLE OBJECTIVES');
    data.unreachable_objectives.forEach(o => lines.push(`  ${o.host} (${o.criticality})`));
    lines.push('');
  }
  const cov = data.coverage || {};
  lines.push(`COVERAGE: ${cov.entries || 0} entries · ${cov.tested || 0} tested · ${cov.gaps || 0} gaps`);
  (cov.gap_entries || []).slice(0, 20).forEach(g => {
    lines.push(`  gap ${g.host}${g.port ? ':' + g.port : ''} ${g.risk_area}: ${g.outcome}`);
  });
  const out = $('paths-output');
  if (out) out.textContent = lines.join('\n') || 'No paths yet — declare an objective and record verified access.';
}

async function addObjective() {
  const eid = await activeEngagementId();
  if (!eid) { setText('paths-status', 'select an engagement first'); return; }
  const host = ($('obj-host')?.value || '').trim();
  if (!host) { setText('paths-status', 'objective host required'); announce('Objective needs a host', true); return; }
  const res = await api(`/api/engagement/${encodeURIComponent(eid)}/objectives`, {
    method: 'POST',
    body: {
      host,
      label: ($('obj-label')?.value || '').trim(),
      kind: $('obj-kind')?.value || 'host',
      criticality: $('obj-criticality')?.value || 'high',
    },
  });
  if (!res || res.detail) {
    setText('paths-status', res?.detail || 'add failed');
    announce(`Objective add failed: ${res?.detail || 'unknown'}`, true);
    return;
  }
  setText('paths-status', `objective ${res.host} saved`);
  announce(`Objective ${res.host} saved`);
  ['obj-host', 'obj-label'].forEach(id => { const el = $(id); if (el) el.value = ''; });
  await loadAttackPaths();
}

async function deleteObjective(host, label) {
  const eid = await activeEngagementId();
  if (!eid) return;
  const query = new URLSearchParams({ host });
  if (label) query.set('label', label);
  const res = await api(`/api/engagement/${encodeURIComponent(eid)}/objectives?${query.toString()}`, { method: 'DELETE' });
  setText('paths-status', res?.detail || 'removed');
  announce(`Objective ${host} removed`);
  await loadAttackPaths();
}

async function addCoverage() {
  const eid = await activeEngagementId();
  if (!eid) { setText('paths-status', 'select an engagement first'); return; }
  const host = ($('cov-host')?.value || '').trim();
  const risk = ($('cov-risk')?.value || '').trim();
  if (!host || !risk) { setText('paths-status', 'coverage host and risk area required'); return; }
  const portRaw = ($('cov-port')?.value || '').trim();
  const res = await api(`/api/engagement/${encodeURIComponent(eid)}/coverage`, {
    method: 'POST',
    body: {
      host,
      port: portRaw ? parseInt(portRaw, 10) : 0,
      risk_area: risk,
      outcome: $('cov-outcome')?.value || 'no_issue_found',
      reason: ($('cov-reason')?.value || '').trim(),
    },
  });
  if (!res || res.detail) {
    setText('paths-status', res?.detail || 'coverage save failed');
    announce(`Coverage save failed: ${res?.detail || 'unknown'}`, true);
    return;
  }
  setText('paths-status', `coverage ${host} ${risk} → ${res.outcome}`);
  announce(`Coverage recorded: ${risk} ${res.outcome}`);
  const reason = $('cov-reason'); if (reason) reason.value = '';
  await loadAttackPaths();
}

async function downloadPathsReport() {
  const eid = await activeEngagementId();
  if (!eid) { setText('paths-status', 'select an engagement first'); return; }
  const res = await api(`/api/engagement/${encodeURIComponent(eid)}/paths/report?fmt=md`);
  if (!res || typeof res.content !== 'string') {
    setText('paths-status', res?.detail || 'report unavailable');
    return;
  }
  const blob = new Blob([res.content], { type: 'text/markdown' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'h4k-attack-paths.md';
  a.click();
  URL.revokeObjectURL(a.href);
  setText('paths-status', 'paths report downloaded');
}

// ═══════════════════════════════════════════
// RUNTIME LIMITS (target noise + AI budget)
// ═══════════════════════════════════════════
async function loadLimits() {
  const [noise, budget] = await Promise.all([
    api('/api/noise/status'),
    api('/api/source/ai/budget'),
  ]);
  if (noise && !noise.detail) {
    setText('noise-chip', `noise: ${noise.profile} · ${noise.rps || 0} req/s`);
    const stats = $('noise-stats');
    if (stats) {
      const lines = [
        `profile: ${noise.profile} (${noise.source || 'env'})`,
        `rps: ${noise.rps} · burst: ${noise.burst} · in-flight: ${noise.max_in_flight} · jitter: ${noise.jitter_ms}ms`,
      ];
      (noise.hosts || []).forEach(h => {
        lines.push(`${h.host}: ${h.requests} req · ${h.in_flight} in flight · ${h.blocked} backoffs${h.blocked_for_s ? ` · blocked ${h.blocked_for_s}s` : ''}`);
      });
      stats.textContent = lines.join('\n');
    }
    const select = $('noise-profile');
    if (select) select.value = noise.profile;
    await loadNoiseGuidance();
  }
  if (budget && !budget.detail) {
    const scopes = Object.entries(budget.scopes || {});
    const totalTokens = scopes.reduce((n, [, v]) => n + (v.tokens || 0), 0);
    const totalCalls = scopes.reduce((n, [, v]) => n + (v.calls || 0), 0);
    setText(
      'ai-budget-chip',
      budget.max_tokens || budget.max_calls
        ? `${totalCalls}/${budget.max_calls || '∞'} calls · ${totalTokens}/${budget.max_tokens || '∞'} tokens`
        : `unlimited · ${totalCalls} calls / ${totalTokens} tokens used`
    );
    const stats = $('ai-budget-stats');
    if (stats) stats.textContent = pretty(budget);
  }
}

async function loadNoiseGuidance() {
  const tool = $('noise-tool')?.value || 'nmap';
  const res = await api(`/api/noise/guidance?tool=${encodeURIComponent(tool)}`);
  const el = $('noise-guidance');
  if (el) {
    el.textContent = res?.detail
      ? res.detail
      : `profile ${res.profile} · ${res.tool}\n${res.flags || '(no tool-specific flags)'}\n${res.note || ''}`;
  }
}

async function setNoiseProfile() {
  const profile = $('noise-profile')?.value || 'off';
  const res = await api('/api/noise/profile', { method: 'POST', body: { profile } });
  setText('noise-chip', res?.detail || `noise: ${res.profile}`);
  announce(res?.detail ? `Noise profile failed: ${res.detail}` : `Noise profile: ${res.profile}`, !!res?.detail);
  await loadLimits();
}

async function resetAiBudget() {
  const res = await api('/api/source/ai/budget/reset', { method: 'POST', body: {} });
  setText('ai-budget-chip', res?.detail || 'budget reset');
  announce('AI budget reset');
  await loadLimits();
}

// ═══════════════════════════════════════════
// APPROVAL GATE
// ═══════════════════════════════════════════
async function loadApprovals() {
  const [status, rules, requests, decisions] = await Promise.all([
    api('/api/approvals/status'),
    api('/api/approvals/rules'),
    api('/api/approvals/requests?status=pending&limit=50'),
    api('/api/approvals/decisions?limit=20'),
  ]);
  if (status && !status.detail) {
    setText('appr-mode', `mode: ${status.mode} · ${status.rules || 0} rules · ${status.pending || 0} pending`);
  }
  renderApprovalRules(rules?.rules || []);
  renderApprovalRequests(requests?.requests || []);
  const audit = $('appr-decisions');
  if (audit) {
    const rows = decisions?.decisions || [];
    audit.textContent = rows.length
      ? rows.map(d => `${d.created_at} · ${d.action} · ${d.decided_by} · ${d.tool} ${ (d.argv || []).join(' ') }${d.reason ? ' — ' + d.reason : ''}`).join('\n')
      : 'No decisions recorded yet.';
  }
}

function renderApprovalRules(rows) {
  const body = $('appr-rules-tbody');
  if (body) {
    body.innerHTML = rows.map(r => `
      <tr>
        <td>${escHtml(r.name)}</td>
        <td><code>${escHtml(r.match_type)}</code></td>
        <td><code>${escHtml(Array.isArray(r.pattern) ? JSON.stringify(r.pattern) : r.pattern)}</code></td>
        <td><span class="v-sev ${r.action === 'deny' ? 'critical' : r.action === 'ask' ? 'medium' : 'low'}">${escHtml(r.action)}</span></td>
        <td>${r.priority}</td>
        <td><button class="btn btn-secondary btn-sm" data-appr-del="${escAttr(r.id)}">Delete</button></td>
      </tr>`).join('');
  }
  const empty = $('appr-rules-empty');
  if (empty) empty.style.display = rows.length ? 'none' : 'block';
}

function renderApprovalRequests(rows) {
  const body = $('appr-requests-tbody');
  if (body) {
    body.innerHTML = rows.map(r => `
      <tr>
        <td><code>${escHtml(r.id)}</code></td>
        <td>${escHtml(r.tool)}</td>
        <td title="${escAttr((r.argv || []).join(' '))}"><code>${escHtml((r.argv || []).join(' ').slice(0, 90))}</code></td>
        <td>${escHtml((r.created_at || '').replace('T', ' ').slice(11, 19))}</td>
        <td>
          <button class="btn btn-primary btn-sm" data-appr-approve="${escAttr(r.id)}">Approve</button>
          <button class="btn btn-danger btn-sm" data-appr-deny="${escAttr(r.id)}">Deny</button>
        </td>
      </tr>`).join('');
  }
  const empty = $('appr-requests-empty');
  if (empty) empty.style.display = rows.length ? 'none' : 'block';
}

async function addApprovalRule() {
  const name = ($('appr-name')?.value || '').trim();
  const patternText = ($('appr-pattern')?.value || '').trim();
  const matchType = $('appr-match')?.value || 'string';
  if (!name || !patternText) { setText('appr-output', 'rule name and pattern required'); return; }
  let pattern = patternText;
  if (matchType === 'argv_prefix') {
    try { pattern = JSON.parse(patternText); }
    catch { setText('appr-output', 'argv prefix must be a JSON array, e.g. ["hydra"]'); return; }
  }
  const res = await api('/api/approvals/rules', {
    method: 'POST',
    body: {
      name, pattern, match_type: matchType,
      action: $('appr-action')?.value || 'ask',
      priority: parseInt($('appr-priority')?.value || '100', 10) || 100,
    },
  });
  setText('appr-output', res?.detail || `rule ${res.name || ''} saved`);
  announce(res?.detail ? `Rule failed: ${res.detail}` : 'Approval rule saved', !!res?.detail);
  await loadApprovals();
}

async function deleteApprovalRule(id) {
  const res = await api(`/api/approvals/rules/${encodeURIComponent(id)}`, { method: 'DELETE' });
  setText('appr-output', res?.detail || 'rule deleted');
  await loadApprovals();
}

async function decideApproval(id, action) {
  const res = await api(`/api/approvals/requests/${encodeURIComponent(id)}/${action}`, {
    method: 'POST', body: { note: `${action} from UI` },
  });
  setText('appr-output', res?.detail || `${id} ${action}d`);
  announce(`Approval request ${id} ${action}d`, action === 'deny');
  await loadApprovals();
}

async function checkApprovalPolicy() {
  const raw = ($('appr-check-argv')?.value || '').trim();
  if (!raw) { setText('appr-output', 'enter a command to check'); return; }
  const argv = raw.split(/\s+/);
  const res = await api('/api/approvals/check', { method: 'POST', body: { argv } });
  setText('appr-output', pretty(res));
  announce(`Policy check: ${res.action || res.detail || 'done'}`, res.action === 'ask' || res.action === 'deny');
}

// ═══════════════════════════════════════════
// FINDING LEDGER (evidence + retest)
// ═══════════════════════════════════════════
function findingOutput(data, label = '') {
  const el = $('fl-output');
  if (!el) return;
  el.textContent = (label ? label + '\n' : '') + pretty(data);
}

async function loadFindings() {
  try {
    const data = await api('/api/findings?limit=200');
    if (!data || data.detail) {
      setText('fl-summary', data?.detail || 'ledger unavailable');
      return;
    }
    state.findings = data.findings || [];
    renderFindings(data);
  } catch (e) {
    setText('fl-summary', 'ledger unavailable');
    findingOutput({ error: e.message }, 'finding ledger');
  }
}

function renderFindings(data) {
  const rows = data.findings || [];
  const summary = data.summary || {};
  setText('fl-summary', `${summary.findings || 0} findings · ${summary.verified || 0} verified · ${summary.evidence || 0} evidence`);

  const body = $('fl-tbody');
  if (body) {
    body.innerHTML = rows.map(f => {
      const sev = sevClass(f.severity);
      return `
        <tr>
          <td><span class="v-sev ${sev}">${escHtml(f.severity)}</span></td>
          <td><code>${escHtml(f.id)}</code> ${escHtml(f.title)}</td>
          <td>${escHtml(f.status)}</td>
          <td>${f.evidence_count || 0}</td>
          <td>${f.verified ? '✅' : '—'}</td>
          <td>${escHtml(f.last_verdict || '—')}</td>
          <td><button class="btn btn-secondary btn-sm" data-fl-pick="${escAttr(f.id)}">Select</button></td>
        </tr>`;
    }).join('');
  }
  const empty = $('fl-empty');
  if (empty) empty.style.display = rows.length ? 'none' : 'block';

  const select = $('fl-select');
  if (select) {
    const previous = select.value;
    select.innerHTML = rows.map(f =>
      `<option value="${escAttr(f.id)}">${escHtml(f.id)} · ${escHtml(f.title)}</option>`
    ).join('');
    if (rows.some(f => f.id === previous)) select.value = previous;
  }
}

function findingTarget() {
  const select = $('fl-select');
  const id = select?.value || '';
  return state.findings.find(f => f.id === id) || null;
}

async function createFinding() {
  const title = ($('fl-title')?.value || '').trim();
  if (!title) {
    setText('fl-status', 'title required');
    announce('Finding needs a title', true);
    return;
  }
  const portRaw = ($('fl-port')?.value || '').trim();
  const body = {
    title,
    severity: $('fl-severity')?.value || 'info',
    source: ($('fl-source')?.value || 'manual').trim() || 'manual',
    host: ($('fl-host')?.value || '').trim(),
    port: portRaw ? parseInt(portRaw, 10) : null,
    description: ($('fl-description')?.value || '').trim(),
  };
  const res = await api('/api/findings', { method: 'POST', body });
  if (!res || res.detail) {
    setText('fl-status', res?.detail || 'create failed');
    findingOutput(res, 'create finding');
    announce(`Finding create failed: ${res?.detail || 'unknown'}`, true);
    return;
  }
  setText('fl-status', `created ${res.id}`);
  findingOutput(res, 'finding created');
  announce(`Finding ${res.id} created`);
  const titleEl = $('fl-title');
  if (titleEl) titleEl.value = '';
  const descEl = $('fl-description');
  if (descEl) descEl.value = '';
  await loadFindings();
  const select = $('fl-select');
  if (select) select.value = res.id;
}

async function attachFindingEvidence() {
  const finding = findingTarget();
  if (!finding) {
    setText('fl-status', 'select a finding first');
    announce('Select a finding before attaching evidence', true);
    return;
  }
  const content = ($('fl-evidence-text')?.value || '').trim();
  if (!content) {
    setText('fl-status', 'evidence content required');
    announce('Evidence content is empty', true);
    return;
  }
  const res = await api(`/api/findings/${encodeURIComponent(finding.id)}/evidence`, {
    method: 'POST',
    body: {
      kind: $('fl-evidence-kind')?.value || 'note',
      label: ($('fl-evidence-label')?.value || '').trim(),
      content,
      captured_by: 'operator',
    },
  });
  if (!res || res.detail) {
    setText('fl-status', res?.detail || 'attach failed');
    findingOutput(res, 'attach evidence');
    announce(`Evidence attach failed: ${res?.detail || 'unknown'}`, true);
    return;
  }
  setText('fl-status', `attached ${res.id} sha256 ${String(res.sha256 || '').slice(0, 12)}…`);
  findingOutput(res, 'evidence attached');
  const textEl = $('fl-evidence-text');
  if (textEl) textEl.value = '';
  announce('Evidence attached');
  await loadFindings();
  const select = $('fl-select');
  if (select) select.value = finding.id;
}

async function recordFindingRetest() {
  const finding = findingTarget();
  if (!finding) {
    setText('fl-status', 'select a finding first');
    announce('Select a finding before recording a retest', true);
    return;
  }
  const summary = ($('fl-retest-summary')?.value || '').trim();
  if (!summary) {
    setText('fl-status', 'retest summary required');
    announce('Retest summary is empty', true);
    return;
  }
  const detail = await api(`/api/findings/${encodeURIComponent(finding.id)}`);
  const existing = (detail.evidence || []).map(e => e.id);
  const inline = ($('fl-retest-evidence')?.value || '').trim();
  const body = {
    verdict: $('fl-verdict')?.value || 'inconclusive',
    summary,
    evidence_ids: existing,
  };
  if (inline) body.inline_evidence = inline;
  if (!existing.length && !inline) {
    setText('fl-status', 'attach evidence (or paste inline evidence) first');
    announce('A retest must cite evidence', true);
    return;
  }
  const res = await api(`/api/findings/${encodeURIComponent(finding.id)}/retest`, {
    method: 'POST',
    body,
  });
  if (!res || res.detail) {
    setText('fl-status', res?.detail || 'retest failed');
    findingOutput(res, 'retest');
    announce(`Retest failed: ${res?.detail || 'unknown'}`, true);
    return;
  }
  setText('fl-status', `${res.verdict} · finding is ${res.finding_status}`);
  findingOutput(res, 'retest recorded');
  announce(`Retest recorded: ${res.verdict}`);
  const summaryEl = $('fl-retest-summary');
  if (summaryEl) summaryEl.value = '';
  const inlineEl = $('fl-retest-evidence');
  if (inlineEl) inlineEl.value = '';
  await loadFindings();
  const select = $('fl-select');
  if (select) select.value = finding.id;
}

async function downloadFindingsReport() {
  try {
    const res = await api('/api/findings/report?fmt=md');
    if (!res || typeof res.content !== 'string') {
      setText('fl-status', res?.detail || 'report unavailable');
      return;
    }
    const blob = new Blob([res.content], { type: 'text/markdown' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'h4k-finding-ledger.md';
    a.click();
    URL.revokeObjectURL(a.href);
    setText('fl-status', 'ledger downloaded');
    announce('Finding ledger downloaded');
  } catch (e) {
    setText('fl-status', 'download failed: ' + e.message);
  }
}

function pickFinding(id) {
  const select = $('fl-select');
  if (select) select.value = id;
  const finding = findingTarget();
  if (finding) {
    setText('fl-status', `${finding.id} selected · ${finding.severity} · ${finding.status}`);
    announce(`Selected finding ${finding.id}`);
  }
}

async function loadPropagationPlan() {
  const card = $('propagation-card');
  const body = $('prop-body');
  if (!card || !body) return;
  card.hidden = false;
  try {
    const s = await api('/api/session');
    const engId = s.scope?.engagement_id;
    if (!engId) {
      body.innerHTML = 'No active engagement scope — set one in the header first.';
      $('btn-propagate-run').hidden = true;
      return;
    }
    const plan = await api(`/api/engagement/${engId}/propagate/plan`);
    const pairs = (plan.pairs || []);
    state.propEngagementId = engId;
    state.propPairs = pairs;
    $('btn-propagate-run').hidden = pairs.length === 0;
    $('prop-results').hidden = true;
    state.propPlan = plan;
    const pairsRender = pairs.slice(0, 40).map(p => `
        <div style="margin-left:14px;">→ <b>${escHtml(p.user || '')}:${escHtml(p.password || '')}</b>
          ⇒ ${escHtml(p.host || '?')}:${escHtml(String(p.port ?? '?'))} (${escHtml(p.service || '?')})
          via ${escHtml(p.module || 'login module')}</div>`).join('');
    body.innerHTML = `
      <div style="margin-bottom:10px;">
        <strong>${plan.credentials ?? 0}</strong> verified credential(s),
        <strong>${plan.targets ?? 0}</strong> candidate service target(s),
        <strong>${plan.attempts ?? 0}</strong> login pairs${plan.capped ? ` (capped at ${plan.max_attempts})` : ''}
      </div>
      ${pairsRender}
      ${pairs.length ? '<div style="color:var(--text-muted);margin-top:6px;">▶ Execute replays each pair once and records the attempt ledger.</div>' : ''}
    `;
  } catch (e) {
    body.textContent = 'Plan failed: ' + e.message;
  }
  card.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

async function executePropagation() {
  const engId = state.propEngagementId;
  if (!engId) return;
  const btn = $('btn-propagate-run');
  const out = $('prop-results');
  if (btn) { btn.disabled = true; }
  if (out) { out.hidden = false; out.innerHTML = '<p class="t-line">replaying verified credentials... (this logs in for real)</p>'; }
  try {
    const res = await api(`/api/engagement/${engId}/propagate`, { method: 'POST', body: { open_sessions: false } });
    if (out) {
      const reached = res.reached || [];
      const attempted = res.attempted || res.pairs || [];
      let html = `<p class="t-line">done — <b>${reached.length}</b> successful login(s), <b>${attempted.length - reached.length}</b> failed:</p>`;
      attempted.forEach(a => {
        html += `<p class="t-line ${a.verified ? 'success' : ''}">${a.verified ? '[!!!] ' : '[-] '}${escHtml(a.user)} → ${escHtml(a.host)}:${escHtml(String(a.port))} (${escHtml(a.service)})</p>`;
      });
      out.innerHTML = html;
    }
    log(`Propagation run: ${(res.reached || []).length} of ${(res.attempted || []).length} pairs verified`, 'info');
    refreshSessionBadge();
    loadPropagationPlan();
  } catch (e) {
    if (out) out.innerHTML = `<p class="t-line error">propagation failed: ${escHtml(e.message)}</p>`;
    log('Propagation failed: ' + e.message, 'error');
  } finally {
    if (btn) btn.disabled = false;
  }
}

// ---- autopilot ----

let apPollTimer = null;
let apLineCount = 0;

async function startAutopilot() {
  const btn = $('btn-ap-start');
  btn.disabled = true;
  try {
    const res = await api('/api/autopilot/start', { method: 'POST' });
    if (res.job_id) {
      log('AUTOPILOT engaged', 'warn');
      logXp(5, '(autopilot start)');
      $('btn-ap-stop').hidden = false;
      if (apPollTimer) clearInterval(apPollTimer);
      apLineCount = 0;
      $('ap-log').innerHTML = '';
      apPollTimer = setInterval(pollAutopilot, 2000);
      pollAutopilot();
    } else {
      log('Autopilot refused: ' + (res.detail || JSON.stringify(res)), 'error');
      btn.disabled = false;
    }
  } catch (e) {
    log('Autopilot start failed: ' + e.message, 'error');
    btn.disabled = false;
  }
}

async function stopAutopilot() {
  $('btn-ap-stop').hidden = true;
  try {
    await api('/api/autopilot/stop', { method: 'POST' });
    log('Autopilot stop requested', 'warn');
  } catch (e) { log('Stop failed: ' + e.message, 'error'); }
}

async function pollAutopilot() {
  try {
    const job = await api('/api/autopilot/status');
    if (job.status === 'idle') { $('ap-status-chip').textContent = 'idle'; return; }
    $('ap-status-chip').textContent = job.stage || job.status;
    $('ap-progress').style.width = (job.progress || 0) + '%';
    setProgress($('ap-progress'), job.progress || 0);
    $('ap-pct').textContent = Math.round(job.progress || 0) + '%';

    const logs = job.log || [];
    const logEl = $('ap-log');
    for (let i = apLineCount; i < logs.length; i++) {
      const p = document.createElement('p');
      p.className = 't-line';
      if (logs[i].includes('[!!!]') || logs[i].includes('pwned')) p.className += ' success';
      else if (logs[i].includes('[!]')) p.className += ' warn';
      else if (logs[i].includes('[-]')) p.className += ' error';
      p.textContent = logs[i];
      logEl.appendChild(p);
    }
    apLineCount = logs.length;
    logEl.scrollTop = logEl.scrollHeight;

    const hosts = job.hosts || {};
    const tbody = $('ap-tbody');
    if (tbody) {
      tbody.innerHTML = Object.entries(hosts).map(([ip, h]) => `
        <tr>
          <td class="fp-ip">${escHtml(ip)}</td>
          <td>${escHtml(String(h.stage || ''))}${h.session_id ? ' 💀' : ''}${h.session_id ? `<button class="btn btn-secondary btn-sm ap-console-btn" data-ssid="${escHtml(h.session_id)}" data-shost="${escHtml(ip)}" title="Open session console">🖥</button>` : ''}</td>
          <td>${escHtml((h.services || []).map(s => s.port + (s.service ? ' ' + s.service : '')).join(', '))}</td>
          <td>${(h.vulns || []).length ? '⚠ ' + escHtml(h.vulns.join(', ')) : ''}</td>
          <td>${escHtml(h.creds || '')}</td>
        </tr>`).join('');
    }

    if (job.status !== 'running') {
      clearInterval(apPollTimer);
      apPollTimer = null;
      $('btn-ap-start').disabled = false;
      $('btn-ap-stop').hidden = true;
      const summary = $('ap-summary');
      if (summary) summary.hidden = false;
      const entries = Object.values(hosts);
      $('ap-chip-hosts').textContent = `${Object.keys(hosts).length} hosts`;
      $('ap-chip-vulns').textContent = `${entries.filter(h => (h.vulns || []).length).length} with vulns`;
      $('ap-chip-creds').textContent = `${(job.message.match(/(\d+) cred/) || [0, 0])[1]} creds`;
      $('ap-chip-sessions').textContent = `${(job.message.match(/(\d+) session/) || [0, 0])[1]} sessions`;
      refreshSessionBadge();
      if (job.status === 'done') {
        log('Autopilot complete: ' + job.message, 'success');
        glitchEffect();
      } else {
        log('Autopilot stopped: ' + job.message, 'warn');
      }
    }
  } catch (e) {
    clearInterval(apPollTimer);
    apPollTimer = null;
    $('btn-ap-start').disabled = false;
    log('Autopilot poll failed: ' + e.message, 'error');
  }
}

function renderPaFound(creds) {
  const wrap = $('pa-found');
  const list = $('pa-found-list');
  if (!wrap || !list) return;
  wrap.hidden = false;
  list.innerHTML = creds.map(c => `
    <div class="pa-cred">
      <span class="fp-ip">${escHtml(c.host)}:${escHtml(c.port)}</span>
      <span class="pa-user">${escHtml(c.user)}</span> :
      <span class="pa-pass">${escHtml(c.password)}</span>
      <span class="pa-svc">${escHtml(c.service)}</span>
    </div>
  `).join('');
}

// ---- Default-Cred Targets card ----

async function loadCredTargets() {
  try {
    const res = await api('/api/passattack/targets');
    renderCredTargets(res.targets || []);
  } catch (e) { log('Cred targets load failed: ' + e.message, 'error'); }
}

function renderCredTargets(targets) {
  const tbody = $('cred-targets-tbody');
  const empty = $('cred-targets-empty');
  const chip = $('cred-targets-count');
  if (!tbody) return;

  empty.hidden = targets.length > 0;
  if (chip) chip.textContent = `${targets.length} targets`;
  if (targets.length === 0) return;

  state.credTargets = targets;
  tbody.innerHTML = targets.map((t, i) => `
    <tr>
      <td class="fp-ip">${escHtml(t.ip)}</td>
      <td class="fp-port">${escHtml(String(t.port))}</td>
      <td>${escHtml(t.service)}</td>
      <td>${escHtml(t.product || '')}</td>
      <td>${escHtml(t.attack_service)}</td>
      <td>${t.creds_found ? '<span class="v-sev low">creds ✓</span>' : `<button class="btn btn-danger cred-target-btn" data-index="${i}" title="Open password attack">🔑</button>`}</td>
      <td>${t.attack_service === 'http-basic' ? `<button class="btn btn-secondary webprobe-btn" data-index="${i}" title="HTTP recon probe">🔍</button>` : ''}</td>
      <td><button class="btn btn-secondary recheck-btn" data-index="${i}" data-ip="${escHtml(t.ip)}" title="Re-fingerprint this host">↻</button></td>
    </tr>`).join('');
}

async function recheckHost(ip) {
  try {
    const res = await api('/api/neighbors/fingerprint', { method: 'POST', body: { ip } });
    if (res.job_id) {
      log(`Re-fingerprinting ${ip}...`, 'info');
      const poll = setInterval(async () => {
        const j = await api(`/api/neighbors/fingerprint/status/${res.job_id}`);
        if (j.status === 'done' || j.status === 'error') {
          clearInterval(poll);
          const open = (j.results || []).reduce((n, r) => n + (r.services || []).filter(s => s.state === 'open').length, 0);
          log(`${ip} rechecked — ${open} open service(s) now`, 'info');
          loadCredTargets();
          loadGraph();
        }
      }, 3000);
    }
  } catch (e) { log(`Recheck ${ip} failed: ` + e.message, 'error'); }
}

async function launchWebProbe(idx) {
  const t = (state.credTargets || [])[idx];
  if (!t) return;
  try {
    const res = await api('/api/webprobe', {
      method: 'POST',
      body: { host: t.ip, port: t.port, tls: t.port === 443 || t.port === 8443 }
    });
    log(`Probe ${t.ip}:${t.port} — server: ${res.server || '?'} | title: ${res.title || '?'} | hit endpoints: ${res.paths.map(p => p.path).join(', ') || 'none'}`, 'info');
    // stash for the password attack card (webapp context)
    state.webProbe = { ...t, ...res };
    const sel = $('pa-service');
    if (sel) openPassAttackCard(t.ip, t.port, t.attack_service);
    const out = $('pa-output');
    if (out) {
      out.hidden = false;
      appendPaOutput(`probe ${t.ip}:${t.port}: ${res.server || '?'} | "${res.title || 'no title'}"`);
      (res.paths || []).forEach(p => appendPaOutput(`  ${p.status} ${p.path}`));
    }
  } catch (e) { log(`Probe failed for ${t.ip}:${t.port}: ` + e.message, 'error'); }
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
  if (!el) return;
  appendTermLine(el, text);
}

// shared terminal line appender: [module] x lines clickable to switch module
function appendTermLine(el, text) {
  if (!el) return;
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
  const fullBtn = $('btn-full-scan');
  if (fullBtn) { fullBtn.disabled = false; fullBtn.classList.remove('loading'); }
  // same class of fix: a job id must only complete once even if a stale
  // poller still holds its handle
  state.fingerprintDone = state.fingerprintDone || new Set();
  if (state.fingerprintDone.has(job.id)) return;
  state.fingerprintDone.add(job.id);
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
  if (fillEl) { fillEl.style.width = '100%'; setProgress(fillEl, 100); }
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
  loadCredTargets();
  renderOverview();
  // authoritative refresh: persisted vulns (covers earlier runs)
  api('/api/neighbors/vulns').then(res => {
    const rows = (res.vulns || []).map(v => ({ services: [{ port: v.port, proto: v.proto, vulns: [v] }], ip: v.ip }));
    renderVulnPanel(rows);
  }).catch(() => {});
}

async function resolveScanTarget() {
  // stale UI state first, then derive from the session store (graph nodes)
  if (state.discoveredTarget) return state.discoveredTarget;
  try {
    const g = await api('/api/graph');
    const ips = (g.nodes || [])
      .filter(n => n.type === 'host' && /^\d+\.\d+\.\d+\.\d+$/.test(n.id))
      .map(n => n.id);
    if (ips.length) {
      const cidrs = [...new Set(ips.map(ip => ip.split('.').slice(0, 3).join('.') + '.0/24'))];
      return cidrs.join(',');
    }
  } catch { /* fall through */ }
  return null;
}

async function startFullScan() {
  const btn = $('btn-full-scan');
  if (btn) { btn.disabled = true; btn.classList.add('loading'); }
  log('Starting full-port fingerprint...', 'info');
  logXp(5, '(recon started)');
  try {
    const res = await api('/api/neighbors/fingerprint', {
      method: 'POST',
      body: { full: true },
    });
    if (res.job_id) {
      state.fingerprintJobId = res.job_id;
      log(`Full port scan job ${res.job_id} started`, 'info');
      startFingerprintPolling();
    } else {
      log('Full port scan failed: ' + JSON.stringify(res), 'error');
      if (btn) { btn.disabled = false; btn.classList.remove('loading'); }
    }
  } catch (e) {
    log('Full port scan error: ' + e.message, 'error');
    if (btn) { btn.disabled = false; btn.classList.remove('loading'); }
  }
}

async function pollScanProgress() {
  if (!scanJobId) return;
  try {
    const res = await api(`/api/jobs/${scanJobId}`);
    updateScanProgressFromJob(res);
    if (['done', 'completed', 'error', 'failed'].includes(res.status)) {
      clearInterval(pollInterval);
      onScanComplete(res);
    }
  } catch (e) { log('Poll error: ' + e.message, 'error'); }
}

function updateScanProgress(data) {
  $('sp-pct').textContent = data.pct + '%';
  $('sp-fill').style.width = data.pct + '%';
  setProgress($('sp-fill'), data.pct);
  $('sp-status').textContent = data.status || '';

  const stages = ['recon', 'fingerprint', 'scan', 'creds', 'attack'];
  const stageEl = $('sp-stages');
  if (stageEl) {
    stageEl.innerHTML = stages.map(s => {
      const cls = s === data.stage ? 'active' : (data.pct > stages.indexOf(s) * 20 ? 'done' : '');
      return `<span class="scan-stage ${cls}">${s}</span>`;
    }).join('');
  }
}

function updateScanProgressFromJob(job) {
  const stageMap = { running: 'scan', completed: 'attack', failed: 'scan' };
  const stage = job.current_module ? job.current_module.split('/').pop().split('_')[0] : 'scan';
  const pct = job.progress || 0;
  updateScanProgress({
    stage,
    pct,
    status: job.cached ? `${job.status} · cached` : job.status,
  });

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
      log('scan report ready — refreshing assets');
      loadCredTargets();
      loadGraph();
    }
  } catch (e) { log('Failed to fetch report: ' + e.message, 'error'); }
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



// ═══════════════════════════════════════════
// VIM NAVIGATION
// ═══════════════════════════════════════════
function vimNavigate(dir) {
  const phases = ['assets', 'walk', 'fuzz', 'report'];
  const idx = phases.indexOf(state.currentPhase);
  if (dir === 'j' && idx < phases.length - 1) setPhase(phases[idx + 1]);
  if (dir === 'k' && idx > 0) setPhase(phases[idx - 1]);
  if (dir === 'h') setPhase(phases[Math.max(0, idx - 1)]);
  if (dir === 'l') setPhase(phases[Math.min(phases.length - 1, idx + 1)]);
}

// ═══════════════════════════════════════════
// INIT
// ═══════════════════════════════════════════

// ═══════════════════════════════════════════
// ACTION PANEL (asset-centric console)
// ═══════════════════════════════════════════

function restoreDefaultPanel() {
  if (!state.defaultPanelHtml) saveDefaultPanel();
  const body = $('ap-body');
  // unconditional: the caller may have already set panelMode='default'
  if (body) body.innerHTML = state.defaultPanelHtml;
  state.panelMode = 'default';
  state.selectedAsset = null;
  state.selectedVulnRow = null;
  bindPanelTabs();
}

function saveDefaultPanel() {
  state.defaultPanelHtml = ($('ap-body') || {}).innerHTML || '';
}

function bindPanelTabs() {
  document.querySelectorAll('.ap-tab').forEach(t => {
    t.classList.toggle('active', t.dataset.aptab === (state.panelTab || 'map'));
  });
  ['pane-map', 'pane-vulns', 'pane-creds'].forEach(id => {
    const el = $(id);
    if (el) el.hidden = id !== 'pane-' + (state.panelTab || 'map');
  });
}

function switchPanelTab(tab) {
  if (state.panelMode !== 'default') { restoreDefaultPanel(); }
  state.panelTab = tab;
  bindPanelTabs();
  if (tab === 'vulns') { loadCveStatus(); }
  if (tab === 'creds') { loadCredTargets(); }
}

function renderActionPanel(kind, data) {
  state.panelMode = kind;
  state.selectedAsset = { kind, ...data };
  const body = $('ap-body');
  if (!body) return;
  if (kind === 'default') { restoreDefaultPanel(); return; }

  if (kind === 'host') {
    $('ap-title').innerHTML = `🖥 Host — ${escHtml(data.ip)} ${BACK_BTN}`;
    body.innerHTML = hostPanelHtml(data);
  } else if (kind === 'service') {
    $('ap-title').innerHTML = `🧩 ${escHtml(data.ip)}:${escHtml(String(data.port))} (${escHtml(data.service || '?')}) ${BACK_BTN}`;
    body.innerHTML = servicePanelHtml(data);
  } else if (kind === 'vuln') {
    $('ap-title').innerHTML = `⚠ ${escHtml(data.vid)} — ${escHtml(data.ip)}:${escHtml(String(data.port))} ${BACK_BTN}`;
    body.innerHTML = vulnPanelHtml(data);
  } else if (kind === 'cred') {
    $('ap-title').innerHTML = `🔑 ${escHtml(data.label || data.id)} ${BACK_BTN}`;
    body.innerHTML = credPanelHtml(data);
  }
  bindPanelTabs();
}

function hostPanelHtml(h) {
  const vulns = h.vulns || [];
  const svcs = h.services || [];
  return `
  <div class="graph-detail-row"><span class="graph-detail-label">Address</span><span class="graph-detail-value graph-id" id="ph-ip">${escHtml(h.ip)}</span></div>
  <div class="graph-detail-row"><span class="graph-detail-label">OS</span><span class="graph-detail-value">${escHtml(h.os || 'unknown')}</span></div>
  <div class="graph-detail-row"><span class="graph-detail-label">Vendor</span><span class="graph-detail-value">${escHtml(h.vendor || h.hostname || '—')}</span></div>
  <div class="graph-detail-row"><span class="graph-detail-label">Status</span><span class="graph-detail-value">${h.has_session ? '💀 session open' : h.vuln_count ? '⚠ ' + h.vuln_count + ' findings' : '—'}</span></div>
  ${h.has_session ? `<div class="ex-actions"><button class="btn btn-secondary" id="btn-host-console">🖥 Open Session Console</button></div>` : ''}
  <h3 style="font-size:13px;margin:12px 0 4px;">Services</h3>
  <div class="host-services">
    ${svcs.map(s => `
      <div class="host-svc-row" data-hsvc="${escHtml(s.port + '/' + (s.proto || 'tcp'))}">
        <span class="fp-port">${escHtml(s.port + '/' + (s.proto || 'tcp'))}</span>
        <span>${escHtml(s.service || '?')} ${escHtml(s.product || '')} ${escHtml(s.version || '')}</span>
        <button class="btn btn-secondary btn-sm webprobe-btn" data-ip="${escHtml(h.ip)}" data-port="${escHtml(String(s.port))}" title="HTTP probe">🔍</button>
        <button class="btn btn-danger btn-sm cred-target-btn" data-ip="${escHtml(h.ip)}" data-port="${escHtml(String(s.port))}" data-svc="${escHtml(s.attack_service || (s.service || '').startsWith('http') ? 'http-basic' : (s.service || 'ssh'))}" title="Password attack">🔑</button>
      </div>`).join('') || '<p class="placeholder">no open services</p>'}
  </div>
  ${vulns.length ? `<h3 style="font-size:13px;margin:12px 0 4px;">Findings</h3>
    <div>${vulns.map(v => `<span class="v-sev ${sevClass(v.detail)}">${escHtml(v.vid || v)}</span>`).join(' ')}</div>
    <div class="ex-actions">
      <button class="btn btn-danger" id="btn-host-exploit">⚔ Exploit Setup — first finding</button>
    </div>` : ''}
  <div class="ex-actions">
    <button class="btn btn-secondary btn-sm recheck-btn" data-ip="${escHtml(h.ip)}" title="Re-fingerprint this host">↻ Re-fingerprint host</button>
    <button class="btn btn-secondary btn-sm deep-btn" data-ip="${escHtml(h.ip)}">⚔️ Deep attack (toolkit)</button>
  </div>`;
}

function servicePanelHtml(s) {
  return `
  <div class="graph-detail-row"><span class="graph-detail-label">Endpoint</span><span class="graph-detail-value graph-id" id="ph-ip">${escHtml(s.ip)}, port ${escHtml(String(s.port))}/${escHtml(s.proto || 'tcp')}</span></div>
  <div class="graph-detail-row"><span class="graph-detail-label">Service</span><span class="graph-detail-value">${escHtml(s.service || '?')} ${escHtml(s.product || '')} ${escHtml(s.version || '')}</span></div>
  <div class="graph-detail-row"><span class="graph-detail-label">State</span><span class="graph-detail-value">${escHtml(s.state || 'open')}</span></div>
  <div class="ex-actions">
    ${s.attack_service ? `<button class="btn btn-danger cred-target-btn" data-ip="${escHtml(s.ip)}" data-port="${escHtml(String(s.port))}" data-svc="${escHtml(s.attack_service)}" title="Password attack">🔑 Password attack</button>` : ''}
    ${(s.service || '').includes('http') ? `<button class="btn btn-secondary webprobe-btn" data-ip="${escHtml(s.ip)}" data-port="${escHtml(String(s.port))}">🔍 HTTP probe</button>` : ''}
    <button class="btn btn-secondary recheck-btn" data-ip="${escHtml(s.ip)}">↻ Re-fingerprint host</button>
  </div>`;
}

let vulnSevClass = (d) => '';
function sevClass(d) { const k = ((d || '') + '').split(':')[0]; return ['critical','high','medium','low'].includes(k.toLowerCase()) ? k.toLowerCase() : ''; }

function vulnPanelHtml(v) {
  const msfHint = (v.detail || '').match(/msf:\s*([^\s|]+)/);
  const module = msfHint ? msfHint[1] : '';
  return `
  <div class="graph-detail-row"><span class="graph-detail-label">Finding</span><span class="graph-detail-value">${escHtml(v.vid)}</span></div>
  <div class="graph-detail-row"><span class="graph-detail-label">Target</span><span class="graph-detail-value graph-id" id="ph-ip">${escHtml(v.ip)}:${escHtml(String(v.port))}</span></div>
  <div class="graph-detail-row"><span class="graph-detail-label">Severity</span><span class="graph-detail-value"><span class="v-sev ${sevClass(v.detail)}">${escHtml((v.detail || 'INFO').split(':')[0])}</span></span></div>
  <div class="graph-detail-row"><span class="graph-detail-label">Detail</span><span class="v-detail">${escHtml((v.detail || '').split(': ').slice(1).join(': '))}</span></div>
  <div class="input-row">
    <div class="input-group grow"><label>Module</label><input type="text" id="ex-module" placeholder="exploit/…" value="${escAttr(module)}" /></div>
    <div class="input-group"><label>RHOST</label><input type="text" id="ex-rhost" value="${escAttr(v.ip)}" /></div>
    <div class="input-group"><label>RPORT</label><input type="text" id="ex-rport" value="${escAttr(String(v.port))}" /></div>
  </div>
  <div class="ex-actions">
    <button class="btn btn-danger" id="btn-launch-exploit">⚔ Launch Exploit</button>
    <button class="btn btn-secondary btn-sm deep-btn" data-ip="${escHtml(v.ip)}">⚔️ Deep attack</button>
    <span class="ex-status" id="ex-status">${module ? 'Module suggested from CVE db — confirm then launch.' : 'No msf hint — enter one or pick a heuristic.'}</span>
  </div>
  <div class="ex-output" id="ex-output" hidden></div>
  <div class="ex-console" id="ex-console" hidden>
    <div class="ex-console-head">
      <span>🖥 Session Console</span>
      <span class="fp-chip" id="ex-console-target">—</span>
    </div>
    <div class="ex-quick">
      <button class="btn btn-secondary btn-sm" data-excmd="sysinfo">sysinfo</button>
      <button class="btn btn-secondary btn-sm" data-excmd="getuid">getuid</button>
      <button class="btn btn-secondary btn-sm" data-excmd="ifconfig">ifconfig</button>
      <button class="btn btn-secondary btn-sm" data-excmd="hashdump">hashdump</button>
    </div>
    <div class="input-row">
      <div class="input-group grow">
        <label>Command</label>
        <input type="text" id="ex-cmd" placeholder="meterpreter/shell command…" />
      </div>
      <button class="btn btn-primary" id="btn-ex-cmd">Run</button>
    </div>
    <div class="ex-output visible" id="ex-console-output"></div>
  </div>`;
}

function credPanelHtml(c) {
  return `
  <div class="graph-detail-row"><span class="graph-detail-label">Credential</span><span class="graph-detail-value">${escHtml(c.label || c.id)}</span></div>
  <div class="graph-detail-row"><span class="graph-detail-label">Verified at</span><span class="graph-detail-value">${escHtml((c.hosts || []).map(x => x.host || x).join(', '))}</span></div>
  ${c.reaches ? `<div class="graph-detail-row"><span class="graph-detail-label">Also reaches</span><span class="graph-detail-value">${escHtml((c.reaches || []).join(', '))}</span></div>` : ''}
  <div class="ex-actions">
    <button class="btn btn-danger cred-target-btn" data-ip="${escHtml((c.hosts || [])[0] || '')}" data-port="${escHtml(String(c.port ?? '22'))}" data-svc="${escHtml(c.service || 'ssh')}" title="Password attack">🔑 Password attack (same family)</button>
  </div>
  <div class="pa-hint" style="margin-top:8px;">Switch to the <b>Report</b> page for the 🧬 propagation plan + execute across every in-scope service.</div>`;
}


function selectGraphNodeFromInventory(el) {
  const kind = el.dataset.kind || 'host';
  if (kind === 'service') {
    selectGraphNode('service', {
      id: el.dataset.id, port: parseInt(el.dataset.port, 10),
      proto: el.dataset.proto, service: el.dataset.service,
      state: el.dataset.state, source: el.dataset.ip,
    });
  } else if (kind === 'cred') {
    selectGraphNode('cred', {
      id: el.dataset.id, label: el.dataset.label,
      service: el.dataset.service,
    });
  } else {
    selectGraphNode('host', { id: el.dataset.id, label: el.dataset.id });
  }
  // highlight without a full re-render
  document.querySelectorAll('.tile.chip-selected, .tile-chip.chip-selected').forEach(x => x.classList.remove('chip-selected'));
  (el.closest('.tile') || el).classList.add('chip-selected');
}

// deep-attack button helper (used by panels)
async function deepAttackHost(ip) {
  log(`Deep toolkit sweep ${ip}...`, 'warn');
  try {
    const res = await api('/api/deepattack', { method: 'POST', body: { target: ip, host: ip, services: [] } });
    if (res.job_id) {
      appendTermLine($('ex-output') || $('ap-body'), `  toolkit job ${res.job_id} started — see Activity/GET /api/deepattack/${res.job_id}`);
      log(`Toolkit job ${res.job_id} launched for ${ip}`, 'info');
    }
  } catch (e) { log('Deep attack failed: ' + e.message, 'error'); }
}

// host console shortcut
async function hostOpenConsole(ip) {
  try {
    const res = await api('/api/sessions');
    const s = (res.sessions || []).find(x => x.host === ip);
    if (s) {
      setPhase('assets');
      openSessionConsole(s.msf_session_id, ip);
    } else { log(`No live session for ${ip}`, 'warn'); }
  } catch (e) { log('Sessions fetch failed: ' + e.message, 'error'); }
}

// web probe that reads panel-local buttons
launchWebProbe = async function (idx) {
  const t = (state.credTargets || [])[idx] || this._t || null;
  if (!t) return;
  try {
    const res = await api('/api/webprobe', {
      method: 'POST',
      body: { host: t.ip, port: t.port, tls: t.port === 443 || t.port === 8443 }
    });
    log(`Probe ${t.ip}:${t.port} — server: ${res.server || '?'} | title: ${res.title || '?'} | hit endpoints: ${res.paths.map(p => p.path).join(', ') || 'none'}`, 'info');
    const out = $('ex-output') || $('pa-output');
    if (out) {
      out.hidden = false;
      appendTermLine(out, `probe ${t.ip}:${t.port}: ${res.server || '?'} | "${res.title || 'no title'}"`);
      (res.paths || []).forEach(p => appendTermLine(out, `  ${p.status} ${p.path}`));
    }
  } catch (e) { log(`Probe failed for ${t.ip}:${t.port}: ` + e.message, 'error'); }
};

function acquireToggle() {
  const a = $('ap-acquire');
  if (a) {
    a.hidden = !a.hidden;
    if (!a.hidden) { (a.querySelector('#target') || {}).focus?.(); }
  }
}

document.addEventListener('DOMContentLoaded', () => {
  // Embedded in the dashboard Operations workspace: hide the console chrome
  // and show exactly one phase.
  const embedParams = new URLSearchParams(location.search);
  if (embedParams.get('embed') === '1') {
    document.body.classList.add('embed');
    const initialPhase = embedParams.get('phase') || 'fuzz';
    const embedTheme = embedParams.get('theme') || 'dark';
    // The console initialiser later forces the Assets phase; re-apply the
    // requested phase after it has finished.
    setTimeout(() => {
      document.documentElement.dataset.theme = embedTheme;
      setPhase(initialPhase);
    }, 0);
    window.addEventListener('message', (event) => {
      if (event.origin !== location.origin) return;
      if (event.data && event.data.type === 'h4k-phase') setPhase(event.data.phase);
    });
  }

  // Scope picker: which engagement's CIDRs constrain aggressive actions.
  refreshSessionBadge();
  loadScopeSelect();
  $('scope-select')?.addEventListener('change', async (e) => {
    const engId = e.target.value || null;
    try {
      const res = await api('/api/session/scope', { method: 'POST', body: { engagement_id: engId } });
      if (res.status === 'scoped') {
        log(`Scope engaged: ${res.name} — actions restricted to ${res.scope.join(', ')}`, 'warn');
        unlockAchievement('os_intel');
      } else {
        log('Scope cleared — actions unrestricted (use only on your own lab)', 'warn');
      }
      updateScopeHint();
      refreshSessionBadge();
    } catch (err) { log('Scope change failed: ' + err.message, 'error'); }
  });
  updateScopeHint();

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

  // Scan button (delegated: the action panel is re-rendered after init)
  document.addEventListener('click', (e) => {
    if (e.target.closest && e.target.closest('#btn-launch-recon')) launchScan();
  });

  // Target input enter (delegated: the panel is re-rendered)
  document.addEventListener('keydown', (e) => {
    if (e.target && e.target.id === 'target' && e.key === 'Enter' && state.scanType === 'ip') {
      launchScan();
    }
  });

  // Scan type tabs (delegated for the same reason)
  document.addEventListener('click', (e) => {
    const tab = e.target.closest && e.target.closest('.st-tab[data-type]');
    if (tab) selectScanType(tab);
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
    localStorage.setItem('h4k-sound', state.soundEnabled ? '1' : '0');
    $('sound-toggle').textContent = state.soundEnabled ? '🔊' : '🔇';
    $('sound-toggle').setAttribute('aria-pressed', state.soundEnabled ? 'true' : 'false');
    announce(`Sound ${state.soundEnabled ? 'on' : 'off'}`);
  });

  // Command palette
  $('cmd-palette-btn').addEventListener('click', () => toggleCmdPalette(true));
  $('cmd-input').addEventListener('input', e => filterPalette(e.target.value));
  $('cmd-input').addEventListener('keydown', e => {
    const items = paletteItems();
    if (e.key === 'ArrowDown') { e.preventDefault(); selectPaletteItem(_paletteIndex + 1); }
    if (e.key === 'ArrowUp') { e.preventDefault(); selectPaletteItem(_paletteIndex - 1); }
    if (e.key === 'Home') { e.preventDefault(); selectPaletteItem(0); }
    if (e.key === 'End') { e.preventDefault(); selectPaletteItem(items.length - 1); }
    if (e.key === 'Enter') {
      const first = items[_paletteIndex] || items[0];
      if (first) executeCmd(first.dataset.cmd);
    }
    if (e.key === 'Escape') toggleCmdPalette(false);
  });

  // Cmd palette item clicks
  document.querySelectorAll('.cmd-item').forEach(item => {
    item.addEventListener('click', () => executeCmd(item.dataset.cmd));
    item.addEventListener('mouseenter', () => {
      const items = paletteItems();
      selectPaletteItem(items.indexOf(item));
    });
  });

  // Keyboard shortcuts
  let gPending = false;
  let gTimer = null;
  document.addEventListener('keydown', e => {
    const tag = (e.target && e.target.tagName) || '';
    const typing = ['INPUT', 'TEXTAREA', 'SELECT'].includes(tag) || e.target?.isContentEditable;
    // Ctrl/⌘+K = command palette, from anywhere (even while typing)
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
      e.preventDefault(); toggleCmdPalette(true); return;
    }
    // Esc always closes the topmost thing, including while typing.
    if (e.key === 'Escape') {
      const dialog = $('shortcuts-dialog');
      if (dialog && dialog.open) { closeShortcuts(); return; }
      if (!$('cmd-palette')?.hidden) { toggleCmdPalette(false); return; }
      if ($('ap-acquire') && !$('ap-acquire').hidden) { $('ap-acquire').hidden = true; return; }
    }
    if (e.ctrlKey || e.metaKey || e.altKey) {
      if (e.ctrlKey && e.key === 'Enter' && state.currentPhase === 'assets') acquireToggle();
      return;
    }
    if (typing) return;

    // `g` prefix: g then a/w/f/l/d/t/n/r/s jumps to a view.
    if (gPending) {
      const dest = PHASE_KEYS[e.key.toLowerCase()];
      gPending = false;
      clearTimeout(gTimer);
      if (dest) { e.preventDefault(); setPhase(dest); }
      return;
    }
    if (e.key === 'g') {
      gPending = true;
      clearTimeout(gTimer);
      gTimer = setTimeout(() => { gPending = false; }, 1200);
      announce('Go to: a assets, w walk, f fuzz, l lab, d AD, t telemetry, n nightly, r report, s settings');
      return;
    }

    // Vim keys
    if (['j', 'k', 'h', 'l'].includes(e.key)) vimNavigate(e.key);
    // Number phases
    if (e.key >= '1' && e.key <= '9') {
      const phase = PHASES[parseInt(e.key, 10) - 1];
      if (phase) { e.preventDefault(); setPhase(phase); }
    }
    // [ / ] step views
    if (e.key === '[' || e.key === ']') {
      e.preventDefault();
      const idx = PHASES.indexOf(state.currentPhase);
      const next = (idx + (e.key === ']' ? 1 : PHASES.length - 1)) % PHASES.length;
      setPhase(PHASES[next]);
    }
    // T = theme
    if (e.key === 't') toggleTheme();
    // / = focus target
    if (e.key === '/') {
      e.preventDefault();
      setPhase('assets');
      if ($('ap-acquire')?.hidden) acquireToggle();
      setTimeout(() => $('target')?.focus(), 30);
    }
    // n = new scan
    if (e.key === 'n') { e.preventDefault(); setPhase('assets'); acquireToggle(); }
    // ? = help
    if (e.key === '?') { e.preventDefault(); openShortcuts(); }
  });

  // Keyboard activation for inventory tiles (buttons are divs for layout).
  document.addEventListener('keydown', e => {
    const tile = e.target.closest && e.target.closest('.tile, .tile-chip');
    if (!tile || !['Enter', ' '].includes(e.key)) return;
    e.preventDefault();
    selectGraphNodeFromInventory(tile);
  });

  // Roving tabindex in the host list: ArrowDown/Up move between tiles.
  document.addEventListener('keydown', e => {
    const tile = e.target.closest && e.target.closest('#inventory-grid .tile');
    if (!tile || !['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(e.key)) return;
    const tiles = Array.from(document.querySelectorAll('#inventory-grid .tile'));
    if (!tiles.length) return;
    e.preventDefault();
    let idx = tiles.indexOf(tile);
    if (e.key === 'ArrowDown') idx = Math.min(tiles.length - 1, idx + 1);
    if (e.key === 'ArrowUp') idx = Math.max(0, idx - 1);
    if (e.key === 'Home') idx = 0;
    if (e.key === 'End') idx = tiles.length - 1;
    tiles.forEach((el, i) => { el.tabIndex = i === idx ? 0 : -1; });
    tiles[idx].focus();
  });

  // Tool buttons
  // panel: acquire toggle + tabs
  $('btn-acquire')?.addEventListener('click', acquireToggle);
  document.addEventListener('click', (e) => {
    const tab = e.target.closest && e.target.closest('.ap-tab[data-aptab]');
    if (tab) switchPanelTab(tab.dataset.aptab);
  });

  // Neighbor panel action buttons (delegated since panel is built dynamically)
  document.addEventListener('click', (e) => {
    if (e.target.closest('#btn-fingerprint')) startFingerprintScan();
    if (e.target.closest('#btn-full-scan')) startFullScan();
    const exBtn = e.target.closest('.v-exploit-btn');
    if (exBtn) openExploitPanel(parseInt(exBtn.dataset.vulnIndex, 10));
    if (e.target.closest('#btn-launch-exploit')) launchExploit();
    if (e.target.closest('#btn-cve-refresh')) refreshCveDb();
    if (e.target.closest('#btn-launch-passattack')) launchPassAttack();
    const ctBtn = e.target.closest('.cred-target-btn');
    if (ctBtn) openPassAttackCard(
      ctBtn.dataset.ip || ((state.credTargets || [])[parseInt(ctBtn.dataset.index, 10)] || {}).ip,
      ctBtn.dataset.port || ((state.credTargets || [])[parseInt(ctBtn.dataset.index, 10)] || {}).port,
      ctBtn.dataset.svc || ((state.credTargets || [])[parseInt(ctBtn.dataset.index, 10)] || {}).attack_service
    );
    const probeBtn = e.target.closest('.webprobe-btn');
    if (probeBtn) {
      const t = (state.credTargets || [])[parseInt(probeBtn.dataset.index, 10)] ||
        { ip: probeBtn.dataset.ip, port: parseInt(probeBtn.dataset.port, 10) };
      launchWebProbe(t);
    }
    const recheckBtn = e.target.closest('.recheck-btn');
    if (recheckBtn) recheckHost(recheckBtn.dataset.ip);
    if (e.target.closest('#btn-fz-start')) startFuzzing();
    if (e.target.closest('#btn-fz-stop')) {
      if (fzJobId) api(`/api/fuzz/${fzJobId}/abort`).catch(() => {});
      $('btn-fz-stop').hidden = true;
    }
    const quickBtn = e.target.closest('[data-excmd]');
    if (quickBtn) runSessionCmd(quickBtn.dataset.excmd);
    if (e.target.closest('#btn-ex-cmd') || (e.target.id === 'ex-cmd' && e.key === 'Enter')) {
      const input = $('ex-cmd');
      if (input && input.value.trim()) {
        runSessionCmd(input.value.trim());
        input.value = '';
      }
    }
    if (e.target.closest('#btn-cred-targets-refresh')) { loadCredTargets(); loadCveStatus(); }
    if (e.target.closest('#btn-ap-start')) startAutopilot();
    if (e.target.closest('#btn-ap-stop')) stopAutopilot();
    const backBtn = e.target.closest('.back-to-assets');
    if (backBtn) { restoreDefaultPanel(); return; }
    if (e.target.closest('#ov-discover')) {
      e.stopPropagation?.();
      state.scanType = 'neighbors';
      launchScan();
      return;
    }
    if (e.target.closest('#ov-specific')) { restoreDefaultPanel(); $('ap-acquire').hidden = false; return; }
    if (e.target.closest('#ov-fingerprint')) { startFingerprintScan(); return; }
    if (e.target.closest('#ov-discover')) {
      e.stopPropagation?.();
      state.scanType = 'neighbors';
      launchScan();
      return;
    }
    if (e.target.closest('#overview-area') && e.target.closest('button')?.id === 'btn-fingerprint') return; // static handler covers
    const invTile = e.target.closest('.tile, .tile-chip');
    if (invTile) {
      e.stopPropagation?.();
      selectGraphNodeFromInventory(invTile);
      return;
    }
    const deepBtn = e.target.closest('.deep-btn');
    if (deepBtn) deepAttackHost(deepBtn.dataset.ip);
    if (e.target.closest('#btn-host-console')) hostOpenConsole(($('ph-ip') || {}).textContent || '');
    const apCon = e.target.closest('.ap-console-btn');
    if (apCon) {
    
      openSessionConsole(apCon.dataset.ssid, apCon.dataset.shost);
    }
    // autopilot page visit refreshes the live view
    if (e.target.closest('.nav-btn[data-phase="autopilot"]')) { if (!apPollTimer) pollAutopilot(); }
    if (e.target.closest('.nav-btn[data-phase="fuzz"]')) { $('fz-live').textContent = 'Ready.'; }
    const rpt = e.target.closest('#btn-session-report');
    if (rpt) downloadSessionReport();
    const pp = e.target.closest('#btn-propagate-plan');
    if (pp) loadPropagationPlan();
    if (e.target.closest('#btn-propagate-run')) executePropagation();
  });

  // Theme toggle
  $('theme-toggle').addEventListener('click', toggleTheme);

  // Close cmd palette on backdrop click
  $('cmd-palette').addEventListener('click', e => {
    if (e.target === $('cmd-palette')) toggleCmdPalette(false);
  });

  saveDefaultPanel();
  state.currentPhase = 'assets';
  updateXpDisplay();
  renderOverview();
  log('h4k operations center ready', 'system');
  setPhase('assets');

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
      restoreDefaultPanel();
      $('sp-strip').hidden = true;
      state.panelTab = 'map';
      bindPanelTabs();
      renderOverview();
      const tb = $('vuln-tbody'); if (tb) tb.innerHTML = '';
      const fpt = $('fp-tbody'); if (fpt) fpt.innerHTML = '';
      const nl = $('neighbors-list'); if (nl) nl.innerHTML = '';
      refreshSessionBadge();
      loadGraph();
    } catch (e) { log('Session reset failed: ' + e.message, 'error'); }
  });
});

async function refreshSessionBadge() {
  const el = $('session-badge');  // right pane badge
  if (!el) return;
  try {
    const s = await api('/api/session');
    el.textContent = `${s.session_id} · ${s.hosts}h ${s.services}s ${s.vulns}v`;
  } catch { el.textContent = 'session: unavailable'; }
}

async function loadScopeSelect() {
  const sel = $('scope-select');
  if (!sel) return;
  try {
    const res = await api('/api/engagement');
    const engs = res.engagements || [];
    const s = await api('/api/session');
    const cur = s.scope?.engagement_id || '';
    while (sel.options.length) sel.remove(0);
    const none = document.createElement('option');
    none.value = '';
    none.textContent = 'scope: none';
    sel.appendChild(none);
    engs.forEach(e => {
      const o = document.createElement('option');
      o.value = e.id;
      o.textContent = `scope: ${e.name}`;
      sel.appendChild(o);
    });
    sel.value = cur;
  } catch { /* msf down / no engagements */ }
}

function updateScopeHint() {
  const sel = $('scope-select');
  if (sel) sel.classList.toggle('scope-active', !!sel.value);
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


const BACK_BTN = '<button class="btn btn-secondary btn-sm back-to-assets" title="Back to all assets">← All assets</button>';


async function renderOverview() {
  let c = { hosts: 0, services: 0, vulns: 0, creds: 0 };
  try { c = { ...c, ...(await api('/api/session')) }; } catch { /* offline */ }
  // re-query AFTER the await: init's synchronous restore may have replaced
  // the ap-body subtree while we were in flight — a pre-await node is stale
  const area = $('overview-area');
  if (!area) return;

  let html = '<div class="ov-card">';
  if (!c.hosts) {
    html += `
      <div class="ov-title">1 · Discover what's on the network<span class="ov-now">← start here</span></div>
      <div class="ov-hint">Sweeps the local subnet for live hosts and fingerprints their open services.</div>
      <div class="ex-actions">
        <button class="btn btn-primary" id="ov-discover">🌐 Discover my network</button>
        <button class="btn btn-secondary btn-sm" id="ov-specific">Or enter a specific IP/CIDR…</button>
      </div>`;
  } else if (!c.services) {
    html += `
      <div class="ov-title">2 · Found ${c.hosts} host(s) — scan their services<span class="ov-now">← do this next</span></div>
      <div class="ov-hint">Probes common ports on every discovered host and flags known vulnerabilities.</div>
      <div class="ex-actions">
        <button class="btn btn-primary" id="ov-fingerprint">🔍 Scan services now</button>
      </div>`;
  } else {
    html += `
      <div class="ov-title">3 · ${c.hosts} hosts · ${c.services} services · ${c.vulns} findings · ${c.creds} creds</div>
      <div class="ov-hint">Pick a host on the left — <b>⚠</b> marks findings, <b>💀</b> marks owned. Tables below for the full detail.</div>`;
  }
  html += '</div>';
  area.innerHTML = html;
}

function refreshOverview() { renderOverview(); }


function renderInventory(data) {
  const grid = $('inventory-grid');
  const empty = $('inventory-empty');
  if (!grid) return;
  const nodes = data.nodes || [];
  const edges = data.edges || [];

  empty.style.display = nodes.length ? 'none' : 'block';

  // group service edges by host
  const svcsByHost = {};
  edges.forEach(e => {
    if (e.type !== 'service') return;
    (svcsByHost[e.source] ||= []).push(e);
  });

  const hosts = nodes
    .filter(n => n.type === 'host')
    .sort(_byIp);

  const sel = state.selectedGraphNode;

  grid.innerHTML = hosts.map(n => {
    const svcs = svcsByHost[n.id] || [];
    const openCount = svcs.filter(e => e.state === 'open').length;
    return `
    <div class="tile ${sel && sel.id === n.id ? 'chip-selected' : ''}" data-kind="host" data-id="${escAttr(n.id)}"
         role="listitem" tabindex="-1"
         aria-label="Host ${escAttr(n.id)}${n.hostname ? ', ' + escAttr(n.hostname) : ''}, ${openCount} open service(s)${n.vuln_count ? ', ' + n.vuln_count + ' finding(s)' : ''}">
      <div class="tile-head">
        <span class="tile-ip">${escHtml(n.id)}</span>
        ${n.has_session ? '<span title="session open">💀</span>' : ''}
        ${n.vuln_count ? `<span class="tile-vuln">⚠ ${n.vuln_count}</span>` : ''}
        ${n.out_of_scope ? '<span class="tile-oos" title="outside engagement scope">⊘</span>' : ''}
      </div>
      <div class="tile-meta">${escHtml(n.vendor || n.hostname || '')}<span class="tile-os"> ${escHtml(n.os || '')}</span></div>
      <div class="tile-chips">
        ${svcs.map(e => `
          <span class="tile-chip chip-svc ${e.state === 'open' ? 'chip-open' : 'chip-closed'}" data-kind="service" data-id="${escAttr(e.target)}"
             role="button" tabindex="-1"
             aria-label="Service ${escAttr((e.service || 'unknown') + ' on ' + n.id + ' port ' + e.port)}"
             data-ip="${escAttr(e.source)}" data-port="${escAttr(String(e.port))}" data-proto="${escAttr(e.proto || 'tcp')}"
             data-service="${escAttr(e.service || '')}" data-product="${escAttr(e.product || '')}"
             data-version="${escAttr(e.version || '')}" data-state="${escAttr(e.state || '')}" title="${escAttr((e.service || '?') + ' on port ' + e.port)}">
            ${escHtml(String(e.port))}
          </span>`).join('')}
      </div>
    </div>`;
  }).join('');

  // credentials strip (engagement overlay only)
  const credNodes = nodes.filter(n => n.type === 'cred');
  const credHtml = credNodes.map(cn => {
    const acc = edges.filter(e => e.type === 'credential' && e.target === cn.id);
    const pivot = edges.find(e => e.type === 'pivot' && e.target === cn.id);
    const reaches = (pivot && pivot.reaches) || [];
    return `
      <div class="tile tile-cred ${sel && sel.id === cn.id ? 'chip-selected' : ''}" data-kind="cred" data-id="${escAttr(cn.id)}"
           role="listitem" tabindex="-1" aria-label="Credential ${escAttr(cn.label || cn.id)}"
           data-label="${escAttr(cn.label || cn.id)}" data-service="${escAttr((pivot && pivot.service) || (acc[0] && acc[0].service) || '')}"
           data-hosts="${escAttr(acc.map(a => a.source).join(','))}" data-reaches="${escAttr(reaches.join(','))}">
        🔑 ${escHtml(cn.label || cn.id)}
        <span class="tile-cred-reach" title="verified at">${escHtml(acc.map(a => a.source).join(', '))}</span>
        ${reaches.length ? `<span class="tile-cred-pivot" title="pivots to">${escHtml(reaches.join(', '))}</span>` : ''}
      </div>`;
  }).join('');
  if (credHtml) grid.innerHTML += `<h3 class="inv-cred-head">Credentials</h3>${credHtml}`;

  // Roving tabindex: one tab stop for the whole host list, arrows move within.
  const tiles = grid.querySelectorAll('.tile');
  tiles.forEach((el, i) => { el.tabIndex = i === 0 ? 0 : -1; });
}

function _byIp(a, b) {
  const qa = _q(a), qb = _q(b);
  for (let i = 0; i < 4; i++) {
    const d = (qa[i] || 0) - (qb[i] || 0);
    if (d) return d;
  }
  return String(a.id).localeCompare(String(b.id));
}
function _q(x) { return String(x.id || '').split('.').map(Number); }

async function loadGraph() {
  try {
    const res = await api('/api/graph');
    // merge the active engagement's graph (credential + pivot edges) in
    try {
      const s = await api('/api/session');
      const engId = s.scope?.engagement_id;
      if (engId) {
        const eng = await api(`/api/engagement/${engId}/graph`);
        const engNodeIds = new Set((eng.nodes || []).map(n => n.id));
        (eng.nodes || []).forEach(n => {
          if ((res.nodes || []).some(m => m.id === n.id)) return;
          (res.nodes ||= []).push(n);
        });
        (eng.edges || []).forEach(e => {
          (res.edges ||= []).push(e);
          if (e.type === 'service') return;
          // ensure credential endpoints exist as nodes even if not in eng.nodes
          if (!engNodeIds.has(e.target) && !(res.nodes || []).some(m => m.id === e.target)) {
            res.nodes.push({ id: e.target, label: e.target, type: 'cred', service_count: 0 });
          }
        });
      }
    } catch { /* engagement graph optional */ }
    state.graphData = res;
    renderInventory(res);
  } catch (e) {
    log('Graph load failed: ' + e.message, 'error');
  }
}







function selectGraphNode(type, data) {
  state.selectedGraphNode = data;
  if (type === 'host') {
    renderActionPanel('host', {
      ip: data.id, os: data.os, vendor: data.vendor, hostname: data.label,
      vuln_count: data.vuln_count || 0, has_session: data.has_session,
      services: servicesOfHost(data.id),
    });
  } else if (type === 'cred') {
    const edges = (state.graphData?.edges || []).filter(e => e.target === data.id);
    renderActionPanel('cred', {
      label: data.label || data.id,
      hosts: edges.map(e => ({ host: e.source })),
      reaches: (edges.find(e => e.type === 'pivot') || {}).reaches || [],
      service: (edges[0] || {}).service || '',
      port: 22,
    });
  } else {
    const edge = (state.graphData?.edges || []).find(e => e.target === data.id)
      || {};
    renderActionPanel('service', {
      ip: edge.source || '?', port: data.port, proto: data.proto,
      service: edge.service || data.service, product: edge.product,
      version: edge.version, state: edge.state,
      attack_service: serviceFamily(edge.service || ''),
    });
  }
}

function serviceFamily(name) {
  const s = (name || '').toLowerCase();
  return (['ssh', 'ftp', 'telnet', 'mysql', 'http'].find(f => s.includes(f)) || '');
}

function servicesOfHost(ip) {
  const seen = new Map();
  (state.graphData?.edges || []).forEach(e => {
    if (e.type === 'service' && e.source === ip && !seen.has(e.port)) {
      seen.set(e.port, {
        port: e.port, proto: e.proto, service: e.service, state: e.state,
        product: e.product, version: e.version, info: e.info,
        attack_service: serviceFamily(e.service),
      });
    }
  });
  return [...seen.values()];
}







function escAttr(s) {
  return escHtml(s);
}

// ---- fuzzing ----

let fzPollTimer = null;
let fzJobId = null;

async function startFuzzing() {
  const host = $('fz-host').value.trim() || '127.0.0.1';
  const port = parseInt($('fz-port').value, 10) || 8080;
  const iters = parseInt($('fz-iters').value, 10) || 2000;
  const timeout = parseInt($('fz-timeout').value, 10) || 60;
  const btn = $('btn-fz-start');
  btn.disabled = true;
  $('btn-fz-stop').hidden = false;
  $('fz-output').hidden = false;
  $('fz-output').innerHTML = '';
  appendFz(`> fuzzing ${host}:${port} (${iters} iterations, ${timeout}s timeout)...`);
  $('fz-live').textContent = 'starting...';
  try {
    const res = await api('/api/fuzz', {
      method: 'POST',
      body: { target: `${host}:${port}`, host, port, scheme: 'http',
              service: 'http', iterations: iters, timeout }
    });
    if (res.job_id) {
      fzJobId = res.job_id;
      if (fzPollTimer) clearInterval(fzPollTimer);
      fzPollTimer = setInterval(pollFuzz, 2500);
    } else {
      $('fz-live').textContent = 'failed to start: ' + JSON.stringify(res);
      btn.disabled = false;
      $('btn-fz-stop').hidden = true;
    }
  } catch (e) {
    $('fz-live').textContent = 'error: ' + e.message;
    btn.disabled = false;
    $('btn-fz-stop').hidden = true;
  }
}

async function pollFuzz() {
  if (!fzJobId) return;
  try {
    const job = await api(`/api/fuzz/${fzJobId}`);
    $('fz-live').textContent = job.message || job.status;
    $('fz-progress').style.width = (job.progress || 0) + '%';
    setProgress($('fz-progress'), job.progress || 0);
    $('fz-pct').textContent = Math.round(job.progress || 0) + '%';
    const cands = job.candidates || [];
    if (cands.length) {
      $('fz-summary').hidden = false;
      $('fz-chip-cves').textContent = `${cands.length} distinct crash(es)`;
      const st = job.stats || {};
      $('fz-chip-exec').textContent = `${st.execs ?? '?'} execs`;
      const out = $('fz-output');
      out.innerHTML = `
        <p class="t-line">distinct crash candidates (deduped):</p>
        ${cands.map(c => `
          <p class="t-line">  [crash] ${escHtml(c.crash || c.bug_class || '?')} — ${escHtml((c.input || '').slice(0, 60))} ${c.reproduce ? '→ ' + escHtml(c.reproduce) : ''}</p>`).join('')}
        <p class="t-line">minimize with “↻ Minimize” after the run finishes</p>`;
    }
    if (['done', 'error'].includes(job.status)) {
      clearInterval(fzPollTimer);
      fzPollTimer = null;
      $('btn-fz-start').disabled = false;
      $('btn-fz-stop').hidden = true;
      if (job.status === 'error') {
        $('fz-live').textContent = 'error: ' + (job.error || '?');
        playSound('error');
      } else {
        log(`Fuzz done — ${cands.length} crash candidate(s)`, cands.length ? 'warn' : 'success');
        unlockAchievement('port_scanner');
      }
    }
  } catch (e) {
    clearInterval(fzPollTimer);
    fzPollTimer = null;
    $('btn-fz-start').disabled = false;
    $('fz-live').textContent = 'poll error: ' + e.message;
  }
}

function appendFz(text) {
  const el = $('fz-output');
  if (!el) return;
  const p = document.createElement('p');
  p.className = 't-line';
  p.textContent = text;
  el.appendChild(p);
}

// ═══════════════════════════════════════════
// SETTINGS / AUTH (#85)
// ═══════════════════════════════════════════
function setText(id, text) {
  const el = $(id);
  if (el) el.textContent = text;
}

function pretty(value, max = 12000) {
  let text;
  try { text = JSON.stringify(value, null, 2); }
  catch { text = String(value); }
  return text.length > max ? text.slice(0, max) + '\n…[truncated]…' : text;
}

async function loadAuthStatus() {
  const cfg = await api('/api/auth/config');
  if (!cfg || cfg.detail) {
    setText('auth-status', 'auth endpoint unavailable');
    return;
  }
  const me = await api('/api/auth/me');
  const signedIn = me && me.role && !me.detail;
  setText('auth-status', cfg.enabled
    ? (signedIn ? `authenticated · ${me.role}` : 'authentication required')
    : 'local session · no auth');
  const detail = [
    `enabled: ${cfg.enabled}`,
    `roles: ${(cfg.roles || []).join(', ')}`,
    `rate limit: ${cfg.rate_limits ? `${cfg.rate_limits.anonymous}/min anonymous, ${cfg.rate_limits.operator}/min operator` : 'n/a'}`,
    signedIn ? `principal: ${me.subject} (${me.method})` : '',
  ].filter(Boolean).join('\n');
  setText('auth-detail', detail);
  const oidc = $('oidc-login');
  if (oidc) oidc.hidden = !(cfg.oidc && cfg.oidc.enabled);
}

async function saveApiKey() {
  const value = ($('set-api-key')?.value || '').trim();
  if (!value) { setText('auth-message', 'Paste a key first.'); return; }
  sessionStorage.setItem('h4k-api-key', value);
  setText('auth-message', 'Key stored for this browser tab only.');
  announce('API key saved');
  await testApiKey();
}

async function testApiKey() {
  const value = ($('set-api-key')?.value || '').trim() || apiKey();
  if (!value) { setText('auth-message', 'No key stored.'); return; }
  const r = await fetch('/api/auth/verify', { headers: { 'X-API-Key': value } });
  const data = await r.json().catch(() => ({}));
  if (r.ok && data.valid) {
    setText('auth-message', `Key valid — ${data.subject} (${data.role}).`);
    announce(`API key valid for ${data.role}`);
  } else {
    setText('auth-message', `Key rejected: ${data.detail || r.status}`);
    announce('API key rejected', true);
  }
  loadAuthStatus();
}

function clearApiKey() {
  sessionStorage.removeItem('h4k-api-key');
  const input = $('set-api-key');
  if (input) input.value = '';
  setText('auth-message', 'Key cleared.');
  loadAuthStatus();
}

function openShortcuts() {
  const dialog = $('shortcuts-dialog');
  if (!dialog) return;
  if (typeof dialog.showModal === 'function') { if (!dialog.open) dialog.showModal(); }
  else { dialog.hidden = false; }
  $('btn-shortcuts-close')?.focus();
  announce('Keyboard shortcuts dialog opened');
}

function closeShortcuts() {
  const dialog = $('shortcuts-dialog');
  if (!dialog) return;
  if (typeof dialog.close === 'function') dialog.close();
  else dialog.hidden = true;
  $('shortcuts-btn')?.focus();
}

// ═══════════════════════════════════════════
// LAB: TRAFFIC KIT + IOT/OT (#87, #90)
// ═══════════════════════════════════════════
let ltJobId = null;
let ltPoll = null;

function renderLab(data, label = '') {
  const el = $('lab-output');
  if (!el) return;
  el.textContent = (label ? label + '\n' : '') + pretty(data);
}

async function startLabTraffic() {
  const target = ($('lt-target')?.value || '').trim();
  if (!target) { setText('lt-status', 'target required'); announce('Lab traffic needs a target', true); return; }
  setText('lt-status', 'starting…');
  const body = {
    profile: $('lt-profile')?.value || 'mixed',
    target,
    count: parseInt($('lt-count')?.value || '20', 10) || 20,
    rate_per_s: parseFloat($('lt-rate')?.value || '2') || 2,
    allow_public: !!$('lt-public')?.checked,
  };
  const res = await api('/api/lab/traffic/run', { method: 'POST', body });
  if (!res || !res.job_id) {
    setText('lt-status', res?.detail || 'failed');
    renderLab(res, 'traffic error');
    announce(`Traffic generation failed: ${res?.detail || 'unknown error'}`, true);
    return;
  }
  ltJobId = res.job_id;
  $('btn-lt-stop').hidden = false;
  setText('lt-status', 'running…');
  announce(`Traffic generation started (${body.profile})`);
  clearInterval(ltPoll);
  ltPoll = setInterval(pollLabTraffic, 600);
}

async function pollLabTraffic() {
  if (!ltJobId) return;
  const job = await api(`/api/lab/traffic/${ltJobId}`);
  if (!job || job.status === 'running') {
    if (job && job.summary) renderLab(job.summary, 'running summary');
    return;
  }
  clearInterval(ltPoll);
  ltPoll = null;
  $('btn-lt-stop').hidden = true;
  ltJobId = null;
  if (job.status === 'error') {
    setText('lt-status', 'error');
    renderLab(job, 'traffic error');
    announce('Traffic generation failed', true);
  } else {
    setText('lt-status', `${job.status} · ${job.summary.events} events`);
    renderLab(job.summary, 'traffic summary');
    announce(`Traffic generation ${job.status}: ${job.summary.events} events, ${job.summary.errors} errors`);
  }
}

async function stopLabTraffic() {
  if (!ltJobId) return;
  await api(`/api/lab/traffic/${ltJobId}/stop`, { method: 'POST' });
  setText('lt-status', 'stop requested');
}

async function runIot(discover) {
  const host = ($('iot-host')?.value || '').trim();
  if (!host) { setText('iot-status', 'host required'); announce('IoT probe needs a host', true); return; }
  const protocol = $('iot-protocol')?.value || 'auto';
  const portRaw = ($('iot-port')?.value || '').trim();
  const body = { host, protocol, timeout: 2 };
  if (portRaw) body.port = parseInt(portRaw, 10);
  setText('iot-status', 'probing…');
  const path = discover ? '/api/lab/iot/discover' : '/api/lab/iot/probe';
  if (discover) delete body.protocol;
  const res = await api(path, { method: 'POST', body });
  if (res && res.detail) {
    setText('iot-status', res.detail);
    renderLab(res, 'IoT error');
    announce(`IoT probe failed: ${res.detail}`, true);
    return;
  }
  if (discover) {
    setText('iot-status', `${res.responsive}/${res.probed} responsive`);
    renderLab(res, 'IoT/OT discovery');
    announce(`IoT discovery found ${res.responsive} responsive of ${res.probed} probes`);
  } else {
    setText('iot-status', res.ok ? 'identified' : 'no answer / not identified');
    renderLab(res, 'IoT/OT probe');
    announce(`IoT probe ${res.ok ? 'identified' : 'did not identify'} ${res.protocol} on ${res.port}`);
  }
}

// ═══════════════════════════════════════════
// AD (#91, #92, #93)
// ═══════════════════════════════════════════
function adBody(extra = {}) {
  const body = {
    domain: ($('ad-domain')?.value || '').trim(),
    dc_ip: ($('ad-dc')?.value || '').trim(),
    username: ($('ad-user')?.value || '').trim(),
    password: $('ad-pass')?.value || '',
    base_dn: ($('ad-base')?.value || '').trim(),
    ...extra,
  };
  return body;
}

function adUsers() {
  return ($('ad-users')?.value || '').split(/[\n,]+/).map(s => s.trim()).filter(Boolean);
}

function adPasswords() {
  return ($('ad-passwords')?.value || '').split(/\n+/).map(s => s.trim()).filter(Boolean);
}

function renderAd(data, label = '') {
  const el = $('ad-output');
  if (!el) return;
  el.textContent = (label ? label + '\n' : '') + pretty(data);
}

async function adRun(path, body, label, statusId = 'ad-status') {
  setText(statusId, 'working…');
  announce(`${label} started`);
  const res = await api(path, { method: 'POST', body });
  if (!res || res.detail) {
    setText(statusId, res?.detail || 'failed');
    renderAd(res, `${label} error`);
    announce(`${label} failed: ${res?.detail || 'unknown'}`, true);
    return res;
  }
  setText(statusId, 'complete');
  renderAd(res, label);
  return res;
}

async function runAdAudit() {
  const body = adBody({ include_smb: !!$('ad-smb')?.checked });
  setText('ad-status', 'auditing…');
  announce('AD domain audit started');
  const res = await api('/api/ad/audit', { method: 'POST', body });
  const el = $('ad-output');
  if (!res || res.detail) {
    setText('ad-status', res?.detail || 'failed');
    if (el) el.textContent = pretty(res, 4000);
    announce(`AD audit failed: ${res?.detail || 'unknown'}`, true);
    return;
  }
  if (!res.ok) {
    setText('ad-status', res.error || 'audit failed');
    if (el) el.textContent = pretty(res, 4000);
    announce(`AD audit failed: ${res.error || 'unknown'}`, true);
    return;
  }
  const lines = [
    `Domain audit — ${res.domain} (${res.dc_ip})`,
    `Risk: ${res.risk} (${res.risk_score}/100) · ${res.findings.length} finding(s)`,
    '',
    ...res.findings.map(f => `[${f.severity.toUpperCase()}] ${f.title}${f.attack_technique ? ' · ' + f.attack_technique : ''}`),
    '',
    ...(res.errors && res.errors.length ? ['Errors:', ...res.errors] : []),
  ];
  if (el) el.textContent = lines.join('\n');
  setText('ad-status', `${res.findings.length} findings · ${res.risk}`);
  announce(`AD audit complete: ${res.findings.length} findings, risk ${res.risk}`);
  log(`AD audit ${res.domain}: ${res.findings.length} findings (${res.risk})`, res.risk === 'critical' ? 'error' : 'warn');
}

async function runAdSpray() {
  const body = adBody({
    users: adUsers(),
    passwords: adPasswords(),
    execute: !!$('ad-execute')?.checked,
    force: !!$('ad-force')?.checked,
    delay: parseFloat($('ad-delay')?.value || '1.5') || 1.5,
  });
  if (!body.passwords.length) { setText('ad-status', 'password list required'); return; }
  const res = await adRun('/api/ad/spray', body, 'Credential spray');
  if (res && res.refused) {
    setText('ad-status', 'refused by lockout guard');
    announce('Spray refused by lockout guard', true);
  } else if (res && res.executed) {
    log(`Spray: ${res.found.length} credential(s) found in ${res.attempt_count} attempt(s)`, res.found.length ? 'warn' : 'info');
    announce(`Spray finished: ${res.found.length} credential(s) found`, res.found.length > 0);
  }
}

function renderBloodHound(data, label) {
  renderAd(data, label);
}

async function bhStatus() {
  setText('bh-status', 'checking…');
  const res = await api('/api/bloodhound/status');
  setText('bh-status', res.reachable ? 'reachable' : 'unreachable');
  renderBloodHound(res, 'BloodHound CE status');
  announce(`BloodHound CE ${res.reachable ? 'reachable' : 'unreachable'}`, !res.reachable);
}

async function bhCollect() {
  const body = {
    ...adBody(),
    base_url: ($('bh-url')?.value || '').trim(),
    username: ($('bh-user')?.value || '').trim() || ($('ad-user')?.value || '').trim(),
    password: $('bh-pass')?.value || $('ad-pass')?.value || '',
  };
  setText('bh-status', 'collecting + uploading…');
  announce('BloodHound collection started');
  const res = await api('/api/bloodhound/collect-upload-analyze', { method: 'POST', body });
  setText('bh-status', res.ok ? 'collected + uploaded' : (res.detail || 'failed'));
  renderBloodHound(res, 'BloodHound collect → upload → analyze');
  announce(res.ok ? 'BloodHound collection uploaded' : 'BloodHound collection failed', !res.ok);
}

async function bhQuery() {
  const body = {
    ...adBody(),
    base_url: ($('bh-url')?.value || '').trim(),
    name: $('bh-query-name')?.value || 'kerberoastable',
  };
  setText('bh-status', 'querying…');
  const res = await api('/api/bloodhound/query', { method: 'POST', body });
  setText('bh-status', res.ok ? 'query complete' : (res.detail || 'failed'));
  renderBloodHound(res, `BloodHound query: ${body.name}`);
}

// ═══════════════════════════════════════════
// TELEMETRY (#94)
// ═══════════════════════════════════════════
async function loadTelemetry() {
  const [summary, detections, events] = await Promise.all([
    api('/api/telemetry/summary'),
    api('/api/telemetry/detections?limit=50'),
    api('/api/telemetry/events?limit=50'),
  ]);
  if (summary && !summary.detail) {
    setText('tel-events', `${summary.events} events`);
    setText('tel-detections', `${summary.detections} detections`);
  }
  renderTelemetryDetections(detections?.detections || []);
  renderTelemetryEvents(events?.events || []);
}

function renderTelemetryDetections(rows) {
  const body = $('tel-dets-tbody');
  if (!body) return;
  body.innerHTML = rows.map(d => `
    <tr>
      <td><span class="v-sev ${sevClass(d.severity)}">${escHtml(d.severity)}</span></td>
      <td>${escHtml(d.title)}</td>
      <td>${escHtml(d.host || '')}</td>
      <td><code>${escHtml(d.technique || '')}</code></td>
    </tr>`).join('');
  const empty = $('tel-dets-empty');
  if (empty) empty.style.display = rows.length ? 'none' : 'block';
}

function renderTelemetryEvents(rows) {
  const body = $('tel-events-tbody');
  if (!body) return;
  body.innerHTML = rows.map(e => `
    <tr>
      <td title="${escAttr(e.ts)}">${escHtml((e.ts || '').replace('T', ' ').slice(0, 19))}</td>
      <td>${escHtml(e.host || '')}</td>
      <td>${escHtml(e.source || '')}</td>
      <td>${escHtml(e.event_id || '')}</td>
      <td title="${escAttr(e.message || '')}">${escHtml((e.message || '').slice(0, 80))}</td>
    </tr>`).join('');
  const empty = $('tel-events-empty');
  if (empty) empty.style.display = rows.length ? 'none' : 'block';
}

async function telemetryAction(path, label) {
  const res = await api(path, { method: 'POST' });
  announce(`${label}: ${res.detection_count ?? res.status ?? 'done'}`);
  await loadTelemetry();
}

// ═══════════════════════════════════════════
// NIGHTLY (#100)
// ═══════════════════════════════════════════
async function loadSchedules() {
  const [status, schedules, runs] = await Promise.all([
    api('/api/automation/status'),
    api('/api/automation/schedules'),
    api('/api/automation/runs?limit=25'),
  ]);
  if (status && !status.detail) {
    setText('nt-status', `${status.enabled ? 'loop on' : 'loop off'} · ${status.schedules} schedule(s)`);
  }
  renderSchedules(schedules?.schedules || []);
  renderRuns(runs?.runs || []);
}

function renderSchedules(rows) {
  const body = $('nt-tbody');
  if (!body) return;
  body.innerHTML = rows.map(s => `
    <tr>
      <td>${escHtml(s.name)}${s.enabled ? '' : ' <span class="tile-oos">disabled</span>'}</td>
      <td><code>${escHtml(s.cron)}</code></td>
      <td>${escHtml((s.next_run || '—').replace('T', ' ').slice(0, 16))}</td>
      <td>${escHtml(s.last_status || 'never')}</td>
      <td class="row-actions">
        <button class="btn btn-secondary btn-sm" data-nt-run="${escAttr(s.id)}">▶ Run</button>
        <button class="btn btn-secondary btn-sm" data-nt-toggle="${escAttr(s.id)}" data-nt-enabled="${s.enabled ? '1' : '0'}">${s.enabled ? 'Disable' : 'Enable'}</button>
        <button class="btn btn-danger btn-sm" data-nt-del="${escAttr(s.id)}">Delete</button>
      </td>
    </tr>`).join('');
  const empty = $('nt-empty');
  if (empty) empty.style.display = rows.length ? 'none' : 'block';
}

function renderRuns(rows) {
  const body = $('nt-runs-tbody');
  if (!body) return;
  body.innerHTML = rows.map(r => `
    <tr>
      <td>${escHtml((r.started_at || '').replace('T', ' ').slice(0, 19))}</td>
      <td>${escHtml(r.status)}</td>
      <td><code>${escHtml(r.job_id || '')}</code></td>
      <td title="${escAttr(r.error || r.summary || '')}">${escHtml((r.error || r.summary || '').slice(0, 60))}</td>
    </tr>`).join('');
  const empty = $('nt-runs-empty');
  if (empty) empty.style.display = rows.length ? 'none' : 'block';
}

async function createSchedule() {
  const body = {
    name: ($('nt-name')?.value || '').trim() || 'Nightly autopilot',
    cron: ($('nt-cron')?.value || '').trim(),
    timezone: ($('nt-tz')?.value || 'UTC').trim(),
    engagement_id: ($('nt-engagement')?.value || '').trim() || ($('scope-select')?.value || ''),
    deep_web: !!$('nt-deep')?.checked,
    enabled: !!$('nt-enabled')?.checked,
  };
  const res = await api('/api/automation/schedules', { method: 'POST', body });
  if (res && res.id) {
    setText('nt-output', `Created ${res.name} — next run ${res.next_run}`);
    announce(`Schedule created: ${res.name}`);
    await loadSchedules();
  } else {
    setText('nt-output', res?.detail || 'create failed');
    announce(`Schedule create failed: ${res?.detail || 'unknown'}`, true);
  }
}

async function validateCron() {
  const body = {
    cron: ($('nt-cron')?.value || '').trim(),
    timezone: ($('nt-tz')?.value || 'UTC').trim(),
    count: 5,
  };
  const res = await api('/api/automation/validate', { method: 'POST', body });
  if (res && res.valid) {
    setText('nt-output', `Valid. Next runs:\n${res.next_runs.join('\n')}`);
    announce('Cron expression is valid');
  } else {
    setText('nt-output', res?.detail || 'invalid');
    announce(`Cron invalid: ${res?.detail || 'unknown'}`, true);
  }
}

async function scheduleAction(path, method, confirmText = '') {
  if (confirmText && !confirm(confirmText)) return;
  const res = await api(path, { method });
  setText('nt-status', res?.detail || res?.status || 'done');
  announce(`Schedule action: ${res?.status || res?.detail || 'done'}`);
  await loadSchedules();
}

// ═══════════════════════════════════════════
// BINDINGS FOR THE NEW PAGES
// ═══════════════════════════════════════════
document.addEventListener('DOMContentLoaded', () => {
  applyPrefs();
  loadAuthStatus();

  $('shortcuts-btn')?.addEventListener('click', openShortcuts);
  $('btn-shortcuts-close')?.addEventListener('click', closeShortcuts);
  $('btn-shortcuts-settings')?.addEventListener('click', openShortcuts);
  $('shortcuts-dialog')?.addEventListener('click', e => {
    if (e.target === $('shortcuts-dialog')) closeShortcuts();
  });

  $('btn-save-key')?.addEventListener('click', saveApiKey);
  $('btn-test-key')?.addEventListener('click', testApiKey);
  $('btn-clear-key')?.addEventListener('click', clearApiKey);

  $('set-theme')?.addEventListener('change', e => setTheme(e.target.value));
  $('set-sound')?.addEventListener('change', e => {
    state.soundEnabled = e.target.checked;
    localStorage.setItem('h4k-sound', state.soundEnabled ? '1' : '0');
    applyPrefs();
  });
  $('set-reduce-motion')?.addEventListener('change', e => {
    localStorage.setItem('h4k-reduce-motion', e.target.checked ? '1' : '0');
    applyPrefs();
    announce(`Reduced motion ${e.target.checked ? 'on' : 'off'}`);
  });

  $('btn-lt-start')?.addEventListener('click', startLabTraffic);
  $('btn-lt-stop')?.addEventListener('click', stopLabTraffic);
  $('btn-iot-probe')?.addEventListener('click', () => runIot(false));
  $('btn-iot-discover')?.addEventListener('click', () => runIot(true));

  $('btn-ad-audit')?.addEventListener('click', runAdAudit);
  $('btn-ad-policy')?.addEventListener('click', () => adRun('/api/ad/policy', adBody(), 'Domain password policy'));
  $('btn-ad-users')?.addEventListener('click', () => adRun('/api/ad/users', adBody(), 'Domain users'));
  $('btn-ad-spray')?.addEventListener('click', runAdSpray);
  $('btn-ad-asrep')?.addEventListener('click', () => adRun('/api/ad/asrep', adBody({
    users: adUsers(), execute: !!$('ad-execute')?.checked,
  }), 'AS-REP roast'));
  $('btn-ad-kerberoast')?.addEventListener('click', () => adRun('/api/ad/kerberoast', adBody({
    execute: !!$('ad-execute')?.checked,
  }), 'Kerberoast'));

  $('btn-bh-status')?.addEventListener('click', bhStatus);
  $('btn-bh-collect')?.addEventListener('click', bhCollect);
  $('btn-bh-query')?.addEventListener('click', bhQuery);

  $('btn-limits-refresh')?.addEventListener('click', loadLimits);
  $('btn-noise-set')?.addEventListener('click', setNoiseProfile);
  $('noise-tool')?.addEventListener('change', loadNoiseGuidance);
  $('btn-ai-budget-reset')?.addEventListener('click', resetAiBudget);

  $('btn-appr-refresh')?.addEventListener('click', loadApprovals);
  $('btn-appr-add-rule')?.addEventListener('click', addApprovalRule);
  $('btn-appr-check')?.addEventListener('click', checkApprovalPolicy);

  $('btn-ap-refresh')?.addEventListener('click', loadAttackPaths);
  $('btn-ap-report')?.addEventListener('click', downloadPathsReport);
  $('btn-obj-add')?.addEventListener('click', addObjective);
  $('btn-cov-add')?.addEventListener('click', addCoverage);

  $('btn-fl-refresh')?.addEventListener('click', loadFindings);
  $('btn-fl-report')?.addEventListener('click', downloadFindingsReport);
  $('btn-fl-create')?.addEventListener('click', createFinding);
  $('btn-fl-add-evidence')?.addEventListener('click', attachFindingEvidence);
  $('btn-fl-retest')?.addEventListener('click', recordFindingRetest);
  $('fl-select')?.addEventListener('change', () => pickFinding($('fl-select')?.value || ''));

  $('btn-tel-refresh')?.addEventListener('click', loadTelemetry);
  $('btn-tel-simulate')?.addEventListener('click', () => telemetryAction('/api/telemetry/simulate', 'Demo telemetry'));
  $('btn-tel-reset')?.addEventListener('click', async () => {
    if (!confirm('Delete all ingested telemetry and detections?')) return;
    await telemetryAction('/api/telemetry/reset', 'Telemetry reset');
  });

  $('btn-nt-create')?.addEventListener('click', createSchedule);
  $('btn-nt-validate')?.addEventListener('click', validateCron);
  $('btn-nt-refresh')?.addEventListener('click', loadSchedules);

  document.addEventListener('click', e => {
    const pick = e.target.closest('[data-fl-pick]');
    if (pick) { pickFinding(pick.dataset.flPick); return; }
    const apprApprove = e.target.closest('[data-appr-approve]');
    if (apprApprove) { decideApproval(apprApprove.dataset.apprApprove, 'approve'); return; }
    const apprDeny = e.target.closest('[data-appr-deny]');
    if (apprDeny) { decideApproval(apprDeny.dataset.apprDeny, 'deny'); return; }
    const apprDel = e.target.closest('[data-appr-del]');
    if (apprDel) { deleteApprovalRule(apprDel.dataset.apprDel); return; }
    const objDel = e.target.closest('[data-obj-del]');
    if (objDel) { deleteObjective(objDel.dataset.objDel, objDel.dataset.objLabel || ''); return; }
    const run = e.target.closest('[data-nt-run]');
    if (run) { scheduleAction(`/api/automation/schedules/${run.dataset.ntRun}/run`, 'POST'); return; }
    const del = e.target.closest('[data-nt-del]');
    if (del) {
      scheduleAction(`/api/automation/schedules/${del.dataset.ntDel}`, 'DELETE', 'Delete this schedule and its run history?');
      return;
    }
    const toggle = e.target.closest('[data-nt-toggle]');
    if (toggle) {
      const enabled = toggle.dataset.ntEnabled !== '1';
      api(`/api/automation/schedules/${toggle.dataset.ntToggle}`, {
        method: 'PATCH', body: { enabled },
      }).then(res => {
        setText('nt-status', res?.detail || (enabled ? 'enabled' : 'disabled'));
        loadSchedules();
      });
      return;
    }
  });
});
