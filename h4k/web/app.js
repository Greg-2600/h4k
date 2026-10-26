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
  saveDefaultPanel();
  state.currentPhase = 'assets';
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
  document.querySelectorAll('.phase, .console').forEach(el => {
    el.hidden = el.dataset.phase !== phase;
  });
  document.querySelectorAll('.nav-btn').forEach(el => {
    el.classList.toggle('active', el.dataset.phase === phase);
  });
  updateHint();
  if (phase === 'assets') {
    loadGraph();
    loadCredTargets();
    loadCveStatus();
    refreshSessionBadge();
    restoreDefaultPanel();
  }
  if (phase === 'report') renderReportPreview();
}

function updateHint() {
  const hints = {
    assets: 'Click a host/service/cred on the canvas — actions appear for that asset',
    walk: 'Requires an active scope — Start walks the entire local network',
    fuzz: 'Point at a service you own and start fuzzing',
    report: '⇩ Report downloads the full writeup; 🧬 plans credential propagation',
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


  document.querySelector('[data-obj="host"]').classList.add('active');


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
  refreshSessionBadge();
  loadScopeSelect();

  // Scope selector: pick the engagement whose CIDRs constrain aggressive actions
  $('scope-select').addEventListener('change', async (e) => {
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
    a.download = `h4k-session-${s.id}.md`;
    a.click();
    URL.revokeObjectURL(a.href);
    log(`Session report ${a.download} downloaded`, 'success');
    logXp(10, '(report)');
  } catch (e) { log('Report failed: ' + e.message, 'error'); }
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
  loadCredTargets();
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



  try {
    const res = await api('/api/scan', {
      method: 'POST',
      body: {
        target: state.discoveredTarget,
        mode: $('mode-select').value,
        depth: $('depth-select').value,
        do_dns_recon: false,
        do_vuln_scan: false,
        try_default_creds: false,
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
    $('ap-title').textContent = '🖥 Host — ' + data.ip;
    body.innerHTML = hostPanelHtml(data);
  } else if (kind === 'service') {
    $('ap-title').textContent = `🧩 ${data.ip}:${data.port} (${data.service || '?'})`;
    body.innerHTML = servicePanelHtml(data);
  } else if (kind === 'vuln') {
    $('ap-title').textContent = `⚠ ${data.vid} — ${data.ip}:${data.port}`;
    body.innerHTML = vulnPanelHtml(data);
  } else if (kind === 'cred') {
    $('ap-title').textContent = '🔑 ' + (data.label || data.id);
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
    if (e.key >= '1' && e.key <= '4') setPhase(['assets','walk','fuzz','report'][parseInt(e.key) - 1]);
    // T = theme
    if (e.key === 't') toggleTheme();
    // ? = help
    if (e.key === '?') log('Shortcuts: j/k/h/l=navigate, 1-5=phases, t=theme, Ctrl+K=palette, Esc=close', 'info');
    // Ctrl+Enter = scan
    if (e.ctrlKey && e.key === 'Enter' && state.currentPhase === 'assets') acquireToggle();
  });

  // Tool buttons
  // panel: acquire toggle + tabs
  $('btn-acquire')?.addEventListener('click', acquireToggle);
  document.querySelectorAll('.ap-tab').forEach(t => {
    t.addEventListener('click', () => switchPanelTab(t.dataset.aptab));
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
      if (state.panelMode !== 'default') restoreDefaultPanel();
      $('sp-strip').hidden = true;
      state.panelTab = 'map';
      bindPanelTabs();
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
    el.textContent = `${s.id} · ${s.hosts}h ${s.services}s ${s.vulns}v`;
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
let graphSimulation = null;

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
    renderGraph(res);
    $('graph-host-count').textContent = (res.nodes || []).length + ' nodes';
    $('graph-svc-count').textContent = (res.edges || []).length + ' edges';
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
    const cls = e.type === 'pivot' ? 'edge edge-pivot'
      : e.type === 'credential' ? 'edge edge-cred'
      : `edge edge-service edge-${e.proto || 'tcp'}`;
    html += `<line class="${cls}" x1="${e.source.x}" y1="${e.source.y}" x2="${e.target.x}" y2="${e.target.y}"/>`;
  });
  html += `</g>`;

  html += `<g class="nodes">`;
  // Service nodes
  const svcByHost = {};
  edges.forEach(e => {
    if (!e.source || !e.target) return;
    if (e.type !== 'service') return;
    const hostId = e.source.id;
    if (!svcByHost[hostId]) svcByHost[hostId] = [];
    svcByHost[hostId].push(e);
  });
  nodes.forEach(n => {
    if (n.type === 'cred') {
      const cls = `node-cred${isSelected ? ' selected' : ''}`;
      html += `<g class="${cls}" data-node-id="${n.id}" data-node-type="cred" data-node-data="${escAttr(JSON.stringify(n))}">`;
      html += `<rect x="${n.x - 26}" y="${n.y - 10}" width="52" height="20" rx="6"/>`;
      html += `<text x="${n.x}" y="${n.y + 4}" text-anchor="middle">${n.label.length > 14 ? n.label.slice(0, 12) + '…' : n.label}</text>`;
      html += `</g>`;
      return;
    }
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
    const lbl = n.label || n.id || '?';
    const shortLabel = lbl.length > 12 ? lbl.slice(0, 10) + '…' : lbl;
    html += `<text x="${n.x}" y="${n.y + 4}" text-anchor="middle">${shortLabel}</text>`;
    html += `</g>`;
  });
  html += `</g>`;
  svg.innerHTML = html;

  // Attach click events
  svg.querySelectorAll('.node-host, .node-service, .node-cred').forEach(el => {
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
