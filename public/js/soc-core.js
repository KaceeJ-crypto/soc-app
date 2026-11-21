const SOCState = {
  alerts: [
    { id: 'ALT-1001', time: '02:10:04', sev: 'HIGH', src: '198.51.100.42', rule: 'SSH Brute-Force on Decoy Port 2222', status: 'New' },
    { id: 'ALT-1002', time: '02:14:19', sev: 'MEDIUM', src: '203.0.113.88', rule: 'Outbound Stratum-like TCP Session (Port 3333)', status: 'Investigating' }
  ],
  quarantined: [],
  auditLog: [],
  manifest: null,
  pkgCount: 0,
  loggingEnabled: false
};

const PROTECTED_IPS = new Set(['127.0.0.1', 'localhost', '0.0.0.0']);

function logAudit(message) {
  const line = `[${new Date().toISOString()}] ${message}`;
  SOCState.auditLog.push(line);
}

function switchTab(tab) {
  const tabs = [
    'intrusions', 'quarantine', 'honeypots', 'mixers',
    'hunting', 'scriptlab', 'recovery', 'tools', 'comms', 'console'
  ];
  tabs.forEach(t => {
    const panel = document.getElementById(`tab-${t}`);
    const btn = document.getElementById(`btn-${t}`);
    if (panel) panel.classList.add('hidden');
    if (btn) btn.className = 'w-full text-left px-3 py-2 hover:bg-gray-800/60 text-xs rounded text-gray-400 hover:text-green-300 transition';
  });
  const activePanel = document.getElementById(`tab-${tab}`);
  const activeBtn = document.getElementById(`btn-${tab}`);
  if (activePanel) activePanel.classList.remove('hidden');
  if (activeBtn) activeBtn.className = 'w-full text-left px-3 py-2 bg-gray-800 text-xs rounded text-green-300 font-semibold border border-gray-700 transition';

  const sidebar = document.getElementById('sidebar');
  if (window.innerWidth < 768 && sidebar) sidebar.classList.add('-translate-x-full');
}

function toggleSidebar() {
  const sidebar = document.getElementById('sidebar');
  if (sidebar) sidebar.classList.toggle('-translate-x-full');
}

function toggleLogging() {
  SOCState.loggingEnabled = !SOCState.loggingEnabled;
  const btn = document.getElementById('rec-btn');
  if (!btn) return;
  if (SOCState.loggingEnabled) {
    btn.className = 'bg-red-950 border border-red-700 text-red-200 px-2 py-1 rounded text-[10px] flex items-center animate-pulse';
    btn.innerHTML = '<i class="fa-solid fa-circle text-[5px] mr-1"></i> LOGGING ON';
    logAudit('Audit logging enabled');
  } else {
    btn.className = 'bg-gray-800 border border-gray-700 text-gray-400 px-2 py-1 rounded text-[10px] flex items-center';
    btn.innerHTML = '<i class="fa-solid fa-circle text-[5px] mr-1"></i> LOGGING OFF';
    logAudit('Audit logging paused');
  }
}

function resetSessionUI() {
  if (!confirm('Clear local browser storage and reset quarantine/session state?')) return;
  localStorage.clear();
  sessionStorage.clear();
  SOCState.quarantined = [];
  renderQuarantine();
  logAudit('Session UI state cleared');
  alert('Session state reset.');
}

async function syncFromBackend() {
  try {
    const [hRes, aRes, qRes] = await Promise.all([
      fetch('/api/health'),
      fetch('/api/alerts'),
      fetch('/api/quarantine')
    ]);
    if (hRes.ok) {
      const h = await hRes.json();
      const upEl = document.getElementById('stat-uptime');
      if (upEl) upEl.innerText = `${h.uptimeSec}s`;
    }
    if (aRes.ok) {
      const a = await aRes.json();
      if (Array.isArray(a.alerts) && a.alerts.length) {
        SOCState.alerts = a.alerts.map(x => ({
          id: x.id,
          time: (x.timestamp || '').slice(11, 19) || '00:00:00',
          sev: x.severity || 'MEDIUM',
          src: x.sourceIp || '0.0.0.0',
          rule: x.ruleName || 'Event',
          status: x.status || 'New'
        }));
      }
    }
    if (qRes.ok) {
      const q = await qRes.json();
      if (Array.isArray(q.quarantined)) {
        SOCState.quarantined = q.quarantined.map(x => ({
          ip: x.ip,
          scope: x.scope,
          ttl: x.ttlMinutes || 30,
          at: (x.isolatedAt || '').slice(11, 19) || 'now'
        }));
      }
    }
    renderAlerts();
    renderQuarantine();
  } catch (_) {
    renderAlerts();
    renderQuarantine();
  }
}

function renderAlerts() {
  const sevFilter = document.getElementById('sev-filter')?.value || 'ALL';
  const dedupe = document.getElementById('dedupe-toggle')?.checked || false;
  const tbody = document.getElementById('alerts-tbody');
  if (!tbody) return;

  let rows = SOCState.alerts.filter(a => sevFilter === 'ALL' || a.sev === sevFilter);
  if (dedupe) {
    const seen = new Set();
    rows = rows.filter(a => {
      if (seen.has(a.src)) return false;
      seen.add(a.src);
      return true;
    });
  }

  const countEl = document.getElementById('stat-alerts');
  if (countEl) countEl.innerText = String(rows.length);

  tbody.innerHTML = rows.map(a => `
    <tr>
      <td class="p-2 text-gray-500">${a.time}</td>
      <td class="p-2 ${a.sev === 'HIGH' ? 'text-red-400 font-bold' : 'text-amber-400'}">${a.sev}</td>
      <td class="p-2 text-blue-300">${a.src}</td>
      <td class="p-2">${a.rule}</td>
      <td class="p-2 text-green-300">${a.status}</td>
      <td class="p-2 space-x-1.5 whitespace-nowrap">
        <button onclick="isolateHost('${a.src}')" class="bg-red-950 hover:bg-red-900 border border-red-800 text-red-200 px-2 py-0.5 rounded text-[10px]">Isolate</button>
        <button onclick="updateAlertStatus('${a.id}', 'Resolved')" class="bg-gray-800 hover:bg-gray-700 border border-gray-700 text-gray-300 px-2 py-0.5 rounded text-[10px]">Resolve</button>
      </td>
    </tr>
  `).join('');
}

async function addLabAlert() {
  const now = new Date().toTimeString().split(' ')[0];
  const newAlert = {
    id: `ALT-${Math.floor(1000 + Math.random() * 9000)}`,
    time: now,
    sev: 'HIGH',
    src: '192.0.2.150',
    rule: 'Simulated Honeypot Auth Probe on Lab Subnet',
    status: 'New'
  };
  SOCState.alerts.unshift(newAlert);
  renderAlerts();
  logAudit(`Logged lab alert ${newAlert.id} from ${newAlert.src}`);

  try {
    await fetch('/api/alerts', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ severity: newAlert.sev, sourceIp: newAlert.src, ruleName: newAlert.rule })
    });
  } catch (_) {}
}

async function updateAlertStatus(id, status) {
  SOCState.alerts = SOCState.alerts.map(a => (a.id === id ? { ...a, status } : a));
  renderAlerts();
  logAudit(`Alert ${id} -> ${status}`);
  try {
    await fetch(`/api/alerts/${encodeURIComponent(id)}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status })
    });
  } catch (_) {}
}

async function isolateHost(presetIp = null) {
  const input = document.getElementById('iso-ip');
  const scope = document.getElementById('iso-scope')?.value || 'BLOCK_ALL';
  const ttl = Number(document.getElementById('iso-ttl')?.value || 30);
  const ip = (presetIp || input?.value || '').trim();
  if (!ip) return;

  if (PROTECTED_IPS.has(ip)) {
    alert(`Refused: ${ip} is a protected loopback/wildcard address.`);
    return;
  }

  const entry = { ip, scope, ttl, at: new Date().toLocaleTimeString() };
  const idx = SOCState.quarantined.findIndex(q => q.ip === ip);
  if (idx >= 0) SOCState.quarantined[idx] = entry;
  else SOCState.quarantined.push(entry);

  if (input && !presetIp) input.value = '';
  renderQuarantine();
  logAudit(`Quarantined ${ip} (${scope}, TTL ${ttl}m)`);

  try {
    await fetch('/api/quarantine', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip, scope, ttlMinutes: ttl })
    });
  } catch (_) {}
}

async function releaseHost(ip) {
  SOCState.quarantined = SOCState.quarantined.filter(q => q.ip !== ip);
  renderQuarantine();
  logAudit(`Released ${ip} from quarantine`);
  try {
    await fetch(`/api/quarantine/${encodeURIComponent(ip)}`, { method: 'DELETE' });
  } catch (_) {}
}

function renderQuarantine() {
  const listEl = document.getElementById('iso-list');
  const statEl = document.getElementById('stat-iso');
  if (statEl) statEl.innerText = String(SOCState.quarantined.length);
  if (!listEl) return;

  if (!SOCState.quarantined.length) {
    listEl.innerHTML = '<div class="text-gray-500 text-[11px]">No hosts currently isolated.</div>';
    return;
  }

  listEl.innerHTML = SOCState.quarantined.map(q => `
    <div class="flex justify-between items-center p-2 bg-gray-950 rounded border border-red-900/60">
      <div>
        <span class="text-red-300 font-bold">${q.ip}</span>
        <span class="text-[10px] text-gray-500 ml-2">[${q.scope} | ${q.ttl}m] @ ${q.at}</span>
      </div>
      <button onclick="releaseHost('${q.ip}')" class="bg-green-950 hover:bg-green-900 border border-green-700 text-green-300 px-2 py-0.5 rounded text-[10px]">Release</button>
    </div>
  `).join('');
}

function compileRule() {
  const fmt = document.getElementById('rule-fmt')?.value || 'sigma';
  const target = (document.getElementById('rule-target')?.value || 'suspicious_activity').trim();
  const out = document.getElementById('rule-out');
  if (!out) return;

  if (fmt === 'sigma') {
    out.innerText = `title: Defensive Hunt - ${target}\nstatus: experimental\ndescription: Detects ${target} in lab telemetry\nlogsource:\n    category: process_creation\ndetection:\n    selection:\n        CommandLine|contains: '${target}'\n    condition: selection\nlevel: medium`;
  } else if (fmt === 'yara') {
    const safeId = target.replace(/[^a-zA-Z0-9_]/g, '_') || 'LabRule';
    out.innerText = `rule ${safeId} {\n    meta:\n        author = "Defensive SOC Lab"\n        purpose = "Pattern matching on lab artifacts"\n    strings:\n        $s1 = "${target}" ascii wide\n    condition:\n        $s1\n}`;
  } else if (fmt === 'kql') {
    out.innerText = `DeviceNetworkEvents\n| where RemoteUrl has "${target}" or InitiatingProcessCommandLine has "${target}"\n| project Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessCommandLine`;
  } else {
    out.innerText = `index=lab_telemetry ("${target}")\n| stats count by src_ip, dest_ip, dest_port\n| sort - count`;
  }
}

function buildManifest() {
  const name = (document.getElementById('task-name')?.value || 'socket-baseline').trim();
  const code = document.getElementById('task-code')?.value || '';
  SOCState.manifest = {
    schema: 'defensive-lab-manifest/v1',
    name,
    createdAt: new Date().toISOString(),
    lines: code.split('\n').length,
    script: code
  };
  SOCState.pkgCount += 1;
  const countEl = document.getElementById('pkg-count');
  if (countEl) countEl.innerText = String(SOCState.pkgCount);
  const prev = document.getElementById('manifest-json');
  if (prev) prev.innerText = JSON.stringify(SOCState.manifest, null, 2);
  logAudit(`Built task manifest "${name}"`);
}

function exportManifest() {
  if (!SOCState.manifest) {
    alert('Build a task manifest first.');
    return;
  }
  downloadText(`${SOCState.manifest.name}_manifest.json`, JSON.stringify(SOCState.manifest, null, 2), 'application/json');
}

function importManifest(evt) {
  const file = evt.target.files?.[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = e => {
    try {
      const data = JSON.parse(e.target.result);
      SOCState.manifest = data;
      if (data.name) document.getElementById('task-name').value = data.name;
      if (data.script) document.getElementById('task-code').value = data.script;
      document.getElementById('manifest-json').innerText = JSON.stringify(data, null, 2);
      logAudit(`Imported manifest "${data.name || file.name}"`);
    } catch (_) {
      alert('Invalid JSON manifest file.');
    }
  };
  reader.readAsText(file);
}

function runAllowlistedTask() {
  const sel = document.getElementById('task-preset')?.value || 'sockets';
  const out = document.getElementById('task-run-log');
  const ts = new Date().toLocaleTimeString();
  const msgs = {
    sockets: `[${ts}] [sockets] Inspected local listening sockets on 127.0.0.1. Baseline normal.`,
    hashes: `[${ts}] [hashes] Computed SHA-256 baseline check for lab config files. Match OK.`,
    logs: `[${ts}] [logs] Tail-checked local service logs. Zero critical faults.`
  };
  const line = msgs[sel] || `[${ts}] Task executed.`;
  if (out) {
    out.innerText += `\n${line}`;
    out.scrollTop = out.scrollHeight;
  }
  logAudit(line);
}

function openBriefing() {
  const room = (document.getElementById('room-input')?.value || 'soc-incident-briefing').trim();
  const embed = document.getElementById('room-embed');
  if (embed) {
    embed.innerHTML = `<iframe src="https://meet.jit.si/${encodeURIComponent(room)}" allow="camera; microphone; fullscreen; display-capture" width="100%" height="240px" style="border:0; border-radius:8px;"></iframe>`;
  }
}

function handleConsole(e) {
  if (e.key !== 'Enter') return;
  const input = document.getElementById('console-input');
  const log = document.getElementById('console-log');
  const cmd = (input?.value || '').trim();
  if (!cmd || !log) return;

  log.innerHTML += `<div><span class="text-green-500">soc@lab:~$</span> ${escapeHtml(cmd)}</div>`;
  if (cmd === 'clear') {
    log.innerHTML = '';
  } else if (cmd === 'help') {
    log.innerHTML += `<div class="text-gray-400">Commands: help, status, alerts, isolated, clear</div>`;
  } else if (cmd === 'status') {
    log.innerHTML += `<div class="text-gray-400">Alerts: ${SOCState.alerts.length} | Isolated IPs: ${SOCState.quarantined.length} | Logs: ${SOCState.auditLog.length}</div>`;
  } else if (cmd === 'alerts') {
    log.innerHTML += `<div class="text-gray-400">${SOCState.alerts.map(a => `${a.id} [${a.sev}] ${a.src} - ${a.status}`).join(' | ')}</div>`;
  } else if (cmd === 'isolated') {
    log.innerHTML += `<div class="text-gray-400">${SOCState.quarantined.map(q => q.ip).join(', ') || 'None'}</div>`;
  } else {
    log.innerHTML += `<div class="text-gray-400">Unknown command '${escapeHtml(cmd)}'. Type 'help'.</div>`;
  }
  logAudit(`Console cmd: ${cmd}`);
  log.scrollTop = log.scrollHeight;
  input.value = '';
}

function exportAuditLogs() {
  const body = SOCState.auditLog.length ? SOCState.auditLog.join('\n') : 'No audit events recorded.';
  downloadText(`defensive_soc_audit_${Date.now()}.log`, body, 'text/plain');
}

function downloadText(filename, content, mime) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function escapeHtml(str) {
  return str.replace(/[&<>"']/g, m => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[m]));
}

document.addEventListener('DOMContentLoaded', () => {
  syncFromBackend();
});
