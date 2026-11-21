const express = require('express');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const AUTH_USER = process.env.SOC_USER || 'admin';
const AUTH_PASS = process.env.SOC_PASS || 'DefensiveLab2026!';

app.use(express.json({ limit: '1mb' }));

// CORS headers for local / lab tunnel access
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// HTTP Basic Authentication middleware
function basicAuth(req, res, next) {
  const header = req.headers.authorization || '';
  if (!header.startsWith('Basic ')) {
    res.setHeader('WWW-Authenticate', 'Basic realm="Defensive SOC Lab"');
    return res.status(401).json({ error: 'Authentication required' });
  }
  const decoded = Buffer.from(header.slice(6), 'base64').toString('utf8');
  const idx = decoded.indexOf(':');
  const user = idx >= 0 ? decoded.slice(0, idx) : '';
  const pass = idx >= 0 ? decoded.slice(idx + 1) : '';

  if (user === AUTH_USER && pass === AUTH_PASS) {
    return next();
  }
  res.setHeader('WWW-Authenticate', 'Basic realm="Defensive SOC Lab"');
  return res.status(401).json({ error: 'Invalid credentials' });
}

app.use(basicAuth);
app.use(express.static(path.join(__dirname, 'public')));

// In-memory defensive lab state
const startTime = Date.now();
let alerts = [
  {
    id: 'ALT-1001',
    timestamp: new Date().toISOString(),
    severity: 'HIGH',
    sourceIp: '198.51.100.42',
    ruleName: 'SURICATA SSH Brute-Force Attempt (Decoy Port 2222)',
    status: 'New'
  },
  {
    id: 'ALT-1002',
    timestamp: new Date().toISOString(),
    severity: 'MEDIUM',
    sourceIp: '203.0.113.88',
    ruleName: 'ZEEK Anomalous Outbound Stratum-like TCP Session (Port 3333)',
    status: 'Investigating'
  }
];
let quarantined = [];

app.get('/api/health', (req, res) => {
  res.json({
    status: 'online',
    uptimeSec: Math.floor((Date.now() - startTime) / 1000),
    alertCount: alerts.length,
    quarantinedCount: quarantined.length
  });
});

app.get('/api/alerts', (req, res) => {
  res.json({ alerts });
});

app.post('/api/alerts', (req, res) => {
  const { severity = 'MEDIUM', sourceIp = '192.0.2.10', ruleName = 'Lab Telemetry Event' } = req.body || {};
  const item = {
    id: `ALT-${Math.floor(1000 + Math.random() * 9000)}`,
    timestamp: new Date().toISOString(),
    severity: ['HIGH', 'MEDIUM', 'LOW'].includes(severity) ? severity : 'MEDIUM',
    sourceIp: String(sourceIp).slice(0, 45),
    ruleName: String(ruleName).slice(0, 160),
    status: 'New'
  };
  alerts.unshift(item);
  res.status(201).json({ alert: item });
});

app.patch('/api/alerts/:id', (req, res) => {
  const { status } = req.body || {};
  const allowed = ['New', 'Investigating', 'Contained', 'Resolved'];
  if (!allowed.includes(status)) {
    return res.status(400).json({ error: 'Invalid status' });
  }
  alerts = alerts.map(a => (a.id === req.params.id ? { ...a, status } : a));
  res.json({ ok: true });
});

app.get('/api/quarantine', (req, res) => {
  res.json({ quarantined });
});

app.post('/api/quarantine', (req, res) => {
  const { ip, scope = 'BLOCK_ALL', ttlMinutes = 30 } = req.body || {};
  const cleanIp = String(ip || '').trim();
  if (!cleanIp) return res.status(400).json({ error: 'IP required' });

  // Protect loopback and local gateway from accidental self-lockout
  const protectedTargets = ['127.0.0.1', 'localhost', '0.0.0.0'];
  if (protectedTargets.includes(cleanIp)) {
    return res.status(400).json({ error: 'Protected loopback/wildcard target cannot be isolated' });
  }

  const existingIdx = quarantined.findIndex(q => q.ip === cleanIp);
  const entry = {
    ip: cleanIp,
    scope,
    ttlMinutes: Number(ttlMinutes) || 30,
    isolatedAt: new Date().toISOString()
  };
  if (existingIdx >= 0) quarantined[existingIdx] = entry;
  else quarantined.push(entry);

  res.status(201).json({ quarantined });
});

app.delete('/api/quarantine/:ip', (req, res) => {
  const target = decodeURIComponent(req.params.ip);
  quarantined = quarantined.filter(q => q.ip !== target);
  res.json({ quarantined });
});

app.listen(PORT, () => {
  console.log(`[+] Defensive SOC Lab server listening on http://0.0.0.0:${PORT}`);
});
