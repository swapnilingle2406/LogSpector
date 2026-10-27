require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFile } = require('child_process'); // execFile is safer than exec (no shell injection)
const rateLimit = require('express-rate-limit');
const { detectAnomalies } = require('./anomaly');
const User = require('./models/User');
const Analysis = require('./models/Analysis');

const app = express();
app.set('trust proxy', 1); // needed when deployed on Render, harmless locally
app.use(cors({ origin: process.env.CLIENT_URL || 'http://localhost:5173' }));
app.use(express.json({ limit: '5mb' }));

// Rate limits: block password guessing and protect your free API quotas
app.use('/api/auth', rateLimit({ windowMs: 15 * 60 * 1000, max: 20, message: { error: 'Too many attempts, try later' } }));
app.use('/api/analyze', rateLimit({ windowMs: 60 * 1000, max: 10, message: { error: 'Max 10 analyses per minute' } }));

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB connected'))
  .catch((e) => console.error('MongoDB error:', e.message));

const sign = (u) => jwt.sign({ id: u._id }, process.env.JWT_SECRET, { expiresIn: '7d' });

function auth(req, res, next) {
  try {
    const token = (req.headers.authorization || '').replace('Bearer ', '');
    req.userId = jwt.verify(token, process.env.JWT_SECRET).id;
    next();
  } catch {
    res.status(401).json({ error: 'Please log in' });
  }
}

// ---------- Auth ----------
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (typeof email !== 'string' || typeof password !== 'string')
      return res.status(400).json({ error: 'Invalid input' });
    if (!email || !password || password.length < 6)
      return res.status(400).json({ error: 'Email and a password of 6+ characters required' });
    if (await User.findOne({ email })) return res.status(400).json({ error: 'Email already registered' });
    const user = await User.create({ email, password });
    res.json({ token: sign(user), email: user.email });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    if (typeof req.body.email !== 'string' || typeof req.body.password !== 'string')
      return res.status(400).json({ error: 'Invalid input' });
    const user = await User.findOne({ email: req.body.email });
    if (!user || !(await user.comparePassword(req.body.password)))
      return res.status(401).json({ error: 'Wrong email or password' });
    res.json({ token: sign(user), email: user.email });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ---------- Forgot / reset password ----------
async function sendResetEmail(to, link) {
  await axios.post('https://api.brevo.com/v3/smtp/email', {
    sender: { name: 'LogSpector', email: process.env.MAIL_FROM },
    to: [{ email: to }],
    subject: 'Reset your LogSpector password',
    htmlContent: `<p>Click the link below to choose a new password. It expires in 15 minutes.</p>
      <p><a href="${link}">${link}</a></p>
      <p>If you did not ask for this, you can ignore this email.</p>`,
  }, {
    headers: { 'api-key': process.env.BREVO_API_KEY, 'content-type': 'application/json' },
    timeout: 10000,
  });
}

app.post('/api/auth/forgot', async (req, res) => {
  // Same answer whether or not the email exists, so nobody can check who has an account
  const generic = { message: 'If that email is registered, a reset link has been sent.' };
  try {
    if (typeof req.body.email !== 'string') return res.status(400).json({ error: 'Invalid input' });
    const user = await User.findOne({ email: req.body.email.toLowerCase().trim() });
    if (user) {
      const token = crypto.randomBytes(32).toString('hex');
      user.resetTokenHash = crypto.createHash('sha256').update(token).digest('hex');
      user.resetTokenExpires = new Date(Date.now() + 15 * 60 * 1000);
      await user.save();
      const base = (process.env.CLIENT_URL || 'http://localhost:5173').replace(/\/$/, '');
      await sendResetEmail(user.email, `${base}/?reset=${token}`);
    }
    res.json(generic);
  } catch (e) {
    console.error('Forgot password error:', e.response?.data || e.message);
    res.json(generic);
  }
});

app.post('/api/auth/reset', async (req, res) => {
  try {
    const { token, password } = req.body;
    if (typeof token !== 'string' || typeof password !== 'string' || password.length < 6)
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    const hash = crypto.createHash('sha256').update(token).digest('hex');
    const user = await User.findOne({ resetTokenHash: hash, resetTokenExpires: { $gt: new Date() } });
    if (!user) return res.status(400).json({ error: 'Reset link is invalid or expired' });
    user.password = password;
    user.resetTokenHash = undefined;
    user.resetTokenExpires = undefined;
    await user.save();
    res.json({ message: 'Password updated. You can log in now.' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ---------- Threat intel ----------
async function lookup(ip) {
  const out = { ip, abuseScore: null, vtMalicious: null, suspicious: false };
  try {
    if (process.env.ABUSEIPDB_KEY) {
      const r = await axios.get('https://api.abuseipdb.com/api/v2/check', {
        params: { ipAddress: ip, maxAgeInDays: 90 },
        headers: { Key: process.env.ABUSEIPDB_KEY, Accept: 'application/json' }, timeout: 8000,
      });
      out.abuseScore = r.data.data.abuseConfidenceScore;
    }
  } catch (e) { /* private IP or rate limit: null */ }
  try {
    if (process.env.VIRUSTOTAL_KEY) {
      const r = await axios.get(`https://www.virustotal.com/api/v3/ip_addresses/${ip}`, {
        headers: { 'x-apikey': process.env.VIRUSTOTAL_KEY }, timeout: 8000,
      });
      out.vtMalicious = r.data.data.attributes.last_analysis_stats.malicious;
    }
  } catch (e) { /* VT free tier = 4 requests/min */ }
  out.suspicious = (out.abuseScore ?? 0) >= 25;
  return out;
}

// ---------- Analyze ----------
app.post('/api/analyze', auth, (req, res) => {
  const { logs, filename } = req.body;
  if (typeof logs !== 'string' || !logs.trim()) return res.status(400).json({ error: 'No logs provided' });

  const tmp = path.join(os.tmpdir(), `logspector-${Date.now()}.log`);
  fs.writeFileSync(tmp, logs);
  const script = path.join(__dirname, '..', 'parser-service', 'main.py');

  execFile(process.env.PYTHON_CMD || 'python', [script, tmp],
    { maxBuffer: 20 * 1024 * 1024, timeout: 20000 }, async (err, stdout) => {
      fs.unlink(tmp, () => {});
      if (err) return res.status(500).json({ error: 'Parser failed: ' + err.message });
      try {
        const parsed = JSON.parse(stdout);
        const ips = [...new Set(parsed.entries.map((e) => e.ip).filter(Boolean))].slice(0, 15);
        const intel = [];
        for (const ip of ips) intel.push(await lookup(ip)); // sequential = gentler on rate limits
        const bad = new Set(intel.filter((i) => i.suspicious).map((i) => i.ip));
        const statusCounts = {};
        parsed.entries.forEach((e) => { if (e.status) statusCounts[e.status] = (statusCounts[e.status] || 0) + 1; });
        const anomalies = detectAnomalies(parsed.entries);
        const doc = await Analysis.create({
          userId: req.userId, filename: filename || 'pasted-logs', format: parsed.format,
          total: parsed.entries.length, suspiciousCount: bad.size, statusCounts, anomalies,
          entries: parsed.entries.slice(0, 500).map((e) => ({ ...e, suspicious: bad.has(e.ip) })), intel,
        });
        res.json(doc);
      } catch (e) { res.status(500).json({ error: 'Analysis failed: ' + e.message }); }
    });
});

// ---------- History ----------
app.get('/api/history', auth, async (req, res) => {
  res.json(await Analysis.find({ userId: req.userId }).sort({ createdAt: -1 }).limit(50));
});
app.delete('/api/history/:id', auth, async (req, res) => {
  await Analysis.deleteOne({ _id: req.params.id, userId: req.userId });
  res.json({ ok: true });
});

app.listen(process.env.PORT || 5000, () => console.log('API running'));