function detectAnomalies(entries) {
  const out = [];
  const byIp = {};
  for (const e of entries) {
    if (!e.ip) continue;
    (byIp[e.ip] = byIp[e.ip] || []).push(e);
  }
  for (const ip in byIp) {
    const list = byIp[ip];
    const failed = list.filter((e) => e.status === '401' || e.status === '403').length;
    if (failed >= 5) out.push({ type: 'Brute force', severity: 'HIGH', ip, detail: failed + ' failed logins' });
    const bad = list.filter((e) => /wp-login|\/admin|\.env|etc\/passwd/i.test(e.request || '')).length;
    if (bad > 0) out.push({ type: 'Suspicious request', severity: 'MEDIUM', ip, detail: bad + ' risky requests' });
  }
  return out;
}

// IMPORTANT: keep this last line exactly as it is
module.exports = { detectAnomalies };