import { useState, useEffect, useMemo } from 'react';
import axios from 'axios';
import { PieChart, Pie, Cell, Tooltip, BarChart, Bar, XAxis, YAxis, ResponsiveContainer } from 'recharts';
import { jsPDF } from 'jspdf';
import './App.css';

const API = import.meta.env.VITE_API_URL || 'http://localhost:5000';
const COLORS = ['#22c55e', '#16a34a', '#eab308', '#f97316', '#ef4444', '#38bdf8'];

export default function App() {
  const [token, setToken] = useState(localStorage.getItem('token'));
  const [resetToken, setResetToken] = useState(new URLSearchParams(window.location.search).get('reset'));
  const [mode, setMode] = useState(resetToken ? 'reset' : 'login');
  const [form, setForm] = useState({ email: '', password: '' });
  const [logs, setLogs] = useState('');
  const [filename, setFilename] = useState('');
  const [fileKey, setFileKey] = useState(0);
  const [result, setResult] = useState(null);
  const [history, setHistory] = useState([]);
  const [showHistory, setShowHistory] = useState(false);
  const [search, setSearch] = useState('');
  const [onlyBad, setOnlyBad] = useState(false);
  const [error, setError] = useState('');
  const [info, setInfo] = useState('');
  const [loading, setLoading] = useState(false);

  const cfg = { headers: { Authorization: `Bearer ${token}` } };

  const loadHistory = async () => {
    try { setHistory((await axios.get(`${API}/api/history`, cfg)).data); }
    catch { logout(); }
  };
  useEffect(() => { if (token) loadHistory(); }, [token]); // eslint-disable-line

  const goMode = (m) => { setMode(m); setError(''); setInfo(''); };

  const submitAuth = async () => {
    setError(''); setInfo('');
    try {
      const { data } = await axios.post(`${API}/api/auth/${mode}`, form);
      localStorage.setItem('token', data.token); setToken(data.token);
    } catch (e) { setError(e.response?.data?.error || 'Server not reachable'); }
  };

  const sendReset = async () => {
    setError(''); setInfo('');
    try {
      const { data } = await axios.post(`${API}/api/auth/forgot`, { email: form.email });
      setInfo(data.message);
    } catch (e) { setError(e.response?.data?.error || 'Server not reachable'); }
  };

  const saveNewPassword = async () => {
    setError(''); setInfo('');
    try {
      const { data } = await axios.post(`${API}/api/auth/reset`, { token: resetToken, password: form.password });
      window.history.replaceState({}, '', window.location.pathname); // remove ?reset=... from the address bar
      setResetToken(null);
      setForm({ email: form.email, password: '' });
      setMode('login');
      setInfo(data.message);
    } catch (e) { setError(e.response?.data?.error || 'Server not reachable'); }
  };

  const logout = () => { localStorage.removeItem('token'); setToken(null); setResult(null); };

  const onFile = (e) => {
    const f = e.target.files[0]; if (!f) return;
    setFilename(f.name);
    const r = new FileReader(); r.onload = () => setLogs(r.result); r.readAsText(f);
  };

  // Empties the log box and resets the file picker so the same file can be chosen again
  const clearLogs = () => {
    setLogs('');
    setFilename('');
    setError('');
    setFileKey((k) => k + 1);
  };

  const analyze = async () => {
    setError(''); setLoading(true);
    try {
      const { data } = await axios.post(`${API}/api/analyze`, { logs, filename }, cfg);
      setResult(data); loadHistory();
    } catch (e) { setError(e.response?.data?.error || 'Analysis failed'); }
    setLoading(false);
  };

  const rows = useMemo(() => (result?.entries || []).filter((e) =>
    (!onlyBad || e.suspicious) && JSON.stringify(e).toLowerCase().includes(search.toLowerCase())), [result, search, onlyBad]);

  const statusData = Object.entries(result?.statusCounts || {}).map(([name, value]) => ({ name, value }));
  const ipCounts = {};
  (result?.entries || []).forEach((e) => { if (e.ip) ipCounts[e.ip] = (ipCounts[e.ip] || 0) + 1; });
  const topIps = Object.entries(ipCounts).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([ip, count]) => ({ ip, count }));

  const download = (content, name, type) => {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([content], { type })); a.download = name; a.click();
  };
  const exportJSON = () => download(JSON.stringify(rows, null, 2), 'logspector.json', 'application/json');
  const exportCSV = () => {
    const q = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`;
    download(['ip,timestamp,status,request,suspicious', ...rows.map((r) =>
      [r.ip, r.timestamp, r.status, r.request, r.suspicious].map(q).join(','))].join('\n'), 'logspector.csv', 'text/csv');
  };
  const exportPDF = () => {
    const doc = new jsPDF(); let y = 15;
    doc.text(`LogSpector report - ${result.format} - ${result.total} entries`, 10, y);
    rows.slice(0, 40).forEach((r) => {
      y += 8; if (y > 280) { doc.addPage(); y = 15; }
      doc.setFontSize(8); doc.text(`${r.ip || '-'} | ${r.status || '-'} | ${String(r.request || '').slice(0, 90)}`, 10, y);
    });
    doc.save('logspector.pdf');
  };

  // ---------- Login / signup / forgot / reset screen ----------
  if (!token || mode === 'reset') return (
    <div className="wrap" style={{ maxWidth: 400 }}>
      <h1>LogSpector</h1>
      <div className="card">
        <h2>
          {mode === 'login' && 'Log in'}
          {mode === 'signup' && 'Sign up'}
          {mode === 'forgot' && 'Forgot password'}
          {mode === 'reset' && 'Choose a new password'}
        </h2>
        {error && <div className="err">{error}</div>}
        {info && <div style={{ color: '#22c55e', marginBottom: 10 }}>{info}</div>}

        {(mode === 'login' || mode === 'signup') && (<>
          <input placeholder="Email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} />
          <input placeholder="Password (6+ chars)" type="password" value={form.password}
            onChange={(e) => setForm({ ...form, password: e.target.value })} />
          <button onClick={submitAuth}>{mode === 'login' ? 'Log in' : 'Create account'}</button>
          <button className="ghost" onClick={() => goMode(mode === 'login' ? 'signup' : 'login')}>
            {mode === 'login' ? 'Need an account?' : 'Have an account?'}</button>
          {mode === 'login' && <button className="ghost" onClick={() => goMode('forgot')}>Forgot password?</button>}
        </>)}

        {mode === 'forgot' && (<>
          <input placeholder="Your account email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} />
          <button onClick={sendReset}>Send reset link</button>
          <button className="ghost" onClick={() => goMode('login')}>Back to log in</button>
        </>)}

        {mode === 'reset' && (<>
          <input placeholder="New password (6+ chars)" type="password" value={form.password}
            onChange={(e) => setForm({ ...form, password: e.target.value })} />
          <button onClick={saveNewPassword}>Save new password</button>
        </>)}
      </div>
    </div>
  );

  return (
    <div className="wrap">
      <header><h1>LogSpector</h1><button className="ghost" onClick={logout}>Log out</button></header>

      <div className="card">
        <h2>Analyze logs</h2>
        <input key={fileKey} type="file" accept=".txt,.log,.json,.csv" onChange={onFile} />
        <div className="logbox">
          <textarea placeholder="...or paste logs here" value={logs} onChange={(e) => setLogs(e.target.value)} />
          {logs && (
            <button className="clear-btn" onClick={clearLogs} title="Clear logs" aria-label="Clear logs">×</button>
          )}
        </div>
        {error && <div className="err">{error}</div>}
        <button onClick={analyze} disabled={loading || !logs.trim()}>{loading ? 'Analyzing...' : 'Analyze'}</button>
      </div>

      {result && (<>
        <div className="stats">
          <div className="card stat"><b>{result.format}</b><span>Detected format</span></div>
          <div className="card stat"><b>{result.total}</b><span>Entries</span></div>
          <div className="card stat"><b>{result.intel.length}</b><span>IPs checked</span></div>
          <div className="card stat"><b style={{ color: '#ef4444' }}>{result.suspiciousCount}</b><span>Suspicious IPs</span></div>
        </div>

        {(result.anomalies || []).length > 0 && (
          <div className="card">
            <h2>Anomalies detected</h2>
            {result.anomalies.map((a, i) => (
              <div key={i} style={{ padding: 8, borderLeft: '4px solid ' + (a.severity === 'HIGH' ? '#ef4444' : '#eab308'), marginBottom: 6 }}>
                <b>{a.severity}</b> · {a.type} · {a.ip} · {a.detail}
              </div>
            ))}
          </div>
        )}

        <div className="charts">
          <div className="card"><h2>Status codes</h2><ResponsiveContainer width="100%" height={220}>
            <PieChart><Pie data={statusData} dataKey="value" nameKey="name" outerRadius={80} label>
              {statusData.map((_, i) => <Cell key={i} fill={COLORS[i % COLORS.length]} />)}</Pie><Tooltip /></PieChart>
          </ResponsiveContainer></div>
          <div className="card"><h2>Top IPs</h2><ResponsiveContainer width="100%" height={220}>
            <BarChart data={topIps}><XAxis dataKey="ip" tick={{ fontSize: 10, fill: '#7f9a88' }} /><YAxis tick={{ fill: '#7f9a88' }} />
              <Tooltip /><Bar dataKey="count" fill="#22c55e" /></BarChart>
          </ResponsiveContainer></div>
        </div>
        <div className="card">
          <div className="row">
            <input placeholder="Search..." value={search} onChange={(e) => setSearch(e.target.value)} />
            <label style={{ paddingTop: 10 }}><input type="checkbox" style={{ width: 'auto' }} checked={onlyBad}
              onChange={(e) => setOnlyBad(e.target.checked)} /> Suspicious only</label>
          </div>
          <button onClick={exportCSV}>CSV</button><button onClick={exportJSON}>JSON</button><button onClick={exportPDF}>PDF</button>
          <div className="tablebox"><table><thead><tr><th>IP</th><th>Time</th><th>Status</th><th>Request</th></tr></thead>
            <tbody>{rows.slice(0, 200).map((r, i) => (
              <tr key={i} className={r.suspicious ? 'bad' : ''}><td>{r.ip}</td><td>{r.timestamp}</td><td>{r.status}</td>
                <td>{String(r.request || '').slice(0, 120)}</td></tr>))}</tbody></table></div>
        </div>
      </>)}

      <div className="card">
        <div className="history-head">
          <h2>History ({history.length})</h2>
          <button
            className={`toggle-btn ${showHistory ? 'open' : ''}`}
            onClick={() => setShowHistory(!showHistory)}
            title={showHistory ? 'Hide history' : 'Show history'}
            aria-label={showHistory ? 'Hide history' : 'Show history'}
          >
            <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor"
              strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="10" />
              <path d="M12 8v8M8 12l4 4 4-4" />
            </svg>
          </button>
        </div>
        {showHistory && (
          <div className="history-list">
            {history.length === 0 && <span style={{ color: '#7f9a88' }}>No analyses yet.</span>}
            {history.map((h) => (
              <div key={h._id} className="row" style={{ marginBottom: 6, alignItems: 'center' }}>
                <span>{h.filename} - {h.format} - {h.total} entries - {new Date(h.createdAt).toLocaleString()}</span>
                <span><button className="ghost" onClick={() => setResult(h)}>Open</button>
                  <button className="ghost" onClick={async () => { await axios.delete(`${API}/api/history/${h._id}`, cfg); loadHistory(); }}>Delete</button></span>
              </div>))}
          </div>
        )}
      </div>
    </div>
  );
}