import { useState, useEffect, useMemo } from 'react';
import axios from 'axios';
import { PieChart, Pie, Cell, Tooltip, BarChart, Bar, XAxis, YAxis, ResponsiveContainer } from 'recharts';
import { jsPDF } from 'jspdf';
import './App.css';

const API = import.meta.env.VITE_API_URL || 'http://localhost:5000';
const COLORS = ['#22c55e', '#16a34a', '#eab308', '#f97316', '#ef4444', '#38bdf8'];

export default function App() {
  const [token, setToken] = useState(localStorage.getItem('token'));
  const [mode, setMode] = useState('login');
  const [form, setForm] = useState({ email: '', password: '' });
  const [logs, setLogs] = useState('');
  const [filename, setFilename] = useState('');
  const [result, setResult] = useState(null);
  const [history, setHistory] = useState([]);
  const [search, setSearch] = useState('');
  const [onlyBad, setOnlyBad] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const cfg = { headers: { Authorization: `Bearer ${token}` } };

  const loadHistory = async () => {
    try { setHistory((await axios.get(`${API}/api/history`, cfg)).data); }
    catch { logout(); }
  };
  useEffect(() => { if (token) loadHistory(); }, [token]); // eslint-disable-line

  const submitAuth = async () => {
    setError('');
    try {
      const { data } = await axios.post(`${API}/api/auth/${mode}`, form);
      localStorage.setItem('token', data.token); setToken(data.token);
    } catch (e) { setError(e.response?.data?.error || 'Server not reachable'); }
  };
  const logout = () => { localStorage.removeItem('token'); setToken(null); setResult(null); };

  const onFile = (e) => {
    const f = e.target.files[0]; if (!f) return;
    setFilename(f.name);
    const r = new FileReader(); r.onload = () => setLogs(r.result); r.readAsText(f);
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

  if (!token) return (
    <div className="wrap" style={{ maxWidth: 400 }}>
      <h1>LogSpector</h1>
      <div className="card">
        <h2>{mode === 'login' ? 'Log in' : 'Sign up'}</h2>
        {error && <div className="err">{error}</div>}
        <input placeholder="Email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} />
        <input placeholder="Password (6+ chars)" type="password" value={form.password}
          onChange={(e) => setForm({ ...form, password: e.target.value })} />
        <button onClick={submitAuth}>{mode === 'login' ? 'Log in' : 'Create account'}</button>
        <button className="ghost" onClick={() => setMode(mode === 'login' ? 'signup' : 'login')}>
          {mode === 'login' ? 'Need an account?' : 'Have an account?'}</button>
      </div>
    </div>
  );

  return (
    <div className="wrap">
      <header><h1>LogSpector</h1><button className="ghost" onClick={logout}>Log out</button></header>

      <div className="card">
        <h2>Analyze logs</h2>
        <input type="file" accept=".txt,.log,.json,.csv" onChange={onFile} />
        <textarea placeholder="...or paste logs here" value={logs} onChange={(e) => setLogs(e.target.value)} />
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

      <div className="card"><h2>History</h2>
        {history.length === 0 && <span style={{ color: '#7f9a88' }}>No analyses yet.</span>}
        {history.map((h) => (
          <div key={h._id} className="row" style={{ marginBottom: 6, alignItems: 'center' }}>
            <span>{h.filename} - {h.format} - {h.total} entries - {new Date(h.createdAt).toLocaleString()}</span>
            <span><button className="ghost" onClick={() => setResult(h)}>Open</button>
              <button className="ghost" onClick={async () => { await axios.delete(`${API}/api/history/${h._id}`, cfg); loadHistory(); }}>Delete</button></span>
          </div>))}
      </div>
    </div>
  );
}
