# LogSpector

Web log analyzer: paste/upload logs, auto-detect format, extract IPs, check AbuseIPDB + VirusTotal, chart results, export CSV/JSON/PDF, per-user history.

**Stack:** React 18 + Vite + Recharts + jsPDF | Node + Express + MongoDB + JWT | Python 3.10+ parser (called via child_process)

## Build guide (do these in order)

### 1. Install tools (and why)
- **Node.js LTS** (runs the backend and builds the frontend): `node -v`, `npm -v`
- **Python 3.10+** (runs the parser): `python --version` (or `python3 --version`)
- **Git** (version control, needed for deployment): `git --version`
- **VS Code** (editor). **Postman** (optional, tests the API).

### 2. Project setup
Copy this folder structure, then `git init` in the root.

### 3. Backend
1. `cd backend && npm install`
2. Copy `.env.example` to `.env`.
3. **MongoDB Atlas:** sign up at mongodb.com/atlas, create a free M0 cluster, *Database Access* -> add a user + password, *Network Access* -> allow `0.0.0.0/0` (for learning), *Connect* -> *Drivers* -> copy the connection string into `MONGO_URI` (add `/logspector` before the `?`).
4. **AbuseIPDB:** free account at abuseipdb.com -> *API* tab -> create key -> `ABUSEIPDB_KEY`.
5. **VirusTotal:** free account at virustotal.com -> profile -> *API key* -> `VIRUSTOTAL_KEY` (free tier: 4 lookups/min, so some IPs may show no VT result).
6. Set `JWT_SECRET` to any long random string.
7. `npm run dev` -> you should see "MongoDB connected".
8. Test: `curl -X POST localhost:5000/api/auth/signup -H "Content-Type: application/json" -d '{"email":"a@b.com","password":"secret1"}'`

### 4. Python parser
```
cd parser-service
python -m venv venv
venv\Scripts\activate        # Windows   |   source venv/bin/activate  # Mac/Linux
python main.py sample.log
```
No packages are needed (standard library only). A virtual environment keeps a project's Python packages separate from other projects.

### 5. Frontend
`cd frontend && npm install && npm run dev` -> open http://localhost:5173. Sign up, paste a sample log, click Analyze.

### 6. Connect and debug
Run backend (port 5000) and frontend (5173) together. If Python isn't found, set `PYTHON_CMD=python3` in `.env`.

### 7. Sample logs for testing
```
# Apache/Nginx
203.0.113.5 - - [10/Oct/2026:13:55:36 +0000] "GET /admin HTTP/1.1" 403 512
198.51.100.7 - - [10/Oct/2026:13:55:40 +0000] "POST /login HTTP/1.1" 200 1024
# Syslog
Oct 10 13:55:36 server sshd[123]: Failed password for root from 203.0.113.5 port 22
# Firewall
Oct 10 13:55:36 fw1 DROP TCP SRC=203.0.113.5 DST=10.0.0.4 DPT=22
# Custom App
2026-10-10 13:55:36 ERROR Login failed for user admin from 198.51.100.7
# CSV
ip,timestamp,status,request
203.0.113.5,2026-10-10T13:55:36Z,404,/wp-login.php
# JSON
{"ip":"203.0.113.5","timestamp":"2026-10-10T13:55:36Z","status":401,"request":"/api/login"}
```
(203.0.113.x and 198.51.100.x are reserved documentation IPs, so AbuseIPDB may return score 0. Use a known bad IP from public blocklists to see a flag.)

### 8. Deploy
1. Push to GitHub (`.env` is git-ignored).
2. **Render** (Web Service): root `backend`, build `npm install`, start `npm start`. Add all `.env` vars, set `CLIENT_URL` to your Vercel URL. Render's Node image includes Python 3, so set `PYTHON_CMD=python3`.
3. **Vercel:** root `frontend`, framework Vite, env `VITE_API_URL=https://your-render-url`.
4. In Atlas *Network Access*, keep Render able to connect.

## Common errors
- **"next is not a function"**: in Mongoose 8, async `pre('save')` hooks must not take `next` (already handled in `User.js`).
- **Cannot find module**: run `npm install` in the right folder.
- **Port in use**: change `PORT` or stop the other process.
- **CORS error**: `CLIENT_URL` in backend `.env` must exactly match the frontend URL.
- **MongoDB connection error**: check password (URL-encode special characters) and Atlas IP allow-list.
- **Python not found**: set `PYTHON_CMD` to `python3` or `py`.

## Next steps
GeoIP map, email alerts, real-time monitoring, user roles, scheduled reports, API keys, anomaly detection, mobile polish, social login, tagging.

MIT License.
