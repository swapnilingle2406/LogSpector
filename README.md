# LogSpector

A web-based log analysis dashboard for security analysts. Paste or upload raw logs, get parsed results, threat-intel enrichment, and exportable reports.

## Overview

LogSpector takes raw log input, auto-detects the format, extracts indicators of compromise (primarily IP addresses), enriches them against AbuseIPDB and VirusTotal, and presents the results in a filterable dashboard with charts, a results table, and export options. Each user has a private analysis history.

It was built as a portfolio project focused on SOC / blue team workflows — the goal was to work through the full pipeline a tier-1 analyst touches: ingest, parse, enrich, visualize, report.

## Features

- Paste or upload log files
- Automatic format detection: Apache/Nginx, Syslog, firewall, custom application, CSV, JSON
- IP extraction and threat-intel lookup via AbuseIPDB and VirusTotal
- Dashboard with stat cards, charts, and a results table
- Export results as CSV, JSON, or PDF
- Per-user analysis history with delete
- JWT-based authentication

## Architecture
frontend (React + Vite)
| axios POST /api/analyze
v
backend (Node + Express)
| child_process.execFile
v
parser-service (Python)
| structured JSON back to Node
v
threat intel (AbuseIPDB, VirusTotal)
|
v
MongoDB (analysis records, users)

- Frontend: React 18, Vite, Recharts, jsPDF
- Backend: Node, Express, Mongoose, JWT
- Parser: Python 3.10+, standard library only
- Database: MongoDB Atlas

The Python parser is called from Node via execFile (not exec) to avoid shell injection when handling untrusted log input.

## Getting started

### Prerequisites

- Node.js LTS
- Python 3.10+
- A MongoDB Atlas cluster (free tier is fine)
- AbuseIPDB and VirusTotal API keys (both free)

### Setup

1. Clone the repository.
2. Create backend/.env from backend/.env.example and fill in:
   - MONGO_URI — your Atlas connection string (append /logspector before the ?)
   - ABUSEIPDB_KEY
   - VIRUSTOTAL_KEY
   - JWT_SECRET — any long random string
   - PYTHON_CMD — python on Windows, python3 on macOS/Linux
3. In Atlas, add your IP to Network Access (or 0.0.0.0/0 for local development).
4. Install and start the backend:
cd backend
npm install
npm run dev

5. Install and start the frontend in a second terminal:
cd frontend
npm install
npm run dev

6. Open http://localhost:5173, sign up, and paste a sample log.

### Sample logs

Apache/Nginx:
203.0.113.5 - - [10/Oct/2026:13:55:36 +0000] "GET /admin HTTP/1.1" 403 512


Syslog:
Oct 10 13:55:36 server sshd[123]: Failed password for root from 203.0.113.5 port 22


Firewall:
Oct 10 13:55:36 fw1 DROP TCP SRC=203.0.113.5 DST=10.0.0.4 DPT=22


JSON:
{"ip":"203.0.113.5","timestamp":"2026-10-10T13:55:36Z","status":401,"request":"/api/login"}


Note: 203.0.113.x and 198.51.100.x are reserved documentation ranges, so AbuseIPDB will report them as clean. Use a known-bad IP to see the threat-intel path trigger.

## Deployment

- Backend to Render: root backend, build npm install, start npm start. Set all .env variables. Render's Node image includes Python 3 — set PYTHON_CMD=python3. Set CLIENT_URL to your Vercel URL.
- Frontend to Vercel: root frontend, framework Vite. Set VITE_API_URL to your Render URL.
- Keep Atlas Network Access open to Render.

## Security notes

- .env is git-ignored; no secrets are committed.
- The Python parser is invoked via execFile to prevent shell injection from untrusted log content.
- JWTs are used for stateless auth; tokens are signed with JWT_SECRET.

## Roadmap

- GeoIP enrichment and map view
- Anomaly detection (failed-login spikes, 403 bursts from a single source)
- Entry tagging for triage workflows
- Scheduled reports
- API keys for programmatic access

## License

MIT
