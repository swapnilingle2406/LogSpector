# LogSpector

Live demo: https://log-spector.vercel.app

<img width="1332" height="557" alt="image" src="https://github.com/user-attachments/assets/c9d02595-0269-481c-99b6-22d75645ad4c" />
<img width="1338" height="474" alt="image" src="https://github.com/user-attachments/assets/a82013e6-14e0-4bb5-80a3-8f32ca250b67" />
<img width="1350" height="630" alt="image" src="https://github.com/user-attachments/assets/8904f25b-a38c-46e6-a4d7-97c7f222b439" />


A web-based log analysis dashboard for security analysts. Paste or upload raw logs, get them parsed automatically, enrich the IP addresses with threat intelligence, and see suspicious activity flagged on a dashboard.

> The live demo runs on free hosting. If the first request takes about a minute, the backend is waking up from sleep.

## Features

- **Paste or upload logs** (`.txt`, `.log`, `.json`, `.csv`) with a one-click clear button
- **Automatic format detection** for Apache, Nginx, JSON, CSV, Syslog, Windows Events, AWS CloudTrail, firewall logs, custom app logs, and plain text
- **Parsing** of IP addresses, timestamps, status codes and requests
- **Threat intelligence** lookups against AbuseIPDB and VirusTotal; IPs with an abuse score of 25 or higher are flagged as suspicious
- **Anomaly detection** (rule-based):
  - **HIGH, brute force:** 5 or more failed logins (HTTP 401/403) from one IP
  - **MEDIUM, suspicious request:** requests to paths attackers commonly probe, such as `/wp-login`, `/admin`, `.env` and `/etc/passwd`
- **Dashboard** with stat cards, a status-code pie chart, a top-IPs bar chart, and a searchable, filterable results table
- **Export** results as CSV, JSON or PDF
- **Accounts:** signup and login with JWT, plus password reset by emailed link
- **Per-user history** of past analyses, collapsible to keep the page tidy
- **Dark green UI**

## Tech stack

| Layer | Technology |
|---|---|
| Frontend | React 18, Vite, Recharts, jsPDF, Axios |
| Backend | Node.js, Express, Mongoose, JWT, bcrypt |
| Parser | Python 3.10+ (standard library only), called from Node with `execFile` |
| Database | MongoDB Atlas (free tier) |
| Threat intel | AbuseIPDB, VirusTotal |
| Email | Brevo transactional email API (password reset) |
| Hosting | Vercel (frontend), Render (backend) |

## How it works

```
Browser (React)
   |  POST /api/analyze  (logs + JWT)
   v
Express API
   |  1. writes logs to a temp file
   |  2. runs parser-service/main.py (20 second timeout)
   |  3. looks up up to 15 unique IPs on AbuseIPDB and VirusTotal
   |  4. runs anomaly detection on the parsed entries
   |  5. saves the analysis to MongoDB for that user
   v
Browser shows stats, anomalies, charts, table and history
```

## Project structure

```
LogSpector/
├── backend/
│   ├── index.js            # Express server: auth, analyze, history, password reset
│   ├── anomaly.js          # Rule-based anomaly detection
│   ├── models/
│   │   ├── User.js         # User schema with password hashing and reset token fields
│   │   └── Analysis.js     # Saved analysis schema (linked to a user)
│   ├── package.json
│   └── .env.example
├── frontend/
│   ├── src/
│   │   ├── App.jsx         # Whole UI: auth screens, upload, charts, table, history
│   │   ├── App.css
│   │   ├── main.jsx
│   │   └── index.css
│   ├── index.html
│   ├── package.json
│   └── vite.config.js
├── parser-service/
│   ├── main.py             # Format detection and parsing
│   └── requirements.txt
├── .gitignore
├── LICENSE
└── README.md
```

## Run it locally

**You need:** Node.js (LTS), Python 3.10+, Git, a free MongoDB Atlas cluster, and free AbuseIPDB and VirusTotal API keys. A Brevo account is only needed for the password reset email.

```bash
git clone https://github.com/swapnilingle2406/LogSpector.git
cd LogSpector
```

**Backend**

```bash
cd backend
npm install
cp .env.example .env     # then fill in your values
npm run dev
```

You should see `API running` and `MongoDB connected`.

**Frontend** (in a second terminal)

```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:5173.

### Environment variables

Backend (`backend/.env`, never commit this file):

| Variable | What it is |
|---|---|
| `MONGO_URI` | MongoDB Atlas connection string |
| `JWT_SECRET` | Long random string used to sign login tokens |
| `ABUSEIPDB_KEY` | AbuseIPDB API key |
| `VIRUSTOTAL_KEY` | VirusTotal API key |
| `CLIENT_URL` | Frontend address allowed by CORS, e.g. `http://localhost:5173` |
| `PYTHON_CMD` | `python` on Windows, `python3` on Mac, Linux and Render |
| `BREVO_API_KEY` | Brevo API key (password reset email) |
| `MAIL_FROM` | Verified Brevo sender address |
| `PORT` | Optional locally; Render sets its own |

Frontend (set on Vercel, optional locally):

| Variable | What it is |
|---|---|
| `VITE_API_URL` | Backend address, e.g. `https://your-backend.onrender.com` |

## API routes

| Method | Route | Auth | Purpose |
|---|---|---|---|
| POST | `/api/auth/signup` | No | Create an account |
| POST | `/api/auth/login` | No | Log in, returns a JWT |
| POST | `/api/auth/forgot` | No | Email a password reset link |
| POST | `/api/auth/reset` | No | Set a new password using the emailed token |
| POST | `/api/analyze` | Yes | Parse and analyze logs |
| GET | `/api/history` | Yes | List the user's saved analyses |
| DELETE | `/api/history/:id` | Yes | Delete one analysis |

## Security notes

- Passwords are hashed with bcrypt; login tokens are JWTs that expire after 7 days.
- Password reset tokens are random, stored only as a SHA-256 hash, valid for 15 minutes, and cleared after use. The forgot-password route gives the same answer whether or not an email exists, so it can't be used to discover accounts.
- Rate limits: 20 auth requests per 15 minutes and 10 analyses per minute per client.
- Auth and analyze inputs are type-checked, which blocks NoSQL injection attempts such as `{"$ne": null}`.
- The Python parser is started with `execFile` (no shell) and a 20 second timeout, so a log can't inject commands or hang the server.
- Secrets live in environment variables and `.env` is git-ignored.

## Try it with sample logs

Paste this into the log box. It should be detected as Apache and raise a HIGH brute-force finding and a MEDIUM suspicious-request finding. Each line must start at the left edge, with no spaces before the IP.

```
203.0.113.9 - - [10/Oct/2026:13:55:01 +0000] "POST /login HTTP/1.1" 401 120
203.0.113.9 - - [10/Oct/2026:13:55:02 +0000] "POST /login HTTP/1.1" 401 120
203.0.113.9 - - [10/Oct/2026:13:55:03 +0000] "POST /login HTTP/1.1" 401 120
203.0.113.9 - - [10/Oct/2026:13:55:04 +0000] "POST /login HTTP/1.1" 401 120
203.0.113.9 - - [10/Oct/2026:13:55:05 +0000] "POST /login HTTP/1.1" 401 120
203.0.113.9 - - [10/Oct/2026:13:55:09 +0000] "GET /wp-login.php HTTP/1.1" 404 0
```

Other formats it recognizes:

```
# Syslog
Oct 10 13:55:36 server sshd[123]: Failed password for root from 203.0.113.5 port 22

# Firewall
Oct 10 13:55:36 fw1 DROP TCP SRC=203.0.113.5 DST=10.0.0.4 DPT=22

# Custom app
2026-10-10 13:55:36 ERROR Login failed for user admin from 198.51.100.7

# CSV
ip,timestamp,status,request
203.0.113.5,2026-10-10T13:55:36Z,404,/wp-login.php

# JSON
{"ip":"203.0.113.5","timestamp":"2026-10-10T13:55:36Z","status":401,"request":"/api/login"}
```

The `203.0.113.x` and `198.51.100.x` addresses are reserved for documentation, so AbuseIPDB will usually score them 0. Use a real reported IP from a public blocklist to see the "suspicious IP" flag.

## Deployment

- **Backend (Render):** root directory `backend`, build command `npm install`, start command `npm start`. Add the backend environment variables above, with `CLIENT_URL` set to your Vercel address and `PYTHON_CMD=python3`.
- **Frontend (Vercel):** root directory `frontend`, Vite preset, and `VITE_API_URL` set to your Render address (no trailing slash).
- **MongoDB Atlas:** allow network access from Render (Network Access, then allow `0.0.0.0/0`), and protect the database with a strong user password.

Both services redeploy automatically on every push to `main`.

## Known limitations

- Windows Event logs are detected, but parsing is basic: IPs are extracted generically rather than from individual event fields.
- Apache and Nginx share the combined log format, so they are told apart only by a hint in the text.
- Only the first 15 unique IPs per analysis are checked against threat intelligence, to respect free API limits.
- Anomaly detection is rule-based and uses fixed thresholds.

## Ideas for later

GeoIP map, tagging, more detection rules (port scanning, traffic spikes), scheduled reports, real-time monitoring, user roles.

## License

MIT. See [LICENSE](LICENSE).
