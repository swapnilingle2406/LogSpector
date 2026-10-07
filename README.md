
Note: `203.0.113.x` and `198.51.100.x` are reserved documentation ranges, so AbuseIPDB will report them as clean. Use a known-bad IP to see the threat-intel path trigger.

## Deployment

- **Backend → Render:** root `backend`, build `npm install`, start `npm start`. Set all `.env` variables. Render's Node image includes Python 3 — set `PYTHON_CMD=python3`. Set `CLIENT_URL` to your Vercel URL.
- **Frontend → Vercel:** root `frontend`, framework Vite. Set `VITE_API_URL` to your Render URL.
- Keep Atlas Network Access open to Render.

## Security notes

- `.env` is git-ignored; no secrets are committed.
- The Python parser is invoked via `execFile` to prevent shell injection from untrusted log content.
- JWTs are used for stateless auth; tokens are signed with `JWT_SECRET`.

## Roadmap

- GeoIP enrichment and map view
- Anomaly detection (failed-login spikes, 403 bursts from a single source)
- Entry tagging for triage workflows
- Scheduled reports
- API keys for programmatic access

## License

MIT
