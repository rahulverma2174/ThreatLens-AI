# ThreatLens AI

Local-first authentication monitoring and defensive threat analysis platform.
The baseline runs on CPU and uses synthetic data or authorized local logs.

## Project layout

- `backend/` - FastAPI API and SQLite persistence
- `frontend/` - React + Vite dashboard
- `dataset/` - Synthetic authentication events for local demonstrations
- `ml-model/` - CPU-friendly anomaly detection components
- `documentation/` - Project and API notes

The backend has a no-login localhost mode and an optional single-user demo
authentication mode. Neither mode provides tenant isolation or makes the
application ready for unrestricted public exposure. Collector source
credentials remain separate from dashboard authentication.

The project is designed for local academic demonstrations using synthetic data
or authorized local logs. Alerts are investigation signals, not proof of an
attack.

## Phase 1: local development

Start the API:

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m scripts.seed_demo_data
uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000/docs` for the interactive API documentation.
The API creates `backend/threatlens.db` on first startup.
The seed command loads the synthetic sample records and is safe to re-run;
it skips events already present.

Start the frontend in a second terminal:

```bash
cd frontend
npm install
npm run dev
```

The Vite development server proxies `/api` requests to the local API.

In the default local mode, the dashboard does not require an analyst account;
its API is restricted to loopback clients. Collector source credentials remain
available under **Administration** for authorized Windows event collection;
see [local-access.md](documentation/local-access.md). The app currently has one
local organization; organization IDs are not attached to every domain record,
so multi-organization use is not supported.

## Authentication and hosted-demo boundaries

ThreatLens supports two authentication modes, selected with
`THREATLENS_AUTH_MODE`:

- **Local mode** (default): no dashboard login is required. Dashboard API
  requests are limited to loopback clients. Keep the backend bound to localhost
  and do not expose this mode to a network.
- **Demo mode**: one configured username and password hash are shared by demo
  users. The backend creates in-memory server-side sessions, uses a secure
  `__Host-` cookie, checks the exact HTTPS `Origin`, and requires a CSRF token
  for state-changing dashboard requests. Login attempts are rate-limited.
  Generate the password hash locally with
  `python -m scripts.hash_demo_password`; do not put a plaintext password in
  configuration.

Demo mode is a limited access gate, not user management or full RBAC. It has no
individual analyst identities, tenant separation, MFA, or shared session store;
sessions and rate-limit state live in one process and do not persist across
restarts. Some administrative operations are disabled in demo access. The app
is a single-organization prototype and is not production-ready for unrestricted
public exposure.

A hosted demo requires HTTPS at the browser-facing endpoint, an exact HTTPS
frontend origin in `THREATLENS_CORS_ORIGINS`, secure cookies, and working
CSRF-header forwarding. The frontend sends relative `/api` URLs and has no
configurable API-base environment variable; serve it and the API on the same
origin, typically with a reverse proxy forwarding `/api` to FastAPI. The Vite
development proxy targets `http://127.0.0.1:8000`. CORS allows credentials in
demo mode and permits the `X-CSRF-Token` header; the frontend carries the token
from the authentication session into mutation requests. Configure
`THREATLENS_DEMO_USERNAME` and a generated
`THREATLENS_DEMO_PASSWORD_HASH`; the hash helper prompts without echoing the
password. `backend/.env.example` contains placeholders only.

Hosted deployment also requires PostgreSQL and a **new, empty database**. Set
`THREATLENS_DATABASE_URL` to a `postgresql+psycopg://...` URL and initialize
that database with `alembic upgrade head` from `backend/`. Do not upload, copy,
or migrate the local SQLite database. The PostgreSQL foundation is in place,
but remaining PostgreSQL runtime compatibility and deployment security review
must be completed before treating hosted use as supported. See
[`documentation/architecture.md`](documentation/architecture.md).

### Local Security Copilot model

Security Copilot can use a local Ollama model to polish explanations grounded
in deterministic database facts. Install Ollama, start `ollama serve`, and pull
the configured model with `ollama pull qwen2.5:3b`. The Security Copilot chat
lets you choose among installed Qwen models; if none is available, it stays in
deterministic database mode. No model provider key is needed; the app calls the
local Ollama API. If Ollama or the model is unavailable, the
existing deterministic response is returned. Set `THREATLENS_OLLAMA_URL`,
`THREATLENS_OLLAMA_MODEL`, and `THREATLENS_OLLAMA_TIMEOUT_SECONDS` in
`backend/.env` to override defaults. The model does not run SQL, detections, or
response actions.

## Features

- FastAPI endpoints for events, dashboard summaries, alerts, IP investigation,
  detection settings, CSV/JSON/Linux authentication-log imports, CSV exports,
  and anomaly scoring.
- File imports accept structured event CSV, JSON/JSONL normalized authentication
  records, and Linux `auth.log` / `secure` records for SSH accepted/failed
  authentication. JSON imports preserve supplied host, event ID and metadata.
  Every attempt receives an
  ingestion run ID with status, accepted/rejected counts, timestamps, and an
  error summary when it fails. Imported events retain that run ID for tracing.
  JSON may be one object, an array of objects, or newline-delimited objects;
  each record needs `username`, `source_ip`, and `status`. Optional fields are
  `timestamp`, `event_type`, `user_agent`, `source_host`, `source_event_id`, and
  `event_metadata`. Invalid files are rejected atomically.
- The alert queue filters by UTC date range, severity, status, source IP, and
  linked authentication event type. Analysts can export the selected alert
  records as a spreadsheet-safe CSV and assign an owner to each alert.
- Analysts can label alerts as true positive, false positive, or benign activity.
  Labels are auditable and feed a per-rule review summary with an observed
  false-positive share; benign labels are excluded from that denominator and
  the result is explicitly limited to the reviewed local sample. If later
  evidence is linked to a reviewed alert or its severity escalates, the old
  outcome is cleared and the reset is recorded for re-review.
- Analyst and collector audit entries are append-only in SQLite and SHA-256
  chained in order. Startup backfills the existing audit history; the Audit
  page verifies entry hashes and the stored chain head and displays each entry's
  hash. The local head detects in-place changes but should be exported to
  independent secure storage for protection against a privileged database rewrite.
- Alert queue supports selecting filtered signals and bulk transitions between
  open, investigating, and resolved. Updates are all-or-nothing, capped at 500
  alerts, and recorded per changed alert in audit history.
- A configurable cross-IP takeover sequence detector correlates failures for
  one account across multiple source IPs with a later successful login. It
  preserves the contributing event IDs, maps the signal to ATT&CK T1110, and
  adds the evidence to the correlated incident's source-IP list.
- Detection thresholds can be replayed against up to 5,000 recent stored events
  before saving. The read-only preview compares current and proposed grouped
  alert candidates, applies active detection exceptions, and samples source IPs
  and event IDs so an analyst can inspect the impact before changing settings.
- Detection Engineering supports analyst-managed rolling-window rules for
  failed counts and distinct usernames/IPs. Each create, edit, enable, or disable
  adds an append-only configuration version and chained audit entry. Read-only
  previews evaluate up to 5,000 recent failed authentication events and do not
  create alerts; enabled custom rules evaluate newly ingested events and stamp
  the producing rule version in the alert key.
- SQLite persistence and configurable brute-force, repeated-failure,
  multi-username authentication-failure indicators, multi-IP account targeting,
  login-burst, same-IP success-after-failures, and distributed-failure-then-
  success rules. Failure count and distinct source-IP thresholds for the
  distributed sequence are adjustable in Settings.
- Behavioral profiles summarize local user/source frequency, failure rates,
  distinct IP/account exposure, and low-frequency UTC login hours. UEBA compares
  the current window with the preceding equal-length window and explains
  heuristic entity-priority factors; these scores are review signals, not
  attack verdicts.
- Explainable 0–100 event risk scores include named rule, behavior, local
  indicator, and optional Isolation Forest factors. Scores are review priority,
  not calibrated probabilities or confirmation of malicious activity.
- Persisted analysis runs and risk assessments support local comparisons across
  repeat runs. Related alerts are grouped into incidents by shared IP or
  username evidence within a 60-minute window; analyst status, owner and notes
  persist. Incident reports export a printable HTML document with case notes,
  checklist, comments, linked alerts, and loaded authentication evidence; use
  the document's print action to save a PDF.
- Local IP, domain, and file-hash indicators store analyst-assigned confidence,
  source, expiry, and notes. IPs correlate with stored authentication events;
  domain/hash matches are only possible if an event source supplies those
  values. These are local records, not external reputation. Blocklist entries
  add review context; allowlisting does not suppress detection.
- Threat Intelligence provides separately stored external IP/domain/hash feed
  observations, manual JSON/CSV HTTPS sync, freshness/failure status, source
  provenance, bounded local IP correlation, and append-only analyst review.
  Feed requests require the exact host in `THREATLENS_FEED_ALLOWED_HOSTS` and
  optional credentials are read only from backend environment variables. See
  [Threat Intelligence documentation](documentation/threat-intelligence-phase2.md)
  for configuration, API endpoints, provenance semantics, and limitations.
- Deterministic Security Copilot intents answer top suspicious IPs, highest
  severity alert, today's failed logins (UTC), accounts targeted from multiple
  IPs, and unusual local behavior using bounded structured queries only.
- Interactive relationship graph and chronological storyline link stored event
  IDs to users, IPs, alerts, and correlated incidents. The graph is bounded to a
  recent local sample; links are evidence associations, not attribution.
- MITRE ATT&CK coverage groups local detection candidates by tactic and
  technique, with rule/alert evidence and direct ATT&CK references. The
  authentication dataset does not contain passwords, so T1110.003
  (Password Spraying) is not claimed as confirmed coverage.
- SOAR builder persists trigger/condition/action definitions and execution
  history. Runs are local simulations; approvals record analyst intent but
  never execute host, network, or alert response actions.
- Unified desktop design tokens, readable tables, responsive layouts,
  contextual evidence panels, local-record search, and Overview status values
  are shared across the workspace.
- Local synthetic data in `dataset/sample_auth_events.csv`.
- Command-center widgets can be hidden and reordered per browser; `Ctrl+K`
  opens global page navigation and local event search. Dashboard health shows
  only API, detection-setting, and stored-event values exposed by the local API.
  Dashboard workflow actions use the “Local analyst” audit label. Model version
  is not tracked. Event source
  label and ingestion time are recorded per event; legacy rows are labeled as
  such instead of having their provenance inferred. A workspace audit history records event imports, analyst
  workflow updates, local indicator changes, detection-setting updates, and
  saved-filter changes.
- Saved event filter presets are stored in the local SQLite workspace and are
  available across browsers connected to that backend. Existing browser-only
  presets migrate into the workspace when the event explorer loads.
- Event data refreshes every 20 seconds while the browser tab is active. Analysts
  can pause/resume polling from the header; the preference is saved per browser.
- Audit history records event ingestion, CSV/JSON imports, alert/incident workflow
  updates, detection-setting changes, local indicator changes, and saved-filter
  changes. Dashboard actions use the “Local analyst” label; collector actions
  retain the registered source identity.
- A local Syslog TCP listener accepts RFC3164/RFC5424 SSH authentication events,
  stores accepted/failed logins through the normal detection and audit pipeline,
  and exposes listener counters in Settings. It binds to loopback and allows
  loopback senders by default. See `documentation/syslog-ingestion.md` before
  enabling remote sources.
- A per-host Windows Security collector forwards Events 4624/4625 with a
  PowerShell agent, one-time bearer tokens stored as hashes, DPAPI-protected
  Windows credentials, resumable record-ID cursors, and idempotent batches.
  The isolated `app.collector` service exposes only authenticated ingestion and
  health routes, while the dashboard API can stay on loopback. Only records
  with a usable remote IP enter the auth correlation pipeline; selected Windows
  evidence fields are retained for analyst review. See
  `documentation/windows-security-ingestion.md` before connecting a host.
- Repeated authentication-failure signals link to ATT&CK T1110 as a review
  candidate. No passwords are collected, so Password Spraying T1110.003 is not
  presented as evidence-backed coverage.

### SOC interface design

- **Visual system:** graphite/navy surfaces (`#080D18`, `#101827`), cyan/blue
  focus accents, restrained severity colors, 4/8/12/16/24 px spacing steps,
  compact tabular data, visible keyboard focus, and reduced-motion support.
- **Application shell:** grouped navigation, collapsible desktop rail, local
  workspace context, global search, notification center, local access label,
  contextual help, live API status, and a `Ctrl+K` command palette.
- **Command center:** authentication timeline, severity distribution, source
  ranking, correlated incident queue, recent stored events, detection activity,
  and operational health. Widget visibility/order is saved in browser storage.
- **Investigation:** event search and filters, pagination, sortable/resizable
  columns, column visibility, multi-row selection, selected event and alert
  CSV exports, import run history, and event/IP details. Relationship graph nodes open evidence-backed detail
  panels; graph links come only from the bounded local event/alert sample.
- **Analytics and response:** on-demand behavioral/model assessment, local IP
  intelligence, incident workflow, deterministic Copilot, reporting, and
  detection settings remain connected to their existing API endpoints.

The backend remains a single local workspace: domain tables do not yet carry
organization IDs, so multi-tenant isolation and untrusted-network deployment
are not supported. Environment switching and deployed model-version tracking
also remain future work.

Run backend tests from `backend/`:

```bash
.venv/bin/python -m pytest -q
```

## Analytics and API

Threat Hunting and the Detection Validation Lab architecture, endpoint contracts,
data bounds, reproducibility snapshots, isolation boundary, and synthetic-only
result semantics are documented in
[`documentation/threat-hunting-and-detection-lab.md`](documentation/threat-hunting-and-detection-lab.md).

The OpenAPI reference at `http://127.0.0.1:8000/docs` includes:

- `GET /api/ingestion/syslog` — listener state, source allowlist, and counters.
- `POST /api/events/upload` — import an event CSV or Linux SSH authentication
  log; returns a durable `run_id`, status, and accepted/rejected counts.
- `GET /api/ingestion/runs?limit=50`, `GET /api/ingestion/runs/{run_id}` —
  inspect recent import attempts and their outcomes.
- `GET /api/alerts?start_date=YYYY-MM-DD&end_date=YYYY-MM-DD&severity=high&status=open&source_ip=203.0.113.8&event_type=ssh`
  — filter detection alerts; date boundaries are UTC and inclusive.
- `PATCH /api/alerts/{alert_id}/disposition` — record an analyst outcome
  (`true_positive`, `false_positive`, or `benign_activity`) with an optional
  review note in audit history.
- `GET /api/analytics/detection-quality` — summarize reviewed and unreviewed
  alerts and observed false-positive share by rule.
- `GET /api/audit/integrity` — verify the ordered audit-entry hash chain and
  compare it with the stored chain head.
- `GET/PATCH /api/settings/detection` — read and tune detection thresholds,
  including distributed-failure count and distinct source-IP count.
- `POST /api/analytics/detection-replay` — compare current and proposed rule
  thresholds on a bounded historical event sample without writing alerts or
  changing stored events.
- `GET /api/reports/alerts.csv?alert_ids=1&alert_ids=2` — export 1–500
  selected alerts as CSV.
- Syslog TCP listener (default `127.0.0.1:5514`) — supported formats, sender
  configuration, and network safety settings are documented in
  `documentation/syslog-ingestion.md`.
- `GET/POST /api/ingestion/sources`, `PATCH/DELETE /api/ingestion/sources/{id}`,
  and `POST /api/ingestion/sources/{id}/rotate` — local-only source management;
  source secrets are returned once and stored only as hashes.
- `POST /api/ingestion/windows/events` — authenticated batches of Windows
  Security logons with duplicate detection and per-source health counters.
  For remote collection, run `uvicorn app.collector:app` on a private interface;
  that service exposes only the event receiver and `/healthz`, not the dashboard.

- `GET /api/analytics/behavior?window_hours=168` — profile up to 5,000
  matching local events over a bounded 1–720 hour window.
- `POST /api/analytics/analyze` — persist an analysis run and explainable risk
  results for up to 500 event IDs (or the latest 500 events). Isolation Forest
  runs only when at least 10 events are available.
- `GET /api/incidents`, `PATCH /api/incidents/{id}` — correlated incident queue
  and analyst workflow.
- `PATCH /api/alerts/bulk` — atomically transition up to 500 alert IDs and
  return the updated alert records; each changed alert receives its own audit
  entry.
- `GET/POST/PUT/DELETE /api/intelligence/indicators` — local IP/domain/hash
  indicators with confidence, provenance, expiry, and IP event-match counts.
- `GET /api/intelligence/relationships` — bounded graph edges from up to 250
  recent events, 100 rule alerts, and correlated incident evidence.
- `GET /api/search?q=...` — bounded search over local events, alerts, and
  incidents.
- `GET /api/dashboard/activity?window_hours=...` — UTC-hour event aggregates
  for the Overview timeline.
- `GET /api/attack/coverage` — local detection candidates with rule/alert
  evidence and qualification notes.
- `/api/soar/workflows` and `/api/soar/executions` — persisted local workflow
  definitions, simulations, and approval records.
- `POST /api/copilot/ask` — deterministic supported-query interface; it does
  not execute generated SQL or call an external LLM.

The analysis run endpoint persists its run metadata and per-event assessments.
`prior_analysis_runs` counts earlier runs containing the same source IP, while
`previous_risk_score` compares the same event across runs. This is historical
context, not an independent confirmation of a repeated attack.

## Synthetic evaluation

Run the controlled evaluation from `backend/`:

```bash
.venv/bin/python -m scripts.evaluate_detection
```

The command writes `dataset/evaluation_auth_events.csv` with 35 labeled events:
20 spread-out routine events and 15 events across brute-force,
password-spraying-indicator, success-after-failures, and multi-IP account
targeting scenarios. The measured results in this controlled sample were:

| Method | Precision | Recall | F1 | False-positive rate | TP / FP / TN / FN |
|---|---:|---:|---:|---:|---:|
| Configured rule detections | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 15 / 0 / 20 / 0 |
| Isolation Forest anomaly indicator | 0.7143 | 1.0000 | 0.8333 | 0.3000 | 15 / 6 / 14 / 0 |

These are measurements on this small, deliberately constructed synthetic
dataset only; they are not production accuracy claims. In particular, the
Isolation Forest's false positives reinforce that anomaly labels are review
signals rather than confirmed incidents.

Local mode has no dashboard login and is restricted to loopback. Demo mode
adds a single shared login, secure cookie sessions, origin checks, and CSRF
protection, but it does not add individual roles or tenant isolation. The
workspace remains a local academic prototype and is not ready for unrestricted
public exposure.
