# Architecture

ThreatLens AI runs locally as a React/Vite client at `127.0.0.1:5173` and a
FastAPI service at `127.0.0.1:8000`. Vite proxies `/api`; FastAPI publishes
validated request/response contracts and OpenAPI documentation at `/docs`.
SQLite is the default SQLAlchemy persistence layer. The backend pins the
synchronous PostgreSQL driver as `psycopg[binary]==3.3.9` and Alembic as
`alembic==1.20.1`. Configure PostgreSQL through `THREATLENS_DATABASE_URL`, for
example `postgresql+psycopg://<user>:<password>@<host>:<port>/<database>`; keep
the URL in the backend environment and do not commit real credentials. Local
SQLite remains the default, and Detection Lab continues to use a separate
temporary SQLite database.

## Backend services

- `app.services.parsing` validates bounded UTF-8 CSV, JSON and JSONL uploads,
  supported event fields, row limits, and normalized event payloads.
- `app.services.ingestion` persists single/batch events, evaluates rules, and
  refreshes correlated incident groups.
- `app.services.detection` applies configured brute-force, repeated-failure,
  multi-username authentication-failure, login-burst, multiple-source-account, and
  success-after-failures rules.
- `app.services.detection_rules` evaluates analyst-managed, versioned
  authentication rules using constrained rolling-window aggregations. Rule
  previews read at most 5,000 recent failures and never create alerts.
- `app.services.behavior` creates bounded user/source profiles, frequency and
  failure-rate summaries, and low-frequency UTC login-hour indicators. The API
  compares current and previous equal-length windows with explainable review
  factors.
- `app.services.anomaly` engineers Pandas/NumPy features and scores the recent
  sample with deterministic, CPU-only scikit-learn Isolation Forest settings.
- `app.services.risk_scoring` combines local rule, behavioral, blocklist, and
  optional model evidence into capped 0–100 event scores and persists analysis
  run history.
- `app.services.correlation` links alerts when their event timelines are within
  60 minutes and share an IP or username.
- `app.services.threat_intelligence` manages analyst-entered IP, domain, and
  hash indicators with confidence, source, and expiry. Only IP values can match
  the current authentication event schema; no external reputation is queried.
- `app.services.threat_indicator_validation` normalizes and validates bounded
  external JSON/CSV feed records. `app.services.threat_feed_transport` fetches
  allowlisted HTTPS feeds with DNS/IP checks, pinned public destinations,
  redirects disabled, bounded response bodies, and environment-only credentials.
  `app.services.threat_intelligence_feeds` persists independent feed
  observations, sync history, freshness, and expiry without changing analyst
  dispositions. `/api/intelligence` exposes feed management, indicator
  correlation, review, and timeline APIs; external IOCs are stored separately
  from analyst-managed `LocalIndicator` records.
- `app.services.copilot` maps supported questions to fixed ORM queries and
  deterministic summaries. It never generates executable SQL.
- `app.services.reporting` builds local summaries and spreadsheet-safe CSV.

`app.routers.operations` retains existing events, alerts, settings, upload,
investigation, scoring, and report APIs. `app.routers.advanced` exposes
behavior/risk analytics, correlated incidents, local indicators, relationships,
ATT&CK coverage, safe SOAR workflow simulation, and Copilot. Existing API
workflows remain available.

The Detection Engineering workspace manages custom failure-count and distinct
entity rules. Each create/update/enable change records a configuration snapshot
and chained audit entry. Rule revisions are append-only in SQLite; generated
alerts include the producing rule revision in their detection key. Custom rule
evaluation is bounded to 5,000 candidate events per rule and currently covers
authentication events only.

## Persistence and migrations

Existing authentication event, alert, and detection-settings tables are
preserved. Additive local-indicator columns store IOC type, confidence, source,
and expiry. New tables store correlated incidents and alert links, SOAR workflow
definitions and execution history, analysis-run metadata, and per-event risk
assessments. Startup continues to create missing tables and applies additive
SQLite migrations. `detection_rules` and
`detection_rule_versions` are additive. SQLite triggers prevent updates or
deletes of rule-version rows. No existing event/alert records are replaced by
the new features.

External threat intelligence uses additive `threat_feeds`,
`threat_feed_sync_runs`, `threat_indicators`, `threat_indicator_sources`, and
append-only `threat_indicator_reviews` tables. A source observation is unique
per canonical indicator, feed, and original reference. Its confidence, expiry,
timestamps, and sync-run association remain independent from observations by
other feeds. An indicator remains active while any source observation is
unexpired. Failed syncs retain the last successful data and timestamp. Review
decisions are separate from external confidence, audited, and cannot be
overwritten by feed updates. SQLite triggers enforce review append-only
behavior.

The Alembic baseline under `backend/migrations/versions/` describes the current
ORM schema for a **new, empty** database. A future fresh PostgreSQL deployment
should set `THREATLENS_DATABASE_URL` to a PostgreSQL URL and run these commands
from `backend/`:

```bash
python -m pip install -r requirements.txt
alembic upgrade head
```

This fresh-database baseline does not upgrade an existing SQLite schema and
does not migrate SQLite data. Existing databases require a separately reviewed,
versioned upgrade path; the current SQLite startup migrations are retained.

Dashboard access depends on `THREATLENS_AUTH_MODE`: local mode has no analyst
login and is loopback-only; demo mode uses one configured shared login with
process-local sessions and CSRF/origin checks. It does not provide individual
analyst identities or tenant isolation. Collector source credentials remain
independently managed and hashed for event receiver access.

## Detection and analyst workflow

Single-event ingestion and bounded CSV/JSON/JSONL imports persist events and
run configured rules. Imported source labels and supplied metadata are retained.
Related alerts are grouped by evidence, not by external attribution.
Incident status and notes are analyst-managed and persist across correlation
refreshes. Alerts can be assigned to an owner. Incident reports can be exported
as printable HTML with loaded event evidence, linked alerts, checklist, comments,
notes, and any generated investigation brief. IP investigation and graph edges
are derived from locally stored events and alerts.

Risk factors are named, capped, and returned with each score. Risk levels are
review priorities, not calibrated probabilities. Isolation Forest results,
rare-hour signals, and locally maintained blocklist labels are not confirmed
attacks. Allowlist entries do not suppress rules or reduce risk scores.

Copilot supports deterministic local queries for suspicious IPs, the highest
severity unresolved alert, today's failed logins in UTC, accounts targeted by
multiple IPs, and unusual local behavior. Unsupported questions and missing
data are reported explicitly. No LLM, external API, or internet connection is
required for deterministic answers. Ollama wording assistance runs only when
the analyst selects an installed Qwen model; without that selection the
database-grounded answer is returned directly.

The evaluation script creates a labeled synthetic dataset and reports measured
precision, recall, F1, confusion counts, and false-positive rate for the rule
engine and Isolation Forest. Results are specific to those controlled
scenarios, not claims about production detection accuracy.

Local dashboard mode is unauthenticated and intended for localhost academic
demonstrations. Demo mode adds a single shared login, but the deployment still
supports one local organization and domain records do not have organization
foreign keys. The application is not production-ready for unrestricted public
exposure. Windows collector endpoints retain their separate source-token
checks. PostgreSQL hosting also requires completion of the remaining runtime
compatibility work and deployment security review.
