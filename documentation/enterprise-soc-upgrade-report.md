# ThreatLens AI Enterprise SOC Upgrade Report

## Scope and architecture

The project remains an existing local-first React/Vite application backed by
FastAPI, SQLAlchemy, and SQLite. Its upload, detection, alert, incident, audit,
reporting, Windows collector, Syslog, and local Copilot workflows were retained.
At the time this upgrade was implemented, the dashboard had no analyst
account/API-key gate and its API was restricted to loopback. The current
backend also supports an optional, limited single-user demo authentication
mode; it does not provide individual analyst accounts or tenant isolation.
Windows collector ingestion retains its separate source-token checks.

The audit found that the app already had useful SOC primitives, but its UI had
small, inconsistent type scales and styling between modules. Overview activity
was based on a bounded event sample, intelligence only represented IPs, graph
edges lacked event-level chronology, and UEBA profiles did not compare adjacent
periods. Analyst API-key tests were stale after the earlier API-key removal.

## Implemented by priority

### 1. Enterprise UI and analyst workspace

- Added shared SOC color, typography, spacing, focus, panel, table, control, and
  responsive layout tokens in `frontend/src/enterprise.css`.
- Tuned shared navigation, tables, drawers, incident and relationship workspaces
  for larger desktop layouts, including 1440px and 1920px viewports.
- Updated Overview to show six backend-backed KPIs, a selectable 24-hour,
  7-day, or 30-day UTC-bucketed activity chart, severity counts, incident owners,
  source registry/heartbeat status, API/detection state, and refresh time.
- Added local search across authentication events, alerts, and incidents, with
  navigation into the selected record's workspace.
- Made first-run dashboard preferences show all available widgets; existing
  saved browser preferences remain intact.

### 2. MITRE ATT&CK

- Added an interactive technique coverage workspace and `/api/attack/coverage`.
- Coverage candidates link configured local rule definitions and stored alert
  records, including source IPs and related event IDs, with review qualifications
  and direct MITRE references.
- Existing multi-username failure detections now map to broad T1110 candidate
  coverage. The app does not claim T1110.003 Password Spraying from usernames
  alone because local authentication records contain no password evidence.

### 3. UEBA

- Existing per-user and per-IP profiles now compare a selected window with the
  immediately preceding equal-length window.
- Added entity review scores and explanations for low-frequency login hours,
  high observed failure share, and increased event volume or new activity.
- Existing risk analysis and optional Isolation Forest remain available. Scores
  are local review signals, not calibrated probabilities or attack verdicts.

### 4. Attack storyline

- Extended the existing ReactFlow graph with event and incident nodes, links to
  stored event IDs, and alert-to-event/incident evidence edges.
- Added a chronological event timeline, with event timestamp, source, user, and
  IP details in the selected-record panel.
- The graph remains bounded to recent local data (250 events, 100 alerts, and
  100 incidents); relationships represent recorded evidence, not attribution.

### 5. SOAR workflows

- Added persistent trigger, optional condition, safe simulation action, and
  approval configuration in the visual workflow builder.
- Added execution history bound to existing local alert/event IDs, with stored
  evidence snapshots and audit records.
- Approval changes the execution to `approved_simulation` only. No endpoint
  isolation, account changes, network blocking, or alert response action is
  connected or executed.

### 6. Threat intelligence

- Extended local indicators to IP, domain, and MD5/SHA-1/SHA-256 hash values.
- Added analyst confidence, source/provenance, expiry, and notes while preserving
  existing IP indicator rows and IP investigation behavior.
- Existing event correlation is exact-IP only because the authentication event
  schema has no domain/hash fields. Expired IP indicators no longer affect risk
  scoring. No external reputation or geolocation is queried.

### 7. Tests and operations

- Updated obsolete analyst-key tests to assert the current local API access
  contract while preserving the separate Windows collector token workflow.
- Added API integration coverage for local search/activity/UEBA/ATT&CK,
  relationship evidence, domain IOC persistence, and approved SOAR simulations.
- Added `httpx2` to backend requirements for current Starlette test-client
  compatibility.
- Updated README and architecture documentation with routes, provenance rules,
  boundaries, and safe workflow behavior.

## Verification performed

| Check | Result |
| --- | --- |
| Backend automated tests | **19 passed** (`.venv/bin/python -m pytest -q`) |
| Frontend production build | **Passed** (`npm run build`) |
| Backend Python compilation | **Passed** (`.venv/bin/python -m compileall -q app tests`) |
| Local API smoke checks | **Passed** for dashboard stats, activity, local search, UEBA, ATT&CK coverage, indicator reads, and relationship graph |
| Persistence workflows | **Passed** in tests for stored indicators, SOAR definitions/executions, rule revisions, and existing analysis/incident flows |
| Import/detection/alert/incident tests | **Passed** in the automated suite, including CSV/JSON/JSONL upload and rule/incident workflows |

Pytest emitted 98 Python 3.14 SQLite datetime-adapter deprecation warnings; they
did not fail the suite. The in-process ASGI tests stalled under the restricted
sandbox, so the suite was run outside the sandbox after confirming that even a
minimal FastAPI test app stalled there. Tests use isolated SQLite databases and
do not write test records into the running workspace database. Live API smoke
checks used read-only requests.

## Boundaries to retain

- The deployment is a single local workspace, not a multi-tenant or untrusted
  network SOC service.
- UEBA factors use the available authentication schema and bounded event
  history; they are heuristic and depend on event coverage and retention.
- ATT&CK results are candidate mappings and should be reviewed against alert
  evidence and rule logic before being reported as coverage.
- Domain/hash IOC values remain manually managed until connected event sources
  provide those values for local comparison.
- SOAR execution is a safe local simulation with approval tracking only; an
  actual response connector would require its own authorization and safeguards.
