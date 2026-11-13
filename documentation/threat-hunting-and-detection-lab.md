# Threat Hunting and Detection Validation Lab

These modules add constrained historical event searches and reproducible synthetic detection scenarios to the existing ThreatLens AI application. They reuse the current FastAPI service, SQLAlchemy models, React workspace, detection engine, risk scoring, saved queries and append-only audit chain.

## Threat Hunting

The hunting service accepts a validated JSON query. Its time range is always applied as a scope; the selected `AND` or `OR` logic combines the listed conditions.

Allowed condition fields are `source_ip`, `username`, `event_type`, `result`, and `severity`. Operators are `equals` and, for usernames only, `contains`. Severity reflects linked local alert records; `unclassified` selects events without a linked alert. Extra fields and arbitrary query text are rejected. SQL is generated using SQLAlchemy expressions and bound parameters.

Bounds: 1–20 conditions, a maximum 365-day range, a maximum page size of 200, offset up to 100,000, up to 100 saved queries, and CSV export capped at 5,000 rows. CSV cells beginning with spreadsheet formula characters are prefixed to prevent formula execution in spreadsheet applications.

Endpoints:

| Method and path | Purpose |
| --- | --- |
| `POST /api/hunting/search` | Run a bounded structured query and return event rows with linked alerts/incidents and execution time. |
| `POST /api/hunting/export` | Export matching events as CSV, subject to a 5,000-row maximum. |
| `GET /api/hunting/queries` | List saved hunting queries. |
| `POST /api/hunting/queries` | Save a validated query. |
| `PUT /api/hunting/queries/{query_id}` | Replace a saved query. |
| `DELETE /api/hunting/queries/{query_id}` | Delete a saved query. |

Saved query changes are written to audit history. Hunting is read-only against event, alert and incident data.

## Detection Validation Lab

The lab provides five deterministic synthetic scenarios: repeated authentication failures, unusual login burst, multiple accounts from one source, unfamiliar source IP, and suspicious login time. Fixture IPs are from documentation-only TEST-NET ranges. Scenario version `1.0` and a fixed fixture generator define the record shapes and expected behavior.

Each run snapshots configured detection thresholds, enabled custom-rule versions and configuration, expected signals, synthetic event records, run status, timestamps, duration, event count and execution mode. Existing built-in detection and risk-scoring functions execute in a separate temporary SQLite file. The file is disposed after execution. The runner does not accept a production database/session argument and does not ingest synthetic rows into workspace events or create production alerts, incidents, analyses or audit entries. A dedicated `detection_lab_runs` row stores the report. Analyst finding reviews are separate explicit actions and append `detection_lab.finding_reviewed` or `detection_lab.finding_review_updated` audit events.

Unfamiliar-source risk signals require at least five historical events for the user. With fewer records, the result is `insufficient_baseline` and the source is not labeled unfamiliar. A fixture that would exceed 250 records is `not_evaluable`; configured thresholds are never lowered to produce a pass. A mismatch between expected and actual signals is reported as `failed`.

All reports are synthetic scenario validation. They do not establish real-world detection accuracy, precision, recall, or attack prevalence. Any technique association is limited to evidence-backed mappings already attached to a generated detection; scenario candidates alone are not claimed as detected techniques.

Endpoints:

| Method and path | Purpose |
| --- | --- |
| `GET /api/detection-lab/scenarios` | List supported scenario descriptions and baseline requirements. |
| `POST /api/detection-lab/runs` | Execute a scenario against the current settings/rule snapshot in isolated SQLite. |
| `GET /api/detection-lab/runs?limit=&offset=` | List persisted runs (limit 1–100, offset up to 100,000). |
| `GET /api/detection-lab/runs/{run_id}/reviews` | List analyst reviews for an execution. |
| `POST /api/detection-lab/runs/{run_id}/reviews` | Review an observed detection as true positive, false positive, expected behavior or needs tuning; notes are capped at 2,000 characters. |
| `GET /api/detection-lab/summary` | Summarize up to the latest 1,000 synthetic runs and reviews. |

## Local persistence and security

The two lab tables and saved hunt table are created through the existing SQLAlchemy `Base.metadata.create_all()` initialization. Existing tables are not rebuilt. Existing production SQLite data remains in place. The application keeps its current localhost-only dashboard API boundary; do not expose it to untrusted networks.

The temporary scenario database uses SQLite and existing local detection services only. No mandatory paid service or external threat feed is used. API documentation is available from the running local FastAPI service at `/docs`.
