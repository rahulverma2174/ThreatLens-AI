# ThreatLens AI — Full Project Report

**Report date:** 13 November 2026
**Project type:** Local-first defensive Security Operations Center (SOC) and authentication threat-analysis platform
**Status:** Implemented for local/academic demonstrations; not a multi-tenant or untrusted-network deployment.

## 1. Executive summary

ThreatLens AI is a local application for ingesting authentication telemetry, applying configurable detections, investigating alerts and incidents, and reviewing explainable behavior/risk signals. It combines a React/Vite analyst interface, a Python/FastAPI service, SQLAlchemy persistence, and SQLite storage. Its interfaces use the existing local records and services rather than requiring a paid cloud service.

The platform includes event ingestion and source administration, built-in and analyst-managed detections, alert and incident workflows, UEBA and risk analysis, MITRE ATT&CK candidate coverage, attack relationships, constrained Threat Hunting, a synthetic Detection Validation Lab, local and external IOC workflows, simulated SOAR, deterministic Security Copilot, audit history, and reporting.

Recent frontend work improved responsive layouts and fixed sidebar scrolling. The sidebar now fills the viewport, scrolls independently, exposes lower navigation items, and leaves desktop main-content scrolling independent. The local API was restarted after being found unavailable; its health endpoint returned `{"status":"ok","service":"ThreatLens AI"}` and dashboard requests returned HTTP 200 during that verification.

## 2. Technology and architecture

| Layer | Technology | Responsibility |
| --- | --- | --- |
| Frontend | React, Vite, JavaScript, CSS | SOC workspace, investigations, review workflows, charts and graphs |
| Backend | Python, FastAPI, Pydantic, SQLAlchemy | Validated APIs, ingestion, detections, correlation and analysis |
| Persistence | SQLite | Authentication events, alerts, incidents, configuration, audit and module history |
| Analytics | Pandas, NumPy, scikit-learn | Bounded feature engineering and CPU-based Isolation Forest scoring |
| Optional local language model | Ollama / Qwen | Selected wording assistance for database-grounded Copilot responses |

The frontend runs at `http://127.0.0.1:5173/`; Vite proxies `/api` requests to FastAPI on `http://127.0.0.1:8000`. OpenAPI documentation is at `http://127.0.0.1:8000/docs`. SQLite is the default database. Main implementation areas are `backend/app/routers/`, `backend/app/services/`, `backend/app/models.py`, and `frontend/src/components/`.

## 3. Implemented capabilities

### Event collection and ingestion

- Ingests individual and batched authentication events.
- Imports bounded structured CSV, JSON and JSONL files, plus supported Linux SSH `auth.log` / `secure` records.
- Preserves supplied event IDs, host labels, metadata, source labels and ingestion-run provenance where available.
- Records import attempts and accepted/rejected counts; invalid imports are handled atomically.
- Provides a loopback Syslog TCP listener for supported RFC3164/RFC5424 SSH authentication events.
- Includes an optional per-host Windows Security event collector for Events 4624/4625, using source tokens, hashed token storage, DPAPI-protected collector credentials, cursors and idempotent batches.

### Detection engineering and alert response

- Built-in authentication detections include repeated failures/brute force, multiple usernames from a source, login bursts, multi-IP account targeting, and success-after-failure sequences.
- Configurable thresholds and time-limited exceptions are available. A read-only replay previews threshold changes against a bounded historical sample without writing alerts.
- Analyst-managed rolling-window rules support failure counts and distinct entities. Rule previews are read-only; rule versions are append-only and generated alerts identify the producing version.
- Alert workflows support date/severity/status/source/event-type filters, owners, analyst dispositions, bulk status changes and CSV export. Changes are audited.
- Related alerts can be grouped into incidents using shared IP or username evidence in a 60-minute window. Analyst status, ownership, notes, checklist and comments persist. Printable incident reports include loaded local evidence.

### UEBA, risk analysis and investigation

- User/source profiles summarize local event frequency, failure rates, distinct exposure and rare UTC login hours.
- UEBA compares current and previous equal-length windows and returns review factors.
- Optional on-demand Isolation Forest analysis uses deterministic CPU settings.
- Event risk scores combine named local rule, behavior, local indicator and optional model evidence; scores are capped at 0–100.
- Analysis runs and risk assessments persist for local comparison.
- Risk values are investigation priorities, not calibrated attack probabilities or verdicts.

### MITRE ATT&CK and attack relationships

- ATT&CK coverage groups locally configured detection candidates and stored alert evidence by tactic and technique.
- Technique mappings are presented as candidates and use evidence available from local rules and records.
- The relationship graph/storyline connects bounded samples of events, users, IPs, alerts and incidents. Edges represent evidence associations, not actor attribution.
- Password Spraying T1110.003 is not claimed as confirmed coverage because password data is not collected.

### Threat Hunting

- Searches historical authentication events using a restricted structured query contract rather than arbitrary SQL, Python or shell input.
- Supports timestamp range and allowlisted conditions over source IP, username, event type, result and linked-alert severity.
- Supports AND/OR, bounded conditions and pagination, query timing/counts, saved queries, related alert/incident links and CSV export.
- CSV output is capped and protected against spreadsheet formula injection. Hunting queries are read-only against event, alert and incident data.

### Detection Validation Lab

- Runs five deterministic synthetic scenarios: repeated failures, unusual login burst, multiple accounts from one source, unfamiliar source IP and suspicious login time.
- Executes the existing detection/risk logic against an isolated temporary SQLite database; synthetic run events do not enter the production workspace.
- Persists scenario version, thresholds, enabled custom-rule snapshot, fixture, execution metadata, expected/actual results and run history.
- Unfamiliar-source results require at least five historical user events. Inadequate history is reported as `insufficient_baseline`.
- Does not lower analyst thresholds to force scenario passes. Scenario outcomes are validation results for the synthetic fixture, not real-world accuracy claims.
- Finding reviews are explicit analyst actions and create audit entries.

### Threat Intelligence and IOC correlation

- Preserves the existing analyst-managed local IP/domain/hash workflow.
- Adds separate external feed, sync-run, canonical indicator, per-feed source observation and append-only review records.
- Supports IPv4/IPv6, domains, MD5, SHA-1 and SHA-256 indicators; normalizes before deduplication.
- Tracks per-source confidence, reference, seen times, expiry and sync-run association. One expired source does not deactivate another active source.
- Supports manually synchronized JSON/CSV feeds with configured field mappings, freshness and bounded failure reporting.
- Feed access requires an HTTPS URL, exact configured host allowlisting, public DNS validation, connect-time address validation/pinning, disabled redirects, timeouts, content validation and response-size limits. Optional credentials are referenced by environment-variable name; secret values are not stored in response payloads.
- IP indicators correlate by exact source IP with local authentication records. The current event schema lacks domain and hash fields, so those correlation results explicitly report unsupported schema.
- External confidence is separate from analyst disposition. Feed updates cannot silently replace review state. Analyst reviews are audited.
- Feeds do not block IPs or perform external response actions. Synchronization is manual; no background scheduler is included.

### SOAR simulation, Copilot, audit and reporting

- SOAR stores trigger/condition/action workflows and execution history. Runs are local simulations. Approval records analyst intent; no host/network blocking or destructive action is executed.
- Security Copilot maps supported questions to fixed, bounded ORM queries and deterministic summaries. It does not generate executable SQL. Optional Ollama wording assistance operates on locally grounded responses.
- Audit records are append-only and SHA-256 chained. The Audit page verifies stored entry order and chain head. Collector source credentials remain separate and are hashed.
- Reporting includes local summaries, spreadsheet-safe CSV, alert exports, and printable incident reports.

### SOC interface and responsive behavior

The interface contains 18 workspaces: Overview, Live Monitoring, Event Explorer, Detection Engineering, Threat Detection, Threat Hunting, Detection Validation Lab, Threat Intelligence, IP Intelligence, Attack Relationships, ATT&CK Coverage, AI Analysis/UEBA, Incident Management, SOAR, Security Copilot, Audit History, Reports, Settings and Administration.

Shared UI behavior includes local search and command navigation, notifications, API status, contextual help, responsive tables, evidence panels, loading/error/empty states and visible keyboard focus. The latest sidebar fix uses `100vh` with `100dvh`, a stable desktop width, a flex-constrained independently scrolling navigation region, and a subtle scrollbar. The mobile drawer retains its scrolling and navigation behavior. Desktop main content scrolls independently.

## 4. Data lifecycle

1. Authorized or synthetic authentication records enter through the API, structured file import, loopback Syslog, or a configured Windows collector.
2. Inputs are validated and normalized; ingestion metadata is retained where provided.
3. The detection engine evaluates configured rules and persists alerts with evidence links.
4. Correlation groups related alerts into incidents; analyst changes and dispositions are persisted and audited.
5. UEBA, risk scoring, graph/storyline, ATT&CK coverage and Copilot read locally stored records and expose bounded evidence.
6. Threat Hunting reads stored records through the restricted query schema.
7. Detection Lab scenario records are evaluated in a temporary SQLite database, while run reports/reviews are stored in lab history.
8. External intelligence is stored separately from local analyst IOCs and is correlated only against fields present in local events.

## 5. Security and operating boundaries

- Local mode does **not** require analyst accounts and is restricted to loopback. Optional demo mode provides one shared login with process-local sessions, HTTPS-origin checks, and CSRF protection; it is not full RBAC or tenant isolation.
- Windows collector ingestion has separate source token checks; Syslog binds to loopback by default.
- Uploads, hunting conditions, paging, exports, replay samples, feed parsing and correlation queries are bounded and validated.
- ORM queries use constrained inputs; the Copilot and Hunting interfaces do not execute arbitrary SQL from user text.
- External feed credentials are supplied through backend environment variables and are not returned as secret values.
- Feed fetching includes SSRF controls; those controls do not turn the dashboard into a safe multi-tenant/public deployment.
- Audit chaining can reveal in-place history changes, but the chain head should be exported to independent protected storage to defend against a privileged rewrite of the entire database.
- The project currently supports one local organization. Domain records do not all carry organization IDs, so tenant isolation is not provided.

## 6. Verification status

| Verification | Latest recorded result |
| --- | --- |
| Full backend pytest suite after Threat Intelligence Phase 2 | **46 passed**; SQLAlchemy/Python datetime-adapter deprecation warnings were reported |
| Frontend production build after responsive and sidebar changes | **Passed** with Vite |
| Responsive page layout | **180 page/viewport checks passed** across 18 workspaces and widths 320, 360, 390, 430, 768, 820, 1024, 1280, 1440 and 1920px |
| Sidebar scroll and independent desktop content scrolling | **12 checks passed** at widths 768, 1024, 1440 and 1920px and heights 600, 768 and 900px |
| Mobile drawer navigation scroll | **Passed** at 390×600px; first and last nav entries visible at their respective scroll positions |
| Local API health after restart | **Passed**: `/api/health` returned status `ok`; dashboard API requests returned 200 |

The frontend package does not define a separate frontend test script/framework. Browser viewport checks verified layout bounds and navigation behavior; they were not an exhaustive manual test of every form, table action, graph gesture or backend workflow at every screen size.

## 7. Known limitations and follow-up work

- Demo authentication is a limited shared-user gate, not individual analyst RBAC. Tenant isolation is not implemented; the application is not production-ready for unrestricted public exposure.
- Current authentication records do not contain domain or file-hash fields, preventing those IOC types from correlating to those records.
- External feeds support configured JSON/CSV mappings and manual synchronization; there is no scheduler or tested live integration with a particular vendor.
- Risk and behavior outputs are explainable review signals, not calibrated probabilities or proof of compromise.
- Synthetic Detection Lab performance describes only the saved controlled scenarios, not production detection accuracy.
- SOAR is simulation-only and does not perform containment or response actions.
- Model deployment/version tracking and environment switching remain future work.
- The existing dashboard is a local single-organization workspace and is not presented as a hardened public SOC service.

## 8. Local run instructions

Start the API in one terminal:

```bash
cd backend
source .venv/bin/activate
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

Start the frontend in another terminal:

```bash
cd frontend
npm install
npm run dev -- --host 127.0.0.1
```

Open `http://127.0.0.1:5173/`; use `http://127.0.0.1:8000/docs` for the API reference. To verify locally, run `cd backend && .venv/bin/python -m pytest -q` and `cd frontend && npm run build`.

## 9. Reference documentation

- [Architecture](architecture.md)
- [Threat Hunting and Detection Validation Lab](threat-hunting-and-detection-lab.md)
- [Threat Intelligence and IOC Correlation](threat-intelligence-phase2.md)
- [Syslog ingestion](syslog-ingestion.md)
- [Windows Security ingestion](windows-security-ingestion.md)
- [Local access boundary](local-access.md)
