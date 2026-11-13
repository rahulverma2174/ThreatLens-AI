# ThreatLens AI — Enterprise SOC Plan

## 1. Existing functionality audit

| Area | Implemented today | Gap against the SOC brief |
|---|---|---|
| SIEM ingestion | Auth-event API, CSV/JSON/JSONL and Linux `auth.log`/`secure` imports, local Syslog TCP, optional Windows Security agent, ingestion source/run tracking and duplicate protection | A general normalized event schema is missing; event types are still focused on authentication |
| Detection | Built-in auth rules, analyst-managed rolling-window rules with append-only revisions, read-only replay, alert dispositions and per-rule review metrics | Custom rules cover failed authentication only; built-in rules are not independently enabled |
| Search and hunting | Paginated event search, local natural-language filters, persisted saved event searches, IP investigation and relationship graph | No explicit time-range query language or hunt history/notes workspace |
| Incident response | Correlated incidents, status, assignee, tasks, comments, evidence event/alert links, incident brief and audit entries | No SLA clock, escalation policy, closure reason, or separate case lifecycle |
| Threat intelligence | Analyst-maintained IP allow/block indicators used as local risk context | No domains/hashes, confidence/expiry, feed import, or matching for non-IP events |
| UEBA and AI | Local behavioral profiles, anomaly/risk scoring, deterministic Copilot with optional local Ollama/Qwen | No durable entity baseline lifecycle or event/alert citations in every Copilot answer |
| MITRE ATT&CK | A few real technique identifiers attached to relevant rules and alerts | No framework-versioned catalog, tactic/technique workspace, or coverage view |
| SOAR | Incident investigation tasks | No playbook definitions, approval steps, simulation runs, or execution history |
| Assets and exposure | Host/source context retained when a collector supplies it | No first-class asset inventory or vulnerability findings |
| Identity and tenancy | Local admin/analyst/viewer roles, hashed/revocable API keys, one default organization, loopback bootstrap | Domain records are not organization-scoped; no multi-tenant isolation or key expiry yet |
| Audit and operations | Hash-chained, append-only audit history with analyst identity for new UI actions; health endpoint; local data provenance labels | No retention controls or external audit-head anchoring; legacy rows retain “Local analyst” |
| Interface | Dark SOC-inspired shell, compact tables, global search/command palette, detection engineering, administration and responsive layouts | Navigation covers 13 work areas today, not the full 17-workspace target |

No live threat counts, IOC reputation, production accuracy, tenant identity, or
asset facts should be inferred from the current local data. Seeded records are
synthetic and must remain labelled as such.

## 2. Target architecture

```text
Collectors / CSV / JSON / API
            |
            v
Source adapters -> validation + normalization -> ingestion runs / provenance
            |                                       |
            v                                       v
       Event store --------------------------> source health
            |
            +--> rule engine + rule revisions --> alerts
            |                                     |
            +--> entity/asset/IOC enrichment -----+
                                                  v
                                  correlation -> incidents / cases
                                                  |
                               analyst actions / simulated SOAR
                                                  |
                                                  v
                                   append-only audit chain

React workspaces -> FastAPI routers -> services -> SQLAlchemy repositories
                                      -> SQLite (local prototype)
                                      -> PostgreSQL (later deployment target)
```

Keep routers thin and put detection, normalization, case, IOC and playbook
logic in services. Preserve the current `AuthEvent` contract during the first
phases; introduce a versioned normalized-event envelope alongside it before
generalizing detections beyond authentication. Use UTC for event and audit
times, store source identity and ingestion provenance, make collector batches
idempotent, and keep all expensive/external enrichment optional.

Trust boundary: until authentication and tenant scoping are implemented, the
dashboard API is a local academic workspace and must not be exposed to an
untrusted network. Keep real endpoint response actions out of scope; SOAR
starts with auditable simulation and explicit analyst approval gates.

## 3. UI redesign specification

Retain the existing graphite/navy palette, restrained severity colors, compact
tables, focus states, reduced-motion support and command palette. Organize the
shell into four groups and map all requested workspaces as follows:

| Group | Workspace |
|---|---|
| Monitor | SOC Command Center, Security Events, Detection Engineering, Alert Management |
| Investigate | Incident Response, Threat Hunting, AI Analytics, UEBA, Threat Intelligence, MITRE ATT&CK |
| Respond | Asset Inventory, Vulnerability Management, SOAR Playbooks, Case Management |
| Govern | Reports & Compliance, Audit Center, Administration |

Use a high-density queue as the default work surface, with saved filters,
keyboard navigation, contextual side panels and evidence links. Detail views
should expose source/time/provenance, related event IDs, rule version, and audit
history. Existing Overview, Events, Alerts, Incidents, Anomaly, Investigation,
Relationships, Copilot, Reports, Audit and Settings pages map to those
workspaces; do not show simulated controls for backend features that do not
exist yet.

## 4. Module dependency map

1. **Foundation:** schema migration discipline, API health, actor identity,
   workspace/org boundary, RBAC and audit attribution.
2. **SIEM core:** source registry -> parsers/normalizers -> idempotent event
   store -> search/saved hunts -> detection rules and replay.
3. **Detection operations:** versioned rules -> alerts -> dispositions/quality
   -> correlation -> incident/case workflow and SLA.
4. **Context:** assets + imported vulnerabilities, IOC types/feeds, ATT&CK
   catalog/version and explicit mappings -> event/alert enrichment and coverage.
5. **Automation:** trigger/condition/action playbooks -> simulation runs ->
   human approval records -> audited execution history.
6. **Analyst experience:** command center, investigation workspaces, reports,
   administration and health/retention controls consume the above APIs.

Authentication/authorization and tenant scoping must precede any deployment or
multi-organization data feature. Existing single-workspace data can migrate to
a default local organization without changing its record IDs.

## 5. Database migration plan

- Keep existing SQLite data and IDs. Add columns/tables through ordered,
  repeatable migrations; do not rely on `create_all` as the long-term migration
  mechanism.
- Establish a migration baseline from the current tables. Add `organizations`,
  `users`, memberships/roles and API-key hashes before tenant-owned domain
  records; backfill existing records into a single `Local workspace`.
- Add versioned detection rule and revision tables. Link generated alerts to
  the exact rule revision that produced them.
- Add generalized normalized events as a compatible parallel table or staged
  nullable fields; backfill only facts already present. Preserve raw source
  references and avoid fabricating host, user, geo or reputation attributes.
- Add IOC type/value/confidence/source/expiry and asset/vulnerability tables
  with uniqueness and provenance. Keep existing `LocalIndicator` IP rows
  readable through a compatibility migration.
- Add cases, evidence links, SLA timestamps, closure reasons and playbook
  definitions/runs as separate tables rather than expanding JSON blobs.
- Validate SQLite migrations in place, then run the same migration set against
  PostgreSQL before claiming PostgreSQL support. Review JSON, index, datetime,
  uniqueness and transaction behavior explicitly.

## 6. Phased implementation roadmap

### Phase 1 — Detection Engineering (implemented v1)

Add analyst-managed threshold rules with constrained aggregation types,
append-only versions, event-pipeline execution, read-only replay, audit records
and a dedicated frontend workspace. Preserve current built-in detections.
Current v1 supports four failed-authentication aggregations and links generated
alerts to the creating rule revision through their detection key.

### Phase 2 — Identity and data foundations (local RBAC and JSON ingest implemented)

Migration tooling, multi-org scoping, and a general cross-source event envelope
remain. A default `Local workspace` organization, local administrator/analyst/
viewer accounts, hashed API-key issuance/revocation, audit attribution, and
JSON/JSONL upload are implemented. JSON imports preserve supplied host, source
event ID, and metadata with an ingestion run. Domain data tables still have no
organization foreign key, so the app is single-org only. Keep collector tokens
separate from dashboard credentials.

### Phase 3 — Hunting, ATT&CK and intelligence

Add time-bounded query/history/notes workflows, a versioned ATT&CK catalog with
evidence-backed coverage, and typed IP/domain/hash IOCs with confidence,
expiration and import provenance. External feeds remain opt-in and unavailable
reputation is shown as unknown.

### Phase 4 — Cases and assets

Build asset inventory only from collector/import evidence, link events/alerts to
assets, support imported vulnerability records, and add case lifecycle,
ownership, SLA/escalation, evidence and closure reasons.

### Phase 5 — Safe SOAR and operational governance

Add playbook definitions, trigger/condition/action validation, simulation,
approval queue and run logs. Add retention controls, source health, API-key
administration, compliance exports and broader integration tests.

### Phase 6 — Enterprise readiness

Complete remaining workspace integration, load/performance checks, PostgreSQL
validation, security review and deployment documentation. A local prototype
does not become production enterprise-ready solely through UI additions.

## Current implementation boundary

Phase 1 evaluates custom rules against new authentication events and emits
review alerts; replay previews read stored events without writing. Rule actions
do not execute commands or block accounts. Organization/RBAC remains a
prerequisite for any untrusted-network deployment.
