# Threat Intelligence and IOC Correlation

This phase adds configurable external feed ingestion while retaining the
existing analyst-managed IP Intelligence workflow. External intelligence is
stored separately and is never treated as analyst-confirmed evidence.

## Local configuration

The backend reads configuration from environment variables (or `backend/.env`):

| Setting | Purpose | Default |
| --- | --- | --- |
| `THREATLENS_FEED_ALLOWED_HOSTS` | Comma-separated exact DNS host allowlist; required for feed access | empty |
| `THREATLENS_FEED_MAX_RESPONSE_BYTES` | Maximum downloaded response body | 5 MiB |
| `THREATLENS_FEED_MAX_RECORDS` | Maximum parsed records per feed | 25,000 |
| `THREATLENS_FEED_CONNECT_TIMEOUT_SECONDS` | Connection timeout | 5 seconds |
| `THREATLENS_FEED_READ_TIMEOUT_SECONDS` | Read timeout | 10 seconds |

Configure a feed using an HTTPS URL on port 443, JSON or CSV format, and a
field mapping. URLs containing credentials, query strings, or fragments are
rejected. Host matching is exact (no implicit subdomains). If a provider needs
a credential, set its secret in the backend environment and enter only the
environment-variable name in the feed configuration. Secret values are not
stored in the database or returned by the API.

Feed requests do not follow redirects, do not use environment proxy settings,
and accept only publicly routable DNS destinations. DNS is checked before the
request and again at connection time; the validated public address is pinned
for the connection while TLS certificate and SNI validation use the configured
host. Downloads, timeouts, content types, feed record counts, and field names
are bounded/validated. Synchronization is manual from the workspace or the
feed sync API; there is no background scheduler.

## Data and provenance

Supported indicators are IPv4/IPv6, IDNA-normalized domains, and MD5, SHA-1,
or SHA-256 hashes. Normalization happens before deduplication. A canonical
indicator has independent source observations, each with feed, original
reference, source confidence (nullable when absent), first/last seen, expiry,
and latest sync-run association. Repeated syncs update the existing observation
for the same source reference. Earliest first-seen and latest last-seen are
preserved. Indicator activity is based on whether at least one source has not
expired; expiry from one feed does not deactivate another active source.

The current authentication event schema contains source IP but no destination
domain or file hash. IP indicators are matched by exact source IP against local
event records. Domain and hash indicators explicitly report unsupported schema
correlation instead of implying a match. Matching local alerts and incidents
are linked by their stored event IDs. Feed confidence remains distinct from
analyst disposition. Analyst reviews append history, update the current review
state, and create entries in the existing chained audit history.

## API surface

All paths are under `/api/intelligence`:

| Method and path | Purpose |
| --- | --- |
| `GET /feeds` | Bounded feed listing with freshness and last sync summary |
| `POST /feeds` | Create a validated feed configuration |
| `PUT /feeds/{feed_id}` | Update a feed configuration |
| `PATCH /feeds/{feed_id}/enabled` | Enable/disable a feed |
| `POST /feeds/{feed_id}/sync` | Start a manual bounded synchronization |
| `GET /feeds/{feed_id}/runs` | Read bounded sync history |
| `GET /iocs` | Search/filter/paginate normalized external indicators |
| `GET /iocs/{indicator_id}` | Read indicator and bounded source provenance |
| `GET /iocs/{indicator_id}/correlation` | Match local events, alerts, and incidents |
| `GET /iocs/{indicator_id}/timeline` | Read source, event, and review history |
| `POST /iocs/{indicator_id}/reviews` | Record an analyst disposition and audit event |

Feed sync returns accepted/rejected counts and bounded validation diagnostics;
raw feed rows and secrets are not echoed. Failed syncs are recorded without
deleting prior successful observations or changing `last_success_at`. Feed
state distinguishes disabled, never synced, syncing, failed, stale, and fresh.

## Interpretation and limits

This module validates source observations and local correlation; it does not
block IPs, execute response actions, or claim that an external indicator is
malicious. A feed's confidence is the provider-supplied value, not a calibrated
platform score. Freshness describes sync recency, while observation expiry
describes the source's own indicator validity. Findings depend on feed quality
and locally retained event coverage. Dashboard access follows the configured
authentication mode: local mode is unauthenticated and loopback-only, while
demo mode provides a limited single-user login without tenant isolation. Neither
mode makes the application ready for unrestricted public exposure.

The workspace does not make live third-party requests until a feed is
configured, allowlisted, and manually synchronized. Automated tests use
controlled fixtures for feed responses and SSRF checks; they do not validate
any specific provider's live availability or schema.
