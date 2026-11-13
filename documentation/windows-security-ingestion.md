# Windows Security event collector

ThreatLens can receive Windows Security logon events from a small PowerShell
collector. The collector reads Event IDs 4624 and 4625, posts bounded batches
over HTTPS or a trusted private network, and checkpoints the Windows log record
ID only after the API acknowledges the batch.

## What is collected

- 4624: successful account logon.
- 4625: failed account logon.
- Account name (qualified with domain when present), remote address, computer,
  channel, event time, Windows record ID, logon type, workstation, failure
  reason, authentication package, and process name.
- Only allowlisted event fields are retained. Raw XML is not stored.
- Events without a username or usable remote IP are counted and skipped. Local
  loopback and unspecified addresses are skipped instead of being represented
  as made-up remote sources. This collector focuses on network-originated
  authentication; it does not ingest interactive or service logons without a
  remote address.

Accepted events use the existing auth event pipeline, so source-IP failure
thresholds, password-spray signals, and success-after-failure correlation work
across Linux SSH and Windows network logons. Windows host, event ID, record ID,
logon type, and selected failure context remain visible in the event inspector.
Some alert rules expose explicit MITRE ATT&CK references: generic brute force
uses T1110, and multiple-account spraying uses T1110.003. These are rule
references, not model-generated classifications.

## Register a source

1. Open **Administration → Windows Security sources** on the local analyst machine.
2. Create one source per Windows host and copy the displayed token. It is shown
   once; the database stores its SHA-256 hash. Rotate it if it is lost.
3. Download `threatlens_windows_agent.ps1` and copy it to the Windows host.
4. From `backend/`, run the isolated receiver on a private interface. It shares
   the dashboard's SQLite database but exposes only health, heartbeat, and
   authenticated event-ingestion routes:

   ```bash
   source .venv/bin/activate
   uvicorn app.collector:app --host 192.168.1.20 --port 8001
   ```

   Replace `192.168.1.20` with the collector host's private LAN address. The
   dashboard API stays on `127.0.0.1:8000`.

5. Open PowerShell as an account permitted to read the Security event log, then
   point the agent at the collector:

   ```powershell
   .\threatlens_windows_agent.ps1 -ApiBaseUrl 'http://192.168.1.20:8001'
   ```

   The script prompts for the token without echoing it and protects it with
   Windows DPAPI in the current user's profile. Its cursor is stored beside
   that credential. Run the scheduled task as the same Windows account. Remove
   `%LOCALAPPDATA%\ThreatLens\source-token.dpapi` to prompt for a replacement
   after token rotation.

The first run starts at the current end of the Security log to avoid importing
an unbounded history. The cursor then advances in small record-ID ranges. If an
API request fails, the range is retried; server-side deduplication uses source,
computer, channel, event ID, record ID, and event time, so retries do not create duplicate
authentication records. The agent sends a heartbeat every polling cycle,
including when no logons occur. The Settings page shows collector check-in time
separately from last event time, sender address, accepted, ignored, and
duplicate counts. Pause, revoke, and token rotation are available per source.

## Network and access boundary

Source administration endpoints are available from localhost without an
analyst API key. Keep the dashboard bound to localhost. See
`documentation/local-access.md` for dashboard access and collector credential
boundaries.
The separate collector service does not expose dashboard reads, analyst
controls, or source administration; event and heartbeat calls require the
source's bearer token. Restrict inbound port 8001 to the collector host and use
HTTPS or a trusted VPN because plain HTTP exposes bearer tokens on the network.
Do not expose the dashboard API on port 8000 to the collector network or the
Internet as an unrestricted service. Local mode has no dashboard login; demo
mode adds a limited shared login but has no tenant scoping or production-ready
role model.

The agent only sends Event IDs 4624/4625 and a bounded set of fields. It does
not make response changes on Windows. Event receipt is evidence for review, not
proof that an account was compromised.
