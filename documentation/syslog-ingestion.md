# Linux SSH Syslog ingestion

ThreatLens can receive SSH authentication messages from rsyslog over TCP. The
listener starts with the API and stores recognized records through the existing
event ingestion, detection, incident correlation, and audit flow.

## Defaults

- Transport: TCP, port `5514`.
- Bind address: `127.0.0.1`.
- Allowed sender addresses: `127.0.0.1/32` and `::1/128`.
- Maximum frame size: 8 KiB.
- Accepted records: OpenSSH accepted/failed password, public key, and
  keyboard-interactive authentication messages, plus common failed SSH PAM
  authentication messages.
- Other syslog messages are counted as ignored and are not stored as auth
  events.

The listener accepts newline-delimited messages and RFC6587 octet-counted
frames. It recognizes RFC3164 and RFC5424 timestamps and records the sender
hostname in the event source label. RFC3164 has no timezone field, so its
timestamp is interpreted in the ThreatLens host's local timezone.

## Forward local SSH messages

Create `/etc/rsyslog.d/60-threatlens.conf` on the same Linux host:

```text
if $programname == 'sshd' then action(type="omfwd" target="127.0.0.1" port="5514" protocol="tcp")
```

Restart rsyslog to apply the forwarding rule:

```bash
sudo systemctl restart rsyslog
```

The Settings page shows listener status and received, ingested, ignored, and
rejected counters. `GET /api/ingestion/syslog` exposes the same operational
status.

## Configure a remote sender

Edit `backend/.env`, then restart the API:

```dotenv
THREATLENS_SYSLOG_ENABLED=true
THREATLENS_SYSLOG_HOST=0.0.0.0
THREATLENS_SYSLOG_PORT=5514
THREATLENS_SYSLOG_ALLOWED_SOURCES=10.20.30.0/24
THREATLENS_SYSLOG_MAX_MESSAGE_BYTES=8192
```

Replace `10.20.30.0/24` with the narrow CIDR containing the authorized log
sender. The listener rejects peers outside this allowlist. TCP Syslog is
unencrypted; keep remote forwarding on a trusted private network or terminate
TLS before it reaches this listener. The application API itself is intended
for localhost demonstrations and has no authentication, so do not expose the
API or Syslog listener directly to an untrusted network.

## Event mapping

Recognized SSH records become `ssh` events with the username, remote source IP,
success/failure status, source hostname label, event timestamp, and receive
time. Invalid IPs, missing usernames, unrelated messages, and malformed or
oversized frames are not inserted. Raw messages are not retained in the event
table.
