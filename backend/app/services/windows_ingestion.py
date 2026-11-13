import hashlib
import hmac
import ipaddress
import secrets
import re
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import IngestionReceipt, IngestionSource
from app.schemas import AuthEventCreate, WindowsSecurityEvent
from app.services.audit import record_audit
from app.services.ingestion import ingest_event_batch

HOST_RE = re.compile(r"[^A-Za-z0-9_.-]+")
LOGON_TYPE_NAMES = {
    "2": "Interactive",
    "3": "Network",
    "4": "Batch",
    "5": "Service",
    "7": "Unlock",
    "8": "NetworkCleartext",
    "9": "NewCredentials",
    "10": "RemoteInteractive",
    "11": "CachedInteractive",
}


def _token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _new_token() -> str:
    return f"tl_src_{secrets.token_urlsafe(32)}"


def _store_token(source: IngestionSource) -> str:
    token = _new_token()
    source.token_hash = _token_digest(token)
    source.token_prefix = token[:24]
    source.enabled = True
    return token


def create_windows_source(db: Session, name: str) -> tuple[IngestionSource, str]:
    source = IngestionSource(name=name.strip(), platform="windows_security")
    token = _store_token(source)
    db.add(source)
    db.flush()
    record_audit(db, "ingestion_source.created", "ingestion_source", source.id, {"name": source.name, "platform": source.platform})
    return source, token


def rotate_windows_source_token(db: Session, source: IngestionSource) -> str:
    token = _store_token(source)
    record_audit(db, "ingestion_source.token_rotated", "ingestion_source", source.id, {"name": source.name})
    return token


def revoke_windows_source(db: Session, source: IngestionSource) -> None:
    source.enabled = False
    source.token_hash = None
    source.token_prefix = None
    record_audit(db, "ingestion_source.revoked", "ingestion_source", source.id, {"name": source.name})


def authenticate_windows_source(db: Session, token: str | None) -> IngestionSource | None:
    if not token or len(token) > 160 or not token.startswith("tl_src_"):
        return None
    source = db.scalar(select(IngestionSource).where(IngestionSource.token_prefix == token[:24]))
    if source is None or source.token_hash is None or not hmac.compare_digest(source.token_hash, _token_digest(token)):
        return None
    if not source.enabled:
        return None
    return source


def _field_map(event: WindowsSecurityEvent) -> dict[str, str]:
    return {key.strip().casefold(): value.strip() for key, value in event.event_data.items()}


def _event_key(event: WindowsSecurityEvent) -> str:
    host = HOST_RE.sub("_", event.computer.strip().casefold())[:255]
    timestamp = event.time_created
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    timestamp = timestamp.astimezone(timezone.utc).isoformat(timespec="microseconds")
    return f"{host}|{event.channel}|{event.event_id}|{event.record_id}|{timestamp}"


def _normalize_windows_event(event: WindowsSecurityEvent) -> tuple[dict[str, object] | None, str | None, str]:
    fields = _field_map(event)
    username = fields.get("targetusername", "")
    domain = fields.get("targetdomainname", "")
    if not username or username in {"-", "(null)"}:
        return None, "no_username", _event_key(event)
    normalized_username = f"{domain}\\{username}" if domain and domain not in {"-", "."} else username
    normalized_username = normalized_username[:128]

    raw_ip = fields.get("ipaddress", "")
    if not raw_ip or raw_ip in {"-", "(null)"}:
        return None, "no_ip", _event_key(event)
    try:
        address = ipaddress.ip_address(raw_ip)
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            address = address.ipv4_mapped
    except ValueError:
        return None, "no_ip", _event_key(event)
    if address.is_loopback or address.is_unspecified:
        return None, "local", _event_key(event)

    hostname = HOST_RE.sub("_", event.computer.strip())[:255] or "unknown"
    logon_type = fields.get("logontype") or None
    safe_metadata: dict[str, object] = {
        "platform": "windows",
        "event_id": event.event_id,
        "record_id": event.record_id,
        "channel": event.channel,
        "logon_type": logon_type,
        "logon_type_name": LOGON_TYPE_NAMES.get(logon_type or "", "Unknown"),
        "domain": domain or None,
        "workstation": fields.get("workstationname") or None,
        "failure_reason": fields.get("failurereason") or None,
        "status_code": fields.get("status") or None,
        "sub_status": fields.get("substatus") or None,
        "authentication_package": fields.get("authenticationpackagename") or None,
        "process_name": fields.get("processname") or None,
    }
    timestamp = event.time_created
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    payload = AuthEventCreate(
        timestamp=timestamp.astimezone(timezone.utc),
        username=normalized_username,
        source_ip=str(address),
        event_type="windows_logon",
        status="success" if event.event_id == 4624 else "failure",
    )
    event_key = _event_key(event)
    return {
        "payload": payload,
        "source_label": f"Windows Security/{hostname}"[:80],
        "source_host": hostname,
        "source_event_id": event_key,
        "event_metadata": safe_metadata,
    }, None, event_key


def ingest_windows_batch(
    db: Session,
    source: IngestionSource,
    events: list[WindowsSecurityEvent],
    sender_ip: str | None,
) -> dict[str, int]:
    counts = {"accepted": 0, "duplicates": 0, "ignored_no_ip": 0, "ignored_local": 0, "ignored_no_username": 0}
    new_records: list[dict[str, object]] = []
    receipt_rows: list[IngestionReceipt] = []
    seen_event_keys: set[str] = set()

    for event in events:
        event_record, ignored_reason, event_key = _normalize_windows_event(event)
        if event_key in seen_event_keys:
            counts["duplicates"] += 1
            continue
        seen_event_keys.add(event_key)
        if db.scalar(
            select(IngestionReceipt.id).where(
                IngestionReceipt.source_id == source.id,
                IngestionReceipt.event_key == event_key,
            )
        ) is not None:
            counts["duplicates"] += 1
            continue
        if ignored_reason:
            counts[f"ignored_{ignored_reason}"] += 1
            receipt_rows.append(IngestionReceipt(source_id=source.id, event_key=event_key, outcome=f"ignored_{ignored_reason}"))
            continue
        assert event_record is not None
        event_record["ingestion_source_id"] = source.id
        new_records.append(event_record)

    ingested_records = ingest_event_batch(db, new_records)
    counts["accepted"] = len(ingested_records)
    for event_record, stored_event in zip(new_records, ingested_records, strict=True):
        receipt_rows.append(
            IngestionReceipt(
                source_id=source.id,
                event_key=str(event_record["source_event_id"]),
                event_id=stored_event.id,
                outcome="ingested",
            )
        )
    db.add_all(receipt_rows)
    source.events_ingested += counts["accepted"]
    source.events_ignored += counts["ignored_no_ip"] + counts["ignored_local"] + counts["ignored_no_username"]
    source.events_duplicated += counts["duplicates"]
    source.last_seen_at = datetime.now(timezone.utc)
    if counts["accepted"]:
        source.last_event_at = max(event.timestamp for event in ingested_records)
    source.last_sender_ip = sender_ip[:45] if sender_ip else None
    record_audit(
        db,
        "windows.events_received",
        "ingestion_source",
        source.id,
        counts,
        actor=f"Windows source: {source.name}"[:128],
    )
    return counts


def mark_windows_source_seen(source: IngestionSource, sender_ip: str | None) -> None:
    source.last_seen_at = datetime.now(timezone.utc)
    source.last_sender_ip = sender_ip[:45] if sender_ip else None
