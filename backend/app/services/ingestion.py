from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.models import AuthEvent
from app.schemas import AuthEventCreate
from app.services.correlation import correlate_alerts
from app.services.detection import evaluate_event


def _event_from_payload(
    payload: AuthEventCreate,
    source_label: str,
    *,
    source_host: str | None = None,
    source_event_id: str | None = None,
    ingestion_source_id: int | None = None,
    import_run_id: int | None = None,
    event_metadata: dict[str, object] | None = None,
) -> AuthEvent:
    timestamp = payload.timestamp or datetime.now(timezone.utc)
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    else:
        timestamp = timestamp.astimezone(timezone.utc)
    event = AuthEvent(
        timestamp=timestamp,
        source_label=source_label[:80],
        username=payload.username.strip(),
        source_ip=str(payload.source_ip),
        event_type=payload.event_type.strip(),
        status=payload.status,
        user_agent=payload.user_agent,
        source_host=source_host,
        source_event_id=source_event_id,
        ingestion_source_id=ingestion_source_id,
        import_run_id=import_run_id,
        event_metadata=event_metadata or {},
    )
    if not event.username or not event.event_type:
        raise ValueError("Username and event type cannot be blank.")
    return event


def ingest_event(
    db: Session,
    payload: AuthEventCreate,
    source_label: str = "API",
    *,
    source_host: str | None = None,
    source_event_id: str | None = None,
    ingestion_source_id: int | None = None,
    import_run_id: int | None = None,
    event_metadata: dict[str, object] | None = None,
) -> AuthEvent:
    return ingest_event_batch(
        db,
        [{
            "payload": payload,
            "source_label": source_label,
            "source_host": source_host,
            "source_event_id": source_event_id,
            "ingestion_source_id": ingestion_source_id,
            "import_run_id": import_run_id,
            "event_metadata": event_metadata,
        }],
    )[0]


def ingest_event_batch(db: Session, records: list[dict[str, object]]) -> list[AuthEvent]:
    events = [
        _event_from_payload(
            record["payload"],
            str(record.get("source_label", "API")),
            source_host=record.get("source_host"),
            source_event_id=record.get("source_event_id"),
            ingestion_source_id=record.get("ingestion_source_id"),
            import_run_id=record.get("import_run_id"),
            event_metadata=record.get("event_metadata"),
        )
        for record in records
    ]
    if not events:
        return []
    db.add_all(events)
    db.flush()
    for event in sorted(events, key=lambda item: (item.timestamp, item.id)):
        evaluate_event(db, event)
    correlate_alerts(db)
    return events


def ingest_events(db: Session, payloads: list[AuthEventCreate], source_label: str = "CSV import") -> int:
    records = [{"payload": payload, "source_label": source_label} for payload in payloads]
    return len(ingest_event_batch(db, records))
