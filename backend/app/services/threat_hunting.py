"""Validated, bounded ORM query execution for authentication event hunts."""

import csv
import io
import time
from datetime import datetime

from sqlalchemy import Integer, and_, cast, exists, func, or_, select, true
from sqlalchemy.orm import Session

from app.models import Alert, AuthEvent, Incident
from app.schemas import HuntCondition, HuntFilterSet

HUNT_EXPORT_MAX_ROWS = 5_000


def _related_ids_expression(model, event_id):
    related = func.json_each(model.related_event_ids).table_valued("value").alias()
    return exists(select(1).select_from(related).where(cast(related.c.value, Integer) == event_id))


def build_hunt_statement(query: HuntFilterSet):
    """Build a SQLAlchemy statement from schema-validated fields only."""
    statement = select(AuthEvent).where(
        AuthEvent.timestamp >= query.start_time,
        AuthEvent.timestamp <= query.end_time,
    )
    predicates = []
    for condition in query.conditions:
        predicates.append(_condition_expression(condition))
    expression = and_(*predicates) if query.logic == "AND" else or_(*predicates)
    return statement.where(expression)


def _condition_expression(condition: HuntCondition):
    if condition.field == "source_ip":
        return AuthEvent.source_ip == condition.value
    if condition.field == "username":
        if condition.operator == "contains":
            return AuthEvent.username.ilike(f"%{_escape_like(condition.value)}%", escape="\\")
        return AuthEvent.username == condition.value
    if condition.field == "event_type":
        return AuthEvent.event_type == condition.value
    if condition.field == "result":
        return AuthEvent.status == condition.value
    if condition.field == "severity":
        severity_match = exists(
            select(1).select_from(Alert).where(
                Alert.severity == condition.value,
                _related_ids_expression(Alert, AuthEvent.id),
            )
        )
        if condition.value == "unclassified":
            return ~exists(select(1).select_from(Alert).where(_related_ids_expression(Alert, AuthEvent.id)))
        return severity_match
    raise ValueError("Unsupported hunt field.")


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def execute_hunt(db: Session, query: HuntFilterSet, limit: int, offset: int) -> dict[str, object]:
    started = time.perf_counter()
    base = build_hunt_statement(query)
    total = db.scalar(select(func.count()).select_from(base.order_by(None).subquery())) or 0
    events = list(db.scalars(base.order_by(AuthEvent.timestamp.desc(), AuthEvent.id.desc()).limit(limit).offset(offset)))
    event_ids = [event.id for event in events]
    alerts_by_event: dict[int, list[Alert]] = {event_id: [] for event_id in event_ids}
    incidents_by_event: dict[int, list[Incident]] = {event_id: [] for event_id in event_ids}
    if event_ids:
        related_alerts = func.json_each(Alert.related_event_ids).table_valued("value").alias()
        alert_rows = db.execute(
            select(Alert, cast(related_alerts.c.value, Integer))
            .join(related_alerts, true())
            .where(cast(related_alerts.c.value, Integer).in_(event_ids))
        ).all()
        for alert, event_id in alert_rows:
            alerts_by_event[event_id].append(alert)
        related_incidents = func.json_each(Incident.related_event_ids).table_valued("value").alias()
        incident_rows = db.execute(
            select(Incident, cast(related_incidents.c.value, Integer))
            .join(related_incidents, true())
            .where(cast(related_incidents.c.value, Integer).in_(event_ids))
        ).all()
        for incident, event_id in incident_rows:
            incidents_by_event[event_id].append(incident)
    results = []
    for event in events:
        results.append({
            "event": event,
            "alerts": alerts_by_event[event.id],
            "incidents": incidents_by_event[event.id],
        })
    return {
        "total": int(total),
        "limit": limit,
        "offset": offset,
        "execution_ms": max(0.0, (time.perf_counter() - started) * 1000),
        "results": results,
    }


def load_hunt_events_for_export(db: Session, query: HuntFilterSet, max_rows: int) -> list[AuthEvent]:
    statement = build_hunt_statement(query).order_by(AuthEvent.timestamp.desc(), AuthEvent.id.desc()).limit(min(max_rows, HUNT_EXPORT_MAX_ROWS) + 1)
    events = list(db.scalars(statement))
    if len(events) > max_rows:
        raise ValueError(f"Export exceeds the requested {max_rows} row limit; narrow the query.")
    return events


def safe_csv_cell(value: object) -> str:
    text = "" if value is None else str(value)
    # Prefix formula-like cells so spreadsheet applications treat them as text.
    if text.lstrip().startswith(("=", "+", "-", "@", "\t", "\r")):
        return "'" + text
    return text


def export_events_csv(events: list[AuthEvent]) -> str:
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(["timestamp", "username", "source_ip", "event_type", "result", "source"])
    for event in events:
        writer.writerow([
            safe_csv_cell(event.timestamp.isoformat() if isinstance(event.timestamp, datetime) else event.timestamp),
            safe_csv_cell(event.username), safe_csv_cell(event.source_ip), safe_csv_cell(event.event_type),
            safe_csv_cell(event.status), safe_csv_cell(event.source_label),
        ])
    return output.getvalue()
