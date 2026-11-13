import csv
import io
import json

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import Alert, AuthEvent


def build_report_summary(db: Session) -> dict[str, object]:
    event_count = db.scalar(select(func.count(AuthEvent.id))) or 0
    success_count = db.scalar(
        select(func.count(AuthEvent.id)).where(AuthEvent.status == "success")
    ) or 0
    failure_count = db.scalar(
        select(func.count(AuthEvent.id)).where(AuthEvent.status == "failure")
    ) or 0
    severities = {
        severity: db.scalar(select(func.count(Alert.id)).where(Alert.severity == severity)) or 0
        for severity in ("critical", "high", "medium", "low")
    }
    return {
        "total_events": event_count,
        "successful_logins": success_count,
        "failed_logins": failure_count,
        "alerts_by_severity": severities,
    }


def build_events_csv(db: Session) -> str:
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(["timestamp", "ingested_at", "source", "source_host", "source_event_id", "username", "source_ip", "event_type", "status", "user_agent", "event_metadata_json"])
    events = db.scalars(select(AuthEvent).order_by(AuthEvent.timestamp.desc()).limit(50_000))
    for event in events:
        writer.writerow(
            [
                event.timestamp.isoformat(),
                event.ingested_at.isoformat() if event.ingested_at else "",
                _spreadsheet_safe(event.source_label),
                _spreadsheet_safe(event.source_host or ""),
                _spreadsheet_safe(event.source_event_id or ""),
                _spreadsheet_safe(event.username),
                event.source_ip,
                _spreadsheet_safe(event.event_type),
                event.status,
                _spreadsheet_safe(event.user_agent or ""),
                _spreadsheet_safe(json.dumps(event.event_metadata or {}, ensure_ascii=False, sort_keys=True)),
            ]
        )
    return output.getvalue()


def build_alerts_csv(db: Session, alert_ids: list[int]) -> str:
    alerts = list(db.scalars(select(Alert).where(Alert.id.in_(alert_ids))))
    alerts_by_id = {alert.id: alert for alert in alerts}
    missing_ids = [alert_id for alert_id in alert_ids if alert_id not in alerts_by_id]
    if missing_ids:
        raise LookupError(f"Alert(s) not found: {', '.join(str(item) for item in missing_ids)}.")

    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(["id", "title", "detection_key", "attack_technique", "severity", "status", "disposition", "disposition_updated_at", "disposition_notes", "source_ip", "created_at", "reason", "related_event_ids", "analyst_notes"])
    for alert_id in alert_ids:
        alert = alerts_by_id[alert_id]
        writer.writerow([
            alert.id,
            _spreadsheet_safe(alert.title),
            _spreadsheet_safe(alert.detection_key),
            _spreadsheet_safe(alert.attack_technique or ""),
            alert.severity,
            alert.status,
            alert.disposition or "",
            alert.disposition_updated_at.isoformat() if alert.disposition_updated_at else "",
            _spreadsheet_safe(alert.disposition_notes),
            alert.source_ip,
            alert.created_at.isoformat(),
            _spreadsheet_safe(alert.reason),
            _spreadsheet_safe(json.dumps(alert.related_event_ids, ensure_ascii=False)),
            _spreadsheet_safe(alert.analyst_notes),
        ])
    return output.getvalue()


def _spreadsheet_safe(value: str) -> str:
    if value.lstrip(" \t\r\n").startswith(("=", "+", "-", "@")):
        return f"'{value}"
    return value
