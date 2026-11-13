import logging
from datetime import date, datetime, time, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.dependencies import get_db
from app.models import Alert, AuthEvent, DetectionSettings, IngestionRun, utc_now
from app.schemas import (
    AlertBulkStatusResult,
    AlertBulkStatusUpdate,
    AlertDispositionUpdate,
    AlertRead,
    AlertStatusUpdate,
    AnomalyScoreRequest,
    AnomalyScoreResponse,
    DetectionReplayRequest,
    DetectionReplayResponse,
    DetectionSettingsRead,
    DetectionSettingsUpdate,
    DetectionQualityResponse,
    IngestionRunList,
    IngestionRunRead,
    IPInvestigation,
)
from app.services.anomaly import score_events
from app.services.audit import record_audit
from app.services.detection import get_detection_settings
from app.services.detection_replay import preview_detection_settings
from app.services.ingestion import ingest_event_batch
from app.services.parsing import CsvImportError, MAX_UPLOAD_BYTES, parse_auth_event_csv, parse_auth_event_json, parse_linux_auth_log
from app.services.reporting import build_alerts_csv, build_events_csv, build_report_summary

router = APIRouter(prefix="/api")
logger = logging.getLogger(__name__)
DbSession = Annotated[Session, Depends(get_db)]


@router.get("/alerts", response_model=list[AlertRead], tags=["Alerts"])
def list_alerts(
    db: DbSession,
    alert_status: str | None = Query(default=None, alias="status", pattern="^(open|investigating|resolved)$"),
    severity: str | None = Query(default=None, pattern="^(critical|high|medium|low)$"),
    start_date: date | None = Query(default=None),
    end_date: date | None = Query(default=None),
    source_ip: str | None = Query(default=None, max_length=45),
    event_type: str | None = Query(default=None, max_length=32),
) -> list[dict[str, object]]:
    if start_date and end_date and start_date > end_date:
        raise HTTPException(status_code=422, detail="start_date must be on or before end_date.")
    query = select(Alert).order_by(Alert.created_at.desc(), Alert.id.desc())
    if alert_status:
        query = query.where(Alert.status == alert_status)
    if severity:
        query = query.where(Alert.severity == severity)
    if source_ip:
        query = query.where(Alert.source_ip == source_ip)
    if start_date:
        query = query.where(Alert.created_at >= datetime.combine(start_date, time.min, tzinfo=timezone.utc))
    if end_date:
        query = query.where(Alert.created_at < datetime.combine(end_date + timedelta(days=1), time.min, tzinfo=timezone.utc))
    candidates = list(db.scalars(query.limit(5_000)))
    related_ids = {event_id for alert in candidates for event_id in alert.related_event_ids}
    event_types_by_alert: dict[int, list[str]] = {alert.id: [] for alert in candidates}
    if related_ids:
        events = db.execute(select(AuthEvent.id, AuthEvent.event_type).where(AuthEvent.id.in_(related_ids)))
        types_by_event = {event_id: event_type for event_id, event_type in events}
        for alert in candidates:
            event_types_by_alert[alert.id] = sorted({types_by_event[event_id] for event_id in alert.related_event_ids if event_id in types_by_event})
    if event_type:
        candidates = [alert for alert in candidates if event_type in event_types_by_alert[alert.id]]
    return [
        {**AlertRead.model_validate(alert).model_dump(), "event_types": event_types_by_alert[alert.id]}
        for alert in candidates[:500]
    ]


@router.get("/analytics/detection-quality", response_model=DetectionQualityResponse, tags=["Detection management"])
def detection_quality(db: DbSession) -> dict[str, object]:
    grouped: dict[str, dict[str, int]] = {}
    rows = db.execute(
        select(Alert.detection_key, Alert.disposition, func.count(Alert.id))
        .group_by(Alert.detection_key, Alert.disposition)
    )
    for detection_key, disposition, count in rows:
        totals = grouped.setdefault(detection_key, {
            "alert_count": 0,
            "true_positive_count": 0,
            "false_positive_count": 0,
            "benign_activity_count": 0,
        })
        totals["alert_count"] += count
        if disposition == "true_positive":
            totals["true_positive_count"] += count
        elif disposition == "false_positive":
            totals["false_positive_count"] += count
        elif disposition == "benign_activity":
            totals["benign_activity_count"] += count

    rules: list[dict[str, object]] = []
    reviewed_alerts = 0
    total_alerts = 0
    for detection_key, totals in sorted(grouped.items()):
        true_positives = totals["true_positive_count"]
        false_positives = totals["false_positive_count"]
        benign = totals["benign_activity_count"]
        reviewed = true_positives + false_positives + benign
        reviewed_alerts += reviewed
        total_alerts += totals["alert_count"]
        adjudicated = true_positives + false_positives
        rules.append({
            "detection_key": detection_key,
            **totals,
            "reviewed_count": reviewed,
            "false_positive_share": false_positives / adjudicated if adjudicated else None,
        })
    return {
        "rules": rules,
        "reviewed_alerts": reviewed_alerts,
        "unreviewed_alerts": total_alerts - reviewed_alerts,
        "notice": "Share is false-positive labels divided by true- and false-positive labels. It excludes benign-activity labels and reflects the reviewed local sample only.",
    }


@router.patch("/alerts/{alert_id}/disposition", response_model=AlertRead, tags=["Detection management"])
def update_alert_disposition(alert_id: int, payload: AlertDispositionUpdate, db: DbSession) -> Alert:
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found.")
    previous = alert.disposition
    notes = payload.notes.strip()
    alert.disposition = payload.disposition
    alert.disposition_notes = notes
    alert.disposition_updated_at = utc_now()
    record_audit(
        db,
        "alert.disposition_updated",
        "alert",
        alert.id,
        {"from": previous, "to": alert.disposition, "notes": notes},
    )
    db.commit()
    db.refresh(alert)
    return alert


@router.patch("/alerts/bulk", response_model=AlertBulkStatusResult, tags=["Alerts"])
def bulk_update_alert_status(payload: AlertBulkStatusUpdate, db: DbSession) -> dict[str, object]:
    alerts = list(db.scalars(select(Alert).where(Alert.id.in_(payload.alert_ids))))
    found_ids = {alert.id for alert in alerts}
    missing_ids = [alert_id for alert_id in payload.alert_ids if alert_id not in found_ids]
    if missing_ids:
        raise HTTPException(status_code=404, detail={"message": "One or more alerts were not found.", "missing_ids": missing_ids})

    updated_count = 0
    for alert in alerts:
        if alert.status == payload.status:
            continue
        previous_status = alert.status
        alert.status = payload.status
        updated_count += 1
        record_audit(
            db,
            "alert.bulk_status_updated",
            "alert",
            alert.id,
            {"from": previous_status, "to": payload.status, "batch_size": len(alerts)},
        )
    db.commit()
    return {"updated_count": updated_count, "alerts": alerts}


@router.patch("/alerts/{alert_id}", response_model=AlertRead, tags=["Alerts"])
def update_alert(alert_id: int, payload: AlertStatusUpdate, db: DbSession) -> Alert:
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found.")
    if payload.status is None and payload.assignee is None and payload.analyst_notes is None:
        raise HTTPException(status_code=422, detail="Provide an alert status, assignee, or analyst notes.")
    if payload.status is not None:
        alert.status = payload.status
    if payload.assignee is not None:
        alert.assignee = payload.assignee.strip() or None
    if payload.analyst_notes is not None:
        alert.analyst_notes = payload.analyst_notes.strip()
    record_audit(db, "alert.updated", "alert", alert.id, payload.model_dump(exclude_unset=True, exclude_none=True))
    db.commit()
    db.refresh(alert)
    return alert


@router.get("/settings/detection", response_model=DetectionSettingsRead, tags=["Settings"])
def read_detection_settings(db: DbSession) -> DetectionSettings:
    settings = get_detection_settings(db)
    db.commit()
    return settings


@router.patch("/settings/detection", response_model=DetectionSettingsRead, tags=["Settings"])
def update_detection_settings(payload: DetectionSettingsUpdate, db: DbSession) -> DetectionSettings:
    changes = payload.model_dump(exclude_unset=True, exclude_none=True)
    if not changes:
        raise HTTPException(status_code=422, detail="Provide at least one setting to update.")
    settings = get_detection_settings(db)
    for name, value in changes.items():
        setattr(settings, name, value)
    record_audit(db, "detection_settings.updated", "settings", settings.id, changes)
    db.commit()
    db.refresh(settings)
    return settings


@router.post("/analytics/detection-replay", response_model=DetectionReplayResponse, tags=["Detection management"])
def replay_detection_settings(payload: DetectionReplayRequest, db: DbSession) -> dict[str, object]:
    persisted = db.get(DetectionSettings, 1)
    current = {
        "brute_force_threshold": persisted.brute_force_threshold if persisted else 5,
        "window_minutes": persisted.window_minutes if persisted else 10,
        "targeted_username_threshold": persisted.targeted_username_threshold if persisted else 4,
        "repeated_failure_threshold": persisted.repeated_failure_threshold if persisted else 3,
        "success_after_failure_threshold": persisted.success_after_failure_threshold if persisted else 3,
        "distributed_failure_threshold": persisted.distributed_failure_threshold if persisted else 3,
        "distributed_source_ip_threshold": persisted.distributed_source_ip_threshold if persisted else 2,
        "monitoring_enabled": persisted.monitoring_enabled if persisted else True,
    }
    proposed = {**current, **payload.settings.model_dump(exclude_none=True)}
    return preview_detection_settings(
        db,
        window_hours=payload.window_hours,
        current_settings=current,
        proposed_settings=proposed,
    )


@router.get("/investigation/{source_ip}", response_model=IPInvestigation, tags=["IP investigation"])
def investigate_ip(source_ip: str, db: DbSession) -> IPInvestigation:
    import ipaddress

    try:
        normalized_ip = str(ipaddress.ip_address(source_ip))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="A valid IPv4 or IPv6 address is required.") from exc
    total_events = db.scalar(
        select(func.count(AuthEvent.id)).where(AuthEvent.source_ip == normalized_ip)
    ) or 0
    failed_logins = db.scalar(
        select(func.count(AuthEvent.id)).where(
            AuthEvent.source_ip == normalized_ip,
            AuthEvent.status == "failure",
        )
    ) or 0
    successful_logins = total_events - failed_logins
    usernames = list(
        db.scalars(
            select(AuthEvent.username)
            .where(AuthEvent.source_ip == normalized_ip)
            .distinct()
            .order_by(AuthEvent.username)
        )
    )
    events = list(
        db.scalars(
            select(AuthEvent)
            .where(AuthEvent.source_ip == normalized_ip)
            .order_by(AuthEvent.timestamp.desc(), AuthEvent.id.desc())
            .limit(500)
        )
    )
    return IPInvestigation(
        source_ip=normalized_ip,
        total_events=total_events,
        failed_logins=failed_logins,
        successful_logins=successful_logins,
        usernames=usernames,
        events=events,
    )


@router.post("/events/upload", response_model=IngestionRunRead, status_code=status.HTTP_201_CREATED, tags=["Authentication events"])
async def upload_events(file: Annotated[UploadFile, File()], db: DbSession) -> dict[str, object]:
    from pathlib import PurePath

    filename = PurePath((file.filename or "").replace("\\", "/")).name[:255] or "uploaded-log"
    extension = filename.lower().rsplit(".", 1)[-1] if "." in filename else ""
    is_linux_auth_log = extension in {"log", "txt"} or filename.lower() == "secure"
    if extension not in {"csv", "json", "jsonl", "ndjson"} and not is_linux_auth_log:
        raise HTTPException(status_code=415, detail="Upload CSV, JSON/JSONL, or Linux auth.log/secure files.")
    source_format = (
        "csv" if extension == "csv"
        else "json" if extension == "json"
        else "jsonl" if extension in {"jsonl", "ndjson"}
        else "linux_auth_log"
    )
    run = IngestionRun(filename=filename, source_format=source_format, status="processing")
    db.add(run)
    db.commit()
    db.refresh(run)
    try:
        content = await file.read(MAX_UPLOAD_BYTES + 1)
        if source_format == "csv":
            payloads = parse_auth_event_csv(content)
            records = [{"payload": payload, "source_label": f"CSV import · {filename[:55]}", "import_run_id": run.id} for payload in payloads]
            rejected = 0
        elif source_format == "linux_auth_log":
            records, rejected = parse_linux_auth_log(content, filename)
            records = [{**record, "import_run_id": run.id} for record in records]
        else:
            records = parse_auth_event_json(content, filename, source_format)
            records = [{**record, "import_run_id": run.id} for record in records]
            rejected = 0
        ingested = ingest_event_batch(db, records)
        run.status = "completed"
        run.accepted_records = len(ingested)
        run.rejected_records = rejected
        run.completed_at = utc_now()
        record_audit(
            db,
            "events.file_imported",
            "ingestion_run",
            run.id,
            {"filename": filename, "source_format": source_format, "accepted": len(ingested), "rejected": rejected},
        )
        db.commit()
        logger.info("authentication_file_imported", extra={"run_id": run.id, "accepted_events": len(ingested), "rejected_records": rejected})
        return _ingestion_run_dict(run)
    except CsvImportError as exc:
        db.rollback()
        run = db.get(IngestionRun, run.id)
        run.status = "failed"
        run.rejected_records = exc.rejected_records
        run.error_summary = str(exc)[:1_000]
        run.completed_at = utc_now()
        record_audit(db, "events.file_import_failed", "ingestion_run", run.id, {"filename": filename, "source_format": source_format, "error": run.error_summary})
        db.commit()
        raise HTTPException(status_code=exc.status_code, detail={"message": str(exc), "run_id": run.id}) from exc
    except Exception as exc:
        db.rollback()
        run = db.get(IngestionRun, run.id)
        run.status = "failed"
        run.error_summary = "The import could not be completed due to an internal processing error."
        run.completed_at = utc_now()
        record_audit(db, "events.file_import_failed", "ingestion_run", run.id, {"filename": filename, "source_format": source_format, "error": run.error_summary})
        db.commit()
        logger.exception("authentication_file_import_failed", extra={"run_id": run.id})
        raise HTTPException(status_code=500, detail={"message": run.error_summary, "run_id": run.id}) from exc


def _ingestion_run_dict(run: IngestionRun) -> dict[str, object]:
    return {
        "run_id": run.id,
        "filename": run.filename,
        "source_format": run.source_format,
        "status": run.status,
        "accepted_records": run.accepted_records,
        "rejected_records": run.rejected_records,
        "error_summary": run.error_summary,
        "created_at": run.created_at,
        "completed_at": run.completed_at,
    }


@router.get("/ingestion/runs", response_model=IngestionRunList, tags=["Authentication events"])
def list_ingestion_runs(db: DbSession, limit: int = Query(default=50, ge=1, le=100)) -> dict[str, object]:
    total = db.scalar(select(func.count(IngestionRun.id))) or 0
    runs = db.scalars(select(IngestionRun).order_by(IngestionRun.created_at.desc(), IngestionRun.id.desc()).limit(limit))
    return {"total": total, "runs": [_ingestion_run_dict(run) for run in runs]}


@router.get("/ingestion/runs/{run_id}", response_model=IngestionRunRead, tags=["Authentication events"])
def read_ingestion_run(run_id: int, db: DbSession) -> dict[str, object]:
    run = db.get(IngestionRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Import run not found.")
    return _ingestion_run_dict(run)


@router.post("/ml/score", response_model=AnomalyScoreResponse, tags=["AI anomaly detection"])
def score_anomalies(payload: AnomalyScoreRequest, db: DbSession) -> AnomalyScoreResponse:
    try:
        results = score_events(db, payload.event_ids)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return AnomalyScoreResponse(
        model="Isolation Forest",
        events_scored=len(results),
        results=results,
        notice="Anomaly scores are review signals, not confirmation of malicious activity.",
    )


@router.get("/reports/summary", tags=["Reports"])
def report_summary(db: DbSession) -> dict[str, object]:
    return build_report_summary(db)


@router.get("/reports/events.csv", tags=["Reports"])
def export_events(db: DbSession) -> StreamingResponse:
    csv_content = build_events_csv(db)
    return StreamingResponse(
        iter([csv_content]),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="threatlens-events.csv"'},
    )


@router.get("/reports/alerts.csv", tags=["Reports"])
def export_selected_alerts(alert_ids: Annotated[list[int], Query(min_length=1, max_length=500)], db: DbSession) -> StreamingResponse:
    if len(set(alert_ids)) != len(alert_ids):
        raise HTTPException(status_code=422, detail="Alert IDs must be unique.")
    try:
        csv_content = build_alerts_csv(db, alert_ids)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return StreamingResponse(
        iter([csv_content]),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="threatlens-selected-alerts.csv"'},
    )
