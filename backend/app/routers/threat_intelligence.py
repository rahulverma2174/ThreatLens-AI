from datetime import datetime, timedelta, timezone
import os
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import Integer, and_, cast, exists, func, or_, select, true
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import get_settings
from app.dependencies import get_db
from app.models import (
    Alert, Incident, ThreatFeed, ThreatFeedSyncRun, ThreatIndicator,
    ThreatIndicatorReview, ThreatIndicatorSource, AuthEvent, utc_now,
)
from app.schemas import (
    ThreatFeedCreate,
    ThreatFeedEnableUpdate,
    ThreatFeedRead,
    ThreatFeedSyncRunRead,
    ThreatFeedUpdate,
    ThreatIndicatorAlertReference,
    ThreatIndicatorCorrelationResponse,
    ThreatIndicatorIncidentReference,
    ThreatIndicatorListResponse,
    ThreatIndicatorRead,
    ThreatIndicatorReviewCreate,
    ThreatIndicatorReviewRead,
    ThreatIndicatorTimelineResponse,
    ThreatIndicatorTimelineEntry,
)
from app.services.audit import record_audit
from app.services.threat_feed_transport import validate_feed_configuration
from app.services.threat_intelligence_feeds import (
    FeedSyncBusyError,
    FeedSyncUnavailableError,
    synchronize_feed,
    indicator_is_active,
    observation_is_active,
)
from app.services.identity import current_actor

router = APIRouter(prefix="/api/intelligence", tags=["Threat intelligence feeds"])
DbSession = Annotated[Session, Depends(get_db)]


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _feed_response(feed: ThreatFeed) -> dict[str, object]:
    now = utc_now()
    if not feed.enabled:
        freshness = "disabled"
    elif feed.last_sync_status == "syncing":
        freshness = "syncing"
    elif feed.last_sync_status == "failed":
        freshness = "failed"
    elif feed.last_success_at is None:
        freshness = "never_synced"
    elif now - _as_utc(feed.last_success_at) > timedelta(minutes=feed.stale_after_minutes):
        freshness = "stale"
    else:
        freshness = "fresh"
    configured = bool(feed.credential_env_var and os.environ.get(feed.credential_env_var))
    return {
        "id": feed.id,
        "name": feed.name,
        "url": feed.url,
        "feed_format": feed.feed_format,
        "field_mapping": feed.field_mapping,
        "credential_env_var": feed.credential_env_var,
        "credential_configured": configured,
        "enabled": feed.enabled,
        "stale_after_minutes": feed.stale_after_minutes,
        "last_attempt_at": feed.last_attempt_at,
        "last_success_at": feed.last_success_at,
        "last_error": feed.last_error,
        "last_sync_status": feed.last_sync_status,
        "freshness": freshness,
        "last_accepted_count": feed.last_accepted_count,
        "last_rejected_count": feed.last_rejected_count,
        "created_at": feed.created_at,
        "updated_at": feed.updated_at,
    }


def _configuration_values(payload: ThreatFeedCreate) -> dict[str, object]:
    return {
        "name": payload.name,
        "url": payload.url,
        "feed_format": payload.feed_format,
        "field_mapping": payload.field_mapping.model_dump(),
        "credential_env_var": payload.credential_env_var,
        "enabled": payload.enabled,
        "stale_after_minutes": payload.stale_after_minutes,
    }


@router.get("/feeds", response_model=list[ThreatFeedRead])
def list_threat_feeds(
    db: DbSession,
    limit: int = Query(default=100, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=10_000),
) -> list[dict[str, object]]:
    feeds = db.scalars(select(ThreatFeed).order_by(ThreatFeed.name, ThreatFeed.id).limit(limit).offset(offset))
    return [_feed_response(feed) for feed in feeds]


@router.post("/feeds", response_model=ThreatFeedRead, status_code=status.HTTP_201_CREATED)
def create_threat_feed(payload: ThreatFeedCreate, db: DbSession) -> dict[str, object]:
    candidate = ThreatFeed(**_configuration_values(payload))
    try:
        validate_feed_configuration(candidate, get_settings())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    db.add(candidate)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="A feed with that name already exists.") from exc
    record_audit(db, "threat_feed.created", "threat_feed", candidate.id, {
        "name": candidate.name,
        "host": validate_feed_configuration(candidate, get_settings()),
        "feed_format": candidate.feed_format,
        "credential_env_var": candidate.credential_env_var,
    })
    db.commit()
    db.refresh(candidate)
    return _feed_response(candidate)


@router.put("/feeds/{feed_id}", response_model=ThreatFeedRead)
def update_threat_feed(feed_id: int, payload: ThreatFeedUpdate, db: DbSession) -> dict[str, object]:
    feed = db.get(ThreatFeed, feed_id)
    if feed is None:
        raise HTTPException(status_code=404, detail="Threat feed not found.")
    if feed.sync_lock_token:
        raise HTTPException(status_code=409, detail="Feed configuration cannot change during synchronization.")
    candidate = ThreatFeed(**_configuration_values(payload))
    try:
        validate_feed_configuration(candidate, get_settings())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    for key, value in _configuration_values(payload).items():
        setattr(feed, key, value)
    feed.updated_at = utc_now()
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="A feed with that name already exists.") from exc
    record_audit(db, "threat_feed.updated", "threat_feed", feed.id, {
        "name": feed.name,
        "host": validate_feed_configuration(feed, get_settings()),
        "feed_format": feed.feed_format,
        "enabled": feed.enabled,
        "credential_env_var": feed.credential_env_var,
    })
    db.commit()
    db.refresh(feed)
    return _feed_response(feed)


@router.patch("/feeds/{feed_id}/enabled", response_model=ThreatFeedRead)
def set_threat_feed_enabled(feed_id: int, payload: ThreatFeedEnableUpdate, db: DbSession) -> dict[str, object]:
    feed = db.get(ThreatFeed, feed_id)
    if feed is None:
        raise HTTPException(status_code=404, detail="Threat feed not found.")
    if feed.sync_lock_token:
        raise HTTPException(status_code=409, detail="Feed state cannot change during synchronization.")
    feed.enabled = payload.enabled
    feed.updated_at = utc_now()
    record_audit(db, "threat_feed.enabled" if feed.enabled else "threat_feed.disabled", "threat_feed", feed.id, {"name": feed.name})
    db.commit()
    db.refresh(feed)
    return _feed_response(feed)


@router.post("/feeds/{feed_id}/sync", response_model=ThreatFeedSyncRunRead)
def sync_threat_feed(feed_id: int, db: DbSession) -> ThreatFeedSyncRun:
    try:
        return synchronize_feed(db, feed_id, get_settings())
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except FeedSyncBusyError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except FeedSyncUnavailableError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/feed-runs", response_model=list[ThreatFeedSyncRunRead])
def list_threat_feed_runs(
    db: DbSession,
    feed_id: int | None = Query(default=None, ge=1),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=100_000),
) -> list[ThreatFeedSyncRun]:
    query = select(ThreatFeedSyncRun)
    if feed_id is not None:
        query = query.where(ThreatFeedSyncRun.feed_id == feed_id)
    return list(db.scalars(query.order_by(ThreatFeedSyncRun.created_at.desc(), ThreatFeedSyncRun.id.desc()).limit(limit).offset(offset)))


def _indicator_payload(
    indicator: ThreatIndicator,
    sources: list[ThreatIndicatorSource],
    matching_event_count: int | None,
    source_count: int | None = None,
) -> dict[str, object]:
    is_active = indicator_is_active(sources)
    return {
        "id": indicator.id,
        "indicator_type": indicator.indicator_type,
        "value": indicator.value,
        "first_seen": indicator.first_seen,
        "last_seen": indicator.last_seen,
        "analyst_disposition": indicator.analyst_disposition,
        "reviewed_at": indicator.reviewed_at,
        "sources": [
            {
                "id": source.id,
                "feed_id": source.feed_id,
                "source_name": source.source_name,
                "source_reference": source.source_reference,
                "confidence": source.confidence,
                "first_seen": source.first_seen,
                "last_seen": source.last_seen,
                "expires_at": source.expires_at,
                "latest_sync_run_id": source.latest_sync_run_id,
                "active": observation_is_active(source),
            }
            for source in sources[:100]
        ],
        "source_count": source_count if source_count is not None else len(sources),
        "sources_truncated": (source_count if source_count is not None else len(sources)) > min(100, len(sources)),
        "active": is_active,
        "correlation_status": "ip_supported" if indicator.indicator_type == "ip" else "unsupported_schema",
        "matching_event_count": matching_event_count,
    }


def _linked_records(db: Session, event_ids: list[int]) -> tuple[dict[int, list[Alert]], dict[int, list[Incident]]]:
    alerts_by_event: dict[int, list[Alert]] = {event_id: [] for event_id in event_ids}
    incidents_by_event: dict[int, list[Incident]] = {event_id: [] for event_id in event_ids}
    if not event_ids:
        return alerts_by_event, incidents_by_event
    alert_ids = func.json_each(Alert.related_event_ids).table_valued("value").alias()
    for alert, event_id in db.execute(
        select(Alert, cast(alert_ids.c.value, Integer))
        .join(alert_ids, true())
        .where(cast(alert_ids.c.value, Integer).in_(event_ids))
    ).all():
        alerts_by_event[event_id].append(alert)
    incident_ids = func.json_each(Incident.related_event_ids).table_valued("value").alias()
    for incident, event_id in db.execute(
        select(Incident, cast(incident_ids.c.value, Integer))
        .join(incident_ids, true())
        .where(cast(incident_ids.c.value, Integer).in_(event_ids))
    ).all():
        incidents_by_event[event_id].append(incident)
    return alerts_by_event, incidents_by_event


def _indicator_or_404(db: Session, indicator_id: int) -> ThreatIndicator:
    indicator = db.get(ThreatIndicator, indicator_id)
    if indicator is None:
        raise HTTPException(status_code=404, detail="Threat indicator not found.")
    return indicator


def _correlated_events(
    db: Session,
    indicator: ThreatIndicator,
    *,
    start_time: datetime | None,
    end_time: datetime | None,
    limit: int,
    offset: int,
) -> tuple[int | None, list[dict[str, object]], str, list[AuthEvent]]:
    if indicator.indicator_type != "ip":
        return None, [], "The authentication event schema has no domain or file-hash field; this indicator cannot be correlated to these records.", []
    statement = select(AuthEvent).where(AuthEvent.source_ip == indicator.value)
    if start_time is not None:
        statement = statement.where(AuthEvent.timestamp >= start_time)
    if end_time is not None:
        statement = statement.where(AuthEvent.timestamp <= end_time)
    total = int(db.scalar(select(func.count()).select_from(statement.order_by(None).subquery())) or 0)
    events = list(db.scalars(statement.order_by(AuthEvent.timestamp.desc(), AuthEvent.id.desc()).limit(limit).offset(offset)))
    ids = [event.id for event in events]
    alerts_by_event, incidents_by_event = _linked_records(db, ids)
    results = [{
        "event": event,
        "alerts": alerts_by_event[event.id],
        "incidents": incidents_by_event[event.id],
    } for event in events]
    return total, results, "Exact source-IP matches from local authentication events; links use stored alert and incident event references.", events


@router.get("/iocs", response_model=ThreatIndicatorListResponse)
def search_threat_indicators(
    db: DbSession,
    indicator_type: Literal["ip", "domain", "hash"] | None = None,
    disposition: Literal["unreviewed", "confirmed", "false_positive"] | None = None,
    feed_id: int | None = Query(default=None, ge=1),
    active: bool | None = None,
    search: str | None = Query(default=None, min_length=1, max_length=255),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0, le=100_000),
) -> dict[str, object]:
    query = select(ThreatIndicator)
    if indicator_type:
        query = query.where(ThreatIndicator.indicator_type == indicator_type)
    if disposition:
        query = query.where(ThreatIndicator.analyst_disposition == disposition)
    if feed_id is not None:
        query = query.where(exists(select(1).where(
            ThreatIndicatorSource.indicator_id == ThreatIndicator.id,
            ThreatIndicatorSource.feed_id == feed_id,
        )))
    if active is not None:
        active_source = exists(select(1).where(
            ThreatIndicatorSource.indicator_id == ThreatIndicator.id,
            or_(ThreatIndicatorSource.expires_at.is_(None), ThreatIndicatorSource.expires_at > utc_now()),
        ))
        query = query.where(active_source if active else ~active_source)
    if search:
        query = query.where(ThreatIndicator.value.ilike(f"%{search.strip()}%"))
    total = int(db.scalar(select(func.count()).select_from(query.order_by(None).subquery())) or 0)
    indicators = list(db.scalars(query.order_by(ThreatIndicator.last_seen.desc(), ThreatIndicator.id.desc()).limit(limit).offset(offset)))
    ids = [item.id for item in indicators]
    sources_by_indicator: dict[int, list[ThreatIndicatorSource]] = {item_id: [] for item_id in ids}
    source_counts: dict[int, int] = {}
    if ids:
        source_counts = {
            indicator_id: int(count)
            for indicator_id, count in db.execute(
                select(ThreatIndicatorSource.indicator_id, func.count(ThreatIndicatorSource.id))
                .where(ThreatIndicatorSource.indicator_id.in_(ids))
                .group_by(ThreatIndicatorSource.indicator_id)
            )
        }
        ranked_sources = select(
            ThreatIndicatorSource.id.label("source_id"),
            func.row_number().over(
                partition_by=ThreatIndicatorSource.indicator_id,
                order_by=(ThreatIndicatorSource.last_seen.desc(), ThreatIndicatorSource.id),
            ).label("source_rank"),
        ).where(ThreatIndicatorSource.indicator_id.in_(ids)).subquery()
        for source in db.scalars(
            select(ThreatIndicatorSource)
            .join(ranked_sources, ThreatIndicatorSource.id == ranked_sources.c.source_id)
            .where(ranked_sources.c.source_rank <= 50)
            .order_by(ThreatIndicatorSource.indicator_id, ThreatIndicatorSource.last_seen.desc(), ThreatIndicatorSource.id)
        ):
            sources_by_indicator[source.indicator_id].append(source)
    ip_values = [item.value for item in indicators if item.indicator_type == "ip"]
    counts = {
        value: count for value, count in db.execute(
            select(AuthEvent.source_ip, func.count(AuthEvent.id))
            .where(AuthEvent.source_ip.in_(ip_values))
            .group_by(AuthEvent.source_ip)
        )
    } if ip_values else {}
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "indicators": [
            _indicator_payload(item, sources_by_indicator[item.id], int(counts.get(item.value, 0)) if item.indicator_type == "ip" else None, source_counts.get(item.id, 0))
            for item in indicators
        ],
    }


@router.get("/iocs/{indicator_id}", response_model=ThreatIndicatorRead)
def get_threat_indicator(indicator_id: int, db: DbSession) -> dict[str, object]:
    indicator = _indicator_or_404(db, indicator_id)
    source_count = int(db.scalar(select(func.count(ThreatIndicatorSource.id)).where(ThreatIndicatorSource.indicator_id == indicator.id)) or 0)
    sources = list(db.scalars(select(ThreatIndicatorSource).where(ThreatIndicatorSource.indicator_id == indicator.id).order_by(ThreatIndicatorSource.last_seen.desc()).limit(101)))
    matching_count = (db.scalar(select(func.count(AuthEvent.id)).where(AuthEvent.source_ip == indicator.value)) or 0) if indicator.indicator_type == "ip" else None
    return _indicator_payload(indicator, sources, int(matching_count) if matching_count is not None else None, source_count)


@router.get("/iocs/{indicator_id}/correlation", response_model=ThreatIndicatorCorrelationResponse)
def correlate_threat_indicator(
    indicator_id: int,
    db: DbSession,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0, le=100_000),
) -> dict[str, object]:
    indicator = _indicator_or_404(db, indicator_id)
    if start_time and start_time.tzinfo is None:
        start_time = start_time.replace(tzinfo=timezone.utc)
    if end_time and end_time.tzinfo is None:
        end_time = end_time.replace(tzinfo=timezone.utc)
    if start_time and end_time and end_time < start_time:
        raise HTTPException(status_code=422, detail="end_time must be on or after start_time.")
    if start_time and end_time and end_time - start_time > timedelta(days=365):
        raise HTTPException(status_code=422, detail="Correlation time range cannot exceed 365 days.")
    total, results, explanation, _events = _correlated_events(
        db, indicator, start_time=start_time, end_time=end_time, limit=limit, offset=offset,
    )
    if indicator.indicator_type != "ip":
        correlation_status = "unsupported_schema"
    else:
        correlation_status = "correlated" if total else "no_matches"
    return {
        "indicator_id": indicator.id,
        "correlation_status": correlation_status,
        "explanation": explanation,
        "total": total,
        "limit": limit,
        "offset": offset,
        "results": results,
    }


@router.post("/iocs/{indicator_id}/reviews", response_model=ThreatIndicatorReviewRead, status_code=status.HTTP_201_CREATED)
def review_threat_indicator(
    indicator_id: int,
    payload: ThreatIndicatorReviewCreate,
    db: DbSession,
) -> ThreatIndicatorReview:
    indicator = _indicator_or_404(db, indicator_id)
    reviewer = current_actor() or "Local analyst"
    review = ThreatIndicatorReview(
        indicator_id=indicator.id,
        disposition=payload.disposition,
        notes=payload.notes.strip(),
        reviewer=reviewer,
    )
    db.add(review)
    db.flush()
    indicator.analyst_disposition = payload.disposition
    indicator.current_review_id = review.id
    indicator.reviewed_at = review.created_at
    indicator.updated_at = utc_now()
    record_audit(db, "threat_indicator.reviewed", "threat_indicator", indicator.id, {
        "review_id": review.id,
        "disposition": payload.disposition,
        "notes": payload.notes.strip(),
        "reviewer": reviewer,
    })
    db.commit()
    db.refresh(review)
    return review


@router.get("/iocs/{indicator_id}/reviews", response_model=list[ThreatIndicatorReviewRead])
def list_threat_indicator_reviews(
    indicator_id: int,
    db: DbSession,
    limit: int = Query(default=50, ge=1, le=200),
) -> list[ThreatIndicatorReview]:
    _indicator_or_404(db, indicator_id)
    return list(db.scalars(
        select(ThreatIndicatorReview)
        .where(ThreatIndicatorReview.indicator_id == indicator_id)
        .order_by(ThreatIndicatorReview.created_at.desc(), ThreatIndicatorReview.id.desc())
        .limit(limit)
    ))


@router.get("/iocs/{indicator_id}/timeline", response_model=ThreatIndicatorTimelineResponse)
def threat_indicator_timeline(
    indicator_id: int,
    db: DbSession,
    limit: int = Query(default=100, ge=1, le=250),
) -> dict[str, object]:
    indicator = _indicator_or_404(db, indicator_id)
    entries: list[ThreatIndicatorTimelineEntry] = []
    sources = list(db.scalars(
        select(ThreatIndicatorSource)
        .where(ThreatIndicatorSource.indicator_id == indicator.id)
        .order_by(ThreatIndicatorSource.last_seen.desc(), ThreatIndicatorSource.id.desc())
        .limit(250)
    ))
    for source in sources:
        entries.append(ThreatIndicatorTimelineEntry(
            occurred_at=source.updated_at,
            kind="feed_observation",
            title=f"Observed by {source.source_name}",
            details={
                "feed_id": source.feed_id,
                "source_reference": source.source_reference,
                "confidence": source.confidence,
                "first_seen": source.first_seen.isoformat(),
                "last_seen": source.last_seen.isoformat(),
                "expires_at": source.expires_at.isoformat() if source.expires_at else None,
                "active": observation_is_active(source),
                "sync_run_id": source.latest_sync_run_id,
            },
        ))

    correlated_events: list[AuthEvent] = []
    if indicator.indicator_type == "ip":
        correlated_events = list(db.scalars(
            select(AuthEvent)
            .where(AuthEvent.source_ip == indicator.value)
            .order_by(AuthEvent.timestamp.desc(), AuthEvent.id.desc())
            .limit(limit)
        ))
        alert_map, incident_map = _linked_records(db, [event.id for event in correlated_events])
        seen_alerts: set[int] = set()
        seen_incidents: set[int] = set()
        for event in correlated_events:
            entries.append(ThreatIndicatorTimelineEntry(
                occurred_at=event.timestamp,
                kind="event",
                title=f"{event.status.title()} authentication for {event.username}",
                details={"event_id": event.id, "source_ip": event.source_ip, "event_type": event.event_type, "source": event.source_label},
            ))
            for alert in alert_map[event.id]:
                if alert.id not in seen_alerts:
                    seen_alerts.add(alert.id)
                    entries.append(ThreatIndicatorTimelineEntry(
                        occurred_at=alert.created_at,
                        kind="alert",
                        title=alert.title,
                        details={"alert_id": alert.id, "severity": alert.severity, "status": alert.status, "detection_key": alert.detection_key},
                    ))
            for incident in incident_map[event.id]:
                if incident.id not in seen_incidents:
                    seen_incidents.add(incident.id)
                    entries.append(ThreatIndicatorTimelineEntry(
                        occurred_at=incident.created_at,
                        kind="incident",
                        title=incident.title,
                        details={"incident_id": incident.id, "severity": incident.severity, "status": incident.status},
                    ))
    reviews = list(db.scalars(
        select(ThreatIndicatorReview)
        .where(ThreatIndicatorReview.indicator_id == indicator.id)
        .order_by(ThreatIndicatorReview.created_at.desc(), ThreatIndicatorReview.id.desc())
        .limit(250)
    ))
    entries.extend(ThreatIndicatorTimelineEntry(
        occurred_at=review.created_at,
        kind="review",
        title=f"Analyst marked indicator {review.disposition.replace('_', ' ')}",
        details={"review_id": review.id, "reviewer": review.reviewer, "notes": review.notes},
    ) for review in reviews)
    entries.sort(key=lambda entry: entry.occurred_at, reverse=True)
    if indicator.indicator_type == "ip":
        correlation_status = "ip_supported"
        notice = "Timeline combines feed provenance, exact-IP local events, linked alerts/incidents, and append-only analyst reviews; each section is bounded."
    else:
        correlation_status = "unsupported_schema"
        notice = "Feed observations and reviews are shown. Local authentication events cannot be correlated because they have no domain/hash fields."
    return {
        "indicator_id": indicator.id,
        "correlation_status": correlation_status,
        "entries": entries[:limit],
        "limit": limit,
        "notice": notice,
    }
