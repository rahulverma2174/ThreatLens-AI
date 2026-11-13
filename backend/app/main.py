import logging
import ipaddress
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Annotated

import httpx
from fastapi import Depends, FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.auth import DemoAuth, DemoAuthMiddleware
from app.database import build_engine, build_session_factory, initialize_schema
from app.dependencies import get_db
from app.models import Alert, AuthEvent, DetectionRule, Incident
from app.services.audit import record_audit
from app.routers.advanced import router as advanced_router
from app.routers.ingestion import router as ingestion_router
from app.routers.operations import router as operations_router
from app.routers.windows_receiver import router as windows_receiver_router
from app.routers.detection_lab import router as detection_lab_router
from app.routers.threat_intelligence import router as threat_intelligence_router
from app.routers.authentication import router as authentication_router
from app.schemas import (
    AuthEventCreate,
    AuthEventRead,
    DashboardStats,
    NaturalEventSearchRequest,
    NaturalEventSearchResponse,
    SyslogIngestionStatus,
)
from app.services.ingestion import ingest_event
from app.services.natural_event_search import LocalModelUnavailable, run_natural_event_search
from app.services.syslog_ingestion import SyslogTCPListener
from app.services.identity import reset_current_actor, set_current_actor

settings = get_settings()
logger = logging.getLogger(__name__)
engine = build_engine(settings.database_url)
SessionFactory = build_session_factory(engine)
syslog_listener = SyslogTCPListener(settings, SessionFactory)


@asynccontextmanager
async def lifespan(_: FastAPI):
    initialize_schema(engine)
    if not app.state.test_mode:
        await syslog_listener.start()
    try:
        yield
    finally:
        if not app.state.test_mode:
            await syslog_listener.stop()


app = FastAPI(
    title=settings.app_name,
    description="Local-first authentication monitoring and defensive threat analysis.",
    version="0.3.0",
    lifespan=lifespan,
)
app.state.session_factory = SessionFactory
app.state.test_mode = False
app.state.auth_mode = settings.auth_mode
app.state.demo_auth = DemoAuth(settings) if settings.auth_mode == "demo" else None
app.include_router(authentication_router)
app.include_router(operations_router)
app.include_router(advanced_router)
app.include_router(ingestion_router)
app.include_router(windows_receiver_router)
app.include_router(detection_lab_router)
app.include_router(threat_intelligence_router)
app.add_middleware(DemoAuthMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=settings.auth_mode == "demo",
    allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE"],
    allow_headers=["Content-Type", "Authorization", "X-CSRF-Token"],
)


@app.middleware("http")
async def local_dashboard_access(request, call_next):
    if request.method == "OPTIONS" or not request.url.path.startswith("/api/"):
        return await call_next(request)
    path = request.url.path
    collector_paths = {
        "/api/ingestion/windows/agent.ps1",
        "/api/ingestion/windows/events",
        "/api/ingestion/windows/heartbeat",
    }
    if path not in collector_paths and not app.state.test_mode and app.state.auth_mode == "local":
        peer = request.client.host if request.client else ""
        try:
            is_loopback = ipaddress.ip_address(peer).is_loopback
        except ValueError:
            is_loopback = False
        if not is_loopback:
            return JSONResponse({"detail": "The dashboard API is available from localhost only."}, status_code=403)
    if app.state.auth_mode != "local":
        return await call_next(request)
    actor_context = set_current_actor("Local analyst")
    try:
        return await call_next(request)
    finally:
        reset_current_actor(actor_context)

DbSession = Annotated[Session, Depends(get_db)]


@app.get("/api/health", tags=["System"])
def health() -> dict[str, str]:
    return {"status": "ok", "service": "ThreatLens AI"}


@app.get("/api/ingestion/syslog", response_model=SyslogIngestionStatus, tags=["Ingestion"])
def syslog_ingestion_status() -> dict[str, object]:
    return syslog_listener.status()


@app.post(
    "/api/events",
    response_model=AuthEventRead,
    status_code=status.HTTP_201_CREATED,
    tags=["Authentication events"],
)
def create_event(payload: AuthEventCreate, db: DbSession) -> AuthEvent:
    try:
        event = ingest_event(db, payload)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    db.flush()
    record_audit(db, "event.ingested", "auth_event", event.id, {"source_ip": event.source_ip, "status": event.status})
    db.commit()
    db.refresh(event)
    logger.info(
        "authentication_event_ingested",
        extra={"event_id": event.id, "event_status": event.status},
    )
    return event


@app.get("/api/events", response_model=list[AuthEventRead], tags=["Authentication events"])
def list_events(
    db: DbSession,
    search: str | None = Query(default=None, min_length=1, max_length=128),
    event_status: str | None = Query(default=None, alias="status", pattern="^(success|failure)$"),
    event_type: str | None = Query(default=None, min_length=1, max_length=32),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> list[AuthEvent]:
    query = select(AuthEvent)
    if search:
        term = f"%{search.strip()}%"
        query = query.where(AuthEvent.username.ilike(term) | AuthEvent.source_ip.ilike(term))
    if event_status:
        query = query.where(AuthEvent.status == event_status)
    if event_type:
        query = query.where(AuthEvent.event_type == event_type)
    return list(
        db.scalars(
            query.order_by(AuthEvent.timestamp.desc(), AuthEvent.id.desc())
            .limit(limit)
            .offset(offset)
        )
    )


@app.get("/api/events/count", tags=["Authentication events"])
def count_events(
    db: DbSession,
    search: str | None = Query(default=None, min_length=1, max_length=128),
    event_status: str | None = Query(default=None, alias="status", pattern="^(success|failure)$"),
    event_type: str | None = Query(default=None, min_length=1, max_length=32),
) -> dict[str, int]:
    query = select(func.count(AuthEvent.id))
    if search:
        term = f"%{search.strip()}%"
        query = query.where(AuthEvent.username.ilike(term) | AuthEvent.source_ip.ilike(term))
    if event_status:
        query = query.where(AuthEvent.status == event_status)
    if event_type:
        query = query.where(AuthEvent.event_type == event_type)
    return {"total": db.scalar(query) or 0}


@app.post(
    "/api/events/natural-search",
    response_model=NaturalEventSearchResponse,
    tags=["Authentication events"],
)
def natural_search_events(payload: NaturalEventSearchRequest, db: DbSession) -> dict[str, object]:
    try:
        return run_natural_event_search(payload.query, db, payload.limit, payload.offset)
    except LocalModelUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"Could not interpret search filters: {exc}") from exc
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail="The local Ollama request failed.") from exc


@app.get("/api/dashboard/stats", response_model=DashboardStats, tags=["Dashboard"])
def dashboard_stats(db: DbSession) -> DashboardStats:
    total = db.scalar(select(func.count(AuthEvent.id))) or 0
    successful = db.scalar(select(func.count(AuthEvent.id)).where(AuthEvent.status == "success")) or 0
    failed = db.scalar(select(func.count(AuthEvent.id)).where(AuthEvent.status == "failure")) or 0
    suspicious_ips = db.scalar(
        select(func.count(func.distinct(Alert.source_ip))).where(
            Alert.severity.in_(("critical", "high")),
            Alert.status != "resolved",
        )
    ) or 0
    critical_alerts = db.scalar(
        select(func.count(Alert.id)).where(Alert.severity == "critical", Alert.status != "resolved")
    ) or 0
    high_alerts = db.scalar(
        select(func.count(Alert.id)).where(Alert.severity == "high", Alert.status != "resolved")
    ) or 0
    medium_alerts = db.scalar(
        select(func.count(Alert.id)).where(Alert.severity == "medium", Alert.status != "resolved")
    ) or 0
    open_incidents = db.scalar(
        select(func.count(Incident.id)).where(Incident.status == "open", Incident.merged_into_id.is_(None))
    ) or 0
    severity_rows = db.execute(
        select(Alert.severity, func.count(Alert.id))
        .where(Alert.status != "resolved")
        .group_by(Alert.severity)
    )
    unresolved_by_severity = {severity: 0 for severity in ("critical", "high", "medium", "low")}
    unresolved_by_severity.update({severity: count for severity, count in severity_rows})
    return DashboardStats(
        total_events=total,
        successful_logins=successful,
        failed_logins=failed,
        suspicious_ips=suspicious_ips,
        critical_alerts=critical_alerts,
        high_alerts=high_alerts,
        medium_alerts=medium_alerts,
        open_incidents=open_incidents,
        unresolved_alerts_by_severity=unresolved_by_severity,
    )


@app.get("/api/dashboard/activity", tags=["Dashboard"])
def dashboard_activity(
    db: DbSession,
    window_hours: int = Query(default=168, ge=1, le=720),
) -> dict[str, object]:
    cutoff = datetime.now(timezone.utc) - timedelta(hours=window_hours)
    bucket = func.strftime("%Y-%m-%dT%H:00:00Z", AuthEvent.timestamp)
    rows = db.execute(
        select(bucket, AuthEvent.status, func.count(AuthEvent.id))
        .where(AuthEvent.timestamp >= cutoff)
        .group_by(bucket, AuthEvent.status)
        .order_by(bucket)
    )
    grouped: dict[str, dict[str, int]] = {}
    for bucket_start, event_status, count in rows:
        if bucket_start is None:
            continue
        item = grouped.setdefault(bucket_start, {"success": 0, "failure": 0})
        item[event_status] = count
    return {
        "window_hours": window_hours,
        "events_count": sum(item["success"] + item["failure"] for item in grouped.values()),
        "buckets": [{"time": time, **values} for time, values in grouped.items()],
        "timezone": "UTC",
    }


@app.get("/api/search", tags=["Search"])
def search_local_records(
    db: DbSession,
    q: str = Query(min_length=2, max_length=128),
    limit: int = Query(default=5, ge=1, le=10),
) -> dict[str, object]:
    """Search locally stored event, alert, and incident records without external enrichment."""
    term = f"%{q.strip()}%"
    results: list[dict[str, object]] = []
    events = db.scalars(
        select(AuthEvent).where(
            AuthEvent.username.ilike(term)
            | AuthEvent.source_ip.ilike(term)
            | AuthEvent.source_host.ilike(term)
        ).order_by(AuthEvent.timestamp.desc()).limit(limit)
    )
    for event in events:
        results.append({"kind": "event", "id": event.id, "title": f"{event.status.title()} authentication · {event.username}", "subtitle": f"{event.source_ip} · {event.event_type} · {event.timestamp.isoformat()}", "source_ip": event.source_ip, "username": event.username})
    alerts = db.scalars(
        select(Alert).where(
            Alert.title.ilike(term) | Alert.reason.ilike(term) | Alert.source_ip.ilike(term)
        ).order_by(Alert.created_at.desc()).limit(limit)
    )
    for alert in alerts:
        results.append({"kind": "alert", "id": alert.id, "title": alert.title, "subtitle": f"{alert.severity} · {alert.source_ip} · {alert.status}", "source_ip": alert.source_ip})
    incidents = db.scalars(select(Incident).order_by(Incident.updated_at.desc()).limit(1000))
    lowered_query = q.strip().lower()
    incident_matches = [incident for incident in incidents if lowered_query in " ".join([
        incident.title,
        incident.summary,
        *incident.source_ips,
        *incident.usernames,
    ]).lower()][:limit]
    for incident in incident_matches:
        results.append({"kind": "incident", "id": incident.id, "title": incident.title, "subtitle": f"{incident.severity} · {incident.status} · {len(incident.related_event_ids)} related events"})
    return {"query": q, "results": results[: limit * 3]}


@app.get("/api/attack/coverage", tags=["MITRE ATT&CK"])
def attack_coverage(db: DbSession) -> dict[str, object]:
    """Return ATT&CK candidates backed by stored rule definitions and alert evidence."""
    techniques = {
        "T1110": {"name": "Brute Force", "tactic": "Credential Access", "tactic_id": "TA0006", "url": "https://attack.mitre.org/techniques/T1110/"},
        "T1110.003": {"name": "Password Spraying", "tactic": "Credential Access", "tactic_id": "TA0006", "url": "https://attack.mitre.org/techniques/T1110/003/"},
    }
    mapping_by_key = {
        "brute_force": "T1110",
        "repeated_failures": "T1110",
        "success_after_failures": "T1110",
        "multiple_usernames": "T1110",
    }
    rule_evidence: dict[str, list[dict[str, object]]] = {key: [] for key in techniques}
    for rule in db.scalars(select(DetectionRule)):
        technique_id = "T1110" if rule.aggregation in {"failed_per_source_ip", "failed_per_username"} else None
        if technique_id:
            rule_evidence[technique_id].append({"source": "configured_rule", "id": rule.id, "name": rule.name, "enabled": rule.enabled, "aggregation": rule.aggregation, "threshold": rule.threshold, "window_minutes": rule.window_minutes})
    alert_evidence: dict[str, list[dict[str, object]]] = {key: [] for key in techniques}
    for alert in db.scalars(select(Alert).order_by(Alert.created_at.desc()).limit(1000)):
        technique_id = alert.attack_technique or mapping_by_key.get(alert.detection_key)
        if technique_id not in techniques:
            continue
        alert_evidence[technique_id].append({"source": "stored_alert", "id": alert.id, "title": alert.title, "detection_key": alert.detection_key, "source_ip": alert.source_ip, "status": alert.status, "related_event_ids": alert.related_event_ids})
    rows = []
    for technique_id, metadata in techniques.items():
        evidence = rule_evidence[technique_id] + alert_evidence[technique_id]
        rows.append({"technique_id": technique_id, **metadata, "mapping_status": "candidate" if evidence else "unmapped", "evidence_count": len(evidence), "evidence": evidence[:100], "qualification": "Pattern association only. Authentication records do not contain password values, so they cannot confirm the password-spraying sub-technique." if technique_id == "T1110.003" else "Candidate association; confirm the alert evidence and rule behavior during review."})
    return {"tactics": [{"id": "TA0006", "name": "Credential Access", "technique_ids": list(techniques)}], "techniques": rows, "notice": "Mappings are review candidates from local rule definitions and alerts, not proof of adversary behavior."}


@app.get("/api/events/{event_id}", response_model=AuthEventRead, tags=["Authentication events"])
def get_event(event_id: int, db: DbSession) -> AuthEvent:
    event = db.get(AuthEvent, event_id)
    if event is None:
        raise HTTPException(status_code=404, detail="Authentication event not found.")
    return event
