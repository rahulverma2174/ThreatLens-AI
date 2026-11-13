from datetime import timedelta
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.dependencies import get_db
from app.models import Alert, AuditEntry, AuthEvent, DetectionException, DetectionRule, DetectionRuleVersion, Incident, IncidentAlert, LocalIndicator, SavedEventSearch, SavedHuntQuery, SoarExecution, SoarWorkflow, utc_now
from app.schemas import (
    AnalyticsRequest,
    AnalyticsResponse,
    BehaviorResponse,
    AuditEntryRead,
    AuditIntegrityRead,
    CopilotRequest,
    CopilotResponse,
    IncidentRead,
    IncidentCommentCreate,
    IncidentCommentRead,
    IncidentBriefRead,
    IncidentUpdate,
    LocalIndicatorCreate,
    LocalIndicatorRead,
    DetectionExceptionCreate,
    DetectionExceptionRead,
    DetectionRuleCreate,
    DetectionRulePreviewRead,
    DetectionRuleRead,
    DetectionRuleUpdate,
    DetectionRuleVersionRead,
    SavedEventSearchCreate,
    SavedEventSearchRead,
    HuntExportRequest,
    HuntQueryCreate,
    HuntQueryRead,
    HuntQueryUpdate,
    HuntSearchRequest,
    HuntSearchResponse,
    SoarExecutionCreate,
    SoarExecutionRead,
    SoarWorkflowCreate,
    SoarWorkflowRead,
)
from app.services.behavior import build_profiles, load_behavior_events
from app.services.audit import record_audit, verify_audit_chain
from app.services.copilot import answer_question
from app.services.local_ai import enhance_local_answer, ollama_status
from app.services.investigation_brief import build_incident_brief
from app.services.correlation import correlate_alerts
from app.services.risk_scoring import analyze_events
from app.services.threat_intelligence import (
    create_local_indicator,
    delete_local_indicator,
    get_local_indicator_map,
    list_local_indicators,
    update_local_indicator,
)
from app.services.detection_rules import preview_rule, rule_configuration
from app.services.threat_hunting import execute_hunt, export_events_csv, load_hunt_events_for_export

router = APIRouter(prefix="/api")
DbSession = Annotated[Session, Depends(get_db)]


@router.post("/hunting/search", response_model=HuntSearchResponse, tags=["Threat hunting"])
def hunt_events(payload: HuntSearchRequest, db: DbSession) -> dict[str, object]:
    return execute_hunt(db, payload.query, payload.limit, payload.offset)


@router.post("/hunting/export", tags=["Threat hunting"])
def export_hunt(payload: HuntExportRequest, db: DbSession) -> Response:
    try:
        events = load_hunt_events_for_export(db, payload.query, payload.max_rows)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    csv_body = export_events_csv(events)
    return Response(
        content=csv_body,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="threatlens-hunt.csv"'},
    )


@router.get("/hunting/queries", response_model=list[HuntQueryRead], tags=["Threat hunting"])
def list_hunt_queries(db: DbSession) -> list[SavedHuntQuery]:
    return list(db.scalars(select(SavedHuntQuery).order_by(SavedHuntQuery.updated_at.desc(), SavedHuntQuery.id.desc()).limit(100)))


@router.post("/hunting/queries", response_model=HuntQueryRead, status_code=status.HTTP_201_CREATED, tags=["Threat hunting"])
def create_hunt_query(payload: HuntQueryCreate, db: DbSession) -> SavedHuntQuery:
    saved = SavedHuntQuery(name=payload.name, description=payload.description, query=payload.query.model_dump(mode="json"))
    db.add(saved)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="A saved hunt already uses that name.") from exc
    record_audit(db, "hunt_query.created", "saved_hunt_query", saved.id, {"name": saved.name})
    db.commit()
    db.refresh(saved)
    return saved


@router.put("/hunting/queries/{query_id}", response_model=HuntQueryRead, tags=["Threat hunting"])
def update_hunt_query(query_id: int, payload: HuntQueryUpdate, db: DbSession) -> SavedHuntQuery:
    saved = db.get(SavedHuntQuery, query_id)
    if saved is None:
        raise HTTPException(status_code=404, detail="Saved hunt not found.")
    saved.name = payload.name
    saved.description = payload.description
    saved.query = payload.query.model_dump(mode="json")
    saved.updated_at = utc_now()
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="A saved hunt already uses that name.") from exc
    record_audit(db, "hunt_query.updated", "saved_hunt_query", saved.id, {"name": saved.name})
    db.commit()
    db.refresh(saved)
    return saved


@router.delete("/hunting/queries/{query_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["Threat hunting"])
def delete_hunt_query(query_id: int, db: DbSession) -> None:
    saved = db.get(SavedHuntQuery, query_id)
    if saved is None:
        raise HTTPException(status_code=404, detail="Saved hunt not found.")
    db.delete(saved)
    record_audit(db, "hunt_query.deleted", "saved_hunt_query", saved.id, {"name": saved.name})
    db.commit()


@router.get("/detection/rules", response_model=list[DetectionRuleRead], tags=["Detection management"])
def list_detection_rules(db: DbSession) -> list[DetectionRule]:
    return list(db.scalars(select(DetectionRule).order_by(DetectionRule.created_at.desc(), DetectionRule.id.desc()).limit(500)))


@router.post("/detection/rules/preview", response_model=DetectionRulePreviewRead, tags=["Detection management"])
def preview_detection_rule(
    payload: DetectionRuleCreate,
    db: DbSession,
    window_hours: int = Query(default=168, ge=1, le=720),
) -> dict[str, object]:
    return preview_rule(db, payload.model_dump(exclude={"change_note", "enabled", "name", "description"}), window_hours)


@router.post("/detection/rules", response_model=DetectionRuleRead, status_code=status.HTTP_201_CREATED, tags=["Detection management"])
def create_detection_rule(payload: DetectionRuleCreate, db: DbSession) -> DetectionRule:
    rule = DetectionRule(
        name=payload.name,
        description=payload.description.strip(),
        aggregation=payload.aggregation,
        threshold=payload.threshold,
        window_minutes=payload.window_minutes,
        severity=payload.severity,
        enabled=payload.enabled,
        current_version=1,
    )
    db.add(rule)
    db.flush()
    configuration = rule_configuration(rule)
    db.add(DetectionRuleVersion(
        rule_id=rule.id,
        version=1,
        configuration=configuration,
        change_note=payload.change_note.strip() or "Initial rule version",
    ))
    record_audit(db, "detection_rule.created", "detection_rule", rule.id, {"version": 1, "configuration": configuration})
    db.commit()
    db.refresh(rule)
    return rule


@router.get("/detection/rules/{rule_id}/versions", response_model=list[DetectionRuleVersionRead], tags=["Detection management"])
def list_detection_rule_versions(rule_id: int, db: DbSession) -> list[DetectionRuleVersion]:
    if db.get(DetectionRule, rule_id) is None:
        raise HTTPException(status_code=404, detail="Detection rule not found.")
    return list(db.scalars(
        select(DetectionRuleVersion)
        .where(DetectionRuleVersion.rule_id == rule_id)
        .order_by(DetectionRuleVersion.version.desc())
        .limit(100)
    ))


@router.patch("/detection/rules/{rule_id}", response_model=DetectionRuleRead, tags=["Detection management"])
def update_detection_rule(rule_id: int, payload: DetectionRuleUpdate, db: DbSession) -> DetectionRule:
    rule = db.get(DetectionRule, rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="Detection rule not found.")
    changes = payload.model_dump(exclude_unset=True, exclude_none=True)
    change_note = str(changes.pop("change_note", "")).strip()
    if not changes:
        raise HTTPException(status_code=422, detail="Provide at least one rule setting to update.")

    before = rule_configuration(rule)
    changed = {key: value for key, value in changes.items() if before.get(key) != value}
    if not changed:
        return rule
    for key, value in changed.items():
        setattr(rule, key, value.strip() if key in {"name", "description"} else value)
    rule.current_version += 1
    rule.updated_at = utc_now()
    after = rule_configuration(rule)
    db.add(DetectionRuleVersion(
        rule_id=rule.id,
        version=rule.current_version,
        configuration=after,
        change_note=change_note or "Rule configuration updated",
    ))
    record_audit(db, "detection_rule.updated", "detection_rule", rule.id, {
        "version": rule.current_version,
        "before": before,
        "after": after,
        "change_note": change_note,
    })
    db.commit()
    db.refresh(rule)
    return rule


@router.post("/detection/rules/{rule_id}/preview", response_model=DetectionRulePreviewRead, tags=["Detection management"])
def preview_saved_detection_rule(
    rule_id: int,
    db: DbSession,
    window_hours: int = Query(default=168, ge=1, le=720),
) -> dict[str, object]:
    rule = db.get(DetectionRule, rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="Detection rule not found.")
    return preview_rule(db, rule_configuration(rule), window_hours)


@router.get("/detection/exceptions", response_model=list[DetectionExceptionRead], tags=["Detection management"])
def list_detection_exceptions(db: DbSession) -> list[DetectionException]:
    return list(db.scalars(select(DetectionException).order_by(DetectionException.expires_at.desc()).limit(500)))


@router.post("/detection/exceptions", response_model=DetectionExceptionRead, status_code=status.HTTP_201_CREATED, tags=["Detection management"])
def create_detection_exception(payload: DetectionExceptionCreate, db: DbSession) -> DetectionException:
    if payload.source_ip is None and payload.username is None:
        raise HTTPException(status_code=422, detail="Provide an IP address or username scope.")
    expires_at = payload.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=utc_now().tzinfo)
    if expires_at <= utc_now():
        raise HTTPException(status_code=422, detail="Exception expiry must be in the future.")
    exception = DetectionException(
        source_ip=str(payload.source_ip) if payload.source_ip else None,
        username=payload.username.strip() if payload.username else None,
        detection_key=payload.detection_key or None,
        reason=payload.reason.strip(),
        expires_at=expires_at,
    )
    db.add(exception)
    db.flush()
    record_audit(db, "detection_exception.created", "detection_exception", exception.id, {"source_ip": exception.source_ip, "username": exception.username, "detection_key": exception.detection_key, "expires_at": exception.expires_at.isoformat()})
    db.commit()
    db.refresh(exception)
    return exception


@router.delete("/detection/exceptions/{exception_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["Detection management"])
def delete_detection_exception(exception_id: int, db: DbSession) -> None:
    exception = db.get(DetectionException, exception_id)
    if exception is None:
        raise HTTPException(status_code=404, detail="Detection exception not found.")
    record_audit(db, "detection_exception.deleted", "detection_exception", exception.id, {"source_ip": exception.source_ip, "username": exception.username})
    db.delete(exception)
    db.commit()


@router.get("/audit", response_model=list[AuditEntryRead], tags=["Audit history"])
def list_audit_entries(
    db: DbSession,
    action: str | None = Query(default=None, max_length=80),
    entity_type: str | None = Query(default=None, max_length=48),
    entity_id: str | None = Query(default=None, max_length=64),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[AuditEntry]:
    query = select(AuditEntry)
    if action:
        query = query.where(AuditEntry.action == action)
    if entity_type:
        query = query.where(AuditEntry.entity_type == entity_type)
    if entity_id:
        query = query.where(AuditEntry.entity_id == entity_id)
    return list(db.scalars(query.order_by(AuditEntry.created_at.desc(), AuditEntry.id.desc()).limit(limit).offset(offset)))


@router.get("/audit/integrity", response_model=AuditIntegrityRead, tags=["Audit history"])
def audit_integrity(db: DbSession) -> dict[str, object]:
    return verify_audit_chain(db)


@router.get("/incidents/{incident_id}/comments", response_model=list[IncidentCommentRead], tags=["Incident management"])
def list_incident_comments(incident_id: int, db: DbSession) -> list[AuditEntry]:
    if db.get(Incident, incident_id) is None:
        raise HTTPException(status_code=404, detail="Incident not found.")
    query = select(AuditEntry).where(
        AuditEntry.entity_type == "incident",
        AuditEntry.entity_id == str(incident_id),
        AuditEntry.action == "incident.comment_added",
    ).order_by(AuditEntry.created_at.desc(), AuditEntry.id.desc()).limit(100)
    return list(db.scalars(query))


@router.post("/incidents/{incident_id}/comments", response_model=IncidentCommentRead, status_code=status.HTTP_201_CREATED, tags=["Incident management"])
def add_incident_comment(incident_id: int, payload: IncidentCommentCreate, db: DbSession) -> AuditEntry:
    if db.get(Incident, incident_id) is None:
        raise HTTPException(status_code=404, detail="Incident not found.")
    comment = payload.comment.strip()
    if not comment:
        raise HTTPException(status_code=422, detail="A comment cannot be empty.")
    entry = AuditEntry(actor="Local analyst", action="incident.comment_added", entity_type="incident", entity_id=str(incident_id), details={"comment": comment})
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry


@router.get("/events/saved-searches", response_model=list[SavedEventSearchRead], tags=["Authentication events"])
def list_saved_searches(db: DbSession) -> list[SavedEventSearch]:
    return list(db.scalars(select(SavedEventSearch).order_by(SavedEventSearch.created_at.desc(), SavedEventSearch.id.desc()).limit(100)))


@router.post("/events/saved-searches", response_model=SavedEventSearchRead, status_code=status.HTTP_201_CREATED, tags=["Authentication events"])
def create_saved_search(payload: SavedEventSearchCreate, db: DbSession) -> SavedEventSearch:
    search = SavedEventSearch(**payload.model_dump())
    search.name = search.name.strip()
    if not search.name:
        raise HTTPException(status_code=422, detail="A saved filter name is required.")
    db.add(search)
    db.flush()
    record_audit(db, "saved_filter.created", "saved_filter", search.id, {"name": search.name})
    db.commit()
    db.refresh(search)
    return search


@router.delete("/events/saved-searches/{search_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["Authentication events"])
def delete_saved_search(search_id: int, db: DbSession) -> None:
    search = db.get(SavedEventSearch, search_id)
    if search is None:
        raise HTTPException(status_code=404, detail="Saved filter not found.")
    db.delete(search)
    record_audit(db, "saved_filter.deleted", "saved_filter", search_id, {"name": search.name})
    db.commit()


@router.get("/analytics/behavior", response_model=BehaviorResponse, tags=["Behavior analytics"])
def behavior_analytics(
    db: DbSession,
    window_hours: int = Query(default=168, ge=1, le=24 * 30),
) -> dict[str, object]:
    events = load_behavior_events(db, window_hours)
    cutoff = utc_now() - timedelta(hours=window_hours)
    previous_events = list(db.scalars(
        select(AuthEvent).where(AuthEvent.timestamp < cutoff, AuthEvent.timestamp >= cutoff - timedelta(hours=window_hours))
        .order_by(AuthEvent.timestamp.desc(), AuthEvent.id.desc()).limit(5000)
    ))

    def compare(entity_field: str) -> list[dict[str, object]]:
        current = build_profiles(events, entity_field=entity_field)
        previous = {str(row["entity"]): row for row in build_profiles(previous_events, entity_field=entity_field)}
        for row in current:
            old = previous.get(str(row["entity"]), {})
            prior_count = int(old.get("event_count", 0))
            factors: list[str] = []
            score = 0
            if int(row["unusual_hour_events"]) > 0:
                factors.append(f"{row['unusual_hour_events']} event(s) fell outside common UTC login hours in the current period")
                score += min(35, int(row["unusual_hour_events"]) * 10)
            if float(row["failure_rate"]) >= 0.5 and int(row["event_count"]) >= 3:
                factors.append(f"Failure rate is {round(float(row['failure_rate']) * 100)}% across {row['event_count']} events")
                score += 25
            if prior_count and int(row["event_count"]) >= max(5, prior_count * 2):
                factors.append(f"Event volume rose from {prior_count} to {row['event_count']} versus the previous equal-length window")
                score += 25
            elif not prior_count:
                factors.append("No activity for this entity was present in the previous comparison window")
                score += 10
            row["entity_risk_score"] = min(100, score)
            row["previous_window_events"] = prior_count
            row["event_count_change"] = int(row["event_count"]) - prior_count
            row["anomaly_factors"] = factors
        return sorted(current, key=lambda row: (-int(row["entity_risk_score"]), -int(row["failures"]), str(row["entity"])))

    return {
        "events_analyzed": len(events),
        "window_hours": window_hours,
        "users": compare("username")[:50],
        "source_ips": compare("source_ip")[:50],
        "notice": (
            "Entity scores compare the selected window with the immediately preceding equal-length period. "
            "They are review signals based on local authentication data, not evidence of an attack."
        ),
    }


@router.post("/analytics/analyze", response_model=AnalyticsResponse, tags=["Risk analytics"])
def run_analytics(payload: AnalyticsRequest, db: DbSession) -> dict[str, object]:
    try:
        result = analyze_events(db, payload.event_ids)
        db.commit()
        return result
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except LookupError as exc:
        db.rollback()
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/incidents", response_model=list[IncidentRead], tags=["Incident management"])
def list_incidents(
    db: DbSession,
    incident_status: Literal["open", "investigating", "resolved"] | None = Query(default=None, alias="status"),
    severity: Literal["critical", "high", "medium", "low"] | None = None,
) -> list[Incident]:
    correlate_alerts(db)
    db.commit()
    query = select(Incident).where(Incident.merged_into_id.is_(None))
    if incident_status:
        query = query.where(Incident.status == incident_status)
    if severity:
        query = query.where(Incident.severity == severity)
    return list(
        db.scalars(query.order_by(Incident.updated_at.desc(), Incident.id.desc()).limit(500))
    )


@router.patch("/incidents/{incident_id}", response_model=IncidentRead, tags=["Incident management"])
def update_incident(
    incident_id: int,
    payload: IncidentUpdate,
    db: DbSession,
) -> Incident:
    incident = db.get(Incident, incident_id)
    if incident is None or incident.merged_into_id is not None:
        raise HTTPException(status_code=404, detail="Incident not found.")
    changes = payload.model_dump(exclude_unset=True, exclude_none=True)
    if not changes:
        raise HTTPException(status_code=422, detail="Provide an incident status or analyst notes.")
    for field, value in changes.items():
        if field == "analyst_notes":
            value = value.strip()
        elif field == "assignee":
            value = value.strip() or None if value else None
        elif field == "tasks":
            value = [task.model_dump() for task in payload.tasks or []]
        setattr(incident, field, value)
    incident.updated_at = utc_now()
    record_audit(db, "incident.updated", "incident", incident.id, changes)
    db.commit()
    db.refresh(incident)
    return incident


@router.post("/incidents/{incident_id}/brief", response_model=IncidentBriefRead, tags=["Incident management"])
def incident_brief(incident_id: int, db: DbSession) -> dict[str, object]:
    incident = db.get(Incident, incident_id)
    if incident is None or incident.merged_into_id is not None:
        raise HTTPException(status_code=404, detail="Incident not found.")
    return build_incident_brief(db, incident)


@router.get(
    "/intelligence/indicators",
    response_model=list[LocalIndicatorRead],
    tags=["Local IP intelligence"],
)
def list_indicators(
    db: DbSession,
    kind: Literal["allowlist", "blocklist"] | None = None,
) -> list[dict[str, object]]:
    result = []
    for indicator in list_local_indicators(db, kind):
        item = LocalIndicatorRead.model_validate(indicator).model_dump()
        item["matching_event_count"] = (db.scalar(select(func.count(AuthEvent.id)).where(AuthEvent.source_ip == indicator.source_ip)) or 0) if indicator.indicator_type == "ip" else 0
        result.append(item)
    return result


@router.post(
    "/intelligence/indicators",
    response_model=LocalIndicatorRead,
    status_code=status.HTTP_201_CREATED,
    tags=["Local IP intelligence"],
)
def create_indicator(payload: LocalIndicatorCreate, db: DbSession) -> LocalIndicator:
    indicator = create_local_indicator(db, payload)
    try:
        db.flush()
        record_audit(db, "indicator.created", "indicator", indicator.id, {"source_ip": indicator.source_ip, "kind": indicator.kind})
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="An indicator already exists for this IP address.",
        ) from exc
    db.refresh(indicator)
    return indicator


@router.put(
    "/intelligence/indicators/{indicator_id}",
    response_model=LocalIndicatorRead,
    tags=["Local IP intelligence"],
)
def update_indicator(
    indicator_id: int,
    payload: LocalIndicatorCreate,
    db: DbSession,
) -> LocalIndicator:
    indicator = update_local_indicator(db, indicator_id, payload)
    if indicator is None:
        raise HTTPException(status_code=404, detail="Local indicator not found.")
    try:
        record_audit(db, "indicator.updated", "indicator", indicator.id, {"source_ip": indicator.source_ip, "kind": indicator.kind})
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="An indicator already exists for this IP address.",
        ) from exc
    db.refresh(indicator)
    return indicator


@router.delete("/intelligence/indicators/{indicator_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["Local IP intelligence"])
def delete_indicator(indicator_id: int, db: DbSession) -> None:
    indicator = db.get(LocalIndicator, indicator_id)
    if indicator is None or not delete_local_indicator(db, indicator_id):
        raise HTTPException(status_code=404, detail="Local indicator not found.")
    record_audit(db, "indicator.deleted", "indicator", indicator_id, {"source_ip": indicator.source_ip, "kind": indicator.kind})
    db.commit()


@router.get("/intelligence/relationships", tags=["Local IP intelligence"])
def relationship_graph(db: DbSession) -> dict[str, list[dict[str, object]]]:
    events = list(
        db.scalars(select(AuthEvent).order_by(AuthEvent.timestamp.desc(), AuthEvent.id.desc()).limit(250))
    )
    alerts = list(db.scalars(select(Alert).order_by(Alert.created_at.desc(), Alert.id.desc()).limit(100)))
    incidents = list(db.scalars(select(Incident).where(Incident.merged_into_id.is_(None)).order_by(Incident.updated_at.desc()).limit(100)))
    indicators = get_local_indicator_map(db)
    nodes: dict[str, dict[str, object]] = {}
    edge_counts: dict[tuple[str, str, str], int] = {}

    def add_ip_node(source_ip: str) -> str:
        node_id = f"ip:{source_ip}"
        indicator = indicators.get(source_ip)
        nodes[node_id] = {
            "id": node_id,
            "label": source_ip,
            "type": "ip",
            "indicator": indicator.kind if indicator else None,
        }
        return node_id

    for event in events:
        ip_node = add_ip_node(event.source_ip)
        user_node = f"user:{event.username}"
        nodes[user_node] = {"id": user_node, "label": event.username, "type": "user"}
        event_node = f"event:{event.id}"
        nodes[event_node] = {"id": event_node, "label": f"{event.status.title()} · {event.username}", "type": "event", "timestamp": event.timestamp.isoformat(), "source_ip": event.source_ip, "username": event.username, "event_type": event.event_type, "status": event.status, "source_label": event.source_label}
        edge_counts[(ip_node, event_node, "observed_event")] = 1
        edge_counts[(user_node, event_node, "principal_event")] = 1
        key = (ip_node, user_node, event.status)
        edge_counts[key] = edge_counts.get(key, 0) + 1
    for alert in alerts:
        ip_node = add_ip_node(alert.source_ip)
        alert_node = f"alert:{alert.id}"
        nodes[alert_node] = {
            "id": alert_node,
            "label": alert.title,
            "type": "alert",
            "severity": alert.severity,
        }
        key = (ip_node, alert_node, "alert")
        edge_counts[key] = 1
        for event_id in alert.related_event_ids:
            if f"event:{event_id}" in nodes:
                edge_counts[(alert_node, f"event:{event_id}", "alert_evidence")] = 1

    for incident in incidents:
        incident_node = f"incident:{incident.id}"
        nodes[incident_node] = {"id": incident_node, "label": incident.title, "type": "incident", "severity": incident.severity, "status": incident.status, "assignee": incident.assignee, "updated_at": incident.updated_at.isoformat()}
        for event_id in incident.related_event_ids:
            if f"event:{event_id}" in nodes:
                edge_counts[(incident_node, f"event:{event_id}", "incident_evidence")] = 1
    for link in db.scalars(select(IncidentAlert)):
        if f"incident:{link.incident_id}" in nodes and f"alert:{link.alert_id}" in nodes:
            edge_counts[(f"incident:{link.incident_id}", f"alert:{link.alert_id}", "incident_alert")] = 1

    edges = [
        {
            "id": f"{source}|{target}|{kind}",
            "source": source,
            "target": target,
            "kind": kind,
            "count": count,
        }
        for (source, target, kind), count in edge_counts.items()
    ]
    return {"nodes": list(nodes.values()), "edges": edges}


@router.get("/soar/workflows", response_model=list[SoarWorkflowRead], tags=["SOAR workflows"])
def list_soar_workflows(db: DbSession) -> list[SoarWorkflow]:
    return list(db.scalars(select(SoarWorkflow).order_by(SoarWorkflow.updated_at.desc(), SoarWorkflow.id.desc()).limit(200)))


@router.post("/soar/workflows", response_model=SoarWorkflowRead, status_code=status.HTTP_201_CREATED, tags=["SOAR workflows"])
def create_soar_workflow(payload: SoarWorkflowCreate, db: DbSession) -> SoarWorkflow:
    if bool(payload.condition_field) != bool(payload.condition_operator and payload.condition_value):
        raise HTTPException(status_code=422, detail="Condition field, operator, and value must be supplied together.")
    workflow = SoarWorkflow(**payload.model_dump())
    db.add(workflow)
    db.flush()
    record_audit(db, "soar.workflow_created", "soar_workflow", workflow.id, {"name": workflow.name, "trigger_type": workflow.trigger_type, "action": workflow.action, "approval_required": workflow.approval_required})
    db.commit()
    db.refresh(workflow)
    return workflow


@router.post("/soar/workflows/{workflow_id}/simulate", response_model=SoarExecutionRead, status_code=status.HTTP_201_CREATED, tags=["SOAR workflows"])
def simulate_soar_workflow(workflow_id: int, payload: SoarExecutionCreate, db: DbSession) -> SoarExecution:
    workflow = db.get(SoarWorkflow, workflow_id)
    if workflow is None or not workflow.enabled:
        raise HTTPException(status_code=404, detail="Enabled workflow not found.")
    if workflow.trigger_type == "alert_created" and payload.entity_type != "alert":
        raise HTTPException(status_code=422, detail="This trigger requires an alert record.")
    if workflow.trigger_type == "event_failure" and payload.entity_type != "event":
        raise HTTPException(status_code=422, detail="This trigger requires an authentication event.")
    record = db.get(Alert if payload.entity_type == "alert" else AuthEvent, payload.entity_id)
    if record is None:
        raise HTTPException(status_code=404, detail="The referenced local record was not found.")
    evidence: dict[str, object]
    if payload.entity_type == "alert":
        evidence = {"id": record.id, "title": record.title, "severity": record.severity, "status": record.status, "source_ip": record.source_ip, "related_event_ids": record.related_event_ids}
    else:
        evidence = {"id": record.id, "username": record.username, "source_ip": record.source_ip, "status": record.status, "event_type": record.event_type, "timestamp": record.timestamp.isoformat()}
    if workflow.trigger_type == "event_failure" and evidence.get("status") != "failure":
        raise HTTPException(status_code=422, detail="The referenced authentication event is not a failure.")
    if workflow.trigger_type == "indicator_match" and not db.scalar(select(LocalIndicator.id).where(LocalIndicator.source_ip == str(evidence.get("source_ip")), LocalIndicator.indicator_type == "ip", (LocalIndicator.expires_at.is_(None)) | (LocalIndicator.expires_at > utc_now()))):
        raise HTTPException(status_code=422, detail="No local indicator matches the referenced source IP.")
    if workflow.condition_field:
        actual = str(evidence.get(workflow.condition_field, "")).lower()
        expected = workflow.condition_value.lower()
        matched = actual == expected if workflow.condition_operator == "equals" else expected in actual
        if not matched:
            raise HTTPException(status_code=422, detail="The workflow condition did not match the local evidence.")
    status_value = "awaiting_approval" if workflow.approval_required else "simulated"
    outcome = f"{workflow.action.replace('_', ' ').title()} prepared as a local simulation; no host, network, or alert response action was executed."
    execution = SoarExecution(workflow_id=workflow.id, status=status_value, entity_type=payload.entity_type, entity_id=payload.entity_id, evidence=evidence, outcome=outcome)
    db.add(execution)
    db.flush()
    record_audit(db, "soar.execution_simulated", "soar_execution", execution.id, {"workflow_id": workflow.id, "status": status_value, "entity_type": payload.entity_type, "entity_id": payload.entity_id})
    db.commit()
    db.refresh(execution)
    return execution


@router.get("/soar/executions", response_model=list[SoarExecutionRead], tags=["SOAR workflows"])
def list_soar_executions(db: DbSession, limit: int = Query(default=100, ge=1, le=500)) -> list[SoarExecution]:
    return list(db.scalars(select(SoarExecution).order_by(SoarExecution.created_at.desc(), SoarExecution.id.desc()).limit(limit)))


@router.patch("/soar/executions/{execution_id}/approve", response_model=SoarExecutionRead, tags=["SOAR workflows"])
def approve_soar_simulation(execution_id: int, db: DbSession) -> SoarExecution:
    execution = db.get(SoarExecution, execution_id)
    if execution is None:
        raise HTTPException(status_code=404, detail="Workflow execution not found.")
    if execution.status != "awaiting_approval":
        raise HTTPException(status_code=409, detail="Only a pending simulation can be approved.")
    execution.status = "approved_simulation"
    execution.approved_by = "Local analyst"
    execution.updated_at = utc_now()
    execution.outcome = "Analyst approved the local simulation record. No host, network, or alert response action was executed."
    record_audit(db, "soar.simulation_approved", "soar_execution", execution.id, {"workflow_id": execution.workflow_id, "entity_type": execution.entity_type, "entity_id": execution.entity_id})
    db.commit()
    db.refresh(execution)
    return execution


@router.post("/copilot/ask", response_model=CopilotResponse, tags=["Security Copilot"])
def ask_copilot(payload: CopilotRequest, db: DbSession) -> dict[str, object]:
    result = answer_question(payload.question.strip(), db)
    if payload.model and result.get("intent") != "unsupported" and result.get("facts"):
        model_status = ollama_status()
        if not model_status["connected"]:
            raise HTTPException(status_code=503, detail="Ollama is unavailable. Start the local Ollama service and retry.")
        if payload.model not in model_status["available_qwen_models"]:
            raise HTTPException(status_code=409, detail="The selected Qwen model is not installed in Ollama.")
        return enhance_local_answer(result, payload.model, model_status)
    return result


@router.get("/copilot/status", tags=["Security Copilot"])
def copilot_status() -> dict[str, object]:
    return ollama_status()
