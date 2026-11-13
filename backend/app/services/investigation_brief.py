from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Alert, AuthEvent, Incident, IncidentAlert, LocalIndicator
from app.services.local_ai import enhance_local_answer, ollama_status


def build_incident_brief(db: Session, incident: Incident) -> dict[str, object]:
    event_ids = sorted(set(incident.related_event_ids))
    events = list(db.scalars(
        select(AuthEvent).where(AuthEvent.id.in_(event_ids)).order_by(AuthEvent.timestamp, AuthEvent.id)
    )) if event_ids else []
    linked_alert_ids = list(db.scalars(select(IncidentAlert.alert_id).where(IncidentAlert.incident_id == incident.id)))
    alerts = list(db.scalars(select(Alert).where(Alert.id.in_(linked_alert_ids)).order_by(Alert.created_at, Alert.id))) if linked_alert_ids else []
    indicators = {item.source_ip: item for item in db.scalars(select(LocalIndicator).where(LocalIndicator.source_ip.in_(incident.source_ips)))} if incident.source_ips else {}

    failures = [event for event in events if event.status == "failure"]
    successes = [event for event in events if event.status == "success"]
    usernames = sorted({event.username for event in events})
    sources = sorted({event.source_ip for event in events})
    facts: list[dict[str, object]] = [
        {"text": f"Incident status: {incident.status}; severity: {incident.severity}; assigned to: {incident.assignee or 'unassigned'}.", "event_ids": []},
        {"text": f"Evidence window: {events[0].timestamp.isoformat()} to {events[-1].timestamp.isoformat()}.", "event_ids": [events[0].id, events[-1].id]} if events else {"text": "No linked event records are available.", "event_ids": []},
        {"text": f"Authentication outcomes: {len(failures)} failures and {len(successes)} successes across {len(events)} linked events.", "event_ids": [event.id for event in events]},
        {"text": f"Source IPs: {', '.join(sources) or 'none'}.", "event_ids": [event.id for event in events]},
        {"text": f"Usernames: {', '.join(usernames) or 'none'}.", "event_ids": [event.id for event in events]},
    ]
    for alert in alerts:
        facts.append({"text": f"Rule alert {alert.id} ({alert.severity}, {alert.status}): {alert.title}. {alert.reason}", "event_ids": list(alert.related_event_ids)})
    for ip, indicator in indicators.items():
        facts.append({"text": f"Local indicator for {ip}: {indicator.kind}; note: {indicator.note or 'none'}.", "event_ids": [event.id for event in events if event.source_ip == ip]})

    deterministic = (
        f"This {incident.severity} severity incident has {len(events)} linked authentication events, "
        f"including {len(failures)} failures and {len(successes)} successes across {len(sources)} source IP(s) "
        f"and {len(usernames)} username(s). Review linked rule alerts and validate the activity against expected operations."
        if events else f"This {incident.severity} severity incident has no linked authentication event records. Review its {len(alerts)} linked rule alert(s) and incident notes."
    )
    ollama_facts = [str(item["text"]) for item in facts]
    result = enhance_local_answer({
        "question": f"Write an evidence-grounded investigation brief for incident {incident.id}: {incident.title}",
        "intent": "incident_brief",
        "answer": deterministic,
        "facts": ollama_facts,
        "suggested_actions": [],
        "data_scope": "Incident and linked evidence from local SQLite records only.",
    })
    status = ollama_status()
    model_used = status["model_ready"] and "Explanation polished by local Ollama" in str(result["data_scope"])
    return {
        "incident_id": incident.id,
        "title": incident.title,
        "summary": result["answer"],
        "facts": facts,
        "event_ids": event_ids,
        "model_used": model_used,
        "generated_at": datetime.now(timezone.utc),
        "notice": "Summary is grounded in stored records. Validate evidence before taking response action.",
    }
