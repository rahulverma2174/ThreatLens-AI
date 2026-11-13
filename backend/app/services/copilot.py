from collections import defaultdict
from datetime import datetime, time, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Alert, AuthEvent, EventRiskAssessment
from app.services.behavior import build_profiles, load_behavior_events

DATA_SCOPE = "Facts come from local SQLite records; no external intelligence was used."


def answer_question(question: str, db: Session) -> dict[str, object]:
    normalized = " ".join(question.lower().split())
    if any(term in normalized for term in ("highest risk", "highest-risk", "explain the highest", "top alert")):
        return _highest_risk_alert(question, db)
    if any(term in normalized for term in ("top", "suspicious ip", "source ip", "ip address")):
        return _top_suspicious_ips(question, db)
    if ("today" in normalized or "today's" in normalized) and any(
        term in normalized for term in ("fail", "failure", "login", "auth")
    ):
        return _today_failures(question, db)
    if any(term in normalized for term in ("multiple ip", "multiple source", "targeted by", "accounts targeted")):
        return _accounts_targeted_by_multiple_ips(question, db)
    if any(term in normalized for term in ("unusual", "behaviour", "behavior", "activity")):
        return _unusual_activity(question, db)
    return {
        "question": question,
        "intent": "unsupported",
        "answer": (
            "I can answer questions about top suspicious IPs, the highest-risk alert, "
            "today's failed logins, accounts targeted by multiple IPs, and unusual local activity."
        ),
        "facts": [],
        "suggested_actions": [],
        "data_scope": DATA_SCOPE,
    }


def _highest_risk_alert(question: str, db: Session) -> dict[str, object]:
    rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    alerts = list(db.scalars(select(Alert).where(Alert.status != "resolved")))
    if not alerts:
        return _empty_result(question, "highest_risk_alert", "No unresolved local rule alerts are available.")
    related_ids = {event_id for alert in alerts for event_id in alert.related_event_ids}
    latest_assessment_by_event: dict[int, EventRiskAssessment] = {}
    if related_ids:
        for assessment in db.scalars(
            select(EventRiskAssessment)
            .where(EventRiskAssessment.event_id.in_(related_ids))
            .order_by(EventRiskAssessment.created_at.desc(), EventRiskAssessment.id.desc())
        ):
            latest_assessment_by_event.setdefault(assessment.event_id, assessment)
    scores_by_alert = {
        alert.id: max(
            (
                latest_assessment_by_event[event_id].score
                for event_id in alert.related_event_ids
                if event_id in latest_assessment_by_event
            ),
            default=None,
        )
        for alert in alerts
    }
    alert = max(
        alerts,
        key=lambda item: (
            scores_by_alert[item.id] is not None,
            scores_by_alert[item.id] if scores_by_alert[item.id] is not None else rank[item.severity],
            rank[item.severity],
            item.created_at,
            item.id,
        ),
    )
    related = list(
        db.scalars(select(AuthEvent).where(AuthEvent.id.in_(alert.related_event_ids)))
    ) if alert.related_event_ids else []
    failures = sum(event.status == "failure" for event in related)
    usernames = sorted({event.username for event in related})
    highest_scored_event = max(
        (
            latest_assessment_by_event[event_id]
            for event_id in alert.related_event_ids
            if event_id in latest_assessment_by_event
        ),
        key=lambda assessment: assessment.score,
        default=None,
    )
    answer = (
        f"The highest latest analyzed event risk is {highest_scored_event.score}/100 "
        f"for “{alert.title}” ({alert.severity}) at {alert.source_ip}."
        if highest_scored_event is not None
        else f"No stored risk score is available yet; the highest-severity unresolved local signal is “{alert.title}” ({alert.severity}) for {alert.source_ip}."
    )
    factors = (
        [str(factor["explanation"]) for factor in highest_scored_event.factors[:5]]
        if highest_scored_event is not None
        else ["Run AI analysis to persist an event risk score; the signal is currently ranked by rule severity only."]
    )
    return {
        "question": question,
        "intent": "highest_risk_alert",
        "answer": answer,
        "facts": [
            alert.reason,
            f"{len(related)} related stored event(s), including {failures} failed login(s).",
            f"Related usernames: {', '.join(usernames) if usernames else 'not present in the linked events'}.",
            f"Current investigation status: {alert.status}.",
            *factors,
        ],
        "suggested_actions": [
            "Review the linked event timeline and confirm whether the activity is expected.",
            "Record the investigation outcome before resolving the signal.",
        ],
        "data_scope": DATA_SCOPE,
    }


def _top_suspicious_ips(question: str, db: Session) -> dict[str, object]:
    alerts = list(db.scalars(select(Alert).where(Alert.status != "resolved")))
    by_ip: dict[str, list[Alert]] = defaultdict(list)
    for alert in alerts:
        by_ip[alert.source_ip].append(alert)
    top = sorted(
        by_ip.items(),
        key=lambda item: (
            max({"low": 1, "medium": 2, "high": 3, "critical": 4}[alert.severity] for alert in item[1]),
            len(item[1]),
        ),
        reverse=True,
    )[:10]
    facts = [
        f"{ip}: {len(ip_alerts)} unresolved rule signal(s), highest severity "
        f"{max((alert.severity for alert in ip_alerts), key=lambda severity: {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}[severity])}."
        for ip, ip_alerts in top
    ]
    answer = (
        f"Found {len(top)} source IP(s) with unresolved local detection signals, ranked by highest alert severity and signal count."
        if top
        else "No unresolved local rule signals currently identify a suspicious source IP."
    )
    return {
        "question": question,
        "intent": "top_suspicious_ips",
        "answer": answer,
        "facts": facts,
        "suggested_actions": ["Review each address against its local event history; no external reputation was queried."],
        "data_scope": DATA_SCOPE,
    }


def _today_failures(question: str, db: Session) -> dict[str, object]:
    now = datetime.now(timezone.utc)
    start = datetime.combine(now.date(), time.min, tzinfo=timezone.utc)
    events = list(
        db.scalars(
            select(AuthEvent).where(
                AuthEvent.status == "failure",
                AuthEvent.timestamp >= start,
                AuthEvent.timestamp < start + timedelta(days=1),
            )
        )
    )
    by_ip: dict[str, int] = defaultdict(int)
    by_user: dict[str, int] = defaultdict(int)
    for event in events:
        by_ip[event.source_ip] += 1
        by_user[event.username] += 1
    top_ips = sorted(by_ip.items(), key=lambda item: (-item[1], item[0]))[:5]
    top_users = sorted(by_user.items(), key=lambda item: (-item[1], item[0]))[:5]
    return {
        "question": question,
        "intent": "today_failed_logins",
        "answer": f"Found {len(events)} failed authentication event(s) dated today in UTC.",
        "facts": [
            f"Top source IP counts: {', '.join(f'{ip} ({count})' for ip, count in top_ips) or 'none'}.",
            f"Top username counts: {', '.join(f'{user} ({count})' for user, count in top_users) or 'none'}.",
        ],
        "suggested_actions": ["Check whether repeated failures are expected for the affected accounts and sources."],
        "data_scope": f"{DATA_SCOPE} Date boundary: {start.isoformat()} through {(start + timedelta(days=1)).isoformat()}.",
    }


def _accounts_targeted_by_multiple_ips(question: str, db: Session) -> dict[str, object]:
    events = list(db.scalars(select(AuthEvent).where(AuthEvent.status == "failure")))
    sources_by_user: dict[str, set[str]] = defaultdict(set)
    counts_by_user: dict[str, int] = defaultdict(int)
    for event in events:
        sources_by_user[event.username].add(event.source_ip)
        counts_by_user[event.username] += 1
    targeted = [
        (username, sources_by_user[username], counts_by_user[username])
        for username in sources_by_user
        if len(sources_by_user[username]) > 1
    ]
    targeted.sort(key=lambda item: (-len(item[1]), -item[2], item[0]))
    facts = [
        f"{username}: {failures} failed event(s) from {len(ips)} source IP(s) ({', '.join(sorted(ips))})."
        for username, ips, failures in targeted[:20]
    ]
    return {
        "question": question,
        "intent": "accounts_targeted_by_multiple_ips",
        "answer": (
            f"Found {len(targeted)} username(s) with failed logins from multiple source IPs."
            if targeted
            else "No username in the stored failed-login records was targeted from multiple source IPs."
        ),
        "facts": facts,
        "suggested_actions": ["Validate account ownership and compare the source-specific event timelines."],
        "data_scope": DATA_SCOPE,
    }


def _unusual_activity(question: str, db: Session) -> dict[str, object]:
    events = load_behavior_events(db, hours=24 * 30)
    source_profiles = build_profiles(events, entity_field="source_ip")
    user_profiles = build_profiles(events, entity_field="username")
    unusual = [
        ("source IP", profile)
        for profile in source_profiles
        if int(profile["event_count"]) >= 5 and (float(profile["failure_rate"]) >= 0.6 or int(profile["unusual_hour_events"]) > 0)
    ] + [
        ("username", profile)
        for profile in user_profiles
        if int(profile["event_count"]) >= 5 and (float(profile["failure_rate"]) >= 0.6 or int(profile["unusual_hour_events"]) > 0)
    ]
    unusual.sort(key=lambda item: (-int(item[1]["failures"]), -int(item[1]["unusual_hour_events"])))
    facts = [
        f"{kind} {profile['entity']}: {profile['event_count']} event(s), "
        f"{profile['failures']} failures ({profile['failure_rate']:.0%}), "
        f"{profile['unusual_hour_events']} low-frequency-hour event(s)."
        for kind, profile in unusual[:10]
    ]
    return {
        "question": question,
        "intent": "unusual_activity",
        "answer": (
            f"Found {len(unusual)} user/source profile(s) meeting the local review heuristics in the last 30 days."
            if unusual
            else "No profiles met the minimum-history and local unusual-activity heuristics in the last 30 days."
        ),
        "facts": facts,
        "suggested_actions": ["Treat these as review indicators; validate against authorized operational context."],
        "data_scope": DATA_SCOPE,
    }


def _empty_result(question: str, intent: str, message: str) -> dict[str, object]:
    return {
        "question": question,
        "intent": intent,
        "answer": message,
        "facts": [],
        "suggested_actions": [],
        "data_scope": DATA_SCOPE,
    }
