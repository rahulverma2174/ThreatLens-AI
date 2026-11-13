from collections import defaultdict
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import (
    Alert,
    AnalysisRun,
    AuthEvent,
    DetectionSettings,
    EventRiskAssessment,
    LocalIndicator,
)
from app.services.detection import get_detection_settings
from app.services.threat_intelligence import get_local_indicator_map

RISK_NOTICE = (
    "Risk levels prioritize analyst review using local evidence; they do not confirm malicious activity."
)
SEVERITY_POINTS = {"low": 5, "medium": 12, "high": 20, "critical": 25}
MIN_USER_BASELINE_EVENTS = 5


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _level(score: int) -> str:
    if score >= 70:
        return "critical"
    if score >= 40:
        return "high"
    if score >= 16:
        return "moderate"
    return "low"


def assess_unfamiliar_source(event: AuthEvent, history: list[AuthEvent]) -> dict[str, object]:
    """Assess a login source only when the account has a minimum observed-history baseline."""
    user_history = [item for item in history if item.username == event.username and item.id != event.id]
    if len(user_history) < MIN_USER_BASELINE_EVENTS:
        return {
            "status": "insufficient_baseline",
            "baseline_events": len(user_history),
            "minimum_baseline_events": MIN_USER_BASELINE_EVENTS,
            "new_source": None,
        }
    seen_sources = {item.source_ip for item in user_history}
    return {
        "status": "assessed",
        "baseline_events": len(user_history),
        "minimum_baseline_events": MIN_USER_BASELINE_EVENTS,
        "new_source": event.source_ip not in seen_sources,
    }


def score_event(
    event: AuthEvent,
    history: list[AuthEvent],
    alerts: list[Alert],
    indicators: dict[str, LocalIndicator],
    settings: DetectionSettings,
    anomaly_classification: str | None,
) -> tuple[int, str, list[dict[str, object]]]:
    at = _as_utc(event.timestamp)
    window_start = at - timedelta(minutes=settings.window_minutes)
    preceding = [
        item
        for item in history
        if item.source_ip == event.source_ip and window_start <= _as_utc(item.timestamp) <= at
    ]
    failures = [item for item in preceding if item.status == "failure"]
    factors: list[dict[str, object]] = []

    def add(key: str, points: int, explanation: str) -> None:
        if points > 0:
            factors.append({"key": key, "points": points, "explanation": explanation})

    if event.status == "failure":
        add("failed_login", 6, "This authentication event failed.")
    source_history = [
        item for item in history if item.source_ip == event.source_ip and item.id != event.id
    ]
    source_failures = sum(item.status == "failure" for item in source_history)
    if len(source_history) >= 5 and source_failures / len(source_history) >= 0.6:
        add(
            "source_failure_baseline",
            12,
            f"{source_failures} of {len(source_history)} other observed events from this source failed.",
        )
    if len(failures) >= settings.repeated_failure_threshold:
        add(
            "repeated_failures",
            min(30, (len(failures) - settings.repeated_failure_threshold + 1) * 8),
            f"{len(failures)} failures from this source were observed within {settings.window_minutes} minutes.",
        )
    targeted_users = {item.username for item in failures}
    if len(targeted_users) >= settings.targeted_username_threshold:
        add(
            "multiple_accounts",
            15,
            f"{len(targeted_users)} distinct usernames were targeted from this source in the detection window.",
        )

    user_history = [item for item in history if item.username == event.username and item.id != event.id]
    source_assessment = assess_unfamiliar_source(event, history)
    if source_assessment["status"] == "assessed" and source_assessment["new_source"]:
        add(
            "new_source_for_user",
            12,
            f"This source IP was not seen in the user's {source_assessment['baseline_events']} observed historical events (minimum baseline: {MIN_USER_BASELINE_EVENTS}).",
        )
    if len(user_history) >= 5:
        hour_counts: dict[int, int] = defaultdict(int)
        for item in user_history:
            hour_counts[_as_utc(item.timestamp).hour] += 1
        if hour_counts[_as_utc(event.timestamp).hour] / len(user_history) < 0.1:
            add(
                "unusual_login_hour",
                10,
                f"This UTC login hour is uncommon in the user's {len(user_history)} observed events.",
            )

    same_user_failures = [
        item for item in failures if item.username == event.username and item.id != event.id
    ]
    if event.status == "success" and len(same_user_failures) >= settings.success_after_failure_threshold:
        add(
            "success_after_failures",
            20,
            f"A success followed {len(same_user_failures)} failures for this username from this source.",
        )
    distributed_user_failures = [
        item
        for item in history
        if item.username == event.username
        and item.status == "failure"
        and window_start <= _as_utc(item.timestamp) <= at
        and (_as_utc(item.timestamp) < at or (at == _as_utc(item.timestamp) and item.id < event.id))
    ]
    distributed_failure_sources = {item.source_ip for item in distributed_user_failures}
    if (
        event.status == "success"
        and len(distributed_user_failures) >= settings.distributed_failure_threshold
        and len(distributed_failure_sources) >= settings.distributed_source_ip_threshold
    ):
        add(
            "distributed_failures_then_success",
            25,
            f"This login followed {len(distributed_user_failures)} failures for the account from {len(distributed_failure_sources)} distinct IPs within {settings.window_minutes} minutes.",
        )

    related_alerts = [
        alert
        for alert in alerts
        if alert.status != "resolved"
        and event.source_ip == alert.source_ip
        and event.id in alert.related_event_ids
    ]
    if related_alerts:
        alert = max(related_alerts, key=lambda item: SEVERITY_POINTS[item.severity])
        add(
            "rule_detection",
            SEVERITY_POINTS[alert.severity],
            f"Related local rule signal: {alert.title} ({alert.severity}).",
        )
    indicator = indicators.get(event.source_ip)
    if indicator is not None and indicator.kind == "blocklist":
        add(
            "local_blocklist",
            15,
            "This IP is on the locally configured blocklist; the analyst-managed label is not independently verified.",
        )
    if anomaly_classification == "suspicious":
        add(
            "model_anomaly",
            10,
            "Isolation Forest marked this event as an anomaly; this is a model review signal only.",
        )

    score = min(100, sum(int(factor["points"]) for factor in factors))
    return score, _level(score), factors


def analyze_events(
    db: Session,
    requested_ids: list[int] | None = None,
) -> dict[str, object]:
    history = list(
        db.scalars(select(AuthEvent).order_by(AuthEvent.timestamp.desc(), AuthEvent.id.desc()).limit(500))
    )
    by_id = {event.id: event for event in history}
    if requested_ids is not None and any(event_id not in by_id for event_id in requested_ids):
        raise LookupError("One or more requested event IDs do not exist in the 500-event analysis window.")
    selected_ids = set(requested_ids) if requested_ids is not None else set(by_id)
    events = [event for event in history if event.id in selected_ids]
    if not events:
        raise ValueError("No authentication events are available for analysis.")

    anomaly_by_id: dict[int, dict[str, object]] = {}
    model_name: str | None = None
    if len(history) >= 10:
        from app.services.anomaly import score_events

        model_results = score_events(db, [event.id for event in events])
        anomaly_by_id = {result["event"].id: result for result in model_results}
        model_name = "Isolation Forest"

    settings = get_detection_settings(db)
    alerts = list(db.scalars(select(Alert).where(Alert.status != "resolved")))
    indicators = get_local_indicator_map(db)
    run = AnalysisRun(events_analyzed=len(events), model_name=model_name)
    db.add(run)
    db.flush()
    source_ips = {event.source_ip for event in events}
    prior_run_counts = {
        source_ip: count
        for source_ip, count in db.execute(
            select(
                EventRiskAssessment.source_ip,
                func.count(func.distinct(EventRiskAssessment.analysis_run_id)),
            )
            .where(
                EventRiskAssessment.source_ip.in_(source_ips),
                EventRiskAssessment.analysis_run_id != run.id,
            )
            .group_by(EventRiskAssessment.source_ip)
        )
    }
    latest_assessment_ids = (
        select(func.max(EventRiskAssessment.id).label("assessment_id"))
        .where(EventRiskAssessment.event_id.in_(selected_ids))
        .group_by(EventRiskAssessment.event_id)
        .subquery()
    )
    previous_scores = {
        event_id: score
        for event_id, score in db.execute(
            select(EventRiskAssessment.event_id, EventRiskAssessment.score).join(
                latest_assessment_ids,
                EventRiskAssessment.id == latest_assessment_ids.c.assessment_id,
            )
        )
    }
    assessments: list[dict[str, object]] = []
    for event in events:
        anomaly = anomaly_by_id.get(event.id)
        score, level, factors = score_event(
            event,
            history,
            alerts,
            indicators,
            settings,
            str(anomaly["classification"]) if anomaly else None,
        )
        prior_runs = prior_run_counts.get(event.source_ip, 0)
        previous_score = previous_scores.get(event.id)
        db.add(
            EventRiskAssessment(
                analysis_run_id=run.id,
                event_id=event.id,
                source_ip=event.source_ip,
                score=score,
                classification=level,
                factors=factors,
            )
        )
        assessments.append(
            {
                "event": event,
                "risk_score": score,
                "risk_level": level,
                "factors": factors,
                "anomaly_score": anomaly["anomaly_score"] if anomaly else None,
                "anomaly_classification": anomaly["classification"] if anomaly else None,
                "prior_analysis_runs": prior_runs,
                "previous_risk_score": previous_score,
            }
        )
    return {
        "analysis_run_id": run.id,
        "events_analyzed": len(events),
        "model": model_name,
        "notice": RISK_NOTICE,
        "results": assessments,
    }
