from datetime import timedelta

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from app.models import Alert, AuthEvent, DetectionException, DetectionRule, DetectionSettings, utc_now
from app.services.audit import record_audit


def get_detection_settings(db: Session) -> DetectionSettings:
    settings = db.get(DetectionSettings, 1)
    if settings is None:
        settings = DetectionSettings(id=1)
        db.add(settings)
        db.flush()
    return settings


def _record_alert(
    db: Session,
    *,
    source_ip: str,
    detection_key: str,
    title: str,
    severity: str,
    reason: str,
    event_ids: list[int],
    attack_technique: str | None = None,
) -> None:
    linked_usernames = set(db.scalars(select(AuthEvent.username).where(AuthEvent.id.in_(event_ids)))) if event_ids else set()
    scope = [DetectionException.source_ip == source_ip]
    if linked_usernames:
        scope.append(DetectionException.username.in_(linked_usernames))
    exception_query = select(DetectionException).where(
        DetectionException.expires_at > utc_now(),
        or_(DetectionException.detection_key.is_(None), DetectionException.detection_key == detection_key),
        or_(*scope),
    )
    if db.scalar(exception_query.limit(1)) is not None:
        return
    existing = db.scalar(
        select(Alert)
        .where(
            Alert.source_ip == source_ip,
            Alert.detection_key == detection_key,
            Alert.status != "resolved",
        )
        .order_by(Alert.created_at.desc())
        .limit(1)
    )
    if existing is not None:
        previous_event_ids = set(existing.related_event_ids)
        newly_linked_ids = sorted(set(event_ids) - previous_event_ids)
        severity_rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        severity_escalated = severity_rank[severity] > severity_rank[existing.severity]
        existing.related_event_ids = sorted(previous_event_ids | set(event_ids))
        existing.reason = reason
        if attack_technique:
            existing.attack_technique = attack_technique
        if severity_escalated:
            existing.severity = severity
        if existing.disposition is not None and (newly_linked_ids or severity_escalated):
            previous_disposition = existing.disposition
            existing.disposition = None
            existing.disposition_notes = ""
            existing.disposition_updated_at = None
            record_audit(
                db,
                "alert.review_reset_new_evidence",
                "alert",
                existing.id,
                {
                    "previous_disposition": previous_disposition,
                    "new_related_event_count": len(newly_linked_ids),
                    "severity_escalated": severity_escalated,
                },
            )
        return
    db.add(
        Alert(
            detection_key=detection_key,
            attack_technique=attack_technique,
            title=title,
            severity=severity,
            reason=reason,
            source_ip=source_ip,
            related_event_ids=sorted(set(event_ids)),
        )
    )


def evaluate_event(db: Session, event: AuthEvent) -> None:
    settings = get_detection_settings(db)
    if not settings.monitoring_enabled:
        return
    start = event.timestamp - timedelta(minutes=settings.window_minutes)
    sequence_boundary = or_(
        AuthEvent.timestamp < event.timestamp,
        and_(AuthEvent.timestamp == event.timestamp, AuthEvent.id <= event.id),
    )
    recent = list(
        db.scalars(
            select(AuthEvent).where(
                AuthEvent.source_ip == event.source_ip,
                AuthEvent.timestamp >= start,
                sequence_boundary,
            )
        )
    )
    failures = [item for item in recent if item.status == "failure"]
    ids = [item.id for item in recent]

    if len(failures) >= settings.repeated_failure_threshold:
        _record_alert(
            db,
            source_ip=event.source_ip,
            detection_key="repeated_failures",
            title="Repeated login failures",
            severity="medium",
            reason=f"{len(failures)} failed login attempts were observed from this IP within {settings.window_minutes} minutes.",
            event_ids=[item.id for item in failures],
            attack_technique="T1110",
        )
    if len(failures) >= settings.brute_force_threshold:
        _record_alert(
            db,
            source_ip=event.source_ip,
            detection_key="brute_force",
            title="Possible brute-force activity",
            severity="critical" if len(failures) >= settings.brute_force_threshold * 2 else "high",
            reason=f"{len(failures)} failed login attempts met the configured threshold of {settings.brute_force_threshold} within {settings.window_minutes} minutes.",
            event_ids=[item.id for item in failures],
            attack_technique="T1110",
        )
    if len(recent) >= settings.brute_force_threshold * 2:
        _record_alert(
            db,
            source_ip=event.source_ip,
            detection_key="login_burst",
            title="Unusual login burst",
            severity="medium",
            reason=f"{len(recent)} login events were observed from this IP within {settings.window_minutes} minutes.",
            event_ids=ids,
        )
    usernames = {item.username for item in failures}
    if len(usernames) >= settings.targeted_username_threshold:
        _record_alert(
            db,
            source_ip=event.source_ip,
            detection_key="multiple_usernames",
            title="Multiple usernames targeted",
            severity="high",
            reason=(
                f"{len(usernames)} distinct usernames were attempted from this IP within "
                f"{settings.window_minutes} minutes; this is a repeated authentication-failure "
                "pattern and does not establish password reuse or a specific ATT&CK sub-technique."
            ),
            event_ids=ids,
            attack_technique="T1110",
        )
    account_failures = list(
        db.scalars(
            select(AuthEvent).where(
                AuthEvent.username == event.username,
                AuthEvent.status == "failure",
                AuthEvent.timestamp >= start,
                sequence_boundary,
            )
        )
    )
    account_sources = {item.source_ip for item in account_failures}
    if len(account_sources) >= 2:
        _record_alert(
            db,
            source_ip=event.source_ip,
            detection_key="multiple_source_ips_account",
            title="Account targeted from multiple source IPs",
            severity="high",
            reason=(
                f"Failed logins for this username were observed from {len(account_sources)} "
                f"source IPs within {settings.window_minutes} minutes."
            ),
            event_ids=[item.id for item in account_failures],
        )
    if event.status == "success":
        prior_failures = [
            item for item in failures if item.id != event.id and item.username == event.username
        ]
        if len(prior_failures) >= settings.success_after_failure_threshold:
            _record_alert(
                db,
                source_ip=event.source_ip,
                detection_key="success_after_failures",
                title="Successful login after repeated failures",
                severity="high",
                reason=f"A successful login followed {len(prior_failures)} failures from the same IP within {settings.window_minutes} minutes.",
                event_ids=ids,
                attack_technique="T1110",
            )

        earlier_event = or_(
            AuthEvent.timestamp < event.timestamp,
            and_(AuthEvent.timestamp == event.timestamp, AuthEvent.id < event.id),
        )
        distributed_failures = list(
            db.scalars(
                select(AuthEvent).where(
                    AuthEvent.username == event.username,
                    AuthEvent.status == "failure",
                    AuthEvent.timestamp >= start,
                    earlier_event,
                )
            )
        )
        failure_sources = {item.source_ip for item in distributed_failures}
        if (
            len(distributed_failures) >= settings.distributed_failure_threshold
            and len(failure_sources) >= settings.distributed_source_ip_threshold
        ):
            _record_alert(
                db,
                source_ip=event.source_ip,
                detection_key="distributed_failures_then_success",
                title="Successful login after distributed failures",
                severity=(
                    "critical"
                    if len(distributed_failures) >= settings.distributed_failure_threshold * 2
                    and len(failure_sources) >= settings.distributed_source_ip_threshold + 1
                    else "high"
                ),
                reason=(
                    f"A successful login for {event.username} followed {len(distributed_failures)} "
                    f"failed attempts from {len(failure_sources)} distinct IPs within "
                    f"{settings.window_minutes} minutes (configured thresholds: "
                    f"{settings.distributed_failure_threshold} failures, "
                    f"{settings.distributed_source_ip_threshold} IPs)."
                ),
                event_ids=sorted([event.id, *(item.id for item in distributed_failures)]),
                attack_technique="T1110",
            )

    if event.status != "failure":
        return
    from app.services.detection_rules import matching_group_for_event

    rules = list(db.scalars(select(DetectionRule).where(DetectionRule.enabled.is_(True))))
    aggregation_labels = {
        "failed_per_source_ip": "failed attempts from one source IP",
        "failed_per_username": "failed attempts for one username",
        "distinct_users_per_source_ip": "distinct usernames targeted from one source IP",
        "distinct_ips_per_username": "distinct source IPs targeting one username",
    }
    for rule in rules:
        match = matching_group_for_event(db, rule, event)
        if match is None:
            continue
        _record_alert(
            db,
            source_ip=str(match["source_ip"]),
            detection_key=f"custom_rule_{rule.id}_v{rule.current_version}",
            title=f"{rule.name} v{rule.current_version}"[:160],
            severity=rule.severity,
            reason=(
                f"Observed {match['observed_value']} {aggregation_labels[rule.aggregation]} "
                f"within {rule.window_minutes} minutes; configured threshold: {rule.threshold}."
            ),
            event_ids=[int(event_id) for event_id in match["event_ids"]],
        )
