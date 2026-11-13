from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from app.models import AuthEvent, DetectionRule, utc_now

MAX_RULE_EVENTS = 5_000
MAX_RULE_EVIDENCE = 200


def rule_configuration(rule: DetectionRule) -> dict[str, object]:
    return {
        "name": rule.name,
        "description": rule.description,
        "aggregation": rule.aggregation,
        "threshold": rule.threshold,
        "window_minutes": rule.window_minutes,
        "severity": rule.severity,
        "enabled": rule.enabled,
    }


def _group_key(rule: DetectionRule | dict[str, object], event: AuthEvent) -> str:
    aggregation = rule.aggregation if isinstance(rule, DetectionRule) else rule["aggregation"]
    if aggregation in {"failed_per_source_ip", "distinct_users_per_source_ip"}:
        return f"ip:{event.source_ip}"
    return f"username:{event.username}"


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _build_groups(rule: DetectionRule | dict[str, object], events: list[AuthEvent]) -> list[dict[str, object]]:
    aggregation = rule.aggregation if isinstance(rule, DetectionRule) else str(rule["aggregation"])
    threshold = rule.threshold if isinstance(rule, DetectionRule) else int(rule["threshold"])
    window_minutes = rule.window_minutes if isinstance(rule, DetectionRule) else int(rule["window_minutes"])
    grouped: dict[str, list[AuthEvent]] = defaultdict(list)
    for event in events:
        grouped[_group_key(rule, event)].append(event)

    matches: list[dict[str, object]] = []
    for key, group in grouped.items():
        ordered = sorted(group, key=lambda row: (_utc(row.timestamp), row.id))
        left = 0
        username_counts: Counter[str] = Counter()
        source_counts: Counter[str] = Counter()
        latest_match: tuple[int, int, int] | None = None
        for right, current in enumerate(ordered):
            cutoff = _utc(current.timestamp) - timedelta(minutes=window_minutes)
            while left <= right and _utc(ordered[left].timestamp) < cutoff:
                username_counts[ordered[left].username] -= 1
                source_counts[ordered[left].source_ip] -= 1
                if username_counts[ordered[left].username] == 0:
                    del username_counts[ordered[left].username]
                if source_counts[ordered[left].source_ip] == 0:
                    del source_counts[ordered[left].source_ip]
                left += 1
            username_counts[current.username] += 1
            source_counts[current.source_ip] += 1
            if aggregation == "distinct_users_per_source_ip":
                observed = len(username_counts)
            elif aggregation == "distinct_ips_per_username":
                observed = len(source_counts)
            else:
                observed = right - left + 1
            if observed < threshold:
                continue
            latest_match = (left, right, observed)
        if latest_match is not None:
            match_left, match_right, observed = latest_match
            window_events = ordered[match_left:match_right + 1]
            matches.append({
                "match_key": key,
                "observed_value": observed,
                "source_ip": window_events[-1].source_ip,
                "usernames": sorted({row.username for row in window_events})[:50],
                "event_ids": [row.id for row in window_events[-MAX_RULE_EVIDENCE:]],
            })
    return sorted(matches, key=lambda row: str(row["match_key"]))


def matching_group_for_event(db: Session, rule: DetectionRule, event: AuthEvent) -> dict[str, object] | None:
    start = event.timestamp - timedelta(minutes=rule.window_minutes)
    sequence_boundary = or_(
        AuthEvent.timestamp < event.timestamp,
        and_(AuthEvent.timestamp == event.timestamp, AuthEvent.id <= event.id),
    )
    query = select(AuthEvent).where(
        AuthEvent.status == "failure",
        AuthEvent.timestamp >= start,
        sequence_boundary,
    )
    if rule.aggregation in {"failed_per_source_ip", "distinct_users_per_source_ip"}:
        query = query.where(AuthEvent.source_ip == event.source_ip)
    else:
        query = query.where(AuthEvent.username == event.username)
    events = list(db.scalars(query.order_by(AuthEvent.timestamp.desc(), AuthEvent.id.desc()).limit(MAX_RULE_EVENTS)))
    group = next((item for item in _build_groups(rule, events) if item["match_key"] == _group_key(rule, event)), None)
    return group


def preview_rule(db: Session, configuration: dict[str, object], window_hours: int) -> dict[str, object]:
    start = utc_now() - timedelta(hours=window_hours)
    events = list(db.scalars(
        select(AuthEvent)
        .where(AuthEvent.status == "failure", AuthEvent.timestamp >= start)
        .order_by(AuthEvent.timestamp.desc(), AuthEvent.id.desc())
        .limit(MAX_RULE_EVENTS + 1)
    ))
    truncated = len(events) > MAX_RULE_EVENTS
    events = events[:MAX_RULE_EVENTS]
    matches = _build_groups(configuration, events)
    return {
        "events_analyzed": len(events),
        "truncated": truncated,
        "candidate_count": len(matches),
        "matched_groups": matches[:100],
        "notice": (
            "Read-only preview over stored failed authentication events. It creates no alerts and is "
            "not a prediction of future activity. The sample is capped at 5,000 events."
        ),
    }
