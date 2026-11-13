from bisect import bisect_left, bisect_right
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AuthEvent, DetectionException, utc_now

MAX_REPLAY_EVENTS = 5_000
RULES = {
    "repeated_failures": "Repeated login failures",
    "brute_force": "Possible brute-force activity",
    "login_burst": "Unusual login burst",
    "multiple_usernames": "Multiple usernames targeted",
    "multiple_source_ips_account": "Account targeted from multiple source IPs",
    "success_after_failures": "Successful login after repeated failures",
    "distributed_failures_then_success": "Successful login after distributed failures",
}


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _evaluate_candidates(
    events: list[AuthEvent],
    settings: dict[str, int | bool],
    exceptions: list[DetectionException],
    now: datetime,
) -> dict[str, object]:
    candidates: dict[tuple[str, str], dict[str, object]] = {}
    suppressed: set[tuple[str, str]] = set()
    by_ip: dict[str, list[AuthEvent]] = defaultdict(list)
    by_username: dict[str, list[AuthEvent]] = defaultdict(list)
    for event in events:
        by_ip[event.source_ip].append(event)
        by_username[event.username].append(event)

    timeline_keys = {
        (dimension, group_key): [(_as_utc(item.timestamp), item.id) for item in group]
        for dimension, groups in (("ip", by_ip), ("username", by_username))
        for group_key, group in groups.items()
    }

    def window(dimension: str, group_key: str, groups: dict[str, list[AuthEvent]], at: datetime, event_id: int, minutes: int) -> list[AuthEvent]:
        items = groups.get(group_key, [])
        if not items:
            return []
        keys = timeline_keys[(dimension, group_key)]
        start = bisect_left(keys, (at - timedelta(minutes=minutes), -1))
        end = bisect_right(keys, (at, event_id))
        return items[start:end]

    def record_candidate(
        detection_key: str,
        source_ip: str,
        event_ids: list[int],
        usernames: set[str],
    ) -> None:
        identity = (detection_key, source_ip)
        exception_matches = any(
            _as_utc(exception.expires_at) > now
            and exception.detection_key in (None, detection_key)
            and (
                exception.source_ip == source_ip
                or (exception.username is not None and exception.username in usernames)
            )
            for exception in exceptions
        )
        if exception_matches:
            suppressed.add(identity)
            return
        candidate = candidates.setdefault(identity, {"event_ids": set(), "source_ip": source_ip})
        candidate["event_ids"].update(event_ids)

    if not settings["monitoring_enabled"]:
        return {"rules": [], "total_candidates": 0, "total_suppressed": 0}

    window_minutes = int(settings["window_minutes"])
    repeated_threshold = int(settings["repeated_failure_threshold"])
    brute_force_threshold = int(settings["brute_force_threshold"])
    targeted_threshold = int(settings["targeted_username_threshold"])
    success_threshold = int(settings["success_after_failure_threshold"])
    distributed_threshold = int(settings["distributed_failure_threshold"])
    distributed_ip_threshold = int(settings["distributed_source_ip_threshold"])

    for event in events:
        at = _as_utc(event.timestamp)
        recent = window("ip", event.source_ip, by_ip, at, event.id, window_minutes)
        failures = [item for item in recent if item.status == "failure"]
        recent_usernames = {item.username for item in recent}
        failure_usernames = {item.username for item in failures}
        failed_ids = [item.id for item in failures]
        recent_ids = [item.id for item in recent]

        if len(failures) >= repeated_threshold:
            record_candidate("repeated_failures", event.source_ip, failed_ids, failure_usernames)
        if len(failures) >= brute_force_threshold:
            record_candidate("brute_force", event.source_ip, failed_ids, failure_usernames)
        if len(recent) >= brute_force_threshold * 2:
            record_candidate("login_burst", event.source_ip, recent_ids, recent_usernames)
        if len(failure_usernames) >= targeted_threshold:
            record_candidate("multiple_usernames", event.source_ip, recent_ids, recent_usernames)

        account_events = window("username", event.username, by_username, at, event.id, window_minutes)
        account_failures = [item for item in account_events if item.status == "failure"]
        account_sources = {item.source_ip for item in account_failures}
        account_usernames = {event.username}
        if len(account_sources) >= 2:
            record_candidate(
                "multiple_source_ips_account",
                event.source_ip,
                [item.id for item in account_failures],
                account_usernames,
            )

        if event.status != "success":
            continue
        same_ip_user_failures = [item for item in failures if item.username == event.username]
        if len(same_ip_user_failures) >= success_threshold:
            record_candidate("success_after_failures", event.source_ip, recent_ids, recent_usernames)
        if (
            len(account_failures) >= distributed_threshold
            and len(account_sources) >= distributed_ip_threshold
        ):
            record_candidate(
                "distributed_failures_then_success",
                event.source_ip,
                [event.id, *(item.id for item in account_failures)],
                account_usernames,
            )

    rule_counts: dict[str, dict[str, object]] = {}
    for (detection_key, source_ip), candidate in candidates.items():
        entry = rule_counts.setdefault(detection_key, {"detection_key": detection_key, "candidate_count": 0, "suppressed_count": 0, "sample_source_ips": [], "sample_event_ids": set()})
        entry["candidate_count"] += 1
        entry["sample_event_ids"].update(candidate["event_ids"])
        if len(entry["sample_source_ips"]) < 8:
            entry["sample_source_ips"].append(source_ip)
    for detection_key, source_ip in suppressed:
        entry = rule_counts.setdefault(detection_key, {"detection_key": detection_key, "candidate_count": 0, "suppressed_count": 0, "sample_source_ips": [], "sample_event_ids": set()})
        entry["suppressed_count"] += 1
        if len(entry["sample_source_ips"]) < 8 and source_ip not in entry["sample_source_ips"]:
            entry["sample_source_ips"].append(source_ip)

    rules = []
    for detection_key, entry in sorted(rule_counts.items()):
        rules.append({
            **entry,
            "title": RULES[detection_key],
            "sample_source_ips": sorted(entry["sample_source_ips"]),
            "sample_event_ids": sorted(entry["sample_event_ids"])[:20],
        })
    return {
        "rules": rules,
        "total_candidates": sum(int(rule["candidate_count"]) for rule in rules),
        "total_suppressed": sum(int(rule["suppressed_count"]) for rule in rules),
    }


def preview_detection_settings(
    db: Session,
    *,
    window_hours: int,
    current_settings: dict[str, int | bool],
    proposed_settings: dict[str, int | bool],
) -> dict[str, object]:
    now = utc_now()
    recent_desc = list(
        db.scalars(
            select(AuthEvent)
            .where(
                AuthEvent.timestamp >= now - timedelta(hours=window_hours),
                AuthEvent.timestamp <= now,
            )
            .order_by(AuthEvent.timestamp.desc(), AuthEvent.id.desc())
            .limit(MAX_REPLAY_EVENTS + 1)
        )
    )
    truncated = len(recent_desc) > MAX_REPLAY_EVENTS
    events = sorted(recent_desc[:MAX_REPLAY_EVENTS], key=lambda item: (_as_utc(item.timestamp), item.id))
    exceptions = list(
        db.scalars(select(DetectionException).where(DetectionException.expires_at > now))
    )
    return {
        "events_analyzed": len(events),
        "truncated": truncated,
        "window_hours": window_hours,
        "current": _evaluate_candidates(events, current_settings, exceptions, now),
        "proposed": _evaluate_candidates(events, proposed_settings, exceptions, now),
        "notice": (
            "Read-only simulation over stored events. It groups candidate signals by rule and source IP. "
            "Currently active exceptions are applied to the whole sample, so this estimates today's "
            "exception policy rather than reconstructing past decisions. Counts are not incident or accuracy metrics."
            + (f" The event sample was capped at {MAX_REPLAY_EVENTS} records." if truncated else "")
        ),
    }
