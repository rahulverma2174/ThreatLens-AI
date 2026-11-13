from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AuthEvent

PROFILE_LIMIT = 5000


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def load_behavior_events(db: Session, hours: int, limit: int = PROFILE_LIMIT) -> list[AuthEvent]:
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    return list(
        db.scalars(
            select(AuthEvent)
            .where(AuthEvent.timestamp >= cutoff)
            .order_by(AuthEvent.timestamp.desc(), AuthEvent.id.desc())
            .limit(limit)
        )
    )


def build_profiles(events: list[AuthEvent], *, entity_field: str) -> list[dict[str, object]]:
    grouped: dict[str, list[AuthEvent]] = defaultdict(list)
    for event in events:
        key = event.username if entity_field == "username" else event.source_ip
        grouped[key].append(event)

    profiles: list[dict[str, object]] = []
    for entity, records in grouped.items():
        failures = sum(event.status == "failure" for event in records)
        hours = Counter(_as_utc(event.timestamp).hour for event in records)
        observed_hours = [
            hour
            for hour, count in hours.items()
            if count / len(records) >= 0.1
        ]
        unusual = sum(
            1
            for event in records
            if len(records) >= 5 and hours[_as_utc(event.timestamp).hour] / len(records) < 0.1
        )
        profiles.append(
            {
                "entity": entity,
                "event_count": len(records),
                "failures": failures,
                "failure_rate": round(failures / len(records), 4),
                "distinct_usernames": len({event.username for event in records}),
                "distinct_source_ips": len({event.source_ip for event in records}),
                "common_login_hours_utc": sorted(observed_hours),
                "unusual_hour_events": unusual,
            }
        )
    return sorted(profiles, key=lambda profile: (-int(profile["failures"]), -int(profile["event_count"]), str(profile["entity"])))
