from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.models import Alert, AuthEvent, Incident, IncidentAlert, utc_now


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def correlate_alerts(db: Session, window_minutes: int = 60) -> list[Incident]:
    alerts = list(db.scalars(select(Alert).order_by(Alert.created_at, Alert.id)))
    if not alerts:
        return []

    all_event_ids = {event_id for alert in alerts for event_id in alert.related_event_ids}
    events = (
        list(db.scalars(select(AuthEvent).where(AuthEvent.id.in_(all_event_ids))))
        if all_event_ids
        else []
    )
    events_by_id = {event.id: event for event in events}
    profiles: dict[int, tuple[set[str], datetime, datetime, set[int]]] = {}
    for alert in alerts:
        related = [events_by_id[event_id] for event_id in alert.related_event_ids if event_id in events_by_id]
        usernames = {event.username for event in related}
        times = [_as_utc(event.timestamp) for event in related] or [_as_utc(alert.created_at)]
        profiles[alert.id] = (usernames, min(times), max(times), {event.id for event in related})

    parent = list(range(len(alerts)))

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(first: int, second: int) -> None:
        first_root = find(first)
        second_root = find(second)
        if first_root != second_root:
            parent[second_root] = first_root

    max_gap = timedelta(minutes=window_minutes)
    for left_index, left in enumerate(alerts):
        left_users, left_start, left_end, _ = profiles[left.id]
        for right_index in range(left_index + 1, len(alerts)):
            right = alerts[right_index]
            right_users, right_start, right_end, _ = profiles[right.id]
            if left.source_ip != right.source_ip and not left_users.intersection(right_users):
                continue
            gap = max(left_start - right_end, right_start - left_end, timedelta())
            if gap <= max_gap:
                union(left_index, right_index)

    clusters: dict[int, list[Alert]] = {}
    for index, alert in enumerate(alerts):
        clusters.setdefault(find(index), []).append(alert)

    existing_links = list(db.scalars(select(IncidentAlert)))
    links_by_alert: dict[int, set[int]] = {}
    for link in existing_links:
        links_by_alert.setdefault(link.alert_id, set()).add(link.incident_id)
    incidents_by_id = {
        incident.id: incident
        for incident in db.scalars(select(Incident))
    }

    db.execute(delete(IncidentAlert))
    severity_rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    results: list[Incident] = []
    new_links: list[IncidentAlert] = []
    for cluster in clusters.values():
        cluster_alert_ids = {alert.id for alert in cluster}
        candidate_ids = {
            incident_id
            for alert_id in cluster_alert_ids
            for incident_id in links_by_alert.get(alert_id, set())
        }
        candidates = [
            incidents_by_id[incident_id]
            for incident_id in candidate_ids
            if incident_id in incidents_by_id and incidents_by_id[incident_id].status != "merged"
        ]
        candidates.sort(
            key=lambda incident: (
                incident.status != "investigating",
                incident.status == "resolved",
                incident.id,
            )
        )
        incident = candidates[0] if candidates else Incident(
            title="",
            severity="low",
            summary="",
            first_seen=utc_now(),
            last_seen=utc_now(),
        )
        if incident.id is None:
            db.add(incident)
            db.flush()
        for duplicate in candidates[1:]:
            duplicate.status = "merged"
            duplicate.merged_into_id = incident.id
            duplicate.updated_at = utc_now()

        cluster_events = {
            event_id
            for alert in cluster
            for event_id in profiles[alert.id][3]
        }
        observed_events = [events_by_id[event_id] for event_id in cluster_events]
        usernames = sorted({event.username for event in observed_events})
        source_ips = sorted(
            {alert.source_ip for alert in cluster}
            | {event.source_ip for event in observed_events}
        )
        observed_times = [_as_utc(event.timestamp) for event in observed_events]
        if not observed_times:
            observed_times = [_as_utc(alert.created_at) for alert in cluster]
        active_alerts = [alert for alert in cluster if alert.status != "resolved"]
        if incident.status == "open" and not active_alerts:
            incident.status = "resolved"

        incident.title = (
            cluster[0].title if len(cluster) == 1 else "Correlated authentication activity"
        )
        incident.severity = max(cluster, key=lambda alert: severity_rank[alert.severity]).severity
        incident.summary = (
            f"{len(cluster)} local rule signal(s) correlate across "
            f"{len(source_ips)} source IP(s) and {len(usernames)} username(s) "
            f"within a {window_minutes}-minute window."
        )
        incident.source_ips = source_ips
        incident.usernames = usernames
        incident.alert_count = len(cluster)
        incident.related_event_ids = sorted(cluster_events)
        incident.first_seen = min(observed_times)
        incident.last_seen = max(observed_times)
        incident.updated_at = utc_now()
        incident.merged_into_id = None
        results.append(incident)
        new_links.extend(
            IncidentAlert(incident_id=incident.id, alert_id=alert.id)
            for alert in cluster
        )

    db.add_all(new_links)
    db.flush()
    return results
