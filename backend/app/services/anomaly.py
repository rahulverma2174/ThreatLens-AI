import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AuthEvent


def score_events(db: Session, requested_ids: list[int] | None) -> list[dict[str, object]]:
    all_events = list(
        db.scalars(select(AuthEvent).order_by(AuthEvent.timestamp.desc()).limit(500))
    )
    if len(all_events) < 10:
        raise ValueError("At least 10 stored authentication events are required for anomaly scoring.")

    selected_ids = set(requested_ids) if requested_ids is not None else {event.id for event in all_events}
    events = [event for event in all_events if event.id in selected_ids]
    if requested_ids is not None and len(events) != len(selected_ids):
        raise LookupError("One or more requested event IDs do not exist in the scoring window.")
    if not events:
        return []

    frame = pd.DataFrame(
        [
            {
                "event_id": event.id,
                "source_ip": event.source_ip,
                "username": event.username,
                "is_failure": float(event.status == "failure"),
                "hour": float(event.timestamp.hour),
            }
            for event in all_events
        ]
    )
    ip_counts = frame.groupby("source_ip").size().to_dict()
    failed_counts = (
        frame.loc[frame["is_failure"] == 1.0]
        .groupby("source_ip")
        .size()
        .to_dict()
    )
    username_counts = frame.groupby("username").size().to_dict()
    frame["ip_event_count"] = frame["source_ip"].map(ip_counts)
    frame["ip_failure_count"] = frame["source_ip"].map(failed_counts).fillna(0)
    frame["username_event_count"] = frame["username"].map(username_counts)
    feature_columns = [
        "is_failure",
        "ip_event_count",
        "ip_failure_count",
        "username_event_count",
        "hour",
    ]
    matrix = frame[feature_columns].to_numpy(dtype=np.float64)
    model = IsolationForest(
        n_estimators=100,
        contamination="auto",
        random_state=42,
        n_jobs=1,
    )
    model.fit(matrix)
    row_indexes = {event_id: index for index, event_id in enumerate(frame["event_id"])}
    selected_indexes = [row_indexes[event.id] for event in events]
    selected_matrix = matrix[selected_indexes]
    labels = model.predict(selected_matrix)
    raw_scores = model.decision_function(selected_matrix)

    results: list[dict[str, object]] = []
    for event, label, raw_score in zip(events, labels, raw_scores, strict=True):
        reasons: list[str] = []
        if failed_counts.get(event.source_ip, 0) >= 3:
            reasons.append(
                f"source IP has {failed_counts[event.source_ip]} failed events in the scoring sample"
            )
        if ip_counts[event.source_ip] >= 5:
            reasons.append(f"source IP appears {ip_counts[event.source_ip]} times in the scoring sample")
        if username_counts[event.username] >= 5:
            reasons.append(
                f"username appears {username_counts[event.username]} times in the scoring sample"
            )
        if not reasons:
            reasons.append("the event's feature combination differs from the learned sample baseline")
        results.append(
            {
                "event": event,
                "anomaly_score": round(float(-raw_score), 6),
                "classification": "suspicious" if label == -1 else "normal",
                "explanation": "; ".join(reasons),
            }
        )
    return results
