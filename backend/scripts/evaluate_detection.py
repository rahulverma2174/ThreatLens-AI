import csv
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.database import Base
from app.models import Alert, AuthEvent
from app.services.anomaly import score_events
from app.services.detection import evaluate_event

DATASET_PATH = Path(__file__).resolve().parents[2] / "dataset" / "evaluation_auth_events.csv"


def build_dataset() -> list[dict[str, str]]:
    start = datetime(2025, 1, 1, tzinfo=timezone.utc)
    rows: list[dict[str, str]] = []

    def add(
        at: datetime,
        username: str,
        source_ip: str,
        outcome: str,
        label: str,
        scenario: str,
    ) -> None:
        rows.append(
            {
                "timestamp": at.isoformat(),
                "username": username,
                "source_ip": source_ip,
                "event_type": "login",
                "status": outcome,
                "ground_truth": label,
                "scenario": scenario,
            }
        )

    for index in range(20):
        source_group = index % 4
        outcome = "failure" if index % 5 == 0 else "success"
        add(
            start + timedelta(hours=index),
            f"demo-user-{index:02d}",
            f"192.0.2.{10 + source_group}",
            outcome,
            "normal",
            "routine-spread-out",
        )

    brute_start = start + timedelta(days=1)
    for index in range(5):
        add(brute_start + timedelta(seconds=index * 30), "admin-demo", "198.51.100.200", "failure", "attack", "brute-force")

    spray_start = brute_start + timedelta(minutes=20)
    for index, username in enumerate(("alice-demo", "bob-demo", "carol-demo", "dave-demo")):
        add(spray_start + timedelta(seconds=index * 20), username, "198.51.100.201", "failure", "attack", "password-spraying-indicator")

    sequence_start = spray_start + timedelta(minutes=20)
    for index, outcome in enumerate(("failure", "failure", "failure", "success")):
        add(sequence_start + timedelta(seconds=index * 25), "service-demo", "198.51.100.202", outcome, "attack", "success-after-failures")

    cross_ip_start = sequence_start + timedelta(minutes=20)
    for index, source_ip in enumerate(("203.0.113.201", "203.0.113.202")):
        add(cross_ip_start + timedelta(seconds=index * 25), "shared-demo", source_ip, "failure", "attack", "account-multiple-source-ips")
    return rows


def write_dataset(path: Path = DATASET_PATH) -> list[dict[str, str]]:
    rows = build_dataset()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    return rows


def calculate_metrics(labels: list[bool], predictions: list[bool]) -> dict[str, float | int]:
    tp = sum(actual and predicted for actual, predicted in zip(labels, predictions, strict=True))
    fp = sum(not actual and predicted for actual, predicted in zip(labels, predictions, strict=True))
    tn = sum(not actual and not predicted for actual, predicted in zip(labels, predictions, strict=True))
    fn = sum(actual and not predicted for actual, predicted in zip(labels, predictions, strict=True))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    false_positive_rate = fp / (fp + tn) if fp + tn else 0.0
    return {
        "true_positive": tp,
        "false_positive": fp,
        "true_negative": tn,
        "false_negative": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "false_positive_rate": round(false_positive_rate, 4),
    }


def evaluate() -> dict[str, object]:
    rows = write_dataset()
    engine = create_engine("sqlite://")
    Base.metadata.create_all(bind=engine)
    with Session(engine, autoflush=False, expire_on_commit=False) as db:
        events: list[AuthEvent] = []
        for row in rows:
            event = AuthEvent(
                timestamp=datetime.fromisoformat(row["timestamp"]),
                username=row["username"],
                source_ip=row["source_ip"],
                event_type=row["event_type"],
                status=row["status"],
            )
            db.add(event)
            db.flush()
            evaluate_event(db, event)
            events.append(event)

        db.flush()
        generated_alerts = list(db.query(Alert).all())
        flagged_ids = {
            event_id
            for alert in generated_alerts
            for event_id in alert.related_event_ids
        }
        labels = [row["ground_truth"] == "attack" for row in rows]
        rule_predictions = [event.id in flagged_ids for event in events]
        model_results = score_events(db, None)
        anomaly_ids = {
            item["event"].id
            for item in model_results
            if item["classification"] == "suspicious"
        }
        anomaly_predictions = [event.id in anomaly_ids for event in events]

    engine.dispose()
    return {
        "dataset": str(DATASET_PATH.relative_to(Path(__file__).resolve().parents[2])),
        "events": len(rows),
        "attack_labeled_events": sum(labels),
        "rule_based": calculate_metrics(labels, rule_predictions),
        "rule_false_negative_scenarios": [
            {
                "scenario": rows[index]["scenario"],
                "username": rows[index]["username"],
                "source_ip": rows[index]["source_ip"],
                "status": rows[index]["status"],
                "timestamp": rows[index]["timestamp"],
            }
            for index, (actual, predicted) in enumerate(zip(labels, rule_predictions, strict=True))
            if actual and not predicted
        ],
        "rule_false_positive_scenarios": [
            rows[index]["scenario"]
            for index, (actual, predicted) in enumerate(zip(labels, rule_predictions, strict=True))
            if not actual and predicted
        ],
        "isolation_forest_anomaly_indicator": calculate_metrics(labels, anomaly_predictions),
        "caveat": "Metrics apply only to this controlled synthetic dataset and are not production accuracy claims.",
    }


if __name__ == "__main__":
    print(json.dumps(evaluate(), indent=2))
