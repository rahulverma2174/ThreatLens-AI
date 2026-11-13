import csv
from pathlib import Path

from sqlalchemy import select

from app.database import initialize_schema
from app.main import SessionFactory, engine
from app.models import AuthEvent
from app.schemas import AuthEventCreate
from app.services.detection import evaluate_event


def main() -> None:
    project_root = Path(__file__).resolve().parents[2]
    csv_path = project_root / "dataset" / "sample_auth_events.csv"
    initialize_schema(engine)
    imported = 0
    with csv_path.open(newline="", encoding="utf-8-sig") as source, SessionFactory.begin() as db:
        for row in csv.DictReader(source):
            payload = AuthEventCreate.model_validate(row)
            existing = db.scalar(
                select(AuthEvent.id).where(
                    AuthEvent.timestamp == payload.timestamp,
                    AuthEvent.username == payload.username,
                    AuthEvent.source_ip == str(payload.source_ip),
                    AuthEvent.status == payload.status,
                )
            )
            if existing is not None:
                continue
            event = AuthEvent(
                timestamp=payload.timestamp,
                source_label="Synthetic demo dataset",
                username=payload.username,
                source_ip=str(payload.source_ip),
                event_type=payload.event_type,
                status=payload.status,
                user_agent=payload.user_agent,
            )
            db.add(event)
            db.flush()
            evaluate_event(db, event)
            imported += 1
    print(f"Seeded {imported} synthetic events from {csv_path.name}.")


if __name__ == "__main__":
    main()
