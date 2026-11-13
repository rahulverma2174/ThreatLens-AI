import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from app.database import initialize_schema
from app.models import DetectionRule, DetectionRuleVersion


def test_sqlite_rule_version_rows_are_append_only() -> None:
    engine = create_engine("sqlite://")
    initialize_schema(engine)
    with Session(engine) as db:
        rule = DetectionRule(
            name="Append only test",
            description="",
            aggregation="failed_per_source_ip",
            threshold=3,
            window_minutes=10,
            severity="medium",
            enabled=True,
            current_version=1,
        )
        db.add(rule)
        db.flush()
        version = DetectionRuleVersion(
            rule_id=rule.id,
            version=1,
            configuration={"threshold": 3},
            change_note="initial",
        )
        db.add(version)
        db.commit()
        version_id = version.id

    with pytest.raises(DBAPIError, match="append-only"):
        with engine.begin() as connection:
            connection.execute(
                text("UPDATE detection_rule_versions SET change_note = 'tampered' WHERE id = :id"),
                {"id": version_id},
            )
    with pytest.raises(DBAPIError, match="append-only"):
        with engine.begin() as connection:
            connection.execute(
                text("DELETE FROM detection_rule_versions WHERE id = :id"),
                {"id": version_id},
            )
    engine.dispose()
