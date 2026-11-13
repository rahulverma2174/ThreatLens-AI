from sqlalchemy import Engine, create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


class Base(DeclarativeBase):
    pass


def build_engine(database_url: str) -> Engine:
    connect_args = {"check_same_thread": False, "timeout": 30} if database_url.startswith("sqlite") else {}
    return create_engine(database_url, connect_args=connect_args)


def build_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def initialize_schema(engine: Engine) -> None:
    Base.metadata.create_all(bind=engine)
    if engine.dialect.name == "sqlite":
        with engine.begin() as connection:
            connection.execute(text("""
                CREATE TRIGGER IF NOT EXISTS detection_rule_versions_no_update
                BEFORE UPDATE ON detection_rule_versions
                BEGIN SELECT RAISE(ABORT, 'detection rule versions are append-only'); END
            """))
            connection.execute(text("""
                CREATE TRIGGER IF NOT EXISTS detection_rule_versions_no_delete
                BEFORE DELETE ON detection_rule_versions
                BEGIN SELECT RAISE(ABORT, 'detection rule versions are append-only'); END
            """))
            connection.execute(text("""
                CREATE TRIGGER IF NOT EXISTS threat_indicator_reviews_no_update
                BEFORE UPDATE ON threat_indicator_reviews
                BEGIN SELECT RAISE(ABORT, 'threat indicator reviews are append-only'); END
            """))
            connection.execute(text("""
                CREATE TRIGGER IF NOT EXISTS threat_indicator_reviews_no_delete
                BEFORE DELETE ON threat_indicator_reviews
                BEGIN SELECT RAISE(ABORT, 'threat indicator reviews are append-only'); END
            """))
    if "alert_count" not in {
        column["name"] for column in inspect(engine).get_columns("incidents")
    }:
        with engine.begin() as connection:
            connection.execute(
                text("ALTER TABLE incidents ADD COLUMN alert_count INTEGER NOT NULL DEFAULT 0")
            )
    if "analyst_notes" not in {column["name"] for column in inspect(engine).get_columns("alerts")}:
        with engine.begin() as connection:
            connection.execute(text("ALTER TABLE alerts ADD COLUMN analyst_notes TEXT NOT NULL DEFAULT ''"))
    indicator_columns = {column["name"] for column in inspect(engine).get_columns("local_indicators")}
    with engine.begin() as connection:
        if "indicator_type" not in indicator_columns:
            connection.execute(text("ALTER TABLE local_indicators ADD COLUMN indicator_type VARCHAR(16) NOT NULL DEFAULT 'ip'"))
        if "confidence" not in indicator_columns:
            connection.execute(text("ALTER TABLE local_indicators ADD COLUMN confidence INTEGER NOT NULL DEFAULT 50"))
        if "source" not in indicator_columns:
            connection.execute(text("ALTER TABLE local_indicators ADD COLUMN source VARCHAR(160) NOT NULL DEFAULT 'Legacy local indicator'"))
        if "expires_at" not in indicator_columns:
            connection.execute(text("ALTER TABLE local_indicators ADD COLUMN expires_at DATETIME"))
    if "attack_technique" not in {column["name"] for column in inspect(engine).get_columns("alerts")}:
        with engine.begin() as connection:
            connection.execute(text("ALTER TABLE alerts ADD COLUMN attack_technique VARCHAR(32)"))
    alert_columns = {column["name"] for column in inspect(engine).get_columns("alerts")}
    with engine.begin() as connection:
        if "assignee" not in alert_columns:
            connection.execute(text("ALTER TABLE alerts ADD COLUMN assignee VARCHAR(128)"))
        if "disposition" not in alert_columns:
            connection.execute(text("ALTER TABLE alerts ADD COLUMN disposition VARCHAR(32)"))
        if "disposition_notes" not in alert_columns:
            connection.execute(text("ALTER TABLE alerts ADD COLUMN disposition_notes TEXT NOT NULL DEFAULT ''"))
        if "disposition_updated_at" not in alert_columns:
            connection.execute(text("ALTER TABLE alerts ADD COLUMN disposition_updated_at DATETIME"))
    with engine.begin() as connection:
        connection.execute(text("""
            UPDATE alerts
            SET attack_technique = CASE detection_key
                WHEN 'multiple_usernames' THEN 'T1110'
                WHEN 'repeated_failures' THEN 'T1110'
                WHEN 'brute_force' THEN 'T1110'
                WHEN 'success_after_failures' THEN 'T1110'
                ELSE attack_technique
            END
            WHERE attack_technique IS NULL
        """))
        connection.execute(text("UPDATE alerts SET attack_technique = 'T1110' WHERE detection_key = 'multiple_usernames' AND attack_technique = 'T1110.003'"))
    if "monitoring_enabled" not in {column["name"] for column in inspect(engine).get_columns("detection_settings")}:
        with engine.begin() as connection:
            connection.execute(
                text("ALTER TABLE detection_settings ADD COLUMN monitoring_enabled BOOLEAN NOT NULL DEFAULT 1")
            )
    detection_setting_columns = {column["name"] for column in inspect(engine).get_columns("detection_settings")}
    with engine.begin() as connection:
        if "distributed_failure_threshold" not in detection_setting_columns:
            connection.execute(text("ALTER TABLE detection_settings ADD COLUMN distributed_failure_threshold INTEGER NOT NULL DEFAULT 3"))
        if "distributed_source_ip_threshold" not in detection_setting_columns:
            connection.execute(text("ALTER TABLE detection_settings ADD COLUMN distributed_source_ip_threshold INTEGER NOT NULL DEFAULT 2"))
    incident_columns = {column["name"] for column in inspect(engine).get_columns("incidents")}
    with engine.begin() as connection:
        if "assignee" not in incident_columns:
            connection.execute(text("ALTER TABLE incidents ADD COLUMN assignee VARCHAR(128)"))
        if "tasks" not in incident_columns:
            connection.execute(text("ALTER TABLE incidents ADD COLUMN tasks JSON NOT NULL DEFAULT '[]'"))
    event_columns = {column["name"] for column in inspect(engine).get_columns("auth_events")}
    with engine.begin() as connection:
        if "source_label" not in event_columns:
            connection.execute(text("ALTER TABLE auth_events ADD COLUMN source_label VARCHAR(80) NOT NULL DEFAULT 'Legacy import'"))
        if "ingested_at" not in event_columns:
            connection.execute(text("ALTER TABLE auth_events ADD COLUMN ingested_at DATETIME"))
        if "source_host" not in event_columns:
            connection.execute(text("ALTER TABLE auth_events ADD COLUMN source_host VARCHAR(255)"))
        if "source_event_id" not in event_columns:
            connection.execute(text("ALTER TABLE auth_events ADD COLUMN source_event_id VARCHAR(512)"))
        if "ingestion_source_id" not in event_columns:
            connection.execute(text("ALTER TABLE auth_events ADD COLUMN ingestion_source_id INTEGER REFERENCES ingestion_sources(id)"))
        if "event_metadata" not in event_columns:
            connection.execute(text("ALTER TABLE auth_events ADD COLUMN event_metadata JSON NOT NULL DEFAULT '{}'"))
        if "import_run_id" not in event_columns:
            connection.execute(text("ALTER TABLE auth_events ADD COLUMN import_run_id INTEGER REFERENCES ingestion_runs(id)"))
        connection.execute(text("CREATE INDEX IF NOT EXISTS ix_auth_events_ingestion_source_id ON auth_events (ingestion_source_id)"))
        connection.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS uq_auth_events_ingestion_source_event ON auth_events (ingestion_source_id, source_event_id)"))
        connection.execute(text("CREATE INDEX IF NOT EXISTS ix_auth_events_import_run_id ON auth_events (import_run_id)"))
    source_columns = {column["name"] for column in inspect(engine).get_columns("ingestion_sources")}
    if "last_event_at" not in source_columns:
        with engine.begin() as connection:
            connection.execute(text("ALTER TABLE ingestion_sources ADD COLUMN last_event_at DATETIME"))
    from app.services.audit_integrity import ensure_audit_chain

    ensure_audit_chain(engine)
