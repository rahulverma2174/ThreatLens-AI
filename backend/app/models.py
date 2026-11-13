from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class IngestionRun(Base):
    __tablename__ = "ingestion_runs"
    __table_args__ = (Index("ix_ingestion_runs_created", "created_at"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    source_format: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="processing", nullable=False)
    accepted_records: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    rejected_records: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    error_summary: Mapped[str] = mapped_column(Text, default="", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AuthEvent(Base):
    __tablename__ = "auth_events"
    __table_args__ = (
        CheckConstraint("status IN ('success', 'failure')", name="ck_auth_events_status"),
        Index("ix_auth_events_timestamp", "timestamp"),
        Index("ix_auth_events_source_ip_timestamp", "source_ip", "timestamp"),
        Index("uq_auth_events_ingestion_source_event", "ingestion_source_id", "source_event_id", unique=True),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    ingested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=True)
    source_label: Mapped[str] = mapped_column(String(80), default="API", nullable=False)
    username: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(32), default="login", nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)
    source_host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    source_event_id: Mapped[str | None] = mapped_column(String(512), nullable=True)
    ingestion_source_id: Mapped[int | None] = mapped_column(ForeignKey("ingestion_sources.id"), nullable=True, index=True)
    import_run_id: Mapped[int | None] = mapped_column(ForeignKey("ingestion_runs.id"), nullable=True)
    event_metadata: Mapped[dict[str, object]] = mapped_column(JSON, default=dict, nullable=False)


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (
        CheckConstraint("severity IN ('critical', 'high', 'medium', 'low')", name="ck_alerts_severity"),
        CheckConstraint("status IN ('open', 'investigating', 'resolved')", name="ck_alerts_status"),
        Index("ix_alerts_source_status", "source_ip", "status"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    detection_key: Mapped[str] = mapped_column(String(48), nullable=False, index=True)
    attack_technique: Mapped[str | None] = mapped_column(String(32), nullable=True)
    title: Mapped[str] = mapped_column(String(160), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    reason: Mapped[str] = mapped_column(String(512), nullable=False)
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    related_event_ids: Mapped[list[int]] = mapped_column(JSON, default=list, nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="open", nullable=False)
    assignee: Mapped[str | None] = mapped_column(String(128), nullable=True)
    analyst_notes: Mapped[str] = mapped_column(Text, default="", nullable=False)
    disposition: Mapped[str | None] = mapped_column(String(32), nullable=True)
    disposition_notes: Mapped[str] = mapped_column(Text, default="", nullable=False)
    disposition_updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


class DetectionSettings(Base):
    __tablename__ = "detection_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    brute_force_threshold: Mapped[int] = mapped_column(Integer, default=5, nullable=False)
    window_minutes: Mapped[int] = mapped_column(Integer, default=10, nullable=False)
    targeted_username_threshold: Mapped[int] = mapped_column(Integer, default=4, nullable=False)
    repeated_failure_threshold: Mapped[int] = mapped_column(Integer, default=3, nullable=False)
    success_after_failure_threshold: Mapped[int] = mapped_column(Integer, default=3, nullable=False)
    distributed_failure_threshold: Mapped[int] = mapped_column(Integer, default=3, nullable=False)
    distributed_source_ip_threshold: Mapped[int] = mapped_column(Integer, default=2, nullable=False)
    monitoring_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class Incident(Base):
    __tablename__ = "incidents"
    __table_args__ = (
        CheckConstraint(
            "severity IN ('critical', 'high', 'medium', 'low')",
            name="ck_incidents_severity",
        ),
        CheckConstraint(
            "status IN ('open', 'investigating', 'resolved', 'merged')",
            name="ck_incidents_status",
        ),
        Index("ix_incidents_status_updated", "status", "updated_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(160), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="open", nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    source_ips: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    usernames: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    alert_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    related_event_ids: Mapped[list[int]] = mapped_column(JSON, default=list, nullable=False)
    analyst_notes: Mapped[str] = mapped_column(Text, default="", nullable=False)
    assignee: Mapped[str | None] = mapped_column(String(128), nullable=True)
    tasks: Mapped[list[dict[str, object]]] = mapped_column(JSON, default=list, nullable=False)
    merged_into_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.id"), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


class IncidentAlert(Base):
    __tablename__ = "incident_alerts"
    __table_args__ = (UniqueConstraint("alert_id", name="uq_incident_alerts_alert_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"), index=True)


class LocalIndicator(Base):
    __tablename__ = "local_indicators"
    __table_args__ = (
        CheckConstraint("kind IN ('allowlist', 'blocklist')", name="ck_local_indicators_kind"),
        UniqueConstraint("source_ip", name="uq_local_indicators_source_ip"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source_ip: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    indicator_type: Mapped[str] = mapped_column(String(16), default="ip", nullable=False)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    note: Mapped[str] = mapped_column(String(500), default="", nullable=False)
    confidence: Mapped[int] = mapped_column(Integer, default=50, nullable=False)
    source: Mapped[str] = mapped_column(String(160), default="Local analyst", nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)

    @property
    def value(self) -> str:
        return self.source_ip


class ThreatFeed(Base):
    __tablename__ = "threat_feeds"
    __table_args__ = (
        UniqueConstraint("name", name="uq_threat_feeds_name"),
        CheckConstraint("feed_format IN ('json', 'csv')", name="ck_threat_feeds_format"),
        CheckConstraint("stale_after_minutes > 0", name="ck_threat_feeds_stale_after"),
        CheckConstraint("last_sync_status IN ('never_synced', 'syncing', 'succeeded', 'partial', 'failed')", name="ck_threat_feeds_sync_status"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    feed_format: Mapped[str] = mapped_column(String(16), nullable=False)
    field_mapping: Mapped[dict[str, str]] = mapped_column(JSON, default=dict, nullable=False)
    credential_env_var: Mapped[str | None] = mapped_column(String(128), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    stale_after_minutes: Mapped[int] = mapped_column(Integer, default=1440, nullable=False)
    last_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str] = mapped_column(String(1000), default="", nullable=False)
    last_sync_status: Mapped[str] = mapped_column(String(24), default="never_synced", nullable=False)
    last_accepted_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_rejected_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    sync_lock_token: Mapped[str | None] = mapped_column(String(64), nullable=True)
    sync_lock_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


class ThreatFeedSyncRun(Base):
    __tablename__ = "threat_feed_sync_runs"
    __table_args__ = (
        Index("ix_threat_feed_sync_runs_created", "created_at"),
        CheckConstraint("status IN ('running', 'succeeded', 'partial', 'failed')", name="ck_threat_feed_sync_runs_status"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    feed_id: Mapped[int] = mapped_column(ForeignKey("threat_feeds.id", ondelete="RESTRICT"), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(24), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    response_bytes: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    fetched_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    accepted_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    inserted_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    updated_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    rejected_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    error_summary: Mapped[str] = mapped_column(String(1000), default="", nullable=False)
    content_sha256: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


class ThreatIndicator(Base):
    __tablename__ = "threat_indicators"
    __table_args__ = (
        UniqueConstraint("indicator_type", "value", name="uq_threat_indicators_type_value"),
        Index("ix_threat_indicators_last_seen", "last_seen"),
        CheckConstraint("indicator_type IN ('ip', 'domain', 'hash')", name="ck_threat_indicators_type"),
        CheckConstraint("analyst_disposition IN ('unreviewed', 'confirmed', 'false_positive')", name="ck_threat_indicators_disposition"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    indicator_type: Mapped[str] = mapped_column(String(16), nullable=False)
    value: Mapped[str] = mapped_column(String(255), nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    analyst_disposition: Mapped[str] = mapped_column(String(24), default="unreviewed", nullable=False)
    current_review_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


class ThreatIndicatorSource(Base):
    __tablename__ = "threat_indicator_sources"
    __table_args__ = (
        UniqueConstraint("indicator_id", "feed_id", "source_reference", name="uq_threat_indicator_source_ref"),
        Index("ix_threat_indicator_sources_expiry", "expires_at"),
        CheckConstraint("confidence IS NULL OR confidence BETWEEN 0 AND 100", name="ck_threat_indicator_sources_confidence"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    indicator_id: Mapped[int] = mapped_column(ForeignKey("threat_indicators.id", ondelete="CASCADE"), nullable=False, index=True)
    feed_id: Mapped[int] = mapped_column(ForeignKey("threat_feeds.id", ondelete="RESTRICT"), nullable=False, index=True)
    source_name: Mapped[str] = mapped_column(String(160), nullable=False)
    source_reference: Mapped[str] = mapped_column(String(512), default="", nullable=False)
    confidence: Mapped[int | None] = mapped_column(Integer, nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    latest_sync_run_id: Mapped[int] = mapped_column(ForeignKey("threat_feed_sync_runs.id", ondelete="RESTRICT"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


class ThreatIndicatorReview(Base):
    __tablename__ = "threat_indicator_reviews"
    __table_args__ = (
        Index("ix_threat_indicator_reviews_created", "created_at"),
        CheckConstraint("disposition IN ('confirmed', 'false_positive')", name="ck_threat_indicator_reviews_disposition"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    indicator_id: Mapped[int] = mapped_column(ForeignKey("threat_indicators.id", ondelete="RESTRICT"), nullable=False, index=True)
    disposition: Mapped[str] = mapped_column(String(24), nullable=False)
    notes: Mapped[str] = mapped_column(String(2000), default="", nullable=False)
    reviewer: Mapped[str] = mapped_column(String(128), default="Local analyst", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


class SoarWorkflow(Base):
    __tablename__ = "soar_workflows"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str] = mapped_column(String(500), default="", nullable=False)
    trigger_type: Mapped[str] = mapped_column(String(32), nullable=False)
    condition_field: Mapped[str] = mapped_column(String(32), default="", nullable=False)
    condition_operator: Mapped[str] = mapped_column(String(16), default="", nullable=False)
    condition_value: Mapped[str] = mapped_column(String(128), default="", nullable=False)
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    approval_required: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


class SoarExecution(Base):
    __tablename__ = "soar_executions"
    __table_args__ = (Index("ix_soar_executions_created", "created_at"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    workflow_id: Mapped[int] = mapped_column(ForeignKey("soar_workflows.id", ondelete="CASCADE"), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    entity_type: Mapped[str] = mapped_column(String(16), nullable=False)
    entity_id: Mapped[int] = mapped_column(Integer, nullable=False)
    evidence: Mapped[dict[str, object]] = mapped_column(JSON, default=dict, nullable=False)
    outcome: Mapped[str] = mapped_column(String(500), nullable=False)
    approved_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


class DetectionException(Base):
    __tablename__ = "detection_exceptions"
    __table_args__ = (CheckConstraint("source_ip IS NOT NULL OR username IS NOT NULL", name="ck_exception_scope"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)
    username: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    detection_key: Mapped[str | None] = mapped_column(String(48), nullable=True, index=True)
    reason: Mapped[str] = mapped_column(String(500), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


class DetectionRule(Base):
    __tablename__ = "detection_rules"
    __table_args__ = (
        CheckConstraint(
            "aggregation IN ('failed_per_source_ip', 'failed_per_username', "
            "'distinct_users_per_source_ip', 'distinct_ips_per_username')",
            name="ck_detection_rules_aggregation",
        ),
        CheckConstraint("severity IN ('critical', 'high', 'medium', 'low')", name="ck_detection_rules_severity"),
        Index("ix_detection_rules_enabled", "enabled"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str] = mapped_column(String(500), default="", nullable=False)
    aggregation: Mapped[str] = mapped_column(String(48), nullable=False)
    threshold: Mapped[int] = mapped_column(Integer, nullable=False)
    window_minutes: Mapped[int] = mapped_column(Integer, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    current_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


class DetectionRuleVersion(Base):
    __tablename__ = "detection_rule_versions"
    __table_args__ = (
        UniqueConstraint("rule_id", "version", name="uq_detection_rule_versions_rule_version"),
        Index("ix_detection_rule_versions_created", "rule_id", "created_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    rule_id: Mapped[int] = mapped_column(ForeignKey("detection_rules.id", ondelete="CASCADE"), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    configuration: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    change_note: Mapped[str] = mapped_column(String(500), default="", nullable=False)
    created_by: Mapped[str] = mapped_column(String(128), default="Local analyst", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


class AnalysisRun(Base):
    __tablename__ = "analysis_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    events_analyzed: Mapped[int] = mapped_column(Integer, nullable=False)
    model_name: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


class EventRiskAssessment(Base):
    __tablename__ = "event_risk_assessments"
    __table_args__ = (
        Index("ix_risk_assessments_event_run", "event_id", "analysis_run_id"),
        Index("ix_risk_assessments_ip_run", "source_ip", "analysis_run_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    analysis_run_id: Mapped[int] = mapped_column(ForeignKey("analysis_runs.id", ondelete="CASCADE"), nullable=False)
    event_id: Mapped[int] = mapped_column(ForeignKey("auth_events.id", ondelete="CASCADE"), nullable=False)
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    score: Mapped[int] = mapped_column(Integer, nullable=False)
    classification: Mapped[str] = mapped_column(String(16), nullable=False)
    factors: Mapped[list[dict[str, object]]] = mapped_column(JSON, default=list, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


class SavedEventSearch(Base):
    __tablename__ = "saved_event_searches"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    search: Mapped[str] = mapped_column(String(128), default="", nullable=False)
    status: Mapped[str] = mapped_column(String(16), default="", nullable=False)
    event_type: Mapped[str] = mapped_column(String(32), default="", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


class SavedHuntQuery(Base):
    __tablename__ = "saved_hunt_queries"
    __table_args__ = (Index("ix_saved_hunt_queries_updated", "updated_at"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
    description: Mapped[str] = mapped_column(String(500), default="", nullable=False)
    query: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


class DetectionLabRun(Base):
    __tablename__ = "detection_lab_runs"
    __table_args__ = (Index("ix_detection_lab_runs_created", "created_at"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scenario_id: Mapped[str] = mapped_column(String(48), nullable=False)
    scenario_version: Mapped[str] = mapped_column(String(24), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    result: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    settings_snapshot: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    enabled_rules_snapshot: Mapped[list[dict[str, object]]] = mapped_column(JSON, default=list, nullable=False)
    fixture_snapshot: Mapped[list[dict[str, object]]] = mapped_column(JSON, default=list, nullable=False)
    execution_metadata: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


class DetectionLabReview(Base):
    __tablename__ = "detection_lab_reviews"
    __table_args__ = (
        UniqueConstraint("run_id", "detection_key", name="uq_detection_lab_review_run_detection"),
        Index("ix_detection_lab_reviews_created", "reviewed_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("detection_lab_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    detection_key: Mapped[str] = mapped_column(String(80), nullable=False)
    disposition: Mapped[str] = mapped_column(String(32), nullable=False)
    notes: Mapped[str] = mapped_column(String(2_000), default="", nullable=False)
    reviewer: Mapped[str] = mapped_column(String(128), default="Local analyst", nullable=False)
    reviewed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


class AuditEntry(Base):
    __tablename__ = "audit_entries"
    __table_args__ = (Index("ix_audit_entries_created", "created_at"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    actor: Mapped[str] = mapped_column(String(128), default="Local analyst", nullable=False)
    action: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    entity_type: Mapped[str] = mapped_column(String(48), nullable=False, index=True)
    entity_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    details: Mapped[dict[str, object]] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    previous_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    entry_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)


class AuditChainState(Base):
    __tablename__ = "audit_chain_state"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    head_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    entry_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


class IngestionSource(Base):
    __tablename__ = "ingestion_sources"
    __table_args__ = (UniqueConstraint("name", name="uq_ingestion_sources_name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    platform: Mapped[str] = mapped_column(String(40), default="windows_security", nullable=False)
    token_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, unique=True)
    token_prefix: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    events_ingested: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    events_ignored: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    events_duplicated: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_event_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_sender_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


class IngestionReceipt(Base):
    __tablename__ = "ingestion_receipts"
    __table_args__ = (
        UniqueConstraint("source_id", "event_key", name="uq_ingestion_receipts_source_event"),
        Index("ix_ingestion_receipts_received", "received_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("ingestion_sources.id", ondelete="CASCADE"), nullable=False)
    event_key: Mapped[str] = mapped_column(String(512), nullable=False)
    event_id: Mapped[int | None] = mapped_column(ForeignKey("auth_events.id", ondelete="SET NULL"), nullable=True)
    outcome: Mapped[str] = mapped_column(String(32), nullable=False)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
