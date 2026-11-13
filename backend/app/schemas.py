from datetime import datetime, timedelta, timezone
import ipaddress
import re
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, field_serializer, field_validator, model_validator


class AuthEventCreate(BaseModel):
    timestamp: datetime | None = None
    username: str = Field(min_length=1, max_length=128)
    source_ip: IPvAnyAddress
    event_type: str = Field(default="login", min_length=1, max_length=32)
    status: Literal["success", "failure"]
    user_agent: str | None = Field(default=None, max_length=512)


class AuthEventRead(BaseModel):
    id: int
    timestamp: datetime
    ingested_at: datetime | None
    source_label: str
    username: str
    source_ip: str
    event_type: str
    status: Literal["success", "failure"]
    user_agent: str | None
    source_host: str | None = None
    source_event_id: str | None = None
    ingestion_source_id: int | None = None
    import_run_id: int | None = None
    event_metadata: dict[str, object] = Field(default_factory=dict)
    model_config = ConfigDict(from_attributes=True)


class NaturalEventSearchRequest(BaseModel):
    query: str = Field(min_length=2, max_length=500)
    limit: int = Field(default=25, ge=1, le=100)
    offset: int = Field(default=0, ge=0)


class NaturalEventSearchFilters(BaseModel):
    username: str | None = Field(default=None, max_length=128)
    source_ip: str | None = Field(default=None, max_length=45)
    status: Literal["success", "failure"] | None = None
    event_type: str | None = Field(default=None, max_length=32)
    since_hours: int | None = Field(default=None, ge=1, le=8760)
    search: str | None = Field(default=None, max_length=128)


class NaturalEventSearchResponse(BaseModel):
    query: str
    filters: NaturalEventSearchFilters
    total: int
    events: list[AuthEventRead]
    limit: int
    offset: int
    model: str
    notice: str


class SyslogIngestionCounters(BaseModel):
    connections: int
    received: int
    ingested: int
    ignored: int
    rejected: int
    errors: int


class SyslogIngestionStatus(BaseModel):
    enabled: bool
    running: bool
    transport: Literal["TCP"]
    host: str
    port: int
    allowed_sources: list[str]
    max_message_bytes: int
    counters: SyslogIngestionCounters
    last_event_at: datetime | None
    last_error: str | None


class IngestionRunRead(BaseModel):
    run_id: int
    filename: str
    source_format: Literal["csv", "linux_auth_log", "json", "jsonl"]
    status: Literal["processing", "completed", "failed"]
    accepted_records: int
    rejected_records: int
    error_summary: str
    created_at: datetime
    completed_at: datetime | None

    @field_serializer("created_at", "completed_at")
    def serialize_run_time(self, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)


class IngestionRunList(BaseModel):
    total: int
    runs: list[IngestionRunRead]


class IngestionSourceCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    platform: Literal["windows_security"] = "windows_security"


class IngestionSourceRead(BaseModel):
    id: int
    name: str
    platform: Literal["windows_security"]
    token_prefix: str | None
    enabled: bool
    events_ingested: int
    events_ignored: int
    events_duplicated: int
    last_seen_at: datetime | None
    last_event_at: datetime | None
    last_sender_ip: str | None
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

    @field_serializer("last_seen_at", "last_event_at", "created_at")
    def serialize_source_time(self, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)


class IngestionSourceCreated(BaseModel):
    source: IngestionSourceRead
    token: str


class IngestionSourceUpdate(BaseModel):
    enabled: bool


class WindowsSecurityEvent(BaseModel):
    event_id: Literal[4624, 4625]
    record_id: int = Field(ge=1, le=9_223_372_036_854_775_807)
    computer: str = Field(min_length=1, max_length=255)
    channel: Literal["Security"] = "Security"
    time_created: datetime
    event_data: dict[str, str] = Field(max_length=32)

    @field_validator("event_data")
    @classmethod
    def bound_event_data(cls, value: dict[str, str]) -> dict[str, str]:
        if any(len(key) > 80 or len(item) > 512 for key, item in value.items()):
            raise ValueError("Windows event fields exceed the allowed size.")
        return value


class WindowsSecurityEventBatch(BaseModel):
    events: list[WindowsSecurityEvent] = Field(min_length=1, max_length=100)


class WindowsSecurityIngestionResult(BaseModel):
    accepted: int
    duplicates: int
    ignored_no_ip: int
    ignored_local: int
    ignored_no_username: int
    source: IngestionSourceRead


class DashboardStats(BaseModel):
    total_events: int
    successful_logins: int
    failed_logins: int
    suspicious_ips: int
    critical_alerts: int
    high_alerts: int = 0
    medium_alerts: int = 0
    open_incidents: int = 0
    unresolved_alerts_by_severity: dict[str, int] = Field(default_factory=dict)


class AlertRead(BaseModel):
    id: int
    title: str
    detection_key: str
    attack_technique: str | None = None
    severity: Literal["critical", "high", "medium", "low"]
    reason: str
    source_ip: str
    related_event_ids: list[int]
    status: Literal["open", "investigating", "resolved"]
    assignee: str | None = None
    analyst_notes: str
    disposition: Literal["true_positive", "false_positive", "benign_activity"] | None = None
    disposition_notes: str = ""
    disposition_updated_at: datetime | None = None
    created_at: datetime
    event_types: list[str] = Field(default_factory=list)
    model_config = ConfigDict(from_attributes=True)


class AlertStatusUpdate(BaseModel):
    status: Literal["open", "investigating", "resolved"] | None = None
    assignee: str | None = Field(default=None, max_length=128)
    analyst_notes: str | None = Field(default=None, max_length=4_000)


class AlertDispositionUpdate(BaseModel):
    disposition: Literal["true_positive", "false_positive", "benign_activity"]
    notes: str = Field(default="", max_length=4_000)


class DetectionQualityRule(BaseModel):
    detection_key: str
    alert_count: int
    reviewed_count: int
    true_positive_count: int
    false_positive_count: int
    benign_activity_count: int
    false_positive_share: float | None


class DetectionQualityResponse(BaseModel):
    rules: list[DetectionQualityRule]
    reviewed_alerts: int
    unreviewed_alerts: int
    notice: str


class AlertBulkStatusUpdate(BaseModel):
    alert_ids: list[int] = Field(min_length=1, max_length=500)
    status: Literal["open", "investigating", "resolved"]

    @field_validator("alert_ids")
    @classmethod
    def unique_alert_ids(cls, value: list[int]) -> list[int]:
        if len(set(value)) != len(value):
            raise ValueError("Alert IDs must be unique.")
        return value


class AlertBulkStatusResult(BaseModel):
    updated_count: int
    alerts: list[AlertRead]


class DetectionSettingsRead(BaseModel):
    brute_force_threshold: int
    window_minutes: int
    targeted_username_threshold: int
    repeated_failure_threshold: int
    success_after_failure_threshold: int
    distributed_failure_threshold: int
    distributed_source_ip_threshold: int
    monitoring_enabled: bool
    model_config = ConfigDict(from_attributes=True)


class DetectionSettingsUpdate(BaseModel):
    brute_force_threshold: int | None = Field(default=None, ge=3, le=100)
    window_minutes: int | None = Field(default=None, ge=1, le=1440)
    targeted_username_threshold: int | None = Field(default=None, ge=2, le=100)
    repeated_failure_threshold: int | None = Field(default=None, ge=2, le=100)
    success_after_failure_threshold: int | None = Field(default=None, ge=2, le=100)
    distributed_failure_threshold: int | None = Field(default=None, ge=2, le=100)
    distributed_source_ip_threshold: int | None = Field(default=None, ge=2, le=20)
    monitoring_enabled: bool | None = None


DetectionAggregation = Literal[
    "failed_per_source_ip",
    "failed_per_username",
    "distinct_users_per_source_ip",
    "distinct_ips_per_username",
]


class DetectionRuleCreate(BaseModel):
    name: str = Field(min_length=3, max_length=120)
    description: str = Field(default="", max_length=500)
    aggregation: DetectionAggregation
    threshold: int = Field(ge=2, le=500)
    window_minutes: int = Field(ge=1, le=1440)
    severity: Literal["critical", "high", "medium", "low"] = "medium"
    enabled: bool = True
    change_note: str = Field(default="Initial rule version", max_length=500)

    @field_validator("name")
    @classmethod
    def trim_rule_name(cls, value: str) -> str:
        value = value.strip()
        if len(value) < 3:
            raise ValueError("Rule name must contain at least three non-space characters.")
        return value


class DetectionRuleUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=3, max_length=120)
    description: str | None = Field(default=None, max_length=500)
    aggregation: DetectionAggregation | None = None
    threshold: int | None = Field(default=None, ge=2, le=500)
    window_minutes: int | None = Field(default=None, ge=1, le=1440)
    severity: Literal["critical", "high", "medium", "low"] | None = None
    enabled: bool | None = None
    change_note: str = Field(default="", max_length=500)

    @field_validator("name")
    @classmethod
    def trim_updated_rule_name(cls, value: str | None) -> str | None:
        if value is None:
            return value
        value = value.strip()
        if len(value) < 3:
            raise ValueError("Rule name must contain at least three non-space characters.")
        return value


class DetectionRuleRead(BaseModel):
    id: int
    name: str
    description: str
    aggregation: DetectionAggregation
    threshold: int
    window_minutes: int
    severity: Literal["critical", "high", "medium", "low"]
    enabled: bool
    current_version: int
    created_at: datetime
    updated_at: datetime
    model_config = ConfigDict(from_attributes=True)


class DetectionRuleVersionRead(BaseModel):
    id: int
    rule_id: int
    version: int
    configuration: dict[str, object]
    change_note: str
    created_by: str
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


class DetectionRulePreviewGroup(BaseModel):
    match_key: str
    observed_value: int
    source_ip: str
    usernames: list[str]
    event_ids: list[int]


class DetectionRulePreviewRead(BaseModel):
    events_analyzed: int
    truncated: bool
    candidate_count: int
    matched_groups: list[DetectionRulePreviewGroup]
    notice: str


class DetectionReplayRequest(BaseModel):
    window_hours: int = Field(default=168, ge=1, le=720)
    settings: DetectionSettingsUpdate = Field(default_factory=DetectionSettingsUpdate)


class DetectionReplayRuleCount(BaseModel):
    detection_key: str
    title: str
    candidate_count: int
    suppressed_count: int
    sample_source_ips: list[str]
    sample_event_ids: list[int]


class DetectionReplaySummary(BaseModel):
    rules: list[DetectionReplayRuleCount]
    total_candidates: int
    total_suppressed: int


class DetectionReplayResponse(BaseModel):
    events_analyzed: int
    truncated: bool
    window_hours: int
    current: DetectionReplaySummary
    proposed: DetectionReplaySummary
    notice: str


class IPInvestigation(BaseModel):
    source_ip: str
    total_events: int
    failed_logins: int
    successful_logins: int
    usernames: list[str]
    events: list[AuthEventRead]


class AnomalyScoreRequest(BaseModel):
    event_ids: list[int] | None = Field(default=None, min_length=1, max_length=500)


class AnomalyResult(BaseModel):
    event: AuthEventRead
    anomaly_score: float
    classification: Literal["suspicious", "normal"]
    explanation: str


class AnomalyScoreResponse(BaseModel):
    model: str
    events_scored: int
    results: list[AnomalyResult]
    notice: str


class RiskFactor(BaseModel):
    key: str
    points: int
    explanation: str


class AnalyticsRequest(BaseModel):
    event_ids: list[int] | None = Field(default=None, min_length=1, max_length=500)


class AnalyticsResult(BaseModel):
    event: AuthEventRead
    risk_score: int
    risk_level: Literal["low", "moderate", "high", "critical"]
    factors: list[RiskFactor]
    anomaly_score: float | None
    anomaly_classification: Literal["suspicious", "normal"] | None
    prior_analysis_runs: int
    previous_risk_score: int | None


class AnalyticsResponse(BaseModel):
    analysis_run_id: int
    events_analyzed: int
    model: str | None
    notice: str
    results: list[AnalyticsResult]


class BehaviorProfile(BaseModel):
    entity: str
    event_count: int
    failures: int
    failure_rate: float
    distinct_usernames: int
    distinct_source_ips: int
    common_login_hours_utc: list[int]
    unusual_hour_events: int
    entity_risk_score: int = 0
    previous_window_events: int = 0
    event_count_change: int = 0
    anomaly_factors: list[str] = Field(default_factory=list)


class BehaviorResponse(BaseModel):
    events_analyzed: int
    window_hours: int
    users: list[BehaviorProfile]
    source_ips: list[BehaviorProfile]
    notice: str


class IncidentTask(BaseModel):
    id: str = Field(min_length=1, max_length=80)
    title: str = Field(min_length=1, max_length=200)
    completed: bool = False


class IncidentRead(BaseModel):
    id: int
    title: str
    severity: Literal["critical", "high", "medium", "low"]
    status: Literal["open", "investigating", "resolved", "merged"]
    summary: str
    source_ips: list[str]
    usernames: list[str]
    alert_count: int
    related_event_ids: list[int]
    analyst_notes: str
    assignee: str | None
    tasks: list[IncidentTask]
    merged_into_id: int | None
    first_seen: datetime
    last_seen: datetime
    created_at: datetime
    updated_at: datetime
    model_config = ConfigDict(from_attributes=True)


class IncidentUpdate(BaseModel):
    status: Literal["open", "investigating", "resolved"] | None = None
    analyst_notes: str | None = Field(default=None, max_length=4_000)
    assignee: str | None = Field(default=None, max_length=128)
    tasks: list[IncidentTask] | None = Field(default=None, max_length=30)


class IncidentCommentCreate(BaseModel):
    comment: str = Field(min_length=1, max_length=2_000)


class IncidentCommentRead(BaseModel):
    id: int
    actor: str
    action: str
    details: dict[str, object]
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


class IncidentBriefFact(BaseModel):
    text: str
    event_ids: list[int] = Field(default_factory=list)


class IncidentBriefRead(BaseModel):
    incident_id: int
    title: str
    summary: str
    facts: list[IncidentBriefFact]
    event_ids: list[int]
    model_used: bool
    generated_at: datetime
    notice: str


class LocalIndicatorCreate(BaseModel):
    source_ip: IPvAnyAddress | None = None
    value: str | None = Field(default=None, max_length=255)
    indicator_type: Literal["ip", "domain", "hash"] = "ip"
    kind: Literal["allowlist", "blocklist"]
    note: str = Field(default="", max_length=500)
    confidence: int = Field(default=50, ge=0, le=100)
    source: str = Field(default="Local analyst", min_length=1, max_length=160)
    expires_at: datetime | None = None

    @model_validator(mode="after")
    def normalize_indicator(self):
        raw_value = self.value or (str(self.source_ip) if self.source_ip else "")
        raw_value = raw_value.strip()
        if not raw_value:
            raise ValueError("Indicator value is required.")
        if self.indicator_type == "ip":
            try:
                raw_value = str(ipaddress.ip_address(raw_value))
            except ValueError as exc:
                raise ValueError("IP indicators must contain a valid IPv4 or IPv6 address.") from exc
        elif self.indicator_type == "domain":
            raw_value = raw_value.lower().rstrip(".")
            if not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))+", raw_value):
                raise ValueError("Domain indicators must be fully qualified domain names.")
        else:
            raw_value = raw_value.lower()
            if not re.fullmatch(r"(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})", raw_value):
                raise ValueError("Hash indicators must be valid MD5, SHA-1, or SHA-256 hexadecimal values.")
        self.value = raw_value
        self.source_ip = raw_value  # Kept as the storage/API compatibility field for existing IP records.
        if self.expires_at is not None:
            expiry = self.expires_at.replace(tzinfo=timezone.utc) if self.expires_at.tzinfo is None else self.expires_at.astimezone(timezone.utc)
            if expiry <= datetime.now(timezone.utc):
                raise ValueError("Indicator expiry must be in the future.")
            self.expires_at = expiry
        return self


class LocalIndicatorRead(BaseModel):
    id: int
    source_ip: str
    value: str
    indicator_type: Literal["ip", "domain", "hash"]
    kind: Literal["allowlist", "blocklist"]
    note: str
    confidence: int
    source: str
    expires_at: datetime | None
    matching_event_count: int = 0
    created_at: datetime
    updated_at: datetime
    model_config = ConfigDict(from_attributes=True)


class ThreatFeedFieldMapping(BaseModel):
    model_config = ConfigDict(extra="forbid")

    records_key: str = Field(default="indicators", min_length=1, max_length=80)
    indicator_type: str = Field(default="type", min_length=1, max_length=80)
    value: str = Field(default="value", min_length=1, max_length=80)
    confidence: str | None = Field(default="confidence", max_length=80)
    first_seen: str | None = Field(default="first_seen", max_length=80)
    last_seen: str | None = Field(default="last_seen", max_length=80)
    expires_at: str | None = Field(default="expires_at", max_length=80)
    reference: str | None = Field(default="reference", max_length=80)


class ThreatFeedCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=2, max_length=120)
    url: str = Field(min_length=9, max_length=2048)
    feed_format: Literal["json", "csv"]
    field_mapping: ThreatFeedFieldMapping = Field(default_factory=ThreatFeedFieldMapping)
    credential_env_var: str | None = Field(default=None, max_length=128, pattern=r"^[A-Z_][A-Z0-9_]{0,127}$")
    enabled: bool = True
    stale_after_minutes: int = Field(default=1440, ge=1, le=43_200)

    @field_validator("name")
    @classmethod
    def normalize_feed_name(cls, value: str) -> str:
        value = value.strip()
        if len(value) < 2:
            raise ValueError("Feed name must contain at least two non-space characters.")
        return value

    @field_validator("url")
    @classmethod
    def validate_https_feed_url(cls, value: str) -> str:
        value = value.strip()
        parsed = urlsplit(value)
        if parsed.scheme.lower() != "https" or not parsed.hostname:
            raise ValueError("Threat feeds must use an HTTPS URL with a hostname.")
        if parsed.username or parsed.password or parsed.fragment or parsed.query:
            raise ValueError("Feed URLs cannot contain embedded credentials, queries, or fragments; configure credentials through the environment.")
        if parsed.port not in {None, 443}:
            raise ValueError("Threat feeds must use the standard HTTPS port 443.")
        return value


class ThreatFeedUpdate(ThreatFeedCreate):
    pass


class ThreatFeedEnableUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool


class ThreatFeedRead(BaseModel):
    id: int
    name: str
    url: str
    feed_format: Literal["json", "csv"]
    field_mapping: ThreatFeedFieldMapping
    credential_env_var: str | None
    credential_configured: bool
    enabled: bool
    stale_after_minutes: int
    last_attempt_at: datetime | None
    last_success_at: datetime | None
    last_error: str
    last_sync_status: Literal["never_synced", "syncing", "succeeded", "partial", "failed"]
    freshness: Literal["never_synced", "syncing", "fresh", "stale", "failed", "disabled"]
    last_accepted_count: int
    last_rejected_count: int
    created_at: datetime
    updated_at: datetime


class ThreatFeedSyncRunRead(BaseModel):
    id: int
    feed_id: int
    status: Literal["running", "succeeded", "partial", "failed"]
    started_at: datetime
    completed_at: datetime | None
    response_bytes: int
    fetched_count: int
    accepted_count: int
    inserted_count: int
    updated_count: int
    rejected_count: int
    error_summary: str
    content_sha256: str
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


class ThreatIndicatorSourceRead(BaseModel):
    id: int
    feed_id: int
    source_name: str
    source_reference: str
    confidence: int | None
    first_seen: datetime
    last_seen: datetime
    expires_at: datetime | None
    latest_sync_run_id: int
    active: bool
    model_config = ConfigDict(from_attributes=True)


class ThreatIndicatorRead(BaseModel):
    id: int
    indicator_type: Literal["ip", "domain", "hash"]
    value: str
    first_seen: datetime
    last_seen: datetime
    analyst_disposition: Literal["unreviewed", "confirmed", "false_positive"]
    reviewed_at: datetime | None
    sources: list[ThreatIndicatorSourceRead]
    source_count: int = Field(ge=0)
    sources_truncated: bool
    active: bool
    correlation_status: Literal["ip_supported", "unsupported_schema"]
    matching_event_count: int | None


class ThreatIndicatorListResponse(BaseModel):
    total: int
    limit: int
    offset: int
    indicators: list[ThreatIndicatorRead]


class ThreatIndicatorReviewCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    disposition: Literal["confirmed", "false_positive"]
    notes: str = Field(default="", max_length=2_000)


class ThreatIndicatorReviewRead(BaseModel):
    id: int
    indicator_id: int
    disposition: Literal["confirmed", "false_positive"]
    notes: str
    reviewer: str
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


class ThreatIndicatorAlertReference(BaseModel):
    id: int
    title: str
    severity: Literal["critical", "high", "medium", "low"]
    status: Literal["open", "investigating", "resolved"]


class ThreatIndicatorIncidentReference(BaseModel):
    id: int
    title: str
    severity: Literal["critical", "high", "medium", "low"]
    status: Literal["open", "investigating", "resolved", "merged"]


class ThreatIndicatorCorrelationRow(BaseModel):
    event: AuthEventRead
    alerts: list[ThreatIndicatorAlertReference] = Field(default_factory=list)
    incidents: list[ThreatIndicatorIncidentReference] = Field(default_factory=list)


class ThreatIndicatorCorrelationResponse(BaseModel):
    indicator_id: int
    correlation_status: Literal["correlated", "no_matches", "unsupported_schema"]
    explanation: str
    total: int | None
    limit: int
    offset: int
    results: list[ThreatIndicatorCorrelationRow]


class ThreatIndicatorTimelineEntry(BaseModel):
    occurred_at: datetime
    kind: Literal["feed_observation", "event", "alert", "incident", "review"]
    title: str
    details: dict[str, object] = Field(default_factory=dict)


class ThreatIndicatorTimelineResponse(BaseModel):
    indicator_id: int
    correlation_status: Literal["ip_supported", "unsupported_schema"]
    entries: list[ThreatIndicatorTimelineEntry]
    limit: int
    notice: str


class DetectionExceptionCreate(BaseModel):
    source_ip: IPvAnyAddress | None = None
    username: str | None = Field(default=None, min_length=1, max_length=128)
    detection_key: str | None = Field(default=None, max_length=48)
    reason: str = Field(min_length=3, max_length=500)
    expires_at: datetime


class DetectionExceptionRead(BaseModel):
    id: int
    source_ip: str | None
    username: str | None
    detection_key: str | None
    reason: str
    expires_at: datetime
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


class CopilotRequest(BaseModel):
    question: str = Field(min_length=1, max_length=500)
    model: str | None = Field(
        default=None,
        max_length=128,
        pattern=r"^qwen[0-9a-zA-Z._-]*(?::[0-9a-zA-Z._-]+)?$",
    )


class CopilotResponse(BaseModel):
    question: str
    intent: str
    answer: str
    facts: list[str]
    suggested_actions: list[str]
    data_scope: str


class SavedEventSearchCreate(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    search: str = Field(default="", max_length=128)
    status: Literal["", "success", "failure"] = ""
    event_type: str = Field(default="", max_length=32)


class SavedEventSearchRead(SavedEventSearchCreate):
    id: int
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


class HuntCondition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    field: Literal["source_ip", "username", "event_type", "result", "severity"]
    operator: Literal["equals", "contains"] = "equals"
    value: str = Field(min_length=1, max_length=128)

    @model_validator(mode="after")
    def validate_field_operator_and_value(self):
        self.value = self.value.strip()
        if not self.value:
            raise ValueError("A hunt condition value cannot be blank.")
        if self.operator == "contains" and self.field != "username":
            raise ValueError("The contains operator is only supported for username.")
        if self.field == "source_ip":
            if self.operator != "equals":
                raise ValueError("Source IP filters support exact matching only.")
            try:
                self.value = str(ipaddress.ip_address(self.value))
            except ValueError as exc:
                raise ValueError("Source IP must be a valid IPv4 or IPv6 address.") from exc
        elif self.field == "event_type":
            if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,32}", self.value):
                raise ValueError("Event type contains unsupported characters or is too long.")
        elif self.field == "result" and self.value not in {"success", "failure"}:
            raise ValueError("Result must be success or failure.")
        elif self.field == "severity" and self.value not in {"critical", "high", "medium", "low", "unclassified"}:
            raise ValueError("Severity must be a known alert severity or unclassified.")
        return self


class HuntFilterSet(BaseModel):
    model_config = ConfigDict(extra="forbid")

    start_time: datetime
    end_time: datetime
    logic: Literal["AND", "OR"] = "AND"
    conditions: list[HuntCondition] = Field(min_length=1, max_length=20)

    @model_validator(mode="after")
    def normalize_and_bound_time_range(self):
        start = self.start_time.replace(tzinfo=timezone.utc) if self.start_time.tzinfo is None else self.start_time.astimezone(timezone.utc)
        end = self.end_time.replace(tzinfo=timezone.utc) if self.end_time.tzinfo is None else self.end_time.astimezone(timezone.utc)
        if end < start:
            raise ValueError("End time must be on or after start time.")
        if end - start > timedelta(days=365):
            raise ValueError("A hunt time range cannot exceed 365 days.")
        self.start_time = start
        self.end_time = end
        return self


class HuntSearchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    query: HuntFilterSet
    limit: int = Field(default=50, ge=1, le=200)
    offset: int = Field(default=0, ge=0, le=100_000)


class HuntExportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    query: HuntFilterSet
    max_rows: int = Field(default=5_000, ge=1, le=5_000)


class HuntQueryCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=3, max_length=100)
    description: str = Field(default="", max_length=500)
    query: HuntFilterSet

    @field_validator("name")
    @classmethod
    def trim_hunt_name(cls, value: str) -> str:
        value = value.strip()
        if len(value) < 3:
            raise ValueError("Hunt name must contain at least three non-space characters.")
        return value


class HuntQueryRead(HuntQueryCreate):
    id: int
    created_at: datetime
    updated_at: datetime
    model_config = ConfigDict(from_attributes=True)


class HuntQueryUpdate(HuntQueryCreate):
    pass


class HuntAlertReference(BaseModel):
    id: int
    title: str
    severity: Literal["critical", "high", "medium", "low"]
    status: Literal["open", "investigating", "resolved"]


class HuntIncidentReference(BaseModel):
    id: int
    title: str
    severity: Literal["critical", "high", "medium", "low"]
    status: Literal["open", "investigating", "resolved", "merged"]


class HuntEventResult(BaseModel):
    event: AuthEventRead
    alerts: list[HuntAlertReference] = Field(default_factory=list)
    incidents: list[HuntIncidentReference] = Field(default_factory=list)


class HuntSearchResponse(BaseModel):
    total: int
    limit: int
    offset: int
    execution_ms: float = Field(ge=0)
    results: list[HuntEventResult]


DetectionLabScenarioId = Literal[
    "repeated_auth_failures",
    "unusual_login_burst",
    "multiple_accounts_one_source",
    "unfamiliar_source_ip",
    "suspicious_login_time",
]


class DetectionLabSettingsSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    brute_force_threshold: int = Field(default=5, ge=2, le=500)
    window_minutes: int = Field(default=10, ge=1, le=1440)
    targeted_username_threshold: int = Field(default=4, ge=2, le=500)
    repeated_failure_threshold: int = Field(default=3, ge=2, le=500)
    success_after_failure_threshold: int = Field(default=3, ge=1, le=500)
    distributed_failure_threshold: int = Field(default=3, ge=1, le=500)
    distributed_source_ip_threshold: int = Field(default=2, ge=2, le=500)
    monitoring_enabled: bool = True


class DetectionLabRuleSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_id: int
    version: int = Field(ge=1)
    name: str
    aggregation: DetectionAggregation
    threshold: int = Field(ge=1, le=10_000)
    window_minutes: int = Field(ge=1, le=1440)
    severity: Literal["critical", "high", "medium", "low"]
    enabled: Literal[True] = True


class DetectionLabScenarioRead(BaseModel):
    scenario_id: DetectionLabScenarioId
    version: str
    name: str
    description: str
    expected_detection_keys: list[str] = Field(default_factory=list)
    expected_risk_factors: list[str] = Field(default_factory=list)
    minimum_baseline_events: int = Field(default=0, ge=0)
    technique_candidates: list[str] = Field(default_factory=list)


class DetectionLabSyntheticEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    timestamp: datetime
    username: str = Field(min_length=1, max_length=128)
    source_ip: IPvAnyAddress
    event_type: str = Field(default="login", min_length=1, max_length=32)
    status: Literal["success", "failure"]


class DetectionLabFixture(BaseModel):
    scenario_id: DetectionLabScenarioId
    scenario_version: str
    supported: bool
    unsupported_reason: str | None = None
    settings_snapshot: DetectionLabSettingsSnapshot
    events: list[DetectionLabSyntheticEvent] = Field(default_factory=list, max_length=250)
    expected_detection_keys: list[str] = Field(default_factory=list)
    expected_risk_factors: list[str] = Field(default_factory=list)
    minimum_baseline_events: int = Field(default=0, ge=0)
    technique_candidates: list[str] = Field(default_factory=list)


class DetectionLabExecutionResult(BaseModel):
    scenario_id: DetectionLabScenarioId
    scenario_version: str
    validation_scope: Literal["synthetic_scenario_validation"] = "synthetic_scenario_validation"
    real_world_accuracy_claim: Literal[False] = False
    status: Literal["passed", "failed", "insufficient_baseline", "not_evaluable"]
    expected_detection_keys: list[str] = Field(default_factory=list)
    actual_detection_keys: list[str] = Field(default_factory=list)
    expected_risk_factors: list[str] = Field(default_factory=list)
    actual_risk_factors: list[str] = Field(default_factory=list)
    missing_detection_keys: list[str] = Field(default_factory=list)
    unexpected_detection_keys: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    unsupported_reason: str | None = None


class DetectionLabRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenario_id: DetectionLabScenarioId


class DetectionLabRunRead(BaseModel):
    id: int
    scenario_id: DetectionLabScenarioId
    scenario_version: str
    status: Literal["passed", "failed", "insufficient_baseline", "not_evaluable"]
    result: DetectionLabExecutionResult
    settings_snapshot: DetectionLabSettingsSnapshot
    enabled_rules_snapshot: list[DetectionLabRuleSnapshot]
    fixture_snapshot: list[DetectionLabSyntheticEvent]
    execution_metadata: dict[str, object]
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


class DetectionLabReviewCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    detection_key: str = Field(min_length=1, max_length=80, pattern=r"^[A-Za-z0-9_.:-]+$")
    disposition: Literal["true_positive", "false_positive", "expected_behavior", "needs_tuning"]
    notes: str = Field(default="", max_length=2_000)


class DetectionLabReviewRead(BaseModel):
    id: int
    run_id: int
    detection_key: str
    disposition: Literal["true_positive", "false_positive", "expected_behavior", "needs_tuning"]
    notes: str
    reviewer: str
    reviewed_at: datetime
    model_config = ConfigDict(from_attributes=True)


class DetectionLabRuleSummary(BaseModel):
    detection_key: str
    scenario_observations: int
    reviewed_count: int
    false_positive_reviews: int
    notice: str


class DetectionLabSummary(BaseModel):
    total_runs: int
    passed_runs: int
    failed_runs: int
    insufficient_baseline_runs: int
    not_evaluable_runs: int
    rule_summaries: list[DetectionLabRuleSummary]
    notice: str


class AuditEntryRead(BaseModel):
    id: int
    actor: str
    action: str
    entity_type: str
    entity_id: str | None
    details: dict[str, object]
    created_at: datetime
    previous_hash: str
    entry_hash: str
    model_config = ConfigDict(from_attributes=True)


class AuditIntegrityRead(BaseModel):
    valid: bool
    checked_entries: int
    head_hash: str | None
    first_invalid_entry_id: int | None
    checked_at: datetime
    message: str


class SoarWorkflowCreate(BaseModel):
    name: str = Field(min_length=3, max_length=120)
    description: str = Field(default="", max_length=500)
    trigger_type: Literal["alert_created", "event_failure", "indicator_match"]
    condition_field: Literal["", "severity", "source_ip", "status"] = ""
    condition_operator: Literal["", "equals", "contains"] = ""
    condition_value: str = Field(default="", max_length=128)
    action: Literal["add_case_note", "simulate_isolation"]
    approval_required: bool = True


class SoarWorkflowRead(SoarWorkflowCreate):
    id: int
    enabled: bool
    created_at: datetime
    updated_at: datetime
    model_config = ConfigDict(from_attributes=True)


class SoarExecutionCreate(BaseModel):
    entity_type: Literal["alert", "event"]
    entity_id: int = Field(ge=1)


class SoarExecutionRead(BaseModel):
    id: int
    workflow_id: int
    status: Literal["awaiting_approval", "simulated", "approved_simulation"]
    entity_type: Literal["alert", "event"]
    entity_id: int
    evidence: dict[str, object]
    outcome: str
    approved_by: str | None
    created_at: datetime
    updated_at: datetime
    model_config = ConfigDict(from_attributes=True)
