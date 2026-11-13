"""Run reproducible detection scenarios in an isolated temporary SQLite file."""

from tempfile import TemporaryDirectory
from pathlib import Path

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from app.database import initialize_schema
from app.models import Alert, AuthEvent, DetectionRule, DetectionSettings, LocalIndicator
from app.schemas import (
    DetectionLabExecutionResult,
    DetectionLabFixture,
    DetectionLabRuleSnapshot,
    DetectionLabSettingsSnapshot,
)
from app.services.detection import evaluate_event
from app.services.risk_scoring import assess_unfamiliar_source, score_event
from app.services.threat_intelligence import get_local_indicator_map


def snapshot_settings(settings: DetectionSettings | None) -> DetectionLabSettingsSnapshot:
    if settings is None:
        return DetectionLabSettingsSnapshot()
    return DetectionLabSettingsSnapshot(
        brute_force_threshold=settings.brute_force_threshold,
        window_minutes=settings.window_minutes,
        targeted_username_threshold=settings.targeted_username_threshold,
        repeated_failure_threshold=settings.repeated_failure_threshold,
        success_after_failure_threshold=settings.success_after_failure_threshold,
        distributed_failure_threshold=settings.distributed_failure_threshold,
        distributed_source_ip_threshold=settings.distributed_source_ip_threshold,
        monitoring_enabled=settings.monitoring_enabled,
    )


def snapshot_enabled_rules(rules: list[DetectionRule]) -> list[DetectionLabRuleSnapshot]:
    return [
        DetectionLabRuleSnapshot(
            rule_id=rule.id,
            version=rule.current_version,
            name=rule.name,
            aggregation=rule.aggregation,
            threshold=rule.threshold,
            window_minutes=rule.window_minutes,
            severity=rule.severity,
            enabled=True,
        )
        for rule in sorted(rules, key=lambda item: item.id)
        if rule.enabled
    ]


def _infrastructure_settings(snapshot: DetectionLabSettingsSnapshot) -> DetectionSettings:
    return DetectionSettings(id=1, **snapshot.model_dump())


def run_scenario_isolated(
    fixture: DetectionLabFixture,
    rules_snapshot: list[DetectionLabRuleSnapshot] | None = None,
) -> DetectionLabExecutionResult:
    """Create, run, and discard a SQLite database that is independent of the workspace DB."""
    rules_snapshot = rules_snapshot or []
    result_base = {
        "scenario_id": fixture.scenario_id,
        "scenario_version": fixture.scenario_version,
        "expected_detection_keys": fixture.expected_detection_keys,
        "expected_risk_factors": fixture.expected_risk_factors,
    }
    if not fixture.supported:
        return DetectionLabExecutionResult(
            **result_base,
            status="not_evaluable",
            evidence=["No synthetic records were generated because the configured thresholds exceed the supported scenario cap."],
            unsupported_reason=fixture.unsupported_reason,
        )

    with TemporaryDirectory(prefix="threatlens-lab-") as workdir:
        db_path = Path(workdir) / "scenario.sqlite3"
        engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False, "timeout": 30})
        try:
            initialize_schema(engine)
            session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
            with session_factory() as db:
                db.add(_infrastructure_settings(fixture.settings_snapshot))
                for rule_data in rules_snapshot:
                    db.add(DetectionRule(
                        id=rule_data.rule_id,
                        name=rule_data.name,
                        description="Isolated lab snapshot",
                        aggregation=rule_data.aggregation,
                        threshold=rule_data.threshold,
                        window_minutes=rule_data.window_minutes,
                        severity=rule_data.severity,
                        enabled=True,
                        current_version=rule_data.version,
                    ))
                db.flush()
                records: list[AuthEvent] = []
                for item in fixture.events:
                    event = AuthEvent(
                        timestamp=item.timestamp,
                        ingested_at=item.timestamp,
                        source_label="Synthetic Detection Lab",
                        username=item.username,
                        source_ip=str(item.source_ip),
                        event_type=item.event_type,
                        status=item.status,
                        user_agent=None,
                        source_host=None,
                        event_metadata={"synthetic": True, "scenario_id": fixture.scenario_id, "scenario_version": fixture.scenario_version},
                    )
                    db.add(event)
                    db.flush()
                    records.append(event)
                    evaluate_event(db, event)
                db.flush()

                alerts = list(db.scalars(select(Alert).order_by(Alert.detection_key)))
                actual_keys = sorted({alert.detection_key for alert in alerts})
                expected_keys = set(fixture.expected_detection_keys)
                actual_key_set = set(actual_keys)
                missing = sorted(expected_keys - actual_key_set)
                unexpected = sorted(actual_key_set - expected_keys)
                evidence = [
                    f"Detection {alert.detection_key}: {alert.reason} Evidence event IDs: {alert.related_event_ids[:12]}."
                    for alert in alerts
                ]
                for key in missing:
                    evidence.append(
                        f"Expected detection {key} did not occur. Configured thresholds and monitoring settings were applied as captured; no threshold was lowered to force a match."
                    )
                actual_factors: list[str] = []
                baseline_state = "assessed"
                if fixture.expected_risk_factors and records:
                    target = records[-1]
                    prior_records = records[:-1]
                    baseline = assess_unfamiliar_source(target, prior_records)
                    baseline_state = str(baseline["status"])
                    if baseline_state == "insufficient_baseline":
                        status_value = "insufficient_baseline"
                        evidence.append(
                            f"User baseline has {baseline['baseline_events']} event(s); minimum required is {baseline['minimum_baseline_events']}."
                        )
                        return DetectionLabExecutionResult(
                            **result_base,
                            status=status_value,
                            actual_detection_keys=actual_keys,
                            missing_detection_keys=missing,
                            unexpected_detection_keys=unexpected,
                            evidence=evidence,
                        )
                    risk_score, _, factors = score_event(
                        target,
                        records,
                        alerts,
                        get_local_indicator_map(db),
                        db.get(DetectionSettings, 1),
                        None,
                    )
                    actual_factors = sorted({str(factor["key"]) for factor in factors})
                    evidence.append(
                        f"Target synthetic event {target.id} scored {risk_score}; historical baseline contains {baseline['baseline_events']} user event(s)."
                    )
                missing_factors = set(fixture.expected_risk_factors) - set(actual_factors)
                supported_detection_scope = fixture.expected_detection_keys or fixture.expected_risk_factors
                status_value = "passed" if not missing and not missing_factors and supported_detection_scope else "failed"
                return DetectionLabExecutionResult(
                    **result_base,
                    status=status_value,
                    actual_detection_keys=actual_keys,
                    actual_risk_factors=actual_factors,
                    missing_detection_keys=missing,
                    unexpected_detection_keys=unexpected,
                    evidence=evidence,
                )
        finally:
            engine.dispose()
