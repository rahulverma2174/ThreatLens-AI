from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from app.schemas import (
    DetectionLabScenarioRead,
    DetectionLabSettingsSnapshot,
    HuntCondition,
    HuntFilterSet,
    HuntQueryCreate,
    HuntSearchRequest,
)
from app.models import Alert, AnalysisRun, AuditEntry, AuthEvent, Incident
from app.services.detection_lab import run_scenario_isolated
from app.services.scenario_fixtures import (
    DEFAULT_FIXTURE_ANCHOR,
    MAX_SCENARIO_EVENTS,
    MIN_USER_BASELINE_EVENTS,
    SCENARIO_VERSION,
    build_scenario_fixture,
    list_scenarios,
)


def _hunt_query(**changes) -> dict[str, object]:
    start = datetime(2025, 1, 1, tzinfo=timezone.utc)
    return {
        "start_time": start.isoformat(),
        "end_time": (start + timedelta(days=7)).isoformat(),
        "logic": "AND",
        "conditions": [{"field": "source_ip", "operator": "equals", "value": "198.51.100.9"}],
        **changes,
    }


def test_hunt_contract_normalizes_ip_and_timezone_and_rejects_unbounded_logic() -> None:
    query = HuntFilterSet.model_validate(_hunt_query())
    assert query.conditions[0].value == "198.51.100.9"
    assert query.start_time.tzinfo == timezone.utc
    assert HuntSearchRequest.model_validate({"query": _hunt_query(), "limit": 25, "offset": 50}).offset == 50
    assert HuntQueryCreate.model_validate({"name": "  Night shift hunt  ", "query": _hunt_query()}).name == "Night shift hunt"

    with pytest.raises(ValidationError):
        HuntSearchRequest.model_validate({"query": _hunt_query(), "sql": "SELECT * FROM auth_events"})
    with pytest.raises(ValidationError):
        HuntFilterSet.model_validate(_hunt_query(logic="XOR"))
    with pytest.raises(ValidationError):
        HuntFilterSet.model_validate(_hunt_query(conditions=[{"field": "__class__", "operator": "equals", "value": "x"}]))


def test_hunt_contract_bounds_dates_conditions_and_field_operator_pairs() -> None:
    start = datetime(2024, 1, 1, tzinfo=timezone.utc)
    with pytest.raises(ValidationError, match="365 days"):
        HuntFilterSet.model_validate({**_hunt_query(), "start_time": start.isoformat(), "end_time": (start + timedelta(days=366)).isoformat()})
    with pytest.raises(ValidationError, match="on or after"):
        HuntFilterSet.model_validate({**_hunt_query(), "start_time": "2025-01-10T00:00:00Z", "end_time": "2025-01-01T00:00:00Z"})
    with pytest.raises(ValidationError, match="contains operator"):
        HuntCondition.model_validate({"field": "severity", "operator": "contains", "value": "high"})
    with pytest.raises(ValidationError, match="valid IPv4 or IPv6"):
        HuntCondition.model_validate({"field": "source_ip", "operator": "equals", "value": "not-an-ip"})
    with pytest.raises(ValidationError, match="success or failure"):
        HuntCondition.model_validate({"field": "result", "operator": "equals", "value": "unknown"})
    with pytest.raises(ValidationError):
        HuntFilterSet.model_validate(_hunt_query(conditions=[{"field": "username", "operator": "contains", "value": "a"}] * 21))


def test_scenario_catalog_and_fixtures_are_versioned_deterministic_and_synthetic() -> None:
    settings = DetectionLabSettingsSnapshot()
    scenarios = list_scenarios()
    assert {item.scenario_id for item in scenarios} == {
        "repeated_auth_failures",
        "unusual_login_burst",
        "multiple_accounts_one_source",
        "unfamiliar_source_ip",
        "suspicious_login_time",
    }
    assert all(item.version == SCENARIO_VERSION for item in scenarios)

    for scenario_id in (
        "repeated_auth_failures",
        "unusual_login_burst",
        "multiple_accounts_one_source",
        "unfamiliar_source_ip",
        "suspicious_login_time",
    ):
        fixture = build_scenario_fixture(scenario_id, settings)
        repeated = build_scenario_fixture(scenario_id, settings)
        assert fixture.model_dump() == repeated.model_dump()
        assert fixture.supported is True
        assert fixture.scenario_version == SCENARIO_VERSION
        assert 0 < len(fixture.events) <= MAX_SCENARIO_EVENTS
        assert all(str(event.source_ip) in {"198.51.100.41", "203.0.113.24", "192.0.2.77"} for event in fixture.events)
        assert all(event.timestamp.tzinfo == timezone.utc for event in fixture.events)

    repeated_failures = build_scenario_fixture("repeated_auth_failures", settings)
    assert {"repeated_failures", "brute_force"}.issubset(repeated_failures.expected_detection_keys)
    assert "T1110" in repeated_failures.technique_candidates
    assert "T1110.003" not in repeated_failures.technique_candidates


def test_baseline_scenarios_have_explicit_minimum_and_explanatory_signal() -> None:
    settings = DetectionLabSettingsSnapshot()
    unfamiliar = build_scenario_fixture("unfamiliar_source_ip", settings)
    unusual_time = build_scenario_fixture("suspicious_login_time", settings)
    assert unfamiliar.minimum_baseline_events == MIN_USER_BASELINE_EVENTS
    assert len(unfamiliar.events) == MIN_USER_BASELINE_EVENTS + 1
    assert len({event.source_ip for event in unfamiliar.events[:-1]}) == 1
    assert unfamiliar.events[-1].source_ip != unfamiliar.events[0].source_ip
    assert unfamiliar.expected_risk_factors == ["new_source_for_user"]
    assert unusual_time.minimum_baseline_events == MIN_USER_BASELINE_EVENTS
    assert unusual_time.expected_risk_factors == ["unusual_login_hour"]
    assert {event.timestamp.hour for event in unusual_time.events[:-1]} == {9}
    assert unusual_time.events[-1].timestamp.hour == 2


def test_thresholds_over_fixture_cap_are_reported_unsupported_not_forced_to_pass() -> None:
    settings = DetectionLabSettingsSnapshot(brute_force_threshold=130)
    fixture = build_scenario_fixture("unusual_login_burst", settings, anchor=DEFAULT_FIXTURE_ANCHOR)
    assert fixture.supported is False
    assert fixture.events == []
    assert str(MAX_SCENARIO_EVENTS) in (fixture.unsupported_reason or "")
    assert "Thresholds were not changed" in (fixture.unsupported_reason or "")


def test_scenario_id_contract_rejects_unknown_ids() -> None:
    with pytest.raises(ValidationError):
        DetectionLabScenarioRead.model_validate({
            "scenario_id": "real_network_attack",
            "version": "1",
            "name": "invalid",
            "description": "invalid",
        })


def test_isolated_lab_runner_matches_repeatable_scenario_and_reports_scope() -> None:
    fixture = build_scenario_fixture("repeated_auth_failures", DetectionLabSettingsSnapshot())
    result = run_scenario_isolated(fixture)
    assert result.status == "passed"
    assert {"repeated_failures", "brute_force"}.issubset(result.actual_detection_keys)
    assert result.validation_scope == "synthetic_scenario_validation"
    assert result.real_world_accuracy_claim is False
    assert any("Evidence event IDs" in item for item in result.evidence)


def test_lab_runner_reports_insufficient_baseline_and_unavailable_thresholds() -> None:
    settings = DetectionLabSettingsSnapshot()
    fixture = build_scenario_fixture("unfamiliar_source_ip", settings)
    insufficient = fixture.model_copy(update={"events": fixture.events[-1:]})
    result = run_scenario_isolated(insufficient)
    assert result.status == "insufficient_baseline"
    assert any("minimum required is 5" in item for item in result.evidence)

    capped = build_scenario_fixture("unusual_login_burst", DetectionLabSettingsSnapshot(brute_force_threshold=130))
    assert run_scenario_isolated(capped).status == "not_evaluable"


def test_isolated_lab_execution_does_not_mutate_workspace_records(client) -> None:
    from datetime import datetime, timedelta, timezone
    from sqlalchemy import select
    from app.main import app

    response = client.post("/api/events", json={
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "username": "production-sentinel", "source_ip": "198.51.100.250",
        "event_type": "login", "status": "failure",
    })
    assert response.status_code == 201
    event_id = response.json()["id"]
    client.post("/api/analytics/analyze", json={"event_ids": [event_id]})
    factory = app.state.session_factory

    def snapshot():
        with factory() as db:
            tables = [AuthEvent, Alert, Incident, AnalysisRun, AuditEntry]
            return {
                model.__tablename__: [
                    tuple((column.key, getattr(row, column.key)) for column in model.__table__.columns)
                    for row in db.scalars(select(model).order_by(model.id)).all()
                ]
                for model in tables
            }

    before = snapshot()
    fixture = build_scenario_fixture("repeated_auth_failures", DetectionLabSettingsSnapshot())
    lab_result = run_scenario_isolated(fixture)
    after = snapshot()
    assert lab_result.status == "passed"
    assert after == before
