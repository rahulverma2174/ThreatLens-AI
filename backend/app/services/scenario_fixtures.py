"""Deterministic, side-effect-free synthetic fixtures for the Detection Lab."""

from datetime import datetime, timedelta, timezone
from typing import Final

from app.schemas import (
    DetectionLabFixture,
    DetectionLabScenarioId,
    DetectionLabScenarioRead,
    DetectionLabSettingsSnapshot,
    DetectionLabSyntheticEvent,
)

SCENARIO_VERSION: Final = "1.0"
MAX_SCENARIO_EVENTS: Final = 250
MIN_USER_BASELINE_EVENTS: Final = 5
DEFAULT_FIXTURE_ANCHOR: Final = datetime(2025, 1, 15, 12, 0, tzinfo=timezone.utc)

SCENARIOS: Final[dict[str, dict[str, object]]] = {
    "repeated_auth_failures": {
        "name": "Repeated authentication failures",
        "description": "Synthetic failed logons from one test source exercise configured repeated-failure thresholds.",
        "minimum_baseline_events": 0,
        "technique_candidates": ["T1110"],
    },
    "unusual_login_burst": {
        "name": "Unusual login burst",
        "description": "Synthetic successful logons from one test source exercise the configured event-volume burst threshold.",
        "minimum_baseline_events": 0,
        "technique_candidates": [],
    },
    "multiple_accounts_one_source": {
        "name": "Multiple accounts from one source",
        "description": "Synthetic failures for distinct test accounts exercise the configured targeted-username threshold.",
        "minimum_baseline_events": 0,
        "technique_candidates": ["T1110"],
    },
    "unfamiliar_source_ip": {
        "name": "Unfamiliar source IP",
        "description": "A synthetic account baseline is followed by a successful event from a source absent from that baseline.",
        "minimum_baseline_events": MIN_USER_BASELINE_EVENTS,
        "technique_candidates": [],
    },
    "suspicious_login_time": {
        "name": "Suspicious login time pattern",
        "description": "A synthetic account baseline at one UTC hour is followed by a successful event at a rare UTC hour.",
        "minimum_baseline_events": MIN_USER_BASELINE_EVENTS,
        "technique_candidates": [],
    },
}

_TEST_IP = "198.51.100.41"
_KNOWN_IP = "203.0.113.24"
_NEW_IP = "192.0.2.77"


def list_scenarios() -> list[DetectionLabScenarioRead]:
    """Return versioned scenario descriptions without implying test outcomes."""
    return [
        DetectionLabScenarioRead(
            scenario_id=scenario_id,  # type: ignore[arg-type]
            version=SCENARIO_VERSION,
            name=str(definition["name"]),
            description=str(definition["description"]),
            minimum_baseline_events=int(definition["minimum_baseline_events"]),
            technique_candidates=list(definition["technique_candidates"]),
        )
        for scenario_id, definition in SCENARIOS.items()
    ]


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _event(at: datetime, username: str, source_ip: str, result: str) -> DetectionLabSyntheticEvent:
    return DetectionLabSyntheticEvent(
        timestamp=_utc(at),
        username=username,
        source_ip=source_ip,
        event_type="login",
        status=result,  # type: ignore[arg-type]
    )


def _expected_repeated(settings: DetectionLabSettingsSnapshot) -> list[str]:
    count = max(settings.repeated_failure_threshold, settings.brute_force_threshold)
    expected = ["repeated_failures", "brute_force"]
    if count >= settings.brute_force_threshold * 2:
        expected.append("login_burst")
    return expected


def _expected_multiple_accounts(settings: DetectionLabSettingsSnapshot) -> list[str]:
    count = settings.targeted_username_threshold
    expected = ["multiple_usernames"]
    if count >= settings.repeated_failure_threshold:
        expected.append("repeated_failures")
    if count >= settings.brute_force_threshold:
        expected.append("brute_force")
    if count >= settings.brute_force_threshold * 2:
        expected.append("login_burst")
    return expected


def build_scenario_fixture(
    scenario_id: DetectionLabScenarioId,
    settings: DetectionLabSettingsSnapshot,
    *,
    anchor: datetime = DEFAULT_FIXTURE_ANCHOR,
) -> DetectionLabFixture:
    """Build deterministic TEST-NET events only; does not access or mutate a database."""
    anchor = _utc(anchor)
    expected_keys: list[str] = []
    expected_factors: list[str] = []
    event_count = 0

    if scenario_id == "repeated_auth_failures":
        event_count = max(settings.repeated_failure_threshold, settings.brute_force_threshold)
        expected_keys = _expected_repeated(settings)
    elif scenario_id == "unusual_login_burst":
        event_count = settings.brute_force_threshold * 2
        expected_keys = ["login_burst"]
    elif scenario_id == "multiple_accounts_one_source":
        event_count = settings.targeted_username_threshold
        expected_keys = _expected_multiple_accounts(settings)
    elif scenario_id == "unfamiliar_source_ip":
        event_count = MIN_USER_BASELINE_EVENTS + 1
        expected_factors = ["new_source_for_user"]
    elif scenario_id == "suspicious_login_time":
        event_count = MIN_USER_BASELINE_EVENTS + 1
        expected_factors = ["unusual_login_hour"]
    else:
        raise ValueError("Unsupported Detection Lab scenario.")

    base = {
        "scenario_id": scenario_id,
        "scenario_version": SCENARIO_VERSION,
        "settings_snapshot": settings,
        "expected_detection_keys": expected_keys,
        "expected_risk_factors": expected_factors,
        "minimum_baseline_events": int(SCENARIOS[scenario_id]["minimum_baseline_events"]),
        "technique_candidates": list(SCENARIOS[scenario_id]["technique_candidates"]),
    }
    if event_count > MAX_SCENARIO_EVENTS:
        return DetectionLabFixture(
            **base,
            supported=False,
            unsupported_reason=(
                f"Current thresholds require {event_count} synthetic records, exceeding the "
                f"scenario cap of {MAX_SCENARIO_EVENTS}. Thresholds were not changed."
            ),
            events=[],
        )

    events: list[DetectionLabSyntheticEvent] = []
    if scenario_id == "repeated_auth_failures":
        events = [_event(anchor + timedelta(seconds=index), "lab-user", _TEST_IP, "failure") for index in range(event_count)]
    elif scenario_id == "unusual_login_burst":
        events = [_event(anchor + timedelta(seconds=index), "lab-user", _TEST_IP, "success") for index in range(event_count)]
    elif scenario_id == "multiple_accounts_one_source":
        events = [_event(anchor + timedelta(seconds=index), f"lab-user-{index + 1}", _TEST_IP, "failure") for index in range(event_count)]
    elif scenario_id == "unfamiliar_source_ip":
        history = [
            _event(anchor - timedelta(days=day), "lab-user", _KNOWN_IP, "success")
            for day in range(MIN_USER_BASELINE_EVENTS, 0, -1)
        ]
        events = history + [_event(anchor, "lab-user", _NEW_IP, "success")]
    elif scenario_id == "suspicious_login_time":
        history = [
            _event((anchor - timedelta(days=day)).replace(hour=9, minute=0, second=0, microsecond=0), "lab-user", _KNOWN_IP, "success")
            for day in range(MIN_USER_BASELINE_EVENTS, 0, -1)
        ]
        target_time = anchor.replace(hour=2, minute=0, second=0, microsecond=0)
        if target_time <= history[-1].timestamp:
            target_time += timedelta(days=1)
        events = history + [_event(target_time, "lab-user", _KNOWN_IP, "success")]

    return DetectionLabFixture(**base, supported=True, unsupported_reason=None, events=events)
