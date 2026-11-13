from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient


def _create_event(
    client: TestClient,
    timestamp: datetime,
    ip: str,
    username: str,
    status: str,
):
    return client.post(
        "/api/events",
        json={
            "timestamp": timestamp.isoformat(),
            "username": username,
            "source_ip": ip,
            "event_type": "login",
            "status": status,
        },
    )


def test_behavior_risk_analysis_and_repeated_runs(client: TestClient) -> None:
    now = datetime.now(timezone.utc)
    event_ids: list[int] = []
    for index in range(12):
        response = _create_event(
            client,
            now + timedelta(seconds=index),
            "198.51.100.91",
            "analyst-demo",
            "failure" if index < 5 else "success",
        )
        assert response.status_code == 201
        event_ids.append(response.json()["id"])

    behavior = client.get("/api/analytics/behavior?window_hours=24").json()
    assert behavior["events_analyzed"] == 12
    assert behavior["users"][0]["entity"] == "analyst-demo"
    assert behavior["users"][0]["failures"] == 5

    first = client.post("/api/analytics/analyze", json={"event_ids": event_ids})
    assert first.status_code == 200
    first_result = next(item for item in first.json()["results"] if item["event"]["id"] == event_ids[4])
    assert 0 <= first_result["risk_score"] <= 100
    assert first_result["anomaly_classification"] in {"normal", "suspicious"}
    assert any(factor["key"] == "repeated_failures" for factor in first_result["factors"])
    assert "do not confirm" in first.json()["notice"]

    second = client.post("/api/analytics/analyze", json={"event_ids": [event_ids[4]]})
    assert second.status_code == 200
    repeated = second.json()["results"][0]
    assert repeated["prior_analysis_runs"] >= 1
    assert repeated["previous_risk_score"] == first_result["risk_score"]


def test_incident_correlation_and_local_indicator_workflow(client: TestClient) -> None:
    now = datetime.now(timezone.utc)
    for index in range(5):
        _create_event(client, now + timedelta(seconds=index), "203.0.113.91", "alice", "failure")

    incidents_response = client.get("/api/incidents")
    assert incidents_response.status_code == 200
    incidents = incidents_response.json()
    assert len(incidents) == 1
    incident = incidents[0]
    assert incident["source_ips"] == ["203.0.113.91"]
    assert "alice" in incident["usernames"]

    updated = client.patch(
        f"/api/incidents/{incident['id']}",
        json={"status": "investigating", "analyst_notes": "Validate synthetic sequence."},
    )
    assert updated.status_code == 200
    refreshed = client.get("/api/incidents").json()[0]
    assert refreshed["status"] == "investigating"
    assert refreshed["analyst_notes"] == "Validate synthetic sequence."

    created = client.post(
        "/api/intelligence/indicators",
        json={"source_ip": "203.0.113.91", "kind": "blocklist", "note": "Local lab marker"},
    )
    assert created.status_code == 201
    duplicate = client.post(
        "/api/intelligence/indicators",
        json={"source_ip": "203.0.113.91", "kind": "allowlist", "note": ""},
    )
    assert duplicate.status_code == 409
    assert client.get("/api/intelligence/indicators?kind=blocklist").json()[0]["note"] == "Local lab marker"

    graph = client.get("/api/intelligence/relationships").json()
    assert any(node["indicator"] == "blocklist" for node in graph["nodes"] if node["type"] == "ip")
    assert any(node["type"] == "event" and node.get("timestamp") for node in graph["nodes"])
    assert any(node["type"] == "incident" for node in graph["nodes"])
    assert any(edge["kind"] == "incident_evidence" for edge in graph["edges"])
    assert graph["edges"]

    analysis = client.post("/api/analytics/analyze", json={}).json()
    blocked_source = next(
        item
        for item in analysis["results"]
        if item["event"]["source_ip"] == "203.0.113.91"
    )
    assert any(factor["key"] == "local_blocklist" for factor in blocked_source["factors"])

    deleted = client.delete(f"/api/intelligence/indicators/{created.json()['id']}")
    assert deleted.status_code == 204


def test_copilot_answers_from_local_records_and_rejects_unknown_intents(client: TestClient) -> None:
    now = datetime.now(timezone.utc)
    _create_event(client, now, "192.0.2.111", "target-user", "failure")
    _create_event(client, now + timedelta(seconds=1), "192.0.2.112", "target-user", "failure")

    targeted = client.post(
        "/api/copilot/ask",
        json={"question": "Which accounts were targeted by multiple IPs?"},
    )
    assert targeted.status_code == 200
    assert targeted.json()["intent"] == "accounts_targeted_by_multiple_ips"
    assert "target-user" in " ".join(targeted.json()["facts"])

    today = client.post(
        "/api/copilot/ask",
        json={"question": "Summarize today's failed login events"},
    )
    assert today.json()["intent"] == "today_failed_logins"
    assert "2 failed" in today.json()["answer"]

    unsupported = client.post("/api/copilot/ask", json={"question": "What is the weather?"})
    assert unsupported.json()["intent"] == "unsupported"
    assert "external intelligence" in unsupported.json()["data_scope"]


def test_account_targeted_from_multiple_source_ips_creates_rule_signal(client: TestClient) -> None:
    now = datetime.now(timezone.utc)
    _create_event(client, now, "192.0.2.121", "shared-account", "failure")
    _create_event(client, now + timedelta(seconds=1), "192.0.2.122", "shared-account", "failure")

    alerts = client.get("/api/alerts").json()
    alert = next(item for item in alerts if item["detection_key"] == "multiple_source_ips_account")
    assert alert["severity"] == "high"
    assert len(alert["related_event_ids"]) == 2
    response = client.post(
        "/api/copilot/ask",
        json={"question": "Find accounts targeted by multiple IPs"},
    ).json()
    assert "shared-account" in " ".join(response["facts"])


def test_success_after_failures_rule_correlates_sequence(client: TestClient) -> None:
    now = datetime.now(timezone.utc)
    for index, outcome in enumerate(("failure", "failure", "failure", "success")):
        _create_event(client, now + timedelta(seconds=index), "192.0.2.131", "service-account", outcome)

    alerts = client.get("/api/alerts").json()
    alert = next(item for item in alerts if item["detection_key"] == "success_after_failures")
    assert len(alert["related_event_ids"]) == 4


def test_copilot_uses_persisted_risk_assessment_when_available(client: TestClient) -> None:
    now = datetime.now(timezone.utc)
    for index in range(5):
        _create_event(client, now + timedelta(seconds=index), "198.51.100.151", "admin", "failure")
    assert client.post("/api/analytics/analyze", json={}).status_code == 200

    answer = client.post(
        "/api/copilot/ask",
        json={"question": "Explain the highest-risk alert"},
    ).json()
    assert "/100" in answer["answer"]
    assert any("failures" in fact.lower() for fact in answer["facts"])


def test_custom_detection_rule_preview_pipeline_and_version_history(client: TestClient) -> None:
    now = datetime.now(timezone.utc)
    for index in range(3):
        assert _create_event(client, now - timedelta(minutes=30 * (index + 1)), "192.0.2.202", "old-window-user", "failure").status_code == 201
    for index in range(3):
        assert _create_event(client, now + timedelta(seconds=index), "198.51.100.201", "versioned-user", "failure").status_code == 201

    config = {
        "name": "Versioned account failures",
        "description": "Review repeated local failures.",
        "aggregation": "failed_per_source_ip",
        "threshold": 3,
        "window_minutes": 10,
        "severity": "high",
        "enabled": True,
        "change_note": "Initial lab rule",
    }
    preview = client.post("/api/detection/rules/preview?window_hours=24", json=config)
    assert preview.status_code == 200
    assert preview.json()["candidate_count"] == 1
    assert preview.json()["matched_groups"][0]["source_ip"] == "198.51.100.201"
    assert all(group["source_ip"] != "192.0.2.202" for group in preview.json()["matched_groups"])
    assert "no alerts" in preview.json()["notice"].lower()

    created = client.post("/api/detection/rules", json=config)
    assert created.status_code == 201
    rule_id = created.json()["id"]
    assert created.json()["current_version"] == 1

    assert _create_event(client, now + timedelta(seconds=3), "198.51.100.201", "versioned-user", "failure").status_code == 201
    first_version_alert = next(
        alert for alert in client.get("/api/alerts").json()
        if alert["detection_key"] == f"custom_rule_{rule_id}_v1"
    )
    assert first_version_alert["severity"] == "high"
    assert len(first_version_alert["related_event_ids"]) == 4
    updated = client.patch(
        f"/api/detection/rules/{rule_id}",
        json={"threshold": 5, "change_note": "Raise the lab threshold"},
    )
    assert updated.status_code == 200
    assert updated.json()["current_version"] == 2
    assert _create_event(client, now + timedelta(seconds=4), "198.51.100.201", "versioned-user", "failure").status_code == 201
    assert any(
        alert["detection_key"] == f"custom_rule_{rule_id}_v2"
        for alert in client.get("/api/alerts").json()
    )

    versions = client.get(f"/api/detection/rules/{rule_id}/versions")
    assert [item["version"] for item in versions.json()] == [2, 1]
    assert versions.json()[0]["configuration"]["threshold"] == 5
    assert versions.json()[1]["configuration"]["threshold"] == 3
    integrity = client.get("/api/audit/integrity").json()
    assert integrity["valid"] is True


def test_dashboard_search_ueba_and_attack_coverage_are_evidence_backed(client: TestClient) -> None:
    now = datetime.now(timezone.utc)
    for index in range(5):
        _create_event(client, now + timedelta(seconds=index), "198.51.100.222", "ueba-user", "failure")
    search = client.get("/api/search?q=ueba-user&limit=5")
    assert search.status_code == 200
    assert any(item["kind"] == "event" and item["username"] == "ueba-user" for item in search.json()["results"])
    activity = client.get("/api/dashboard/activity?window_hours=24")
    assert activity.status_code == 200
    assert activity.json()["events_count"] == 5
    behavior = client.get("/api/analytics/behavior?window_hours=24").json()
    profile = next(item for item in behavior["users"] if item["entity"] == "ueba-user")
    assert "entity_risk_score" in profile
    assert "previous_window_events" in profile
    coverage = client.get("/api/attack/coverage").json()
    assert coverage["techniques"]
    assert all("evidence" in technique and "qualification" in technique for technique in coverage["techniques"])


def test_local_ioc_domain_and_approved_soar_workflow_are_simulation_only(client: TestClient) -> None:
    domain = client.post("/api/intelligence/indicators", json={
        "indicator_type": "domain", "value": "Example.org", "kind": "blocklist",
        "note": "Authorized lab IOC", "confidence": 73, "source": "IR case 42",
    })
    assert domain.status_code == 201
    assert domain.json()["value"] == "example.org"
    assert domain.json()["confidence"] == 73
    assert domain.json()["source"] == "IR case 42"
    assert domain.json()["matching_event_count"] == 0

    now = datetime.now(timezone.utc)
    for index in range(5):
        _create_event(client, now + timedelta(seconds=index), "203.0.113.222", "soar-user", "failure")
    alert = client.get("/api/alerts").json()[0]
    workflow = client.post("/api/soar/workflows", json={
        "name": "Require reviewed simulation", "trigger_type": "alert_created",
        "action": "simulate_isolation", "approval_required": True,
    })
    assert workflow.status_code == 201
    assert any(item["id"] == workflow.json()["id"] for item in client.get("/api/soar/workflows").json())
    run = client.post(f"/api/soar/workflows/{workflow.json()['id']}/simulate", json={"entity_type": "alert", "entity_id": alert["id"]})
    assert run.status_code == 201
    assert run.json()["status"] == "awaiting_approval"
    approved = client.patch(f"/api/soar/executions/{run.json()['id']}/approve")
    assert approved.status_code == 200
    assert approved.json()["status"] == "approved_simulation"
    assert "no host" in approved.json()["outcome"].lower()
    assert any(item["id"] == run.json()["id"] for item in client.get("/api/soar/executions").json())
    persisted_ioc = next(item for item in client.get("/api/intelligence/indicators").json() if item["id"] == domain.json()["id"])
    assert persisted_ioc["value"] == "example.org"
