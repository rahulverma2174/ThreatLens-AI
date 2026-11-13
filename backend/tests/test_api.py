import json
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient


def create_event(client: TestClient, timestamp: datetime, ip: str, user: str, outcome: str = "failure"):
    return client.post(
        "/api/events",
        json={
            "timestamp": timestamp.isoformat(),
            "username": user,
            "source_ip": ip,
            "event_type": "login",
            "status": outcome,
        },
    )


def test_health_and_event_count_filtering(client: TestClient) -> None:
    assert client.get("/api/health").json()["status"] == "ok"
    assert create_event(client, datetime.now(timezone.utc), "203.0.113.8", "demo").status_code == 201
    assert client.get("/api/events/count?status=failure&search=demo").json() == {"total": 1}
    assert client.get("/api/dashboard/stats").json()["failed_logins"] == 1


def test_brute_force_and_incident_notes_workflow(client: TestClient) -> None:
    now = datetime.now(timezone.utc)
    for index in range(5):
        assert create_event(client, now + timedelta(seconds=index), "198.51.100.24", "admin").status_code == 201
    alerts = client.get("/api/alerts").json()
    brute_force = next(alert for alert in alerts if alert["detection_key"] == "brute_force")
    assert brute_force["severity"] == "high"
    updated = client.patch(
        f"/api/alerts/{brute_force['id']}",
        json={"status": "investigating", "analyst_notes": "Reviewing synthetic sequence."},
    )
    assert updated.json()["status"] == "investigating"
    assert updated.json()["analyst_notes"] == "Reviewing synthetic sequence."
    assert client.get("/api/investigation/198.51.100.24").json()["failed_logins"] == 5


def test_rule_engine_covers_multiple_username_burst_and_success(client: TestClient) -> None:
    now = datetime.now(timezone.utc)
    for index in range(10):
        outcome = "failure" if index < 4 else "success"
        assert create_event(client, now + timedelta(seconds=index), "192.0.2.90", f"user-{index % 4}", outcome).status_code == 201
    keys = {item["detection_key"] for item in client.get("/api/alerts").json()}
    assert {"multiple_usernames", "login_burst"} <= keys


def test_monitoring_settings_and_csv_ingest_export(client: TestClient) -> None:
    assert client.patch("/api/settings/detection", json={"monitoring_enabled": False}).json()["monitoring_enabled"] is False
    csv_body = "timestamp,username,source_ip,event_type,status,user_agent\n2026-11-11T09:00:00Z,alice,203.0.113.20,login,failure,synthetic\n"
    imported = client.post("/api/events/upload", files={"file": ("sample.csv", csv_body, "text/csv")})
    assert imported.status_code == 201
    assert imported.json()["accepted_records"] == 1
    assert imported.json()["status"] == "completed"
    assert "alice" in client.get("/api/reports/events.csv").text
    assert client.get("/api/reports/summary").json()["total_events"] == 1


def test_csv_rejects_bad_file_and_anomaly_needs_minimum_sample(client: TestClient) -> None:
    response = client.post("/api/events/upload", files={"file": ("bad.bin", "x", "application/octet-stream")})
    assert response.status_code == 415
    assert client.post("/api/ml/score", json={}).status_code == 422


def test_json_and_jsonl_import_preserve_normalized_provenance_atomically(client: TestClient) -> None:
    now = datetime.now(timezone.utc)
    records = [
        {
            "timestamp": now.isoformat(),
            "username": "json-user",
            "source_ip": "203.0.113.61",
            "event_type": "ssh",
            "status": "failure",
            "source_host": "edge-01",
            "source_event_id": "syslog-0007",
            "event_metadata": {"facility": "authpriv"},
        },
        {
            "timestamp": (now + timedelta(seconds=1)).isoformat(),
            "username": "json-user",
            "source_ip": "203.0.113.61",
            "event_type": "ssh",
            "status": "success",
        },
    ]
    imported = client.post(
        "/api/events/upload",
        files={"file": ("auth-events.json", json.dumps(records), "application/json")},
    )
    assert imported.status_code == 201
    assert imported.json()["source_format"] == "json"
    assert imported.json()["accepted_records"] == 2
    events = client.get("/api/events?limit=10").json()
    first = next(event for event in events if event["source_event_id"] == "syslog-0007")
    assert first["source_host"] == "edge-01"
    assert first["event_metadata"]["facility"] == "authpriv"
    assert first["event_metadata"]["ingestion_format"] == "json"

    jsonl = '{"username":"would-import","source_ip":"203.0.113.62","status":"failure"}\nnot-json'
    rejected = client.post(
        "/api/events/upload",
        files={"file": ("invalid.jsonl", jsonl, "application/x-ndjson")},
    )
    assert rejected.status_code == 422
    assert client.get("/api/events/count").json()["total"] == 2
