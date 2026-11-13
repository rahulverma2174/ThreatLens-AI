from datetime import datetime, timezone

from fastapi.testclient import TestClient


def test_local_dashboard_api_does_not_require_analyst_api_key(client: TestClient) -> None:
    assert client.get("/api/health").status_code == 200
    assert client.get("/api/events").status_code == 200
    assert client.get("/api/auth/status").status_code == 404
    assert client.get("/api/admin/users").status_code == 404


def test_windows_collector_keeps_its_separate_source_token(client: TestClient) -> None:
    source = client.post("/api/ingestion/sources", json={"name": "win-auth-test"})
    assert source.status_code == 201
    source_token = source.json()["token"]
    response = client.post(
        "/api/ingestion/windows/events",
        headers={"Authorization": f"Bearer {source_token}"},
        json={
            "events": [{
                "event_id": 4625,
                "record_id": 71,
                "computer": "SECURE-WIN01",
                "time_created": datetime.now(timezone.utc).isoformat(),
                "event_data": {
                    "TargetUserName": "failed-user",
                    "IpAddress": "203.0.113.71",
                    "LogonType": "3",
                },
            }],
        },
    )
    assert response.status_code == 200
    assert response.json()["accepted"] == 1
    assert response.json()["source"]["name"] == "win-auth-test"
