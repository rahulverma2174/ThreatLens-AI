from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient


def _event(client: TestClient, at: datetime, username: str, ip: str, result: str = "failure") -> int:
    response = client.post("/api/events", json={
        "timestamp": at.isoformat(), "username": username, "source_ip": ip,
        "event_type": "login", "status": result,
    })
    assert response.status_code == 201
    return response.json()["id"]


def _query(start: datetime, end: datetime, conditions: list[dict[str, str]], logic: str = "AND") -> dict[str, object]:
    return {"start_time": start.isoformat(), "end_time": end.isoformat(), "logic": logic, "conditions": conditions}


def test_hunt_search_and_saved_queries_are_bounded_and_audited(client: TestClient) -> None:
    start = datetime.now(timezone.utc)
    event_id = _event(client, start, "hunt-user", "198.51.100.201")
    _event(client, start + timedelta(seconds=1), "other-user", "203.0.113.201", "success")
    body = {"query": _query(start - timedelta(seconds=1), start + timedelta(seconds=10), [
        {"field": "username", "operator": "contains", "value": "hunt"},
        {"field": "result", "operator": "equals", "value": "failure"},
    ])}
    response = client.post("/api/hunting/search", json=body)
    assert response.status_code == 200
    assert response.json()["total"] == 1
    assert response.json()["results"][0]["event"]["id"] == event_id
    assert response.json()["execution_ms"] >= 0

    saved = client.post("/api/hunting/queries", json={"name": "Failure hunt", "query": body["query"]})
    assert saved.status_code == 201
    listed = client.get("/api/hunting/queries")
    assert listed.status_code == 200 and listed.json()[0]["id"] == saved.json()["id"]
    audit = client.get("/api/audit?action=hunt_query.created&entity_type=saved_hunt_query")
    assert audit.status_code == 200
    assert audit.json()[0]["entity_id"] == str(saved.json()["id"])
    assert client.delete(f"/api/hunting/queries/{saved.json()['id']}").status_code == 204


def test_hunt_export_protects_csv_formulas_and_enforces_row_cap(client: TestClient) -> None:
    start = datetime.now(timezone.utc)
    _event(client, start, "=2+2", "198.51.100.202")
    body = {"query": _query(start - timedelta(seconds=1), start + timedelta(seconds=1), [
        {"field": "username", "operator": "equals", "value": "=2+2"},
    ]), "max_rows": 1}
    response = client.post("/api/hunting/export", json=body)
    assert response.status_code == 200
    assert "' =2+2" not in response.text
    assert "'=2+2" in response.text
    assert response.headers["content-type"].startswith("text/csv")

    body["max_rows"] = 0
    assert client.post("/api/hunting/export", json=body).status_code == 422


def test_hunt_rejects_unsupported_fields_and_excessive_ranges(client: TestClient) -> None:
    start = datetime.now(timezone.utc)
    malformed = {"query": _query(start - timedelta(days=366), start, [
        {"field": "source_ip", "operator": "equals", "value": "not-an-ip"},
    ])}
    assert client.post("/api/hunting/search", json=malformed).status_code == 422
    injection = {"query": _query(start - timedelta(seconds=1), start, [
        {"field": "__class__", "operator": "equals", "value": "x"},
    ])}
    assert client.post("/api/hunting/search", json=injection).status_code == 422


def test_hunt_links_alert_and_incident_evidence_and_filters_by_severity(client: TestClient) -> None:
    start = datetime.now(timezone.utc)
    for index in range(5):
        _event(client, start + timedelta(seconds=index), "hunt-target", "198.51.100.221")
    response = client.post("/api/hunting/search", json={"query": _query(
        start - timedelta(seconds=1), start + timedelta(seconds=10),
        [{"field": "severity", "operator": "equals", "value": "high"}],
    ), "limit": 20, "offset": 0})
    assert response.status_code == 200, response.text
    assert response.json()["total"] >= 1
    row = response.json()["results"][0]
    assert row["alerts"] and any(alert["severity"] == "high" for alert in row["alerts"])
    assert row["incidents"]


def test_lab_run_persists_reproducibility_snapshot_without_workspace_or_audit_changes(client: TestClient) -> None:
    from sqlalchemy import select
    from app.main import app
    from app.models import Alert, AnalysisRun, AuditEntry, AuthEvent, DetectionLabRun, Incident

    factory = app.state.session_factory

    def workspace_snapshot():
        with factory() as db:
            return {
                model.__tablename__: [
                    tuple((column.key, getattr(row, column.key)) for column in model.__table__.columns)
                    for row in db.scalars(select(model).order_by(model.id)).all()
                ]
                for model in (AuthEvent, Alert, Incident, AnalysisRun, AuditEntry)
            }

    before = workspace_snapshot()
    response = client.post("/api/detection-lab/runs", json={"scenario_id": "repeated_auth_failures"})
    assert response.status_code == 201, response.text
    run = response.json()
    assert run["status"] == "passed"
    assert run["scenario_version"] == "1.0"
    assert run["execution_metadata"]["isolated_database"] == "temporary_sqlite_file"
    assert run["execution_metadata"]["synthetic_event_count"] == 5
    assert run["settings_snapshot"]["brute_force_threshold"] == 5
    assert run["fixture_snapshot"]
    assert run["result"]["validation_scope"] == "synthetic_scenario_validation"
    assert workspace_snapshot() == before

    history = client.get("/api/detection-lab/runs?limit=5")
    assert history.status_code == 200 and history.json()[0]["id"] == run["id"]
    lab_rows = client.get("/api/detection-lab/summary").json()
    assert lab_rows["total_runs"] == 1
    assert "do not measure real-world detection accuracy" in lab_rows["notice"]

    review_response = client.post(f"/api/detection-lab/runs/{run['id']}/reviews", json={
        "detection_key": "brute_force", "disposition": "false_positive", "notes": "Reviewed synthetic output.",
    })
    assert review_response.status_code == 201
    audit = client.get("/api/audit?action=detection_lab.finding_reviewed&entity_type=detection_lab_review")
    assert audit.status_code == 200 and audit.json()[0]["details"]["disposition"] == "false_positive"


def test_lab_rejects_reviews_for_unobserved_keys_and_does_not_force_pass(client: TestClient) -> None:
    run = client.post("/api/detection-lab/runs", json={"scenario_id": "repeated_auth_failures"}).json()
    review = client.post(f"/api/detection-lab/runs/{run['id']}/reviews", json={
        "detection_key": "made_up_rule", "disposition": "false_positive",
    })
    assert review.status_code == 422

    disabled = client.patch("/api/settings/detection", json={"monitoring_enabled": False})
    assert disabled.status_code == 200
    result = client.post("/api/detection-lab/runs", json={"scenario_id": "repeated_auth_failures"})
    assert result.status_code == 201
    assert result.json()["status"] == "failed"
    assert result.json()["result"]["missing_detection_keys"]
