from datetime import datetime, timezone
from time import perf_counter
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.dependencies import get_db
from app.models import DetectionLabReview, DetectionLabRun, DetectionRule, DetectionSettings, utc_now
from app.schemas import (
    DetectionLabReviewCreate,
    DetectionLabReviewRead,
    DetectionLabRunRead,
    DetectionLabRunRequest,
    DetectionLabScenarioRead,
    DetectionLabSummary,
    DetectionLabRuleSummary,
)
from app.services.audit import record_audit
from app.services.detection_lab import run_scenario_isolated, snapshot_enabled_rules, snapshot_settings
from app.services.scenario_fixtures import build_scenario_fixture, list_scenarios

router = APIRouter(prefix="/api/detection-lab", tags=["Detection Validation Lab"])
DbSession = Annotated[Session, Depends(get_db)]
LAB_SCOPE_NOTICE = (
    "These figures summarize deterministic synthetic scenario validation in this workspace. "
    "They do not measure real-world detection accuracy, precision, recall, or attack prevalence."
)


@router.get("/scenarios", response_model=list[DetectionLabScenarioRead])
def scenarios() -> list[DetectionLabScenarioRead]:
    return list_scenarios()


@router.post("/runs", response_model=DetectionLabRunRead, status_code=status.HTTP_201_CREATED)
def execute_scenario(payload: DetectionLabRunRequest, db: DbSession) -> DetectionLabRun:
    started_at = datetime.now(timezone.utc)
    started = perf_counter()
    stored_settings = db.get(DetectionSettings, 1)
    settings_snapshot = snapshot_settings(stored_settings)
    enabled_rules = list(db.scalars(
        select(DetectionRule).where(DetectionRule.enabled.is_(True)).order_by(DetectionRule.id).limit(500)
    ))
    rules_snapshot = snapshot_enabled_rules(enabled_rules)
    fixture = build_scenario_fixture(payload.scenario_id, settings_snapshot, anchor=started_at)
    result = run_scenario_isolated(fixture, rules_snapshot)
    completed_at = datetime.now(timezone.utc)
    run = DetectionLabRun(
        scenario_id=fixture.scenario_id,
        scenario_version=fixture.scenario_version,
        status=result.status,
        result=result.model_dump(mode="json"),
        settings_snapshot=settings_snapshot.model_dump(mode="json"),
        enabled_rules_snapshot=[item.model_dump(mode="json") for item in rules_snapshot],
        fixture_snapshot=[item.model_dump(mode="json") for item in fixture.events],
        execution_metadata={
            "started_at": started_at.isoformat(),
            "completed_at": completed_at.isoformat(),
            "duration_ms": round((perf_counter() - started) * 1000, 3),
            "isolated_database": "temporary_sqlite_file",
            "synthetic_event_count": len(fixture.events),
            "execution_mode": "scenario_validation_only",
        },
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    # A scenario run records only its dedicated lab row. Production events, alerts,
    # incidents, analyses, and audit history remain outside the isolated runner.
    return run


@router.get("/runs", response_model=list[DetectionLabRunRead])
def run_history(
    db: DbSession,
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=100_000),
) -> list[DetectionLabRun]:
    return list(db.scalars(
        select(DetectionLabRun).order_by(DetectionLabRun.created_at.desc(), DetectionLabRun.id.desc()).limit(limit).offset(offset)
    ))


@router.get("/runs/{run_id}/reviews", response_model=list[DetectionLabReviewRead])
def run_reviews(run_id: int, db: DbSession) -> list[DetectionLabReview]:
    if db.get(DetectionLabRun, run_id) is None:
        raise HTTPException(status_code=404, detail="Detection Lab run not found.")
    return list(db.scalars(select(DetectionLabReview).where(DetectionLabReview.run_id == run_id).order_by(DetectionLabReview.reviewed_at.desc())))


@router.post("/runs/{run_id}/reviews", response_model=DetectionLabReviewRead, status_code=status.HTTP_201_CREATED)
def review_finding(run_id: int, payload: DetectionLabReviewCreate, db: DbSession) -> DetectionLabReview:
    run = db.get(DetectionLabRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Detection Lab run not found.")
    observed = set(run.result.get("actual_detection_keys", []))
    if payload.detection_key not in observed:
        raise HTTPException(status_code=422, detail="Only a detection observed in this run can be reviewed.")
    review = db.scalar(select(DetectionLabReview).where(
        DetectionLabReview.run_id == run_id,
        DetectionLabReview.detection_key == payload.detection_key,
    ))
    action = "detection_lab.finding_reviewed"
    if review is None:
        review = DetectionLabReview(
            run_id=run_id,
            detection_key=payload.detection_key,
            disposition=payload.disposition,
            notes=payload.notes.strip(),
        )
        db.add(review)
        db.flush()
    else:
        review.disposition = payload.disposition
        review.notes = payload.notes.strip()
        review.reviewed_at = utc_now()
        action = "detection_lab.finding_review_updated"
    record_audit(db, action, "detection_lab_review", review.id, {
        "run_id": run_id,
        "detection_key": payload.detection_key,
        "disposition": payload.disposition,
        "notes": payload.notes.strip(),
    })
    db.commit()
    db.refresh(review)
    return review


@router.get("/summary", response_model=DetectionLabSummary)
def lab_summary(db: DbSession) -> dict[str, object]:
    runs = list(db.scalars(select(DetectionLabRun).order_by(DetectionLabRun.created_at.desc()).limit(1_000)))
    run_ids = [run.id for run in runs]
    reviews = list(db.scalars(select(DetectionLabReview).where(DetectionLabReview.run_id.in_(run_ids)))) if run_ids else []
    observed_by_key: dict[str, int] = {}
    for run in runs:
        for key in set(run.result.get("actual_detection_keys", [])):
            observed_by_key[key] = observed_by_key.get(key, 0) + 1
    reviews_by_key: dict[str, list[DetectionLabReview]] = {}
    for review in reviews:
        reviews_by_key.setdefault(review.detection_key, []).append(review)
    keys = sorted(set(observed_by_key) | set(reviews_by_key))
    per_rule = [
        DetectionLabRuleSummary(
            detection_key=key,
            scenario_observations=observed_by_key.get(key, 0),
            reviewed_count=len(reviews_by_key.get(key, [])),
            false_positive_reviews=sum(item.disposition == "false_positive" for item in reviews_by_key.get(key, [])),
            notice="Synthetic scenario observations only; not a real-world accuracy metric.",
        )
        for key in keys
    ]
    return {
        "total_runs": len(runs),
        "passed_runs": sum(run.status == "passed" for run in runs),
        "failed_runs": sum(run.status == "failed" for run in runs),
        "insufficient_baseline_runs": sum(run.status == "insufficient_baseline" for run in runs),
        "not_evaluable_runs": sum(run.status == "not_evaluable" for run in runs),
        "rule_summaries": per_rule,
        "notice": LAB_SCOPE_NOTICE if len(runs) < 1_000 else f"{LAB_SCOPE_NOTICE} Summary is limited to the latest 1,000 runs.",
    }
