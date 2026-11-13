from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from app.dependencies import get_db
from app.models import IngestionSource
from app.schemas import IngestionSourceRead, WindowsSecurityEventBatch, WindowsSecurityIngestionResult
from app.services.windows_ingestion import (
    authenticate_windows_source,
    ingest_windows_batch,
    mark_windows_source_seen,
)

router = APIRouter(prefix="/api/ingestion/windows", tags=["Windows event collector"])
DbSession = Annotated[Session, Depends(get_db)]


def _authenticated_source(db: Session, authorization: str | None) -> IngestionSource:
    scheme, _, token = (authorization or "").partition(" ")
    source = authenticate_windows_source(db, token if scheme.lower() == "bearer" else None)
    if source is None:
        raise HTTPException(status_code=401, detail="A valid enabled ingestion-source bearer token is required.")
    return source


@router.post("/events", response_model=WindowsSecurityIngestionResult)
def ingest_windows_events(
    payload: WindowsSecurityEventBatch,
    request: Request,
    db: DbSession,
    authorization: Annotated[str | None, Header()] = None,
) -> dict[str, object]:
    source = _authenticated_source(db, authorization)
    counts = ingest_windows_batch(db, source, payload.events, request.client.host if request.client else None)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="A concurrent batch used the same Windows record IDs. Retry this batch; accepted records are deduplicated.") from exc
    db.refresh(source)
    return {**counts, "source": source}


@router.post("/heartbeat", response_model=IngestionSourceRead)
def windows_source_heartbeat(
    request: Request,
    db: DbSession,
    authorization: Annotated[str | None, Header()] = None,
) -> IngestionSource:
    source = _authenticated_source(db, authorization)
    mark_windows_source_seen(source, request.client.host if request.client else None)
    db.commit()
    db.refresh(source)
    return source
