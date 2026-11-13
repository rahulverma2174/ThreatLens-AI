from pathlib import Path
import ipaddress
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.dependencies import get_db
from app.models import IngestionSource
from app.schemas import (
    IngestionSourceCreate,
    IngestionSourceCreated,
    IngestionSourceRead,
    IngestionSourceUpdate,
)
from app.services.audit import record_audit
from app.services.windows_ingestion import (
    create_windows_source,
    revoke_windows_source,
    rotate_windows_source_token,
)

router = APIRouter(prefix="/api/ingestion", tags=["Ingestion"])
DbSession = Annotated[Session, Depends(get_db)]


def require_local_admin(request: Request) -> None:
    if getattr(request.app.state, "test_mode", False):
        return
    peer = request.client.host if request.client else ""
    try:
        local = ipaddress.ip_address(peer).is_loopback
    except ValueError:
        local = False
    if not local:
        raise HTTPException(status_code=403, detail="Ingestion-source administration is available from the local analyst workstation only.")


LocalAdmin = Annotated[None, Depends(require_local_admin)]


@router.get("/sources", response_model=list[IngestionSourceRead])
def list_sources(db: DbSession, _: LocalAdmin) -> list[IngestionSource]:
    return list(db.scalars(select(IngestionSource).order_by(IngestionSource.created_at.desc(), IngestionSource.id.desc()).limit(200)))


@router.post("/sources", response_model=IngestionSourceCreated, status_code=status.HTTP_201_CREATED)
def create_source(payload: IngestionSourceCreate, db: DbSession, _: LocalAdmin) -> dict[str, object]:
    name = payload.name.strip()
    if len(name) < 2:
        raise HTTPException(status_code=422, detail="Source name must contain at least two non-space characters.")
    if db.scalar(select(IngestionSource.id).where(IngestionSource.name.ilike(name))) is not None:
        raise HTTPException(status_code=409, detail="An ingestion source with that name already exists.")
    try:
        source, token = create_windows_source(db, name)
        db.commit()
        db.refresh(source)
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="An ingestion source with that name already exists.") from exc
    return {"source": source, "token": token}


@router.post("/sources/{source_id}/rotate", response_model=IngestionSourceCreated)
def rotate_source(source_id: int, db: DbSession, _: LocalAdmin) -> dict[str, object]:
    source = db.get(IngestionSource, source_id)
    if source is None:
        raise HTTPException(status_code=404, detail="Ingestion source not found.")
    token = rotate_windows_source_token(db, source)
    db.commit()
    db.refresh(source)
    return {"source": source, "token": token}


@router.patch("/sources/{source_id}", response_model=IngestionSourceRead)
def update_source(source_id: int, payload: IngestionSourceUpdate, db: DbSession, _: LocalAdmin) -> IngestionSource:
    source = db.get(IngestionSource, source_id)
    if source is None:
        raise HTTPException(status_code=404, detail="Ingestion source not found.")
    if payload.enabled and source.token_hash is None:
        raise HTTPException(status_code=409, detail="This source token was revoked. Rotate its token before re-enabling it.")
    source.enabled = payload.enabled
    record_audit(db, "ingestion_source.enabled" if payload.enabled else "ingestion_source.disabled", "ingestion_source", source.id, {"name": source.name})
    db.commit()
    db.refresh(source)
    return source


@router.delete("/sources/{source_id}", response_model=IngestionSourceRead)
def revoke_source(source_id: int, db: DbSession, _: LocalAdmin) -> IngestionSource:
    source = db.get(IngestionSource, source_id)
    if source is None:
        raise HTTPException(status_code=404, detail="Ingestion source not found.")
    revoke_windows_source(db, source)
    db.commit()
    db.refresh(source)
    return source


@router.get("/windows/agent.ps1", include_in_schema=False)
def download_windows_agent() -> FileResponse:
    script = Path(__file__).resolve().parents[2] / "scripts" / "threatlens_windows_agent.ps1"
    return FileResponse(script, media_type="text/plain", filename="threatlens_windows_agent.ps1")
