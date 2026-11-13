from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import LocalIndicator, utc_now
from app.schemas import LocalIndicatorCreate


def get_local_indicator_map(db: Session) -> dict[str, LocalIndicator]:
    now = utc_now()
    return {
        indicator.source_ip: indicator
        for indicator in db.scalars(select(LocalIndicator).where(
            LocalIndicator.indicator_type == "ip",
            (LocalIndicator.expires_at.is_(None)) | (LocalIndicator.expires_at > now),
        ))
    }


def list_local_indicators(db: Session, kind: str | None = None) -> list[LocalIndicator]:
    query = select(LocalIndicator).order_by(LocalIndicator.updated_at.desc(), LocalIndicator.id.desc())
    if kind:
        query = query.where(LocalIndicator.kind == kind)
    return list(db.scalars(query.limit(1000)))


def create_local_indicator(db: Session, payload: LocalIndicatorCreate) -> LocalIndicator:
    indicator = LocalIndicator(
        source_ip=str(payload.value),
        indicator_type=payload.indicator_type,
        kind=payload.kind,
        note=payload.note.strip(),
        confidence=payload.confidence,
        source=payload.source.strip(),
        expires_at=payload.expires_at,
    )
    db.add(indicator)
    return indicator


def update_local_indicator(
    db: Session,
    indicator_id: int,
    payload: LocalIndicatorCreate,
) -> LocalIndicator | None:
    indicator = db.get(LocalIndicator, indicator_id)
    if indicator is None:
        return None
    indicator.source_ip = str(payload.value)
    indicator.indicator_type = payload.indicator_type
    indicator.kind = payload.kind
    indicator.note = payload.note.strip()
    indicator.confidence = payload.confidence
    indicator.source = payload.source.strip()
    indicator.expires_at = payload.expires_at
    indicator.updated_at = utc_now()
    return indicator


def delete_local_indicator(db: Session, indicator_id: int) -> bool:
    indicator = db.get(LocalIndicator, indicator_id)
    if indicator is None:
        return False
    db.delete(indicator)
    return True
