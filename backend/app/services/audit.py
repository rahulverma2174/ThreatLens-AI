from sqlalchemy.orm import Session

from app.models import AuditEntry
from app.services.audit_integrity import verify_audit_chain
from app.services.identity import current_actor


def record_audit(
    db: Session,
    action: str,
    entity_type: str,
    entity_id: int | str | None = None,
    details: dict[str, object] | None = None,
    actor: str | None = None,
) -> None:
    """Add an audit record to the current transaction."""
    db.add(
        AuditEntry(
            actor=actor or current_actor() or "Local analyst",
            action=action,
            entity_type=entity_type,
            entity_id=str(entity_id) if entity_id is not None else None,
            details=details or {},
        )
    )
