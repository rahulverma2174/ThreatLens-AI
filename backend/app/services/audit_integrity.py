import hashlib
import json
import threading
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import Engine, event, select, text
from sqlalchemy.orm import Session

from app.models import AuditChainState, AuditEntry, utc_now

GENESIS_HASH = "0" * 64
_APPEND_LOCK = threading.Lock()
_LOCK_HELD_KEY = "threatlens_audit_chain_lock_held"


def _canonical_time(value: datetime | str) -> str:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00")) if isinstance(value, str) else value
    normalized = parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
    return normalized.replace(tzinfo=None).isoformat(timespec="microseconds")


def _canonical_details(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value if value is not None else {}


def calculate_entry_hash(
    previous_hash: str,
    *,
    actor: str,
    action: str,
    entity_type: str,
    entity_id: str | None,
    details: Any,
    created_at: datetime | str,
) -> str:
    payload = json.dumps(
        {
            "actor": actor,
            "action": action,
            "entity_type": entity_type,
            "entity_id": entity_id,
            "details": _canonical_details(details),
            "created_at": _canonical_time(created_at),
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    digest = hashlib.sha256()
    digest.update(b"ThreatLens-Audit-v1\0")
    digest.update(bytes.fromhex(previous_hash))
    digest.update(b"\0")
    digest.update(payload)
    return digest.hexdigest()


def ensure_audit_chain(engine: Engine) -> None:
    """Migrate existing audit rows into a hash chain and initialize its head."""
    from sqlalchemy import inspect

    columns = {column["name"] for column in inspect(engine).get_columns("audit_entries")}
    migration_needed = "previous_hash" not in columns or "entry_hash" not in columns
    with engine.begin() as connection:
        if "previous_hash" not in columns:
            connection.execute(text("ALTER TABLE audit_entries ADD COLUMN previous_hash VARCHAR(64)"))
        if "entry_hash" not in columns:
            connection.execute(text("ALTER TABLE audit_entries ADD COLUMN entry_hash VARCHAR(64)"))

        if migration_needed:
            rows = connection.execute(text(
                "SELECT id, actor, action, entity_type, entity_id, details, created_at "
                "FROM audit_entries ORDER BY id"
            )).mappings().all()
            previous_hash = GENESIS_HASH
            entry_count = 0
            for row in rows:
                entry_hash = calculate_entry_hash(
                    previous_hash,
                    actor=row["actor"],
                    action=row["action"],
                    entity_type=row["entity_type"],
                    entity_id=row["entity_id"],
                    details=row["details"],
                    created_at=row["created_at"],
                )
                connection.execute(
                    text("UPDATE audit_entries SET previous_hash = :previous_hash, entry_hash = :entry_hash WHERE id = :id"),
                    {"previous_hash": previous_hash, "entry_hash": entry_hash, "id": row["id"]},
                )
                previous_hash = entry_hash
                entry_count += 1
            state = connection.execute(text("SELECT id FROM audit_chain_state WHERE id = 1")).first()
            if state:
                connection.execute(
                    text("UPDATE audit_chain_state SET head_hash = :head, entry_count = :count, updated_at = :updated WHERE id = 1"),
                    {"head": previous_hash, "count": entry_count, "updated": utc_now()},
                )
            else:
                connection.execute(
                    text("INSERT INTO audit_chain_state (id, head_hash, entry_count, updated_at) VALUES (1, :head, :count, :updated)"),
                    {"head": previous_hash, "count": entry_count, "updated": utc_now()},
                )
        else:
            entry_count = connection.execute(text("SELECT COUNT(*) FROM audit_entries")).scalar_one()
            state = connection.execute(text("SELECT id FROM audit_chain_state WHERE id = 1")).first()
            if state is None and entry_count == 0:
                connection.execute(
                    text("INSERT INTO audit_chain_state (id, head_hash, entry_count, updated_at) VALUES (1, :head, 0, :updated)"),
                    {"head": GENESIS_HASH, "updated": utc_now()},
                )

        if engine.dialect.name == "sqlite":
            connection.execute(text("""
                CREATE TRIGGER IF NOT EXISTS threatlens_audit_no_update
                BEFORE UPDATE ON audit_entries
                BEGIN SELECT RAISE(ABORT, 'audit entries are append-only'); END
            """))
            connection.execute(text("""
                CREATE TRIGGER IF NOT EXISTS threatlens_audit_no_delete
                BEFORE DELETE ON audit_entries
                BEGIN SELECT RAISE(ABORT, 'audit entries are append-only'); END
            """))


@event.listens_for(Session, "before_flush")
def _chain_pending_audit_entries(session: Session, flush_context: object, instances: object) -> None:
    pending = [entry for entry in session.new if isinstance(entry, AuditEntry) and not entry.entry_hash]
    if not pending:
        return
    if not session.info.get(_LOCK_HELD_KEY):
        _APPEND_LOCK.acquire()
        session.info[_LOCK_HELD_KEY] = True

    connection = session.connection()
    state = connection.execute(text(
        "SELECT head_hash, entry_count FROM audit_chain_state WHERE id = 1"
    )).first()
    if state is None:
        raise RuntimeError("The audit chain head is missing; refusing to write an unchained audit entry.")
    previous_hash, entry_count = state

    for entry in pending:
        entry.actor = entry.actor or "Local analyst"
        entry.details = entry.details or {}
        entry.created_at = entry.created_at or utc_now()
        entry.previous_hash = previous_hash
        entry.entry_hash = calculate_entry_hash(
            previous_hash,
            actor=entry.actor,
            action=entry.action,
            entity_type=entry.entity_type,
            entity_id=entry.entity_id,
            details=entry.details,
            created_at=entry.created_at,
        )
        entry_count += 1
        connection.execute(
            text("UPDATE audit_chain_state SET head_hash = :head, entry_count = :count, updated_at = :updated WHERE id = 1"),
            {"head": entry.entry_hash, "count": entry_count, "updated": utc_now()},
        )
        previous_hash = entry.entry_hash


@event.listens_for(Session, "after_transaction_end")
def _release_audit_chain_lock(session: Session, transaction: object) -> None:
    if getattr(transaction, "parent", None) is None and session.info.pop(_LOCK_HELD_KEY, False):
        _APPEND_LOCK.release()


def verify_audit_chain(db: Session) -> dict[str, object]:
    entries = list(db.scalars(select(AuditEntry).order_by(AuditEntry.id)))
    state = db.get(AuditChainState, 1)
    previous_hash = GENESIS_HASH
    first_invalid_entry_id: int | None = None
    for entry in entries:
        computed_hash = calculate_entry_hash(
            previous_hash,
            actor=entry.actor,
            action=entry.action,
            entity_type=entry.entity_type,
            entity_id=entry.entity_id,
            details=entry.details,
            created_at=entry.created_at,
        )
        if first_invalid_entry_id is None and (
            entry.previous_hash != previous_hash or entry.entry_hash != computed_hash
        ):
            first_invalid_entry_id = entry.id
        previous_hash = entry.entry_hash or ""

    head_matches = state is not None and state.entry_count == len(entries) and state.head_hash == previous_hash
    valid = first_invalid_entry_id is None and head_matches
    if valid:
        message = f"Verified {len(entries)} append-only audit entries and the stored chain head."
    elif first_invalid_entry_id is not None:
        message = f"Audit chain verification failed at entry #{first_invalid_entry_id}."
    elif state is None:
        message = "The audit chain head record is missing."
    else:
        message = "The verified audit entries do not match the stored chain head or entry count."
    return {
        "valid": valid,
        "checked_entries": len(entries),
        "head_hash": state.head_hash if state else None,
        "first_invalid_entry_id": first_invalid_entry_id,
        "checked_at": utc_now(),
        "message": message,
    }
