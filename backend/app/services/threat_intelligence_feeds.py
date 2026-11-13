"""External threat-feed indicator provenance and deduplicated persistence."""

from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
import secrets

from sqlalchemy import case, or_, select, update
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from app.config import Settings
from app.models import ThreatFeed, ThreatFeedSyncRun, ThreatIndicator, ThreatIndicatorSource, utc_now
from app.schemas import ThreatFeedFieldMapping
from app.services.audit import record_audit
from app.services.threat_feed_transport import fetch_feed_body
from app.services.threat_indicator_validation import FeedIndicatorRecord, parse_feed_body


class FeedSyncBusyError(RuntimeError):
    pass


class FeedSyncUnavailableError(RuntimeError):
    pass


def upsert_feed_indicators(
    db: Session,
    feed: ThreatFeed,
    sync_run: ThreatFeedSyncRun,
    indicators: Iterable[FeedIndicatorRecord],
) -> dict[str, int]:
    """Atomically upsert canonical IOC identities and source-specific observations."""
    inserted = 0
    updated = 0
    now = utc_now()
    for item in indicators:
        prior_id = db.scalar(select(ThreatIndicator.id).where(
            ThreatIndicator.indicator_type == item.indicator_type,
            ThreatIndicator.value == item.value,
        ))
        indicator_insert = sqlite_insert(ThreatIndicator).values(
            indicator_type=item.indicator_type,
            value=item.value,
            first_seen=item.first_seen,
            last_seen=item.last_seen,
            analyst_disposition="unreviewed",
            created_at=now,
            updated_at=now,
        )
        db.execute(indicator_insert.on_conflict_do_update(
            index_elements=["indicator_type", "value"],
            set_={
                "first_seen": case(
                    (ThreatIndicator.first_seen > indicator_insert.excluded.first_seen, indicator_insert.excluded.first_seen),
                    else_=ThreatIndicator.first_seen,
                ),
                "last_seen": case(
                    (ThreatIndicator.last_seen < indicator_insert.excluded.last_seen, indicator_insert.excluded.last_seen),
                    else_=ThreatIndicator.last_seen,
                ),
                "updated_at": now,
            },
        ))
        indicator_id = db.scalar(select(ThreatIndicator.id).where(
            ThreatIndicator.indicator_type == item.indicator_type,
            ThreatIndicator.value == item.value,
        ))
        if indicator_id is None:
            raise RuntimeError("Indicator upsert did not produce a persisted indicator.")
        inserted += prior_id is None
        updated += prior_id is not None

        source_insert = sqlite_insert(ThreatIndicatorSource).values(
            indicator_id=indicator_id,
            feed_id=feed.id,
            source_name=feed.name,
            source_reference=item.source_reference,
            confidence=item.confidence,
            first_seen=item.first_seen,
            last_seen=item.last_seen,
            expires_at=item.expires_at,
            latest_sync_run_id=sync_run.id,
            created_at=now,
            updated_at=now,
        )
        source_updates = {
            "source_name": source_insert.excluded.source_name,
            "first_seen": case(
                (ThreatIndicatorSource.first_seen > source_insert.excluded.first_seen, source_insert.excluded.first_seen),
                else_=ThreatIndicatorSource.first_seen,
            ),
            "last_seen": case(
                (ThreatIndicatorSource.last_seen < source_insert.excluded.last_seen, source_insert.excluded.last_seen),
                else_=ThreatIndicatorSource.last_seen,
            ),
            "latest_sync_run_id": source_insert.excluded.latest_sync_run_id,
            "updated_at": now,
        }
        if item.confidence is not None:
            source_updates["confidence"] = source_insert.excluded.confidence
        if item.expiry_supplied or item.expires_at is not None:
            source_updates["expires_at"] = source_insert.excluded.expires_at
        db.execute(source_insert.on_conflict_do_update(
            index_elements=["indicator_id", "feed_id", "source_reference"],
            set_=source_updates,
        ))
    return {"inserted_count": int(inserted), "updated_count": int(updated)}


def observation_is_active(source: ThreatIndicatorSource, now: datetime | None = None) -> bool:
    now = now or datetime.now(timezone.utc)
    expiry = source.expires_at
    if expiry is None:
        return True
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    return expiry > now


def indicator_is_active(sources: Iterable[ThreatIndicatorSource], now: datetime | None = None) -> bool:
    """An indicator remains active while any independent source observation is active."""
    return any(observation_is_active(source, now) for source in sources)


def _safe_failure_message(error: Exception) -> str:
    if isinstance(error, ValueError):
        return str(error)[:1000]
    # Do not echo request headers, URLs, response bodies, or arbitrary exception
    # payloads where a provider may have reflected sensitive input.
    return f"Feed synchronization failed ({type(error).__name__})."


def synchronize_feed(
    db: Session,
    feed_id: int,
    settings: Settings,
    *,
    fetcher=fetch_feed_body,
) -> ThreatFeedSyncRun:
    """Claim a feed atomically, fetch/validate it, and persist provenance transactionally."""
    feed = db.get(ThreatFeed, feed_id)
    if feed is None:
        raise LookupError("Threat feed not found.")
    if not feed.enabled:
        raise FeedSyncUnavailableError("Disabled feeds cannot be synchronized.")

    now = utc_now()
    token = secrets.token_hex(24)
    claim = db.execute(
        update(ThreatFeed)
        .where(
            ThreatFeed.id == feed_id,
            ThreatFeed.enabled.is_(True),
            or_(ThreatFeed.sync_lock_token.is_(None), ThreatFeed.sync_lock_expires_at <= now),
        )
        .values(
            sync_lock_token=token,
            sync_lock_expires_at=now + timedelta(seconds=90),
            last_attempt_at=now,
            last_sync_status="syncing",
            updated_at=now,
        )
        .execution_options(synchronize_session=False)
    )
    if claim.rowcount != 1:
        db.rollback()
        raise FeedSyncBusyError("A synchronization for this feed is already in progress.")
    db.commit()
    feed = db.get(ThreatFeed, feed_id)
    if feed is not None:
        db.refresh(feed)
    if feed is None or feed.sync_lock_token != token:
        db.rollback()
        raise FeedSyncBusyError("Synchronization lock could not be acquired.")

    started_at = utc_now()
    prior_runs = list(db.scalars(select(ThreatFeedSyncRun).where(
        ThreatFeedSyncRun.feed_id == feed_id,
        ThreatFeedSyncRun.status == "running",
    )))
    for prior in prior_runs:
        prior.status = "failed"
        prior.completed_at = started_at
        prior.error_summary = "Previous synchronization ended before completion; no new indicator changes were applied."
    run = ThreatFeedSyncRun(feed_id=feed_id, status="running", started_at=started_at)
    db.add(run)
    db.commit()
    db.refresh(run)
    run_id = run.id
    response_bytes = 0
    fetched_count = accepted_count = rejected_count = inserted_count = updated_count = 0
    digest = ""
    try:
        body, response_bytes = fetcher(feed, settings)
        parsed = parse_feed_body(
            body,
            feed.feed_format,
            # JSON in the model may be a plain mapping; validation re-applies the
            # field allowlist before choosing feed-controlled keys.
            ThreatFeedFieldMapping.model_validate(feed.field_mapping),
            max_bytes=settings.feed_max_response_bytes,
            max_records=settings.feed_max_records,
        )
        fetched_count = int(parsed["fetched_count"])
        accepted_count = int(parsed["accepted_count"])
        rejected_count = int(parsed["rejected_count"])
        digest = str(parsed["content_sha256"])
        db.refresh(feed)
        db.refresh(run)
        counts = upsert_feed_indicators(db, feed, run, parsed["indicators"])
        inserted_count = counts["inserted_count"]
        updated_count = counts["updated_count"]
        completed_at = utc_now()
        status_value = "partial" if rejected_count else "succeeded"
        run.status = status_value
        run.completed_at = completed_at
        run.response_bytes = response_bytes
        run.fetched_count = fetched_count
        run.accepted_count = accepted_count
        run.inserted_count = inserted_count
        run.updated_count = updated_count
        run.rejected_count = rejected_count
        run.content_sha256 = digest
        errors = parsed["error_examples"]
        run.error_summary = ("; ".join(errors[:4]))[:1000] if errors else ""
        feed.last_attempt_at = started_at
        feed.last_success_at = completed_at
        feed.last_error = run.error_summary
        feed.last_sync_status = status_value
        feed.last_accepted_count = accepted_count
        feed.last_rejected_count = rejected_count
        feed.sync_lock_token = None
        feed.sync_lock_expires_at = None
        feed.updated_at = completed_at
        record_audit(db, "threat_feed.sync_completed", "threat_feed_sync_run", run.id, {
            "feed_id": feed.id,
            "status": status_value,
            "fetched_count": fetched_count,
            "accepted_count": accepted_count,
            "inserted_count": inserted_count,
            "updated_count": updated_count,
            "rejected_count": rejected_count,
        })
        db.commit()
        db.refresh(run)
        return run
    except Exception as exc:
        db.rollback()
        run = db.get(ThreatFeedSyncRun, run_id)
        feed = db.get(ThreatFeed, feed_id)
        if run is None or feed is None:
            raise
        completed_at = utc_now()
        message = _safe_failure_message(exc)
        run.status = "failed"
        run.completed_at = completed_at
        run.response_bytes = response_bytes
        run.fetched_count = fetched_count
        run.accepted_count = accepted_count
        run.inserted_count = 0
        run.updated_count = 0
        run.rejected_count = rejected_count
        run.content_sha256 = digest
        run.error_summary = message
        feed.last_attempt_at = started_at
        feed.last_error = message
        feed.last_sync_status = "failed"
        feed.last_accepted_count = 0
        feed.last_rejected_count = rejected_count
        feed.sync_lock_token = None
        feed.sync_lock_expires_at = None
        feed.updated_at = completed_at
        record_audit(db, "threat_feed.sync_failed", "threat_feed_sync_run", run.id, {
            "feed_id": feed.id,
            "error": message,
            "fetched_count": fetched_count,
            "rejected_count": rejected_count,
        })
        db.commit()
        db.refresh(run)
        return run
