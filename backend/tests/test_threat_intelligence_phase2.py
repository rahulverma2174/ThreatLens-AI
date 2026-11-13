import json
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import delete, func, inspect, select, update

from app.database import initialize_schema
from app.main import app
from app.models import (
    LocalIndicator, ThreatFeed, ThreatFeedSyncRun, ThreatIndicator,
    ThreatIndicatorReview, ThreatIndicatorSource,
)
from app.config import Settings
from app.routers import threat_intelligence as threat_intelligence_router
from app.schemas import ThreatFeedFieldMapping
from app.services.threat_indicator_validation import parse_feed_body
from app.services.threat_intelligence_feeds import (
    FeedSyncBusyError, indicator_is_active, synchronize_feed, upsert_feed_indicators,
)
from app.services.threat_feed_transport import (
    _PinnedSyncBackend,
    resolve_public_feed_addresses,
    validate_feed_configuration,
)


def test_additive_intelligence_schema_preserves_existing_local_iocs(client) -> None:
    created = client.post("/api/intelligence/indicators", json={
        "indicator_type": "ip", "value": "198.51.100.61", "kind": "allowlist",
        "confidence": 70, "source": "legacy workflow",
    })
    assert created.status_code == 201
    factory = app.state.session_factory
    engine = factory.kw["bind"]

    initialize_schema(engine)
    tables = set(inspect(engine).get_table_names())
    assert {
        "threat_feeds", "threat_feed_sync_runs", "threat_indicators",
        "threat_indicator_sources", "threat_indicator_reviews",
    }.issubset(tables)
    with factory() as db:
        existing = db.get(LocalIndicator, created.json()["id"])
        assert existing is not None
        assert existing.source_ip == "198.51.100.61"
        assert existing.kind == "allowlist"


def test_external_ioc_review_rows_are_append_only(client) -> None:
    from sqlalchemy.exc import IntegrityError

    factory = app.state.session_factory
    with factory() as db:
        now = datetime.now(timezone.utc)
        indicator = ThreatIndicator(
            indicator_type="ip", value="203.0.113.62", first_seen=now, last_seen=now,
        )
        db.add(indicator)
        db.flush()
        review = ThreatIndicatorReview(indicator_id=indicator.id, disposition="confirmed", notes="test")
        db.add(review)
        db.commit()
        review_id = review.id
    with factory() as db:
        with pytest.raises(IntegrityError, match="append-only"):
            db.execute(update(ThreatIndicatorReview).where(ThreatIndicatorReview.id == review_id).values(notes="rewritten"))
            db.commit()
    with factory() as db:
        with pytest.raises(IntegrityError, match="append-only"):
            db.execute(delete(ThreatIndicatorReview).where(ThreatIndicatorReview.id == review_id))
            db.commit()


def test_feed_parser_normalizes_all_supported_indicator_values_and_rejects_invalid_rows() -> None:
    now = datetime.now(timezone.utc)
    data = {
        "indicators": [
            {"type": "IP", "value": "198.51.100.20", "confidence": 85, "reference": "entry-1", "first_seen": now.isoformat(), "last_seen": (now + timedelta(minutes=1)).isoformat()},
            {"type": "ip", "value": "198.51.100.20", "confidence": 90, "reference": "entry-1", "first_seen": (now - timedelta(days=1)).isoformat(), "last_seen": (now + timedelta(minutes=2)).isoformat()},
            {"type": "domain", "value": "Exämple.org", "reference": "entry-2"},
            {"type": "hash", "value": "A" * 32, "reference": "entry-3"},
            {"type": "hash", "value": "b" * 40, "reference": "entry-4"},
            {"type": "hash", "value": "c" * 64, "reference": "entry-5"},
            {"type": "ip", "value": "127.0.0.1/8", "reference": "invalid"},
            {"type": "domain", "value": "https://bad.example", "reference": "invalid-2"},
        ],
    }
    parsed = parse_feed_body(
        json.dumps(data).encode(), "json", ThreatFeedFieldMapping(),
        max_bytes=100_000, max_records=100,
    )
    assert parsed["fetched_count"] == 8
    assert parsed["accepted_count"] == 5
    assert parsed["rejected_count"] == 2
    assert len(parsed["indicators"]) == 5
    ip = next(item for item in parsed["indicators"] if item.value == "198.51.100.20")
    assert ip.first_seen == now - timedelta(days=1)
    assert ip.last_seen == now + timedelta(minutes=2)
    assert ip.confidence == 90
    domain = next(item for item in parsed["indicators"] if item.indicator_type == "domain")
    assert domain.value == "xn--exmple-cua.org"
    assert domain.confidence is None


def test_feed_parser_enforces_size_record_and_csv_validation_limits() -> None:
    mapping = ThreatFeedFieldMapping()
    with pytest.raises(ValueError, match="byte limit"):
        parse_feed_body(b"{}", "json", mapping, max_bytes=1, max_records=5)
    with pytest.raises(ValueError, match="record limit"):
        parse_feed_body(b'{"indicators":[{},{}]}', "json", mapping, max_bytes=1000, max_records=1)
    result = parse_feed_body(
        b"type,value,reference\nip,198.51.100.1,csv-1\n",
        "csv", mapping, max_bytes=1000, max_records=5,
    )
    assert result["accepted_count"] == 1


def test_feed_upserts_deduplicate_sources_preserve_timestamps_and_independent_expiry(client) -> None:
    from app.services.threat_indicator_validation import FeedIndicatorRecord

    factory = app.state.session_factory
    now = datetime.now(timezone.utc)
    with factory() as db:
        feed_one = ThreatFeed(name="Feed One", url="https://intel-one.example/feed", feed_format="json")
        feed_two = ThreatFeed(name="Feed Two", url="https://intel-two.example/feed", feed_format="json")
        db.add_all([feed_one, feed_two])
        db.flush()
        run_one = ThreatFeedSyncRun(feed_id=feed_one.id, status="succeeded", started_at=now)
        run_two = ThreatFeedSyncRun(feed_id=feed_two.id, status="succeeded", started_at=now)
        db.add_all([run_one, run_two])
        db.flush()
        expired_observation = FeedIndicatorRecord(
            indicator_type="ip", value="198.51.100.77", confidence=64,
            first_seen=now - timedelta(days=4), last_seen=now - timedelta(days=1),
            expires_at=now - timedelta(hours=1), source_reference="one-77",
        )
        active_observation = FeedIndicatorRecord(
            indicator_type="ip", value="198.51.100.77", confidence=88,
            first_seen=now - timedelta(days=3), last_seen=now,
            expires_at=now + timedelta(days=2), source_reference="two-77",
        )
        first_counts = upsert_feed_indicators(db, feed_one, run_one, [expired_observation])
        second_counts = upsert_feed_indicators(db, feed_two, run_two, [active_observation])
        assert first_counts == {"inserted_count": 1, "updated_count": 0}
        assert second_counts == {"inserted_count": 0, "updated_count": 1}

        indicator = db.scalar(select(ThreatIndicator).where(ThreatIndicator.value == "198.51.100.77"))
        assert indicator is not None
        indicator.analyst_disposition = "false_positive"
        indicator.reviewed_at = now
        run_three = ThreatFeedSyncRun(feed_id=feed_one.id, status="succeeded", started_at=now + timedelta(minutes=1))
        db.add(run_three)
        db.flush()
        refreshed = expired_observation.model_copy(update={
            "first_seen": now - timedelta(days=5),
            "last_seen": now + timedelta(minutes=1),
            "confidence": 70,
        })
        upsert_feed_indicators(db, feed_one, run_three, [refreshed])
        run_four = ThreatFeedSyncRun(feed_id=feed_one.id, status="succeeded", started_at=now + timedelta(minutes=2))
        db.add(run_four)
        db.flush()
        sparse_refresh = FeedIndicatorRecord(
            indicator_type="ip", value="198.51.100.77", source_reference="one-77",
            first_seen=now - timedelta(days=2), last_seen=now + timedelta(minutes=2),
        )
        upsert_feed_indicators(db, feed_one, run_four, [sparse_refresh])
        sources = list(db.scalars(select(ThreatIndicatorSource).where(ThreatIndicatorSource.indicator_id == indicator.id)))
        db.flush()
        db.refresh(indicator)
        assert len(sources) == 2
        assert indicator.first_seen.replace(tzinfo=timezone.utc) == now - timedelta(days=5)
        assert indicator.last_seen.replace(tzinfo=timezone.utc) == now + timedelta(minutes=2)
        assert indicator.analyst_disposition == "false_positive"
        assert indicator_is_active(sources, now)
        expired = next(source for source in sources if source.feed_id == feed_one.id)
        assert expired.latest_sync_run_id == run_four.id
        assert expired.confidence == 70
        assert expired.expires_at.replace(tzinfo=timezone.utc) == now - timedelta(hours=1)
        assert db.scalar(select(func.count(ThreatIndicatorSource.id))) == 2
        db.commit()


def test_feed_destination_allowlist_and_dns_results_block_prohibited_networks(monkeypatch) -> None:
    from app.models import ThreatFeed
    from app.services import threat_feed_transport

    settings = Settings(feed_allowed_hosts="feeds.example")
    feed = ThreatFeed(name="feed", url="https://feeds.example/data.json", feed_format="json")
    assert validate_feed_configuration(feed, settings) == "feeds.example"
    with pytest.raises(ValueError, match="not in"):
        validate_feed_configuration(
            ThreatFeed(name="other", url="https://not-allowed.example/ioc", feed_format="json"),
            settings,
        )
    with pytest.raises(ValueError, match="HTTPS"):
        validate_feed_configuration(
            ThreatFeed(name="http", url="http://feeds.example/data", feed_format="json"), settings,
        )

    def result(address):
        return [(2, 1, 6, "", (address, 443))]

    monkeypatch.setattr(threat_feed_transport.socket, "getaddrinfo", lambda *args, **kwargs: result("93.184.216.34"))
    assert resolve_public_feed_addresses("feeds.example") == ["93.184.216.34"]

    monkeypatch.setattr(threat_feed_transport.socket, "getaddrinfo", lambda *args, **kwargs: result("10.0.0.8"))
    with pytest.raises(ValueError, match="prohibited destination"):
        resolve_public_feed_addresses("feeds.example")


def test_feed_connect_time_validation_pins_numeric_destination_and_blocks_rebinding(monkeypatch) -> None:
    from httpcore._backends.sync import SyncBackend
    from app.services import threat_feed_transport

    monkeypatch.setattr(
        threat_feed_transport.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [(2, 1, 6, "", ("93.184.216.34", 443))],
    )
    connected = {}
    monkeypatch.setattr(SyncBackend, "connect_tcp", lambda self, host, port, *args, **kwargs: connected.update(host=host, port=port) or "stream")
    backend = _PinnedSyncBackend()
    assert backend.connect_tcp("feeds.example", 443) == "stream"
    assert connected == {"host": "93.184.216.34", "port": 443}

    # Simulate a DNS answer changing between preflight and socket connect.
    answers = iter(["93.184.216.34", "127.0.0.1"])
    monkeypatch.setattr(
        threat_feed_transport.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [(2, 1, 6, "", (next(answers), 443))],
    )
    assert resolve_public_feed_addresses("feeds.example") == ["93.184.216.34"]
    with pytest.raises(ValueError, match="prohibited destination"):
        backend.connect_tcp("feeds.example", 443)


def test_feed_management_api_never_returns_or_persists_secret_values(client, monkeypatch) -> None:
    monkeypatch.setattr(threat_intelligence_router, "get_settings", lambda: Settings(feed_allowed_hosts="feeds.example"))
    monkeypatch.setenv("THREATLENS_FEED_DEMO_TOKEN", "top-secret-value")
    payload = {
        "name": "Demo feed", "url": "https://feeds.example/data.json", "feed_format": "json",
        "credential_env_var": "THREATLENS_FEED_DEMO_TOKEN", "stale_after_minutes": 60,
    }
    response = client.post("/api/intelligence/feeds", json=payload)
    assert response.status_code == 201, response.text
    assert response.json()["credential_configured"] is True
    assert "top-secret-value" not in response.text
    assert "top-secret-value" not in client.get("/api/intelligence/feeds").text
    with app.state.session_factory() as db:
        feed = db.get(ThreatFeed, response.json()["id"])
        assert feed.credential_env_var == "THREATLENS_FEED_DEMO_TOKEN"
        assert "top-secret-value" not in repr(feed)

    duplicate = client.post("/api/intelligence/feeds", json=payload)
    assert duplicate.status_code == 409
    secret_url = client.post("/api/intelligence/feeds", json={
        **payload, "name": "URL secret", "url": "https://feeds.example/data?token=top-secret-value",
    })
    assert secret_url.status_code == 422
    disabled = client.patch(f"/api/intelligence/feeds/{response.json()['id']}/enabled", json={"enabled": False})
    assert disabled.status_code == 200 and disabled.json()["freshness"] == "disabled"
    assert client.post(f"/api/intelligence/feeds/{response.json()['id']}/sync").status_code == 409


def test_feed_sync_failure_preserves_previous_success_and_indicator_sources(client) -> None:
    factory = app.state.session_factory
    settings = Settings(feed_allowed_hosts="feeds.example")
    with factory() as db:
        feed = ThreatFeed(name="sync demo", url="https://feeds.example/iocs.json", feed_format="json")
        db.add(feed)
        db.commit()
        feed_id = feed.id

    body = json.dumps({"indicators": [{
        "type": "ip", "value": "198.51.100.190", "confidence": 81, "reference": "feed-ref-190",
    }]}).encode()
    with factory() as db:
        successful = synchronize_feed(db, feed_id, settings, fetcher=lambda _feed, _settings: (body, len(body)))
        assert successful.status == "succeeded"
        successful_at = successful.completed_at
        assert successful.inserted_count == 1
    with factory() as db:
        failed = synchronize_feed(
            db, feed_id, settings,
            fetcher=lambda _feed, _settings: (_ for _ in ()).throw(TimeoutError("top-secret-value")),
        )
        assert failed.status == "failed"
        assert "top-secret-value" not in failed.error_summary
    with factory() as db:
        feed = db.get(ThreatFeed, feed_id)
        assert feed.last_sync_status == "failed"
        assert feed.last_success_at.replace(tzinfo=timezone.utc) == successful_at.replace(tzinfo=timezone.utc)
        assert db.scalar(select(func.count(ThreatIndicator.id))) == 1
        assert db.scalar(select(func.count(ThreatIndicatorSource.id))) == 1


def test_concurrent_feed_sync_claim_is_rejected(client) -> None:
    factory = app.state.session_factory
    with factory() as db:
        feed = ThreatFeed(name="locked feed", url="https://feeds.example/locked.json", feed_format="json")
        feed.sync_lock_token = "active-sync-token"
        feed.sync_lock_expires_at = datetime.now(timezone.utc) + timedelta(minutes=1)
        db.add(feed)
        db.commit()
        feed_id = feed.id
    with factory() as db:
        with pytest.raises(FeedSyncBusyError, match="already in progress"):
            synchronize_feed(db, feed_id, Settings(feed_allowed_hosts="feeds.example"), fetcher=lambda *_args: (b"{}", 2))


def test_feed_fresh_stale_failed_and_disabled_states_are_distinct(client, monkeypatch) -> None:
    monkeypatch.setattr(threat_intelligence_router, "get_settings", lambda: Settings(feed_allowed_hosts="feeds.example"))
    settings = Settings(feed_allowed_hosts="feeds.example")
    payload = {
        "name": "Freshness feed", "url": "https://feeds.example/freshness.json", "feed_format": "json",
        "stale_after_minutes": 60,
    }
    created = client.post("/api/intelligence/feeds", json=payload)
    assert created.status_code == 201
    feed_id = created.json()["id"]
    assert created.json()["freshness"] == "never_synced"
    body = b'{"indicators":[]}'
    with app.state.session_factory() as db:
        success = synchronize_feed(db, feed_id, settings, fetcher=lambda *_args: (body, len(body)))
        assert success.status == "succeeded"
    assert client.get("/api/intelligence/feeds").json()[0]["freshness"] == "fresh"

    with app.state.session_factory() as db:
        feed = db.get(ThreatFeed, feed_id)
        feed.last_success_at = datetime.now(timezone.utc) - timedelta(hours=2)
        feed.last_sync_status = "succeeded"
        db.commit()
    assert client.get("/api/intelligence/feeds").json()[0]["freshness"] == "stale"

    with app.state.session_factory() as db:
        failed = synchronize_feed(db, feed_id, settings, fetcher=lambda *_args: (_ for _ in ()).throw(TimeoutError()))
        assert failed.status == "failed"
    assert client.get("/api/intelligence/feeds").json()[0]["freshness"] == "failed"
    disabled = client.patch(f"/api/intelligence/feeds/{feed_id}/enabled", json={"enabled": False})
    assert disabled.status_code == 200 and disabled.json()["freshness"] == "disabled"


def test_ioc_search_correlation_timeline_and_analyst_review_api(client) -> None:
    now = datetime.now(timezone.utc)
    for index in range(5):
        response = client.post("/api/events", json={
            "timestamp": (now + timedelta(seconds=index)).isoformat(),
            "username": "intel-target", "source_ip": "203.0.113.180",
            "event_type": "login", "status": "failure",
        })
        assert response.status_code == 201

    factory = app.state.session_factory
    with factory() as db:
        feed = ThreatFeed(name="IOC feed", url="https://feeds.example/iocs", feed_format="json")
        db.add(feed)
        db.flush()
        run = ThreatFeedSyncRun(feed_id=feed.id, status="succeeded", started_at=now, completed_at=now)
        db.add(run)
        db.flush()
        ip = ThreatIndicator(indicator_type="ip", value="203.0.113.180", first_seen=now, last_seen=now)
        domain = ThreatIndicator(indicator_type="domain", value="bad.example", first_seen=now, last_seen=now)
        db.add_all([ip, domain])
        db.flush()
        db.add_all([
            ThreatIndicatorSource(
                indicator_id=ip.id, feed_id=feed.id, source_name=feed.name, source_reference="ip-ref",
                confidence=91, first_seen=now, last_seen=now, expires_at=now + timedelta(days=2), latest_sync_run_id=run.id,
            ),
            ThreatIndicatorSource(
                indicator_id=domain.id, feed_id=feed.id, source_name=feed.name, source_reference="domain-ref",
                confidence=77, first_seen=now, last_seen=now, expires_at=None, latest_sync_run_id=run.id,
            ),
        ])
        db.commit()
        ip_id, domain_id = ip.id, domain.id

    listing = client.get("/api/intelligence/iocs?indicator_type=ip&active=true")
    assert listing.status_code == 200, listing.text
    ip_row = next(item for item in listing.json()["indicators"] if item["id"] == ip_id)
    assert ip_row["matching_event_count"] == 5
    assert ip_row["sources"][0]["confidence"] == 91

    correlation = client.get(f"/api/intelligence/iocs/{ip_id}/correlation?limit=10")
    assert correlation.status_code == 200, correlation.text
    assert correlation.json()["correlation_status"] == "correlated"
    assert correlation.json()["total"] == 5
    assert correlation.json()["results"][0]["alerts"]
    assert correlation.json()["results"][0]["incidents"]

    domain_result = client.get(f"/api/intelligence/iocs/{domain_id}/correlation")
    assert domain_result.status_code == 200
    assert domain_result.json()["correlation_status"] == "unsupported_schema"
    assert domain_result.json()["total"] is None
    assert "no domain or file-hash field" in domain_result.json()["explanation"]

    review = client.post(f"/api/intelligence/iocs/{ip_id}/reviews", json={
        "disposition": "false_positive", "notes": "Feed finding reviewed against local context.",
    })
    assert review.status_code == 201, review.text
    assert client.get(f"/api/intelligence/iocs/{ip_id}").json()["analyst_disposition"] == "false_positive"
    reviews = client.get(f"/api/intelligence/iocs/{ip_id}/reviews").json()
    assert len(reviews) == 1 and reviews[0]["id"] == review.json()["id"]
    timeline = client.get(f"/api/intelligence/iocs/{ip_id}/timeline?limit=100")
    assert timeline.status_code == 200
    kinds = {item["kind"] for item in timeline.json()["entries"]}
    assert {"feed_observation", "event", "alert", "incident", "review"}.issubset(kinds)
    audit = client.get("/api/audit?action=threat_indicator.reviewed&entity_type=threat_indicator")
    assert audit.status_code == 200
    assert audit.json()[0]["details"]["disposition"] == "false_positive"
