"""Canonicalization and bounded parsing of external indicator feeds."""

import csv
import hashlib
import io
import ipaddress
import json
import re
from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from app.schemas import ThreatFeedFieldMapping

MAX_FEED_ERROR_EXAMPLES = 20
MAX_FEED_ERROR_LENGTH = 240


def normalize_indicator(indicator_type: str, value: str) -> tuple[str, str]:
    raw = value.strip()
    if indicator_type == "ip":
        try:
            return "ip", str(ipaddress.ip_address(raw))
        except ValueError as exc:
            raise ValueError("Invalid IPv4 or IPv6 indicator.") from exc
    if indicator_type == "domain":
        if raw.endswith("."):
            raw = raw[:-1]
        if not raw or "://" in raw or "/" in raw or "*" in raw or "@" in raw:
            raise ValueError("Domain indicators must be hostnames, not URLs or wildcard values.")
        try:
            normalized = raw.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ValueError("Domain indicator contains invalid IDN data.") from exc
        if len(normalized) > 253 or not re.fullmatch(
            r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))+",
            normalized,
        ):
            raise ValueError("Domain indicator must be a fully qualified domain name.")
        try:
            ipaddress.ip_address(normalized)
        except ValueError:
            return "domain", normalized
        raise ValueError("IP literals must use the IP indicator type.")
    if indicator_type == "hash":
        normalized = raw.lower()
        if not re.fullmatch(r"(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})", normalized):
            raise ValueError("Hash indicators must be valid MD5, SHA-1, or SHA-256 hexadecimal values.")
        return "hash", normalized
    raise ValueError("Indicator type must be ip, domain, or hash.")


def normalize_timestamp(value: datetime | None, fallback: datetime) -> datetime:
    current = value or fallback
    return current.replace(tzinfo=timezone.utc) if current.tzinfo is None else current.astimezone(timezone.utc)


class FeedIndicatorRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    indicator_type: str
    value: str = Field(min_length=1, max_length=255)
    confidence: int | None = Field(default=None, ge=0, le=100)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    expires_at: datetime | None = None
    source_reference: str = Field(default="", max_length=512)
    expiry_supplied: bool = Field(default=False, exclude=True)

    @field_validator("source_reference")
    @classmethod
    def trim_source_reference(cls, value: str) -> str:
        return value.strip()

    @model_validator(mode="after")
    def normalize(self):
        self.indicator_type, self.value = normalize_indicator(self.indicator_type.lower().strip(), self.value)
        now = datetime.now(timezone.utc)
        self.first_seen = normalize_timestamp(self.first_seen, now)
        self.last_seen = normalize_timestamp(self.last_seen, self.first_seen)
        if self.last_seen < self.first_seen:
            raise ValueError("last_seen cannot be earlier than first_seen.")
        if self.expires_at is not None:
            self.expires_at = normalize_timestamp(self.expires_at, now)
        return self


def _extract_row(row: dict[str, object], mapping: ThreatFeedFieldMapping) -> FeedIndicatorRecord:
    def get(mapped_key: str | None, fallback: str | None = None):
        if mapped_key is not None and mapped_key in row:
            return row[mapped_key]
        if fallback and fallback in row:
            return row[fallback]
        return None

    confidence = get(mapping.confidence)
    first_seen = get(mapping.first_seen)
    last_seen = get(mapping.last_seen)
    expiry = get(mapping.expires_at)
    return FeedIndicatorRecord.model_validate({
        "indicator_type": get(mapping.indicator_type, "indicator_type"),
        "value": get(mapping.value),
        "confidence": confidence if confidence not in {"", None} else None,
        "first_seen": first_seen if first_seen not in {"", None} else None,
        "last_seen": last_seen if last_seen not in {"", None} else None,
        "expires_at": expiry if expiry not in {"", None} else None,
        "expiry_supplied": bool(mapping.expires_at and expiry not in {"", None}),
        "source_reference": get(mapping.reference, "id") or "",
    })


def parse_feed_body(
    body: bytes,
    feed_format: str,
    field_mapping: ThreatFeedFieldMapping,
    *,
    max_bytes: int,
    max_records: int,
) -> dict[str, object]:
    """Parse bounded JSON/CSV, return deduplicated valid rows and bounded errors."""
    if len(body) > max_bytes:
        raise ValueError(f"Feed response exceeds the configured {max_bytes}-byte limit.")
    try:
        decoded = body.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("Feed response must be UTF-8 encoded.") from exc
    if feed_format == "json":
        try:
            root = json.loads(decoded)
        except json.JSONDecodeError as exc:
            raise ValueError("Feed response is not valid JSON.") from exc
        if isinstance(root, list):
            rows = root
        elif isinstance(root, dict):
            rows = root.get(field_mapping.records_key)
        else:
            rows = None
        if not isinstance(rows, list):
            raise ValueError("JSON feed must contain an indicator array.")
        if len(rows) > max_records:
            raise ValueError(f"Feed contains more than the configured {max_records}-record limit.")
        input_rows = rows
    elif feed_format == "csv":
        reader = csv.DictReader(io.StringIO(decoded, newline=""), strict=True)
        if not reader.fieldnames:
            raise ValueError("CSV feed must include a header row.")
        input_rows = []
        try:
            for row_number, row in enumerate(reader, start=1):
                if row_number > max_records:
                    raise ValueError(f"Feed contains more than the configured {max_records}-record limit.")
                input_rows.append(dict(row))
        except csv.Error as exc:
            raise ValueError("Feed CSV contains a malformed record.") from exc
    else:
        raise ValueError("Unsupported feed format.")

    deduplicated: dict[tuple[str, str, str], FeedIndicatorRecord] = {}
    errors: list[str] = []
    rejected = 0
    for index, row in enumerate(input_rows):
        if not isinstance(row, dict):
            rejected += 1
            if len(errors) < MAX_FEED_ERROR_EXAMPLES:
                errors.append(f"row {index + 1}: expected an object")
            continue
        try:
            item = _extract_row(row, field_mapping)
        except (ValidationError, ValueError, TypeError) as exc:
            rejected += 1
            if len(errors) < MAX_FEED_ERROR_EXAMPLES:
                if isinstance(exc, ValidationError):
                    message = "; ".join(
                        f"{'.'.join(str(part) for part in issue['loc'])}: {issue['msg']}"
                        for issue in exc.errors(include_input=False)
                    )
                else:
                    message = str(exc)
                message = message.replace("\n", " ")[:MAX_FEED_ERROR_LENGTH]
                errors.append(f"row {index + 1}: {message}")
            continue
        key = (item.indicator_type, item.value, item.source_reference)
        existing = deduplicated.get(key)
        if existing is None:
            deduplicated[key] = item
        else:
            existing.first_seen = min(existing.first_seen, item.first_seen)
            existing.last_seen = max(existing.last_seen, item.last_seen)
            # Confidence/expiry are source-specific properties of the latest row.
            if item.confidence is not None:
                existing.confidence = item.confidence
            if item.expiry_supplied:
                existing.expires_at = item.expires_at
    return {
        "fetched_count": len(input_rows),
        "accepted_count": len(deduplicated),
        "rejected_count": rejected,
        "indicators": list(deduplicated.values()),
        "error_examples": errors,
        "content_sha256": hashlib.sha256(body).hexdigest(),
    }
