import ipaddress
import json
import re
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import AuthEvent
from app.schemas import NaturalEventSearchFilters
from app.services.local_ai import ollama_status


class LocalModelUnavailable(Exception):
    pass


def interpret_query(query: str) -> NaturalEventSearchFilters:
    status = ollama_status()
    if not status["connected"] or not status["model_ready"]:
        raise LocalModelUnavailable("Local Ollama model is unavailable. Use the standard event filters or start Ollama.")
    settings = get_settings()
    schema = {
        "type": "object",
        "properties": {
            "username": {"type": ["string", "null"]},
            "source_ip": {"type": ["string", "null"]},
            "status": {"type": ["string", "null"], "enum": ["success", "failure", None]},
            "event_type": {"type": ["string", "null"]},
            "since_hours": {"type": ["integer", "null"], "minimum": 1, "maximum": 8760},
            "search": {"type": ["string", "null"]},
        },
        "required": ["username", "source_ip", "status", "event_type", "since_hours", "search"],
    }
    response = httpx.post(
        f"{settings.ollama_url.rstrip('/')}/api/chat",
        json={
            "model": settings.ollama_model,
            "stream": False,
            "format": schema,
            "options": {"temperature": 0},
            "messages": [
                {"role": "system", "content": "Convert the user request into event search filters only. Do not answer the question. Extract exact usernames/IPs, success/failure, event type, and relative time in hours. Use null for unspecified filters. Put other literal terms into search. Never output SQL, commands, or extra fields."},
                {"role": "user", "content": query},
            ],
        },
        timeout=settings.ollama_timeout_seconds,
    )
    response.raise_for_status()
    raw = json.loads(response.json()["message"]["content"])
    # Some models encode relative windows as negative offsets (for example, -24).
    # This field represents a lookback duration, so normalize that common form.
    if isinstance(raw, dict) and isinstance(raw.get("since_hours"), int) and raw["since_hours"] < 0:
        raw["since_hours"] = abs(raw["since_hours"])
    if isinstance(raw, dict) and isinstance(raw.get("event_type"), str):
        event_type = raw["event_type"].strip().lower()
        canonical_types = ("mfa", "vpn", "ssh", "login")
        raw["event_type"] = next((kind for kind in canonical_types if kind in event_type), raw["event_type"])
    filters = NaturalEventSearchFilters.model_validate(raw)
    if filters.source_ip:
        filters.source_ip = str(ipaddress.ip_address(filters.source_ip))
    if filters.search:
        search = filters.search.strip()
        if ":" in search:
            filters.search = None
        else:
            words = set(re.findall(r"[a-z0-9_.-]+", search.lower()))
            captured = set()
            for value in (filters.username, filters.source_ip, filters.event_type):
                if value:
                    captured.update(re.findall(r"[a-z0-9_.-]+", value.lower()))
            if filters.status:
                captured.update({"failure", "failed", "fail", "unsuccessful"} if filters.status == "failure" else {"success", "successful"})
            if filters.since_hours:
                captured.update({"last", "past", "previous", "hour", "hours", "hr", "hrs", "day", "days", "week", "weeks"})
            if words and words <= captured:
                filters.search = None
    if not any((filters.username, filters.source_ip, filters.status, filters.event_type, filters.since_hours, filters.search)):
        filters.search = query.strip()[:128]
    return filters


def run_natural_event_search(query: str, db: Session, limit: int, offset: int) -> dict[str, object]:
    filters = interpret_query(query)
    statement = select(AuthEvent)
    conditions = []
    if filters.username:
        conditions.append(AuthEvent.username == filters.username)
    if filters.source_ip:
        conditions.append(AuthEvent.source_ip == filters.source_ip)
    if filters.status:
        conditions.append(AuthEvent.status == filters.status)
    if filters.event_type:
        conditions.append(AuthEvent.event_type == filters.event_type)
    if filters.since_hours:
        start = datetime.now(timezone.utc) - timedelta(hours=filters.since_hours)
        conditions.append(AuthEvent.timestamp >= start)
    if filters.search:
        term = f"%{filters.search.strip()}%"
        conditions.append(or_(AuthEvent.username.ilike(term), AuthEvent.source_ip.ilike(term)))
    if conditions:
        statement = statement.where(*conditions)
    total = db.scalar(select(func.count()).select_from(statement.subquery())) or 0
    events = list(db.scalars(statement.order_by(AuthEvent.timestamp.desc(), AuthEvent.id.desc()).limit(limit).offset(offset)))
    return {
        "query": query,
        "filters": filters,
        "total": total,
        "events": events,
        "limit": limit,
        "offset": offset,
        "model": get_settings().ollama_model,
        "notice": "Ollama extracted allowlisted filters; the API executed a parameterized database query. No SQL was generated or run by the model.",
    }
