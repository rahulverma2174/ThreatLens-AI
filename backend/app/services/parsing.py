import csv
import io
import json
from pathlib import PurePath

from pydantic import ValidationError

from app.schemas import AuthEventCreate
from app.services.syslog_ingestion import parse_auth_syslog

MAX_UPLOAD_BYTES = 5 * 1024 * 1024
MAX_UPLOAD_ROWS = 5_000
CSV_FIELDS = {"timestamp", "username", "source_ip", "event_type", "status", "user_agent"}
JSON_FIELDS = {
    "timestamp", "username", "source_ip", "event_type", "status", "user_agent",
    "source_host", "source_event_id", "event_metadata",
}


class CsvImportError(ValueError):
    def __init__(self, status_code: int, detail: str, rejected_records: int = 0):
        super().__init__(detail)
        self.status_code = status_code
        self.rejected_records = rejected_records


def parse_auth_event_csv(content: bytes) -> list[AuthEventCreate]:
    if len(content) > MAX_UPLOAD_BYTES:
        raise CsvImportError(413, "CSV upload exceeds the 5 MB limit.")
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise CsvImportError(400, "CSV must be UTF-8 encoded.") from exc

    reader = csv.DictReader(io.StringIO(text))
    fieldnames = reader.fieldnames or []
    headers = set(fieldnames)
    required = {"username", "source_ip", "status"}
    if not required.issubset(headers) or headers - CSV_FIELDS or len(headers) != len(fieldnames):
        raise CsvImportError(
            422,
            f"CSV headers must include {sorted(required)} and may only contain {sorted(CSV_FIELDS)}.",
        )

    events: list[AuthEventCreate] = []
    invalid_rows: list[str] = []
    for row_number, row in enumerate(reader, start=2):
        if row_number > MAX_UPLOAD_ROWS + 1:
            raise CsvImportError(413, f"CSV exceeds the {MAX_UPLOAD_ROWS}-row limit.", len(invalid_rows) + 1)
        if None in row:
            invalid_rows.append(f"row {row_number}: unexpected extra columns")
            continue
        try:
            payload = AuthEventCreate.model_validate(
                {key: value or None for key, value in row.items() if key is not None}
            )
        except ValidationError as exc:
            first_error = exc.errors()[0]
            field = ".".join(str(part) for part in first_error.get("loc", ())) or "record"
            invalid_rows.append(f"row {row_number}: invalid {field}")
            continue
        if not payload.username.strip() or not payload.event_type.strip():
            invalid_rows.append(f"row {row_number}: username or event type is blank")
            continue
        events.append(payload)
    if invalid_rows:
        first_issue = invalid_rows[0]
        raise CsvImportError(
            422,
            f"CSV contains {len(invalid_rows)} invalid row(s); no rows were imported. First issue: {first_issue}.",
            len(invalid_rows),
        )
    if not events:
        raise CsvImportError(422, "CSV contains no authentication events.")
    return events


def parse_auth_event_json(
    content: bytes,
    filename: str,
    source_format: str,
) -> list[dict[str, object]]:
    if len(content) > MAX_UPLOAD_BYTES:
        raise CsvImportError(413, "JSON upload exceeds the 5 MB limit.")
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise CsvImportError(400, "JSON upload must be UTF-8 encoded.") from exc

    if source_format == "jsonl":
        rows: list[object] = []
        for line_number, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise CsvImportError(422, f"JSONL contains invalid JSON on line {line_number}.") from exc
    else:
        try:
            document = json.loads(text)
        except json.JSONDecodeError as exc:
            raise CsvImportError(422, "JSON file is malformed.") from exc
        rows = document if isinstance(document, list) else [document]

    if not rows:
        raise CsvImportError(422, "JSON upload contains no event records.")
    if len(rows) > MAX_UPLOAD_ROWS:
        raise CsvImportError(413, f"JSON upload exceeds the {MAX_UPLOAD_ROWS}-record limit.", len(rows) - MAX_UPLOAD_ROWS)

    safe_filename = PurePath(filename).name[:255] or f"events.{source_format}"
    records: list[dict[str, object]] = []
    for record_number, row in enumerate(rows, start=1):
        if not isinstance(row, dict):
            raise CsvImportError(422, f"JSON record {record_number} must be an object.", 1)
        unknown_fields = set(row) - JSON_FIELDS
        if unknown_fields:
            field = sorted(unknown_fields)[0]
            raise CsvImportError(422, f"JSON record {record_number} contains unsupported field '{field}'.", 1)
        metadata = row.get("event_metadata", {})
        if metadata is None:
            metadata = {}
        if not isinstance(metadata, dict):
            raise CsvImportError(422, f"JSON record {record_number} event_metadata must be an object.", 1)
        source_host = row.get("source_host")
        source_event_id = row.get("source_event_id")
        if source_host is not None and (not isinstance(source_host, str) or len(source_host) > 255):
            raise CsvImportError(422, f"JSON record {record_number} source_host must be a string of at most 255 characters.", 1)
        if source_event_id is not None and (not isinstance(source_event_id, str) or len(source_event_id) > 512):
            raise CsvImportError(422, f"JSON record {record_number} source_event_id must be a string of at most 512 characters.", 1)
        try:
            payload = AuthEventCreate.model_validate({key: row[key] for key in AuthEventCreate.model_fields if key in row})
        except ValidationError as exc:
            first_error = exc.errors()[0]
            field = ".".join(str(part) for part in first_error.get("loc", ())) or "record"
            raise CsvImportError(422, f"JSON record {record_number} has an invalid {field}.", 1) from exc
        if not payload.username.strip() or not payload.event_type.strip():
            raise CsvImportError(422, f"JSON record {record_number} has a blank username or event type.", 1)

        event_metadata = dict(metadata)
        event_metadata.setdefault("ingestion_format", source_format)
        event_metadata.setdefault("record_number", record_number)
        host = source_host.strip() if isinstance(source_host, str) else ""
        source_id = source_event_id.strip() if isinstance(source_event_id, str) else ""
        records.append({
            "payload": payload,
            "source_label": f"JSON import · {safe_filename[:55]}",
            "source_host": host or None,
            "source_event_id": source_id or None,
            "event_metadata": event_metadata,
        })
    return records


def parse_linux_auth_log(content: bytes, filename: str = "linux-auth.log") -> tuple[list[dict[str, object]], int]:
    if len(content) > MAX_UPLOAD_BYTES:
        raise CsvImportError(413, "Log upload exceeds the 5 MB limit.")
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise CsvImportError(400, "Linux auth log must be UTF-8 encoded.") from exc

    lines = text.splitlines()
    if len(lines) > MAX_UPLOAD_ROWS:
        raise CsvImportError(413, f"Log exceeds the {MAX_UPLOAD_ROWS}-line limit.", len(lines) - MAX_UPLOAD_ROWS)

    records: list[dict[str, object]] = []
    rejected = 0
    safe_filename = PurePath(filename).name[:255] or "linux-auth.log"
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        parsed = parse_auth_syslog(line.encode("utf-8"))
        if parsed is None:
            rejected += 1
            continue
        payload = AuthEventCreate(
            timestamp=parsed["timestamp"],
            username=str(parsed["username"]),
            source_ip=str(parsed["source_ip"]),
            event_type="ssh",
            status=parsed["status"],
        )
        host = str(parsed.get("source_host") or "unknown")
        records.append({
            "payload": payload,
            "source_label": f"Linux auth.log/{host}",
            "source_host": host,
            "event_metadata": {"ingestion_format": "linux_auth_log", "line_number": line_number, "filename": safe_filename},
        })

    if not records:
        raise CsvImportError(422, "No supported SSH authentication records were found in this log.", rejected)
    return records, rejected
