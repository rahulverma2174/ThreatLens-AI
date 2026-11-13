import asyncio
import ipaddress
import logging
import re
from datetime import datetime, timezone
from typing import Literal

from sqlalchemy.orm import Session, sessionmaker

from app.config import Settings
from app.models import AuthEvent
from app.schemas import AuthEventCreate
from app.services.audit import record_audit
from app.services.ingestion import ingest_event

logger = logging.getLogger(__name__)

PRI_RE = re.compile(r"^<\d{1,3}>")
RFC5424_RE = re.compile(r"^\d+\s+(\d{4}-\d\d-\d\dT[^\s]+)\s+(\S+)\s+")
RFC3164_RE = re.compile(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d)\s+(\S+)\s+")
SSH_AUTH_RE = re.compile(
    r"\b(?P<result>Accepted|Failed)\s+(?P<method>password|publickey|keyboard-interactive(?:/\S+)?)\s+"
    r"for\s+(?:(?:invalid|illegal)\s+user\s+)?(?P<username>\S+)\s+from\s+(?P<source_ip>\S+)\s+port\s+\d+",
    re.IGNORECASE,
)
SSH_PAM_RE = re.compile(r"\bauthentication failure\b.*\brhost=(?P<source_ip>\S+).*\buser=(?P<username>\S+)", re.IGNORECASE)
HOST_RE = re.compile(r"[^A-Za-z0-9_.-]+")


def _parse_timestamp(message: str) -> tuple[datetime | None, str | None]:
    match = RFC5424_RE.match(message)
    if match:
        raw_timestamp, hostname = match.groups()
        if raw_timestamp != "-":
            try:
                parsed = datetime.fromisoformat(raw_timestamp.replace("Z", "+00:00"))
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                return parsed.astimezone(timezone.utc), hostname
            except ValueError:
                pass
    match = RFC3164_RE.match(message)
    if match:
        raw_timestamp, hostname = match.groups()
        try:
            parsed = datetime.strptime(raw_timestamp, "%b %d %H:%M:%S")
            local_now = datetime.now().astimezone()
            parsed = parsed.replace(year=local_now.year, tzinfo=local_now.tzinfo)
            # RFC3164 omits both year and timezone; use the receiver's local zone.
            if parsed > local_now.replace(microsecond=0):
                parsed = parsed.replace(year=parsed.year - 1)
            return parsed.astimezone(timezone.utc), hostname
        except ValueError:
            pass
    return None, None


def parse_auth_syslog(raw: bytes) -> dict[str, object] | None:
    message = raw.decode("utf-8", errors="replace").strip().replace("\x00", "")
    if not message:
        return None
    message = PRI_RE.sub("", message, count=1)
    if "sshd" not in message.lower():
        return None
    timestamp, hostname = _parse_timestamp(message)
    ssh_match = SSH_AUTH_RE.search(message)
    if ssh_match:
        fields = ssh_match.groupdict()
        username = fields["username"]
        source_ip = fields["source_ip"].rstrip(".,;:")
        status: Literal["success", "failure"] = "success" if fields["result"].lower() == "accepted" else "failure"
    elif pam_match := SSH_PAM_RE.search(message):
        username = pam_match.group("username")
        source_ip = pam_match.group("source_ip").rstrip(".,;:")
        status = "failure"
    else:
        return None
    try:
        source_ip = str(ipaddress.ip_address(source_ip))
    except ValueError:
        return None
    username = username.strip()[:128]
    if not username or username.lower() in {"unknown", "(unknown)"}:
        return None
    safe_hostname = HOST_RE.sub("_", hostname or "unknown")[:48]
    return {
        "timestamp": timestamp or datetime.now(timezone.utc),
        "username": username,
        "source_ip": source_ip,
        "event_type": "ssh",
        "status": status,
        "source_label": f"Syslog TCP/{safe_hostname}",
        "source_host": safe_hostname,
    }


class SyslogTCPListener:
    def __init__(self, settings: Settings, session_factory: sessionmaker[Session]) -> None:
        self.settings = settings
        self.session_factory = session_factory
        self.server: asyncio.Server | None = None
        self.counters: dict[str, int] = {
            "connections": 0,
            "received": 0,
            "ingested": 0,
            "ignored": 0,
            "rejected": 0,
            "errors": 0,
        }
        self.last_event_at: datetime | None = None
        self.last_error: str | None = None
        try:
            self.allowed_networks = [ipaddress.ip_network(item, strict=False) for item in settings.allowed_syslog_networks]
        except ValueError as exc:
            self.allowed_networks = []
            self.last_error = f"Invalid THREATLENS_SYSLOG_ALLOWED_SOURCES: {exc}"

    async def start(self) -> None:
        if not self.settings.syslog_enabled:
            return
        if self.last_error:
            logger.error("syslog_listener_configuration_error", extra={"error": self.last_error})
            return
        try:
            self.server = await asyncio.start_server(
                self._handle_client,
                self.settings.syslog_host,
                self.settings.syslog_port,
                limit=self.settings.syslog_max_message_bytes + 64,
            )
            logger.info(
                "syslog_listener_started",
                extra={"host": self.settings.syslog_host, "port": self.settings.syslog_port},
            )
        except OSError as exc:
            self.last_error = str(exc)
            logger.exception("syslog_listener_start_failed")

    async def stop(self) -> None:
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()
            self.server = None

    def status(self) -> dict[str, object]:
        return {
            "enabled": self.settings.syslog_enabled,
            "running": self.server is not None and self.server.is_serving(),
            "transport": "TCP",
            "host": self.settings.syslog_host,
            "port": self.settings.syslog_port,
            "allowed_sources": [str(network) for network in self.allowed_networks],
            "max_message_bytes": self.settings.syslog_max_message_bytes,
            "counters": dict(self.counters),
            "last_event_at": self.last_event_at,
            "last_error": self.last_error,
        }

    def _is_allowed(self, peer_ip: str) -> bool:
        try:
            address = ipaddress.ip_address(peer_ip)
            if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
                address = address.ipv4_mapped
            return any(address.version == network.version and address in network for network in self.allowed_networks)
        except ValueError:
            return False

    async def _read_message(self, reader: asyncio.StreamReader) -> bytes | None:
        first = await reader.read(1)
        if not first:
            return None
        if first.isdigit():
            prefix = bytearray(first)
            while len(prefix) <= 10:
                next_byte = await reader.read(1)
                if not next_byte:
                    return bytes(prefix)
                if next_byte == b" ":
                    if not bytes(prefix).isdigit():
                        break
                    size = int(prefix)
                    if size < 1 or size > self.settings.syslog_max_message_bytes:
                        raise ValueError("Syslog frame exceeds the configured size limit.")
                    return await reader.readexactly(size)
                if not next_byte.isdigit():
                    prefix.extend(next_byte)
                    break
                prefix.extend(next_byte)
            rest = await reader.readuntil(b"\n")
            return bytes(prefix) + rest
        try:
            return first + await reader.readuntil(b"\n")
        except asyncio.IncompleteReadError as exc:
            return first + exc.partial if exc.partial else first

    def _store_message(self, raw: bytes, peer_ip: str) -> bool:
        parsed = parse_auth_syslog(raw)
        if parsed is None:
            return False
        payload = AuthEventCreate(
            timestamp=parsed["timestamp"],
            username=parsed["username"],
            source_ip=parsed["source_ip"],
            event_type=parsed["event_type"],
            status=parsed["status"],
        )
        with self.session_factory() as db:
            event: AuthEvent = ingest_event(db, payload, source_label=str(parsed["source_label"]))
            db.flush()
            record_audit(
                db,
                "event.ingested",
                "auth_event",
                event.id,
                {"source_ip": event.source_ip, "status": event.status, "transport": "syslog_tcp", "sender": peer_ip},
                actor="Syslog receiver",
            )
            db.commit()
        return True

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        peer_ip = str(peer[0]) if peer else "unknown"
        if not self._is_allowed(peer_ip):
            self.counters["rejected"] += 1
            writer.close()
            await writer.wait_closed()
            return
        self.counters["connections"] += 1
        try:
            while True:
                try:
                    raw = await self._read_message(reader)
                except (asyncio.LimitOverrunError, asyncio.IncompleteReadError, ValueError):
                    self.counters["rejected"] += 1
                    break
                if raw is None:
                    break
                raw = raw.strip()
                if not raw:
                    continue
                self.counters["received"] += 1
                try:
                    stored = await asyncio.to_thread(self._store_message, raw, peer_ip)
                    if stored:
                        self.counters["ingested"] += 1
                        self.last_event_at = datetime.now(timezone.utc)
                    else:
                        self.counters["ignored"] += 1
                except Exception:
                    self.counters["errors"] += 1
                    logger.exception("syslog_event_ingestion_failed", extra={"sender": peer_ip})
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
