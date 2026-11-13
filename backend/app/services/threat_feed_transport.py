"""HTTPS-only feed retrieval with destination validation and connect-time IP pinning."""

import ipaddress
import os
import socket
import ssl
from urllib.parse import urlsplit

import httpcore
import httpx
from httpcore._backends.sync import SyncBackend

from app.config import Settings
from app.models import ThreatFeed


def _hostname(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        raise ValueError("Threat feeds must use HTTPS and include a hostname.")
    if parsed.username or parsed.password or parsed.fragment or parsed.query or parsed.port not in {None, 443}:
        raise ValueError("Feed URL includes a prohibited credential, query, fragment, or port.")
    try:
        ipaddress.ip_address(parsed.hostname)
    except ValueError:
        return parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
    raise ValueError("Feed URLs must use an allowlisted hostname, not an IP literal.")


def validate_feed_configuration(feed: ThreatFeed, settings: Settings) -> str:
    host = _hostname(feed.url)
    allowed_hosts = settings.allowed_feed_hosts
    if not allowed_hosts:
        raise ValueError("No allowed external feed hosts are configured.")
    if host not in allowed_hosts:
        raise ValueError("Feed hostname is not in THREATLENS_FEED_ALLOWED_HOSTS.")
    return host


def resolve_public_feed_addresses(host: str, port: int = 443) -> list[str]:
    """Resolve and reject the host if any DNS answer is not globally routable."""
    try:
        records = socket.getaddrinfo(host, port, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    except OSError as exc:
        raise ValueError("Feed hostname could not be resolved.") from exc
    addresses = list(dict.fromkeys(record[4][0].split("%", 1)[0] for record in records))
    if not addresses:
        raise ValueError("Feed hostname resolved to no address.")
    for address in addresses:
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError as exc:
            raise ValueError("Feed DNS returned an invalid address.") from exc
        if not parsed.is_global:
            raise ValueError("Feed DNS resolved to a private, local, reserved, or otherwise prohibited destination.")
    return addresses


class _PinnedSyncBackend(SyncBackend):
    """Resolve at connect time and connect to a validated numeric IP, never the hostname."""

    def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        addresses = resolve_public_feed_addresses(host, port)
        last_error: Exception | None = None
        for address in addresses:
            try:
                # Connecting to the numeric result pins the connection and prevents a
                # second OS DNS lookup after the security check. httpcore still uses
                # the request origin hostname for TLS SNI and certificate validation.
                return super().connect_tcp(address, port, timeout, local_address, socket_options)
            except Exception as exc:
                last_error = exc
        if last_error:
            raise last_error
        raise ValueError("Feed host has no validated destination addresses.")


class _PinnedHTTPTransport(httpx.HTTPTransport):
    def __init__(self, settings: Settings):
        limits = httpx.Limits(max_connections=1, max_keepalive_connections=0)
        super().__init__(verify=True, trust_env=False, http1=True, http2=False, limits=limits, retries=0)
        self._pool.close()
        # httpx's public HTTPTransport does not yet expose httpcore's NetworkBackend
        # parameter. Replacing its pool keeps the normal HTTPX request/response layer
        # while routing every socket connection through the validating backend.
        self._pool = httpcore.ConnectionPool(
            ssl_context=ssl.create_default_context(),
            max_connections=1,
            max_keepalive_connections=0,
            keepalive_expiry=0.0,
            http1=True,
            http2=False,
            retries=0,
            network_backend=_PinnedSyncBackend(),
        )


def fetch_feed_body(feed: ThreatFeed, settings: Settings) -> tuple[bytes, int]:
    """Fetch a feed with allowlisting, connect-time DNS validation, and a body cap."""
    host = validate_feed_configuration(feed, settings)
    # Validate DNS before initializing the client, then repeat validation and pin the
    # exact numeric destination inside the socket backend when the connection opens.
    resolve_public_feed_addresses(host, 443)
    timeout = httpx.Timeout(
        connect=settings.feed_connect_timeout_seconds,
        read=settings.feed_read_timeout_seconds,
        write=settings.feed_read_timeout_seconds,
        pool=settings.feed_connect_timeout_seconds,
    )
    headers = {"Accept": "application/json, text/csv;q=0.9"}
    if feed.credential_env_var:
        secret = os.environ.get(feed.credential_env_var)
        if not secret:
            raise ValueError(f"Credential environment variable {feed.credential_env_var} is not set.")
        headers["Authorization"] = f"Bearer {secret}"
    body = bytearray()
    with httpx.Client(
        transport=_PinnedHTTPTransport(settings),
        timeout=timeout,
        follow_redirects=False,
        trust_env=False,
        headers=headers,
    ) as client:
        with client.stream("GET", feed.url) as response:
            if 300 <= response.status_code < 400:
                raise ValueError("Feed redirects are disabled.")
            response.raise_for_status()
            content_length = response.headers.get("content-length")
            if content_length:
                try:
                    if int(content_length) > settings.feed_max_response_bytes:
                        raise ValueError("Feed response exceeds the configured size limit.")
                except ValueError as exc:
                    if str(exc).startswith("Feed response"):
                        raise
                    raise ValueError("Feed returned an invalid Content-Length header.") from exc
            media_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
            allowed_types = {"application/json", "text/json", "text/csv", "application/csv", "application/octet-stream"}
            if media_type and media_type not in allowed_types and not media_type.endswith("+json"):
                raise ValueError("Feed returned an unexpected content type.")
            for chunk in response.iter_bytes():
                if len(body) + len(chunk) > settings.feed_max_response_bytes:
                    raise ValueError("Feed response exceeds the configured size limit.")
                body.extend(chunk)
            return bytes(body), len(body)
