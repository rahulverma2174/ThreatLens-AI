from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "ThreatLens AI"
    # Keep local SQLite as the default; PostgreSQL uses e.g. postgresql+psycopg://...
    # repr=False prevents accidental disclosure when settings are represented in logs.
    database_url: str = Field(default="sqlite:///./threatlens.db", repr=False)
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"
    auth_mode: Literal["local", "demo"] = "local"
    demo_username: str = ""
    demo_password_hash: str = ""
    demo_session_ttl_seconds: int = Field(default=1800, ge=300, le=86400)
    demo_login_attempts: int = Field(default=8, ge=1, le=100)
    demo_login_window_seconds: int = Field(default=900, ge=60, le=86400)
    demo_global_login_attempts: int = Field(default=50, ge=1, le=1000)
    cookie_samesite: Literal["lax", "strict", "none"] = "none"
    ollama_url: str = "http://127.0.0.1:11434"
    ollama_model: str = "qwen2.5:3b"
    ollama_timeout_seconds: float = 90
    syslog_enabled: bool = True
    syslog_host: str = "127.0.0.1"
    syslog_port: int = Field(default=5514, ge=1, le=65535)
    syslog_allowed_sources: str = "127.0.0.1/32,::1/128"
    syslog_max_message_bytes: int = Field(default=8192, ge=256, le=65536)
    feed_allowed_hosts: str = ""
    feed_max_response_bytes: int = Field(default=5_242_880, ge=1024, le=20_971_520)
    feed_max_records: int = Field(default=25_000, ge=1, le=100_000)
    feed_connect_timeout_seconds: float = Field(default=5.0, ge=0.5, le=30.0)
    feed_read_timeout_seconds: float = Field(default=10.0, ge=0.5, le=60.0)

    model_config = SettingsConfigDict(env_prefix="THREATLENS_", env_file=".env", extra="ignore")

    def __repr__(self) -> str:
        # Database URLs may contain passwords; never include them in a settings repr.
        return f"Settings(app_name={self.app_name!r}, database_url='<redacted>', auth_mode={self.auth_mode!r})"

    @property
    def allowed_origins(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def session_cookie_secure(self) -> bool:
        # Hosted demo authentication must only issue cookies over HTTPS.
        return self.auth_mode == "demo"

    @property
    def allowed_syslog_networks(self) -> list[str]:
        return [network.strip() for network in self.syslog_allowed_sources.split(",") if network.strip()]

    @property
    def allowed_feed_hosts(self) -> set[str]:
        return {host.strip().lower().rstrip(".") for host in self.feed_allowed_hosts.split(",") if host.strip()}


@lru_cache
def get_settings() -> Settings:
    return Settings()
