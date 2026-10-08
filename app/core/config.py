"""Application settings, loaded from environment variables / .env."""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", case_sensitive=False)

    app_name: str = "CyberGuard Unified Security Engine"
    app_version: str = "0.1.0"
    log_level: str = "INFO"
    api_key: str = ""
    max_upload_bytes: int = 10 * 1024 * 1024
    allowed_origins: str = "http://localhost:3000,http://127.0.0.1:3000"

    @property
    def origins(self) -> list[str]:
        return [o.strip() for o in self.allowed_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
