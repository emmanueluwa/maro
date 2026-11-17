"""Application configuration, read from environment variables prefixed with APP_."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, PostgresDsn, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Local development database. Never acceptable in production (enforced below).
DEV_DATABASE_URL = "postgresql+asyncpg://maro:maro@localhost:5432/maro"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="APP_", env_file=".env", extra="ignore"
    )

    environment: Literal["development", "staging", "production"] = "development"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    allowed_origins: list[str] = ["http://localhost:3000"]

    # repr=False keeps the password out of logs and error messages.
    database_url: PostgresDsn = Field(
        default=DEV_DATABASE_URL, validate_default=True, repr=False
    )

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    @model_validator(mode="after")
    def _reject_development_defaults_in_production(self) -> Settings:
        """Fail at startup rather than run production against a development database."""
        if self.is_production and str(self.database_url) == DEV_DATABASE_URL:
            raise ValueError("APP_DATABASE_URL must be set explicitly in production")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
