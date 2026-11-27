"""Application configuration, read from environment variables prefixed with APP_."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, PostgresDsn, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Local development values. Never acceptable in production (enforced below).
DEV_DATABASE_URL = "postgresql+asyncpg://maro:maro@localhost:5432/maro"
DEV_SECRET_KEY = "development-only-secret-key-never-use-this-in-production"

MIN_SECRET_KEY_LENGTH = 32


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="APP_",
        env_file=".env",
        extra="ignore",
        # Without this, a configuration mistake prints the offending value in the error,
        # and that value may be a password or key. Errors name the field, never its contents.
        hide_input_in_errors=True,
    )

    environment: Literal["development", "staging", "production"] = "development"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    allowed_origins: list[str] = ["http://localhost:3000"]

    # repr=False keeps these out of printed settings; hide_input_in_errors (above) keeps
    # them out of error messages.
    database_url: PostgresDsn = Field(
        default=DEV_DATABASE_URL, validate_default=True, repr=False
    )
    # Used to make sign-in codes unforgeable. Rotating it invalidates all pending codes.
    secret_key: SecretStr = Field(default=SecretStr(DEV_SECRET_KEY), repr=False)

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    @model_validator(mode="after")
    def _check_secrets(self) -> Settings:
        """Fail at startup rather than run with a weak secret or a development database."""
        if len(self.secret_key.get_secret_value()) < MIN_SECRET_KEY_LENGTH:
            raise ValueError(
                f"APP_SECRET_KEY must be at least {MIN_SECRET_KEY_LENGTH} characters"
            )
        if self.is_production and str(self.database_url) == DEV_DATABASE_URL:
            raise ValueError("APP_DATABASE_URL must be set explicitly in production")
        if self.is_production and self.secret_key.get_secret_value() == DEV_SECRET_KEY:
            raise ValueError("APP_SECRET_KEY must be set explicitly in production")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
