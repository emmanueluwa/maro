"""Tests for configuration: defaults, validation and the production safety guard."""

import os

import pytest
from pydantic import ValidationError

from app.config import DEV_DATABASE_URL, Settings, get_settings

REAL_DATABASE_URL = "postgresql+asyncpg://user:s3cret@db.internal:5432/maro"


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch: pytest.MonkeyPatch):
    """Start every test with no APP_ variables set, no .env file read, and a fresh cache."""
    for key in list(os.environ):
        if key.startswith("APP_"):
            monkeypatch.delenv(key)
    monkeypatch.setitem(Settings.model_config, "env_file", None)
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def load_settings(monkeypatch: pytest.MonkeyPatch, **env: str) -> Settings:
    """Build Settings from only the given APP_ variables."""
    for name, value in env.items():
        monkeypatch.setenv(f"APP_{name.upper()}", value)
    return Settings()


def test_defaults_suit_local_development(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = load_settings(monkeypatch)
    assert settings.environment == "development"
    assert settings.log_level == "INFO"
    assert settings.allowed_origins == ["http://localhost:3000"]
    assert str(settings.database_url) == DEV_DATABASE_URL
    assert not settings.is_production


def test_production_requires_explicit_database_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(ValidationError, match="APP_DATABASE_URL"):
        load_settings(monkeypatch, environment="production")


def test_production_rejects_development_database_even_if_set_explicitly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(ValidationError, match="APP_DATABASE_URL"):
        load_settings(
            monkeypatch, environment="production", database_url=DEV_DATABASE_URL
        )


def test_production_accepts_explicit_database_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = load_settings(
        monkeypatch, environment="production", database_url=REAL_DATABASE_URL
    )
    assert settings.is_production


def test_staging_may_use_the_development_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert not load_settings(monkeypatch, environment="staging").is_production


def test_rejects_non_postgres_database_url(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValidationError):
        load_settings(monkeypatch, database_url="mysql://user:pw@host/db")


def test_rejects_unknown_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValidationError):
        load_settings(monkeypatch, environment="prodution")  # deliberate typo


def test_rejects_unknown_log_level(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValidationError):
        load_settings(monkeypatch, log_level="LOUD")


def test_allowed_origins_read_from_json(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = load_settings(
        monkeypatch,
        allowed_origins='["http://localhost:3000", "https://app.example.com"]',
    )
    assert settings.allowed_origins == [
        "http://localhost:3000",
        "https://app.example.com",
    ]


def test_database_password_never_appears_in_repr_or_str(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = load_settings(monkeypatch, database_url=REAL_DATABASE_URL)
    assert "s3cret" not in repr(settings)
    assert "s3cret" not in str(settings)


def test_get_settings_is_cached() -> None:
    assert get_settings() is get_settings()
