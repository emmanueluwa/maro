"""Tests for configuration: defaults, validation, and the safety rules around secrets."""

import os

import pytest
from pydantic import ValidationError

from app.config import (
    DEV_DATABASE_URL,
    DEV_SECRET_KEY,
    MIN_SECRET_KEY_LENGTH,
    Settings,
    get_settings,
)

REAL_DATABASE_URL = "postgresql+asyncpg://user:s3cret@db.internal:5432/maro"
REAL_SECRET_KEY = "a-long-production-secret-key-0123456789abcdef"
PRODUCTION = {
    "environment": "production",
    "database_url": REAL_DATABASE_URL,
    "secret_key": REAL_SECRET_KEY,
}


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
    assert settings.secret_key.get_secret_value() == DEV_SECRET_KEY
    assert not settings.is_production


def test_production_requires_explicit_database_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(ValidationError, match="APP_DATABASE_URL"):
        load_settings(monkeypatch, environment="production", secret_key=REAL_SECRET_KEY)


def test_production_rejects_development_database_even_if_set_explicitly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(ValidationError, match="APP_DATABASE_URL"):
        load_settings(
            monkeypatch,
            environment="production",
            database_url=DEV_DATABASE_URL,
            secret_key=REAL_SECRET_KEY,
        )


def test_production_requires_explicit_secret_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(ValidationError, match="APP_SECRET_KEY"):
        load_settings(
            monkeypatch, environment="production", database_url=REAL_DATABASE_URL
        )


def test_production_rejects_development_secret_even_if_set_explicitly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(ValidationError, match="APP_SECRET_KEY"):
        load_settings(
            monkeypatch,
            environment="production",
            database_url=REAL_DATABASE_URL,
            secret_key=DEV_SECRET_KEY,
        )


def test_production_accepts_explicit_database_url_and_secret_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = load_settings(monkeypatch, **PRODUCTION)
    assert settings.is_production


def test_staging_may_use_the_development_defaults(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert not load_settings(monkeypatch, environment="staging").is_production


def test_secret_key_must_be_long_enough_in_every_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(ValidationError, match=f"at least {MIN_SECRET_KEY_LENGTH}"):
        load_settings(monkeypatch, secret_key="x" * (MIN_SECRET_KEY_LENGTH - 1))

    assert load_settings(monkeypatch, secret_key="x" * MIN_SECRET_KEY_LENGTH)


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


def test_secrets_never_appear_in_repr_or_str(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = load_settings(monkeypatch, **PRODUCTION)

    for printed in (
        repr(settings),
        str(settings),
        repr(settings.secret_key),
        str(settings.secret_key),
    ):
        assert "s3cret" not in printed
        assert REAL_SECRET_KEY not in printed


@pytest.mark.parametrize(
    ("variable", "bad_value", "leak", "field_named"),
    [
        (
            "database_url",
            "mysql://admin:Sup3rS3cretPw@db.internal/maro",
            "Sup3rS3cretPw",
            "database_url",
        ),
        (
            "database_url",
            "not a url but contains hunter2hunter2",
            "hunter2hunter2",
            "database_url",
        ),
        ("secret_key", "tooShortToBeSafe", "tooShortToBeSafe", "APP_SECRET_KEY"),
    ],
)
def test_configuration_errors_never_reveal_the_secret_value(
    monkeypatch: pytest.MonkeyPatch,
    variable: str,
    bad_value: str,
    leak: str,
    field_named: str,
) -> None:
    """A deployment mistake must not put a password or key into the logs."""
    with pytest.raises(ValidationError) as caught:
        load_settings(monkeypatch, **{variable: bad_value})

    message = str(caught.value)
    assert leak not in message
    assert field_named in message  # still tells the operator WHICH setting is wrong


def test_get_settings_is_cached() -> None:
    assert get_settings() is get_settings()
