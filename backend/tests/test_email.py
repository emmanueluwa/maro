"""Tests for the email module: what each sender does, and what it must never do."""

import logging

import pytest

from app.config import Settings
from app.email import (
    ConsoleEmailSender,
    EmailMessage,
    EmailNotConfiguredError,
    RefusingEmailSender,
    create_email_sender,
)

pytestmark = pytest.mark.anyio

PRODUCTION_URL = "postgresql+asyncpg://u:p@db.internal:5432/maro"
PRODUCTION_KEY = "a-long-production-secret-key-0123456789abcdef"


def settings_for(environment: str) -> Settings:
    return Settings(
        _env_file=None,
        environment=environment,
        database_url=PRODUCTION_URL,
        secret_key=PRODUCTION_KEY,
    )


MESSAGE = EmailMessage(
    to="ada@example.com", subject="Your code", body="Your code is 123 456"
)


def test_a_message_never_prints_its_body() -> None:
    """The body can hold a sign-in code, so printing a message must not reveal it."""
    assert "123 456" not in repr(MESSAGE)
    assert "123 456" not in str(MESSAGE)
    assert "ada@example.com" in repr(MESSAGE)


async def test_the_console_sender_prints_the_email_so_a_developer_can_read_it(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger="app.email"):
        await ConsoleEmailSender().send(MESSAGE)

    printed = caplog.text
    assert "ada@example.com" in printed
    assert "Your code" in printed
    assert "Your code is 123 456" in printed
    assert "development only" in printed
    assert "nothing was really sent" in printed


async def test_the_refusing_sender_refuses_and_reveals_nothing(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.DEBUG), pytest.raises(
        EmailNotConfiguredError
    ) as caught:
        await RefusingEmailSender().send(MESSAGE)

    for leaked in ("123 456", "ada@example.com"):
        assert leaked not in caplog.text
        assert leaked not in str(caught.value)


def test_only_development_gets_the_console_sender() -> None:
    assert isinstance(
        create_email_sender(settings_for("development")), ConsoleEmailSender
    )


@pytest.mark.parametrize("environment", ["staging", "production"])
def test_everywhere_else_refuses_instead_of_printing_codes_into_logs(
    environment: str, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING, logger="app.email"):
        sender = create_email_sender(settings_for(environment))

    assert isinstance(sender, RefusingEmailSender)
    assert (
        "sign-in codes cannot be delivered" in caplog.text
    )  # a loud warning at startup
