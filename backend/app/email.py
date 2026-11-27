"""Sending email.

The rest of the app only knows the `EmailSender` interface, so a real provider can be
plugged in later without touching anything else.

For now there are two senders:
  * ConsoleEmailSender (development only): prints the email in the terminal, so you can
    read your own sign-in code without any email provider.
  * RefusingEmailSender (everywhere else): refuses to send, loudly. Until a real sender
    exists, production must not silently print sign-in codes into its logs.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Protocol

from app.config import Settings

logger = logging.getLogger("app.email")


@dataclass(frozen=True)
class EmailMessage:
    to: str
    subject: str
    body: str = field(
        repr=False
    )  # may contain a sign-in code, so it never appears when printed


class EmailSender(Protocol):
    async def send(self, message: EmailMessage) -> None: ...


class EmailNotConfiguredError(RuntimeError):
    """Raised when something tries to send email but no real sender is set up."""


class ConsoleEmailSender:
    """Development only. Prints the email instead of sending it."""

    async def send(self, message: EmailMessage) -> None:
        rule = "=" * 64
        logger.warning(
            "\n%s\nEMAIL (development only: nothing was really sent)\nTo:      %s\nSubject: %s\n\n%s\n%s",
            rule,
            message.to,
            message.subject,
            message.body,
            rule,
        )


class RefusingEmailSender:
    """Used wherever no real email sender is configured. Never prints or logs the message."""

    async def send(self, message: EmailMessage) -> None:
        raise EmailNotConfiguredError(
            "no email sender is configured, so the email was not sent"
        )


def create_email_sender(settings: Settings) -> EmailSender:
    if settings.environment == "development":
        return ConsoleEmailSender()
    logger.warning(
        "no real email sender is configured: sign-in codes cannot be delivered"
    )
    return RefusingEmailSender()
