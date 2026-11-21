"""The User model."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, String, Uuid, func, text
from sqlalchemy.orm import Mapped, mapped_column, validates

from app.db import Base


class User(Base):
    """A person who can sign in to Maro.

    Sign-in credentials (passkeys, login links, sessions) live in their own tables,
    so this table holds only who the person is.
    """

    __tablename__ = "users"
    __table_args__ = (
        # Emails are always stored lowercase, so "A@x.com" and "a@x.com" can never
        # become two accounts. The validator below normalises; this is the safety net.
        CheckConstraint("email = lower(email)", name="email_is_lowercase"),
        CheckConstraint("length(email) > 3", name="email_is_not_trivial"),
    )

    # Random UUIDs: they reveal nothing about how many users exist and cannot be guessed.
    # Python generates the id when the row is saved; the database default covers rows
    # created by other tools. (The id is not available until the row is saved.)
    id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    email: Mapped[str] = mapped_column(
        String(320), unique=True
    )  # 320 is the email standard's maximum
    display_name: Mapped[str | None] = mapped_column(String(100))
    # Switching this off blocks sign-in without deleting anything.
    is_active: Mapped[bool] = mapped_column(server_default=text("true"))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    @validates("email")
    def _normalise_email(self, key: str, value: str) -> str:
        return value.strip().lower()

    def __repr__(self) -> str:
        # The id only: emails are personal data and must not end up in logs.
        return f"User(id={self.id})"
