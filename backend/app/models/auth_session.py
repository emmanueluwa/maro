"""The AuthSession model: a signed-in browser or device."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    LargeBinary,
    String,
    Uuid,
    func,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base


class AuthSession(Base):
    """One signed-in session.

    The browser holds a long random token in a secure cookie. This table stores only
    a SHA-256 hash of that token, never the token itself, so a leaked copy of the
    database cannot be used to sign in as anyone.
    """

    __tablename__ = "auth_sessions"
    __table_args__ = (
        CheckConstraint("length(token_hash) = 32", name="token_hash_is_sha256"),
        CheckConstraint("expires_at > created_at", name="expires_after_creation"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    # Deleting a user deletes their sessions with them.
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    token_hash: Mapped[bytes] = mapped_column(LargeBinary, unique=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    # A hard limit: after this moment the session is dead however recently it was used.
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    # Signing out sets this. The row is kept so there is a record of the session.
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Lets the person recognise their own devices in a "where am I signed in" list.
    user_agent: Mapped[str | None] = mapped_column(String(512))

    def __repr__(self) -> str:
        # The id only: never anything that could help someone impersonate a session.
        return f"AuthSession(id={self.id})"
