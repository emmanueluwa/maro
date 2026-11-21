"""The LoginCode model: a one-time code emailed to someone so they can sign in."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    LargeBinary,
    Uuid,
    func,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base


class LoginCode(Base):
    """A six-digit sign-in code that has been sent to a user.

    Six digits is only a million possibilities, so the rules around it matter:
      - Only a keyed hash (HMAC-SHA256) of the code is stored, never the code itself.
        A plain hash of a six-digit number could be reversed instantly; the secret key
        is what makes a leaked copy of this table useless.
      - A code works once, and only until `expires_at` (minutes, not hours).
      - Wrong guesses are counted in `attempts`, and the code dies after a few.
      - A user can have only ONE live code at a time, enforced by the database itself
        (see the index below). Asking for a new code retires the old one.
    """

    __tablename__ = "login_codes"
    __table_args__ = (
        CheckConstraint("length(code_hash) = 32", name="code_hash_is_hmac_sha256"),
        CheckConstraint("expires_at > created_at", name="expires_after_creation"),
        CheckConstraint("attempts >= 0", name="attempts_not_negative"),
        # At most one row per user may be unused. Used (consumed) rows are unlimited.
        Index(
            "uq_login_codes_one_live_code_per_user",
            "user_id",
            unique=True,
            postgresql_where=text("consumed_at IS NULL"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    # Deleting a user deletes their codes with them.
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    # Deliberately NOT unique: two different people can legitimately be sent the same
    # six digits, and a uniqueness rule would turn that coincidence into an error.
    code_hash: Mapped[bytes] = mapped_column(LargeBinary)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    # Set when the code is used, or retired because a newer code replaced it.
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Wrong guesses so far. The limit itself lives in the service, so it can be tuned.
    attempts: Mapped[int] = mapped_column(server_default=text("0"))

    def __repr__(self) -> str:
        # The id only: never the hash, and never whose code it is.
        return f"LoginCode(id={self.id})"
