"""Session service: issue, verify and end sign-in sessions.

How it works:
  1. On sign-in, a long random token is generated and handed to the browser (in a
     secure cookie, added in a later step).
  2. Only a SHA-256 hash of the token is stored. The token itself is never saved or
     logged, so a leaked database cannot be used to sign in as anyone.
  3. On every request the browser's token is hashed and looked up.

A session stops working when ANY of these is true: it was signed out, it passed its
hard expiry, it has been idle too long, or its user was deactivated.

Every function takes `now` so tests can move time forward without waiting.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AuthSession, User

SESSION_LIFETIME = timedelta(days=30)  # hard limit, never extended
IDLE_TIMEOUT = timedelta(days=7)  # signed out after this long without use
TOUCH_INTERVAL = timedelta(minutes=5)  # "last seen" is saved at most this often
PURGE_RETENTION = timedelta(
    days=30
)  # finished sessions are kept this long, then deleted

TOKEN_BYTES = 32  # 256 bits of randomness
MAX_TOKEN_LENGTH = 128  # real tokens are 43 characters; anything longer is junk
MAX_USER_AGENT_LENGTH = 512


class InactiveUserError(Exception):
    """Raised when asked to sign in a deactivated user."""


@dataclass(frozen=True)
class IssuedSession:
    """A freshly created session. The token must be given to the browser, then forgotten."""

    session: AuthSession
    token: str = field(
        repr=False
    )  # never appears when this object is printed or logged


@dataclass(frozen=True)
class Authenticated:
    user: User
    session: AuthSession


def generate_token() -> str:
    return secrets.token_urlsafe(TOKEN_BYTES)


def hash_token(token: str) -> bytes:
    """SHA-256 is enough here: tokens are random and 256 bits long, so there is nothing to guess."""
    return hashlib.sha256(token.encode("utf-8")).digest()


def _now() -> datetime:
    return datetime.now(UTC)


def _lookup_hash(token: str) -> bytes | None:
    """Hash a token from the outside world, or None if it cannot possibly be genuine."""
    if not token or len(token) > MAX_TOKEN_LENGTH:
        return None
    try:
        return hash_token(token)
    except UnicodeEncodeError:  # e.g. lone surrogate characters
        return None


async def create_session(
    db: AsyncSession,
    user: User,
    *,
    user_agent: str | None = None,
    now: datetime | None = None,
    lifetime: timedelta = SESSION_LIFETIME,
) -> IssuedSession:
    """Sign a user in. The session is saved before the token is handed back."""
    if not user.is_active:
        raise InactiveUserError
    now = now or _now()
    token = generate_token()
    session = AuthSession(
        user_id=user.id,
        token_hash=hash_token(token),
        created_at=now,
        last_seen_at=now,
        expires_at=now + lifetime,
        user_agent=user_agent[:MAX_USER_AGENT_LENGTH] if user_agent else None,
    )
    db.add(session)
    await db.commit()
    return IssuedSession(session=session, token=token)


async def get_valid_session(
    db: AsyncSession,
    token: str,
    *,
    now: datetime | None = None,
    idle_timeout: timedelta = IDLE_TIMEOUT,
) -> Authenticated | None:
    """Return the user and session for a token, or None if it is not (or no longer) valid."""
    token_hash = _lookup_hash(token)
    if token_hash is None:
        return None
    now = now or _now()
    row = (
        await db.execute(
            select(AuthSession, User)
            .join(User, User.id == AuthSession.user_id)
            .where(
                AuthSession.token_hash == token_hash,
                AuthSession.revoked_at.is_(None),
                AuthSession.expires_at > now,
                AuthSession.last_seen_at > now - idle_timeout,
                User.is_active.is_(True),
            )
        )
    ).one_or_none()
    return Authenticated(user=row.User, session=row.AuthSession) if row else None


async def touch_session(
    db: AsyncSession,
    session: AuthSession,
    *,
    now: datetime | None = None,
    interval: timedelta = TOUCH_INTERVAL,
) -> bool:
    """Record that the session was just used, at most once per `interval`.

    Saving on every request would turn each page view into a database write. This keeps
    the idle timeout accurate to within a few minutes. The hard expiry is never extended.
    """
    now = now or _now()
    if now - session.last_seen_at < interval:
        return False
    session.last_seen_at = now
    await db.commit()
    return True


async def revoke_token(
    db: AsyncSession, token: str, *, now: datetime | None = None
) -> bool:
    """Sign out the session that owns this token. Safe to repeat; unknown tokens do nothing."""
    token_hash = _lookup_hash(token)
    if token_hash is None:
        return False
    result = await db.execute(
        update(AuthSession)
        .where(AuthSession.token_hash == token_hash, AuthSession.revoked_at.is_(None))
        .values(revoked_at=now or _now())
        .execution_options(synchronize_session=False)
    )
    await db.commit()
    return result.rowcount > 0


async def revoke_all_for_user(
    db: AsyncSession,
    user_id: uuid.UUID,
    *,
    except_session_id: uuid.UUID | None = None,
    now: datetime | None = None,
) -> int:
    """Sign a user out everywhere, optionally keeping the current session. Returns how many ended."""
    statement = (
        update(AuthSession)
        .where(AuthSession.user_id == user_id, AuthSession.revoked_at.is_(None))
        .values(revoked_at=now or _now())
        .execution_options(synchronize_session=False)
    )
    if except_session_id is not None:
        statement = statement.where(AuthSession.id != except_session_id)
    result = await db.execute(statement)
    await db.commit()
    return result.rowcount


async def purge_finished_sessions(
    db: AsyncSession,
    *,
    now: datetime | None = None,
    retention: timedelta = PURGE_RETENTION,
) -> int:
    """Delete sessions that ended more than `retention` ago. Meant to run on a schedule."""
    cutoff = (now or _now()) - retention
    result = await db.execute(
        delete(AuthSession)
        .where(or_(AuthSession.expires_at < cutoff, AuthSession.revoked_at < cutoff))
        .execution_options(synchronize_session=False)
    )
    await db.commit()
    return result.rowcount
