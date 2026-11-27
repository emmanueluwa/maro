"""Login codes: sign in with a six-digit code sent by email.

Six digits is only a million possibilities, so safety comes from the rules around the
code, not from the code:

  * Stored as a KEYED hash (HMAC-SHA256 with the app's secret key, plus the user's id).
    An unkeyed hash of a six-digit number can be reversed instantly; without the secret
    key, a leaked copy of the database is useless.
  * Short life (10 minutes), single use, and at most 5 wrong guesses per code.
  * Account-wide limit: at most 10 wrong guesses per hour across ALL of a user's codes.
    Without it, an attacker could simply keep asking for fresh codes.
  * One live code per user, enforced by the database. Asking for a new code retires the
    old one, so there is never more than one code to guess.
  * A cooldown between codes, so the form cannot be used to flood someone's inbox.

Nothing here reveals WHY something failed. `issue_login_code` and `verify_login_code`
return None for every kind of failure, so callers (and therefore attackers) learn nothing
about which emails have accounts. The reason is logged for operators, without any
personal data.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import re
import secrets
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.models import LoginCode, User

logger = logging.getLogger("app.auth")

CODE_LENGTH = 6
CODE_LIFETIME = timedelta(minutes=10)
MAX_ATTEMPTS_PER_CODE = 5
RESEND_COOLDOWN = timedelta(seconds=60)
FAILURE_WINDOW = timedelta(hours=1)
MAX_FAILURES_PER_WINDOW = 10

MAX_EMAIL_LENGTH = 320
MAX_RAW_CODE_LENGTH = 32  # people type spaces and dashes; anything longer is junk

_CODE_PATTERN = re.compile(rf"[0-9]{{{CODE_LENGTH}}}")  # ASCII digits only
_SEPARATORS = str.maketrans("", "", " -")  # people type "123 456" or "123-456"


@dataclass(frozen=True)
class IssuedLoginCode:
    """A code that has been created and must now be emailed. Never printed or logged.

    Plain values only, so it stays usable whatever happens to the database session afterwards.
    """

    user_id: uuid.UUID
    email: str
    expires_at: datetime
    code: str = field(repr=False)


def generate_code() -> str:
    return f"{secrets.randbelow(10**CODE_LENGTH):0{CODE_LENGTH}d}"


def normalise_code(raw: str) -> str | None:
    """Turn what a person typed into exactly six ASCII digits, or None if it cannot be a code."""
    if len(raw) > MAX_RAW_CODE_LENGTH:
        return None
    cleaned = raw.strip().translate(_SEPARATORS)
    return cleaned if _CODE_PATTERN.fullmatch(cleaned) else None


def _signing_key(settings: Settings) -> bytes:
    """A key derived for this one purpose, so the secret key is never used raw."""
    secret = settings.secret_key.get_secret_value().encode("utf-8")
    return hmac.new(secret, b"maro/login-code/v1", hashlib.sha256).digest()


def hash_code(code: str, user_id: uuid.UUID, settings: Settings) -> bytes:
    """Keyed hash of a code. Including the user id means the same six digits give different
    hashes for different people, so a code can never be replayed against someone else.
    """
    return hmac.new(
        _signing_key(settings), user_id.bytes + code.encode("ascii"), hashlib.sha256
    ).digest()


def _now() -> datetime:
    return datetime.now(UTC)


def _clean_email(email: str) -> str | None:
    """Normalise an email typed by a person, or None if it cannot possibly be one.

    Rejects control characters (a NUL byte makes the database itself raise an error)
    and anything that cannot be encoded as text.
    """
    cleaned = email.strip().lower()
    if not cleaned or len(cleaned) > MAX_EMAIL_LENGTH:
        return None
    if any(ord(character) < 32 or ord(character) == 127 for character in cleaned):
        return None
    try:
        cleaned.encode("utf-8")
    except UnicodeEncodeError:  # e.g. lone surrogate characters
        return None
    return cleaned


async def _find_active_user(
    db: AsyncSession, email: str, *, lock: bool = False
) -> User | None:
    """The active user with this email. `lock=True` holds their row until the transaction ends,
    so two requests for the same person are handled one after the other, never at once.
    """
    cleaned = _clean_email(email)
    if cleaned is None:
        return None
    statement = select(User).where(User.email == cleaned, User.is_active.is_(True))
    if lock:
        # FOR NO KEY UPDATE: conflicts with itself (so requests for one person queue up) but not with
        # the "does this user exist" check other tables make, so it blocks as little as possible.
        statement = statement.with_for_update(key_share=True)
    return await db.scalar(statement)


async def _recent_failures(db: AsyncSession, user_id: uuid.UUID, now: datetime) -> int:
    """Wrong guesses across all of this user's recent codes."""
    total = await db.scalar(
        select(func.coalesce(func.sum(LoginCode.attempts), 0)).where(
            LoginCode.user_id == user_id,
            LoginCode.created_at > now - FAILURE_WINDOW,
        )
    )
    return int(total or 0)


async def issue_login_code(
    db: AsyncSession,
    email: str,
    *,
    settings: Settings,
    now: datetime | None = None,
    lifetime: timedelta = CODE_LIFETIME,
    cooldown: timedelta = RESEND_COOLDOWN,
) -> IssuedLoginCode | None:
    """Create a code for this email, or return None if no code should be sent.

    None covers: no such account, deactivated account, asked too soon after the last code,
    or the account is temporarily locked after too many wrong guesses. The caller must
    answer the person identically in every case.
    """
    now = now or _now()
    # Locked, so two simultaneous requests are decided one after the other: the second sees
    # the first one's code and is stopped by the cooldown instead of replacing it.
    user = await _find_active_user(db, email, lock=True)
    if user is None:
        logger.info("login code not issued: reason=no_active_account")
        return None
    user_id, user_email = user.id, user.email  # read now: a rollback would discard them

    if await _recent_failures(db, user_id, now) >= MAX_FAILURES_PER_WINDOW:
        await db.rollback()  # ends the transaction, which releases the lock
        logger.info("login code not issued: reason=locked user=%s", user_id)
        return None
    latest = await db.scalar(
        select(func.max(LoginCode.created_at)).where(LoginCode.user_id == user_id)
    )
    if latest is not None and now - latest < cooldown:
        await db.rollback()
        logger.info("login code not issued: reason=cooldown user=%s", user_id)
        return None

    code = generate_code()
    await db.execute(
        update(LoginCode)
        .where(LoginCode.user_id == user_id, LoginCode.consumed_at.is_(None))
        .values(consumed_at=now)
        .execution_options(synchronize_session=False)
    )
    db.add(
        LoginCode(
            user_id=user_id,
            code_hash=hash_code(code, user_id, settings),
            created_at=now,
            expires_at=now + lifetime,
        )
    )
    try:
        await db.commit()
    except IntegrityError:
        # Should not happen now that requests are serialised, but the database has the final say:
        # it allows only one live code per user, so the loser sends nothing.
        await db.rollback()
        logger.info("login code not issued: reason=concurrent_request user=%s", user_id)
        return None
    return IssuedLoginCode(
        user_id=user_id, email=user_email, expires_at=now + lifetime, code=code
    )


async def verify_login_code(
    db: AsyncSession,
    email: str,
    code: str,
    *,
    settings: Settings,
    now: datetime | None = None,
    max_attempts: int = MAX_ATTEMPTS_PER_CODE,
) -> User | None:
    """Return the user if the code is right, or None for every kind of failure."""
    now = now or _now()
    user = await _find_active_user(db, email)
    if user is None:
        logger.info("login code rejected: reason=no_active_account")
        return None
    user_id = user.id  # read now: a rollback would discard it
    attempt = normalise_code(code)
    if attempt is None:
        logger.info("login code rejected: reason=malformed user=%s", user_id)
        return None  # cannot be right, so it does not count against the user's guesses

    # Lock the row so simultaneous guesses are counted one after another and none is lost.
    live = await db.scalar(
        select(LoginCode)
        .where(LoginCode.user_id == user_id, LoginCode.consumed_at.is_(None))
        .with_for_update()
    )
    if live is None:
        logger.info("login code rejected: reason=no_live_code user=%s", user_id)
        return None
    if await _recent_failures(db, user_id, now) >= MAX_FAILURES_PER_WINDOW:
        await db.rollback()
        logger.info("login code rejected: reason=locked user=%s", user_id)
        return None
    if live.expires_at <= now:
        live.consumed_at = now
        await db.commit()
        logger.info("login code rejected: reason=expired user=%s", user_id)
        return None

    if hmac.compare_digest(live.code_hash, hash_code(attempt, user_id, settings)):
        live.consumed_at = now
        await db.commit()
        return user

    attempts = live.attempts + 1
    live.attempts = attempts
    if attempts >= max_attempts:
        live.consumed_at = now  # burned: even the right code no longer works
    await db.commit()
    logger.info(
        "login code rejected: reason=wrong_code user=%s attempts=%s", user_id, attempts
    )
    return None
