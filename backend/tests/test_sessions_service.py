"""Tests for the session service, run against a real PostgreSQL (see conftest.py).

Time is controlled by passing `now`, so expiry and idle rules are tested without waiting.
"""

import hashlib
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import sessions
from app.auth.sessions import (
    IDLE_TIMEOUT,
    SESSION_LIFETIME,
    TOUCH_INTERVAL,
    InactiveUserError,
    create_session,
    generate_token,
    get_valid_session,
    hash_token,
    purge_finished_sessions,
    revoke_all_for_user,
    revoke_token,
    touch_session,
)
from app.models import AuthSession, User

pytestmark = pytest.mark.anyio

NOW = datetime(2026, 11, 21, 12, 0, tzinfo=UTC)


async def make_user(
    db: AsyncSession, email: str = "ada@example.com", *, active: bool = True
) -> User:
    user = User(email=email, is_active=active)
    db.add(user)
    await db.commit()
    return user


@pytest.fixture
async def user(db: AsyncSession) -> User:
    return await make_user(db)


async def count_sessions(db: AsyncSession) -> int:
    return await db.scalar(select(func.count()).select_from(AuthSession)) or 0


# --- tokens -------------------------------------------------------------------


def test_tokens_are_long_unique_and_url_safe() -> None:
    tokens = {generate_token() for _ in range(200)}

    assert len(tokens) == 200
    assert all(len(token) >= 43 for token in tokens)  # 256 bits
    assert all(token.replace("-", "").replace("_", "").isalnum() for token in tokens)


def test_hash_is_sha256_and_deterministic() -> None:
    assert hash_token("abc") == hashlib.sha256(b"abc").digest()
    assert len(hash_token("abc")) == 32
    assert hash_token("abc") != hash_token("abd")


# --- creating sessions --------------------------------------------------------


async def test_only_the_hash_is_stored_never_the_token(
    db: AsyncSession, user: User
) -> None:
    issued = await create_session(db, user, now=NOW)

    stored = await db.scalar(select(AuthSession.token_hash))
    assert stored == hash_token(issued.token)
    assert issued.token.encode() != stored
    # Searching every column of every session for the raw token must find nothing.
    dump = (
        (await db.execute(text("SELECT row_to_json(s)::text FROM auth_sessions s")))
        .scalars()
        .all()
    )
    assert all(issued.token not in row for row in dump)


async def test_issued_session_never_prints_its_token(
    db: AsyncSession, user: User
) -> None:
    issued = await create_session(db, user, now=NOW)

    assert issued.token not in repr(issued)
    assert issued.token not in str(issued)


async def test_new_session_has_the_expected_times(db: AsyncSession, user: User) -> None:
    issued = await create_session(db, user, now=NOW)

    assert issued.session.created_at == NOW
    assert issued.session.last_seen_at == NOW
    assert issued.session.expires_at == NOW + SESSION_LIFETIME
    assert issued.session.revoked_at is None


async def test_long_user_agents_are_shortened_not_rejected(
    db: AsyncSession, user: User
) -> None:
    issued = await create_session(db, user, user_agent="x" * 5000, now=NOW)

    assert issued.session.user_agent == "x" * 512


async def test_deactivated_users_cannot_sign_in(db: AsyncSession) -> None:
    inactive = await make_user(db, active=False)

    with pytest.raises(InactiveUserError):
        await create_session(db, inactive, now=NOW)
    assert await count_sessions(db) == 0


# --- checking tokens ----------------------------------------------------------


async def test_valid_token_returns_the_user_and_session(
    db: AsyncSession, user: User
) -> None:
    issued = await create_session(db, user, now=NOW)

    result = await get_valid_session(db, issued.token, now=NOW + timedelta(minutes=1))

    assert result is not None
    assert result.user.id == user.id
    assert result.session.id == issued.session.id


async def test_unknown_token_is_rejected(db: AsyncSession, user: User) -> None:
    await create_session(db, user, now=NOW)

    assert await get_valid_session(db, generate_token(), now=NOW) is None


async def test_a_token_with_one_character_changed_is_rejected(
    db: AsyncSession, user: User
) -> None:
    """Guards against a bug that only hashes part of the token."""
    issued = await create_session(db, user, now=NOW)
    last = issued.token[-1]
    altered = issued.token[:-1] + ("A" if last != "A" else "B")

    assert await get_valid_session(db, altered, now=NOW) is None
    assert await get_valid_session(db, issued.token[:-1], now=NOW) is None
    assert await get_valid_session(db, issued.token + " ", now=NOW) is None


@pytest.mark.parametrize(
    "junk",
    [
        "",
        " ",
        "x" * 10_000,
        "\ud800",
        "../../etc/passwd",
        "'; DROP TABLE users;--",
        "\x00",
    ],
)
async def test_malformed_tokens_are_rejected_without_errors(
    db: AsyncSession, user: User, junk: str
) -> None:
    await create_session(db, user, now=NOW)

    assert await get_valid_session(db, junk, now=NOW) is None
    assert await revoke_token(db, junk, now=NOW) is False


async def test_oversized_tokens_are_rejected_before_any_hashing(
    db: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    def must_not_run(token: str) -> bytes:
        raise AssertionError("an oversized token must not be hashed")

    monkeypatch.setattr(sessions, "hash_token", must_not_run)

    assert await get_valid_session(db, "x" * 10_000, now=NOW) is None


async def test_session_is_rejected_after_signing_out(
    db: AsyncSession, user: User
) -> None:
    issued = await create_session(db, user, now=NOW)

    assert await revoke_token(db, issued.token, now=NOW) is True

    assert await get_valid_session(db, issued.token, now=NOW) is None


async def test_signing_out_twice_is_harmless(db: AsyncSession, user: User) -> None:
    issued = await create_session(db, user, now=NOW)

    assert await revoke_token(db, issued.token, now=NOW) is True
    assert await revoke_token(db, issued.token, now=NOW) is False
    assert await revoke_token(db, generate_token(), now=NOW) is False


async def test_session_is_rejected_after_its_hard_expiry(
    db: AsyncSession, user: User
) -> None:
    issued = await create_session(db, user, now=NOW)

    # Used daily, so the idle rule never triggers: only the hard limit can end it.
    for day in range(1, 30):
        moment = NOW + timedelta(days=day)
        result = await get_valid_session(db, issued.token, now=moment)
        assert result is not None
        await touch_session(db, result.session, now=moment)

    assert (
        await get_valid_session(
            db, issued.token, now=NOW + timedelta(days=29, hours=23)
        )
        is not None
    )
    assert await get_valid_session(db, issued.token, now=NOW + SESSION_LIFETIME) is None
    assert (
        await get_valid_session(
            db, issued.token, now=NOW + SESSION_LIFETIME + timedelta(days=1)
        )
        is None
    )


async def test_session_is_rejected_after_being_idle_too_long(
    db: AsyncSession, user: User
) -> None:
    issued = await create_session(db, user, now=NOW)

    assert (
        await get_valid_session(
            db, issued.token, now=NOW + IDLE_TIMEOUT - timedelta(minutes=1)
        )
        is not None
    )
    assert (
        await get_valid_session(
            db, issued.token, now=NOW + IDLE_TIMEOUT + timedelta(minutes=1)
        )
        is None
    )


async def test_using_a_session_keeps_it_alive(db: AsyncSession, user: User) -> None:
    issued = await create_session(db, user, now=NOW)
    day_six = NOW + timedelta(days=6)

    result = await get_valid_session(db, issued.token, now=day_six)
    assert result is not None
    await touch_session(db, result.session, now=day_six)

    # Without the touch this would be 12 days idle and rejected.
    assert (
        await get_valid_session(db, issued.token, now=NOW + timedelta(days=12))
        is not None
    )


async def test_session_is_rejected_when_its_user_is_deactivated(
    db: AsyncSession, user: User
) -> None:
    issued = await create_session(db, user, now=NOW)
    assert await get_valid_session(db, issued.token, now=NOW) is not None

    user.is_active = False
    await db.commit()

    assert await get_valid_session(db, issued.token, now=NOW) is None


# --- keeping "last seen" up to date --------------------------------------------


async def test_touching_is_throttled(db: AsyncSession, user: User) -> None:
    issued = await create_session(db, user, now=NOW)

    soon = NOW + TOUCH_INTERVAL - timedelta(seconds=1)
    assert await touch_session(db, issued.session, now=soon) is False
    assert issued.session.last_seen_at == NOW

    later = NOW + TOUCH_INTERVAL
    assert await touch_session(db, issued.session, now=later) is True
    assert issued.session.last_seen_at == later


async def test_touching_never_extends_the_hard_expiry(
    db: AsyncSession, user: User
) -> None:
    issued = await create_session(db, user, now=NOW)
    original_expiry = issued.session.expires_at

    await touch_session(db, issued.session, now=NOW + timedelta(days=10))

    assert issued.session.expires_at == original_expiry


# --- signing out everywhere ------------------------------------------------------


async def test_sign_out_everywhere_ends_every_session_of_that_user_only(
    db: AsyncSession, user: User
) -> None:
    other = await make_user(db, "grace@example.com")
    mine = [await create_session(db, user, now=NOW) for _ in range(3)]
    theirs = await create_session(db, other, now=NOW)

    ended = await revoke_all_for_user(db, user.id, now=NOW)

    assert ended == 3
    for issued in mine:
        assert await get_valid_session(db, issued.token, now=NOW) is None
    assert await get_valid_session(db, theirs.token, now=NOW) is not None


async def test_sign_out_everywhere_can_keep_the_current_session(
    db: AsyncSession, user: User
) -> None:
    current = await create_session(db, user, now=NOW)
    others = [await create_session(db, user, now=NOW) for _ in range(2)]

    ended = await revoke_all_for_user(
        db, user.id, except_session_id=current.session.id, now=NOW
    )

    assert ended == 2
    assert await get_valid_session(db, current.token, now=NOW) is not None
    for issued in others:
        assert await get_valid_session(db, issued.token, now=NOW) is None


async def test_sign_out_everywhere_does_not_recount_finished_sessions(
    db: AsyncSession, user: User
) -> None:
    first = await create_session(db, user, now=NOW)
    await create_session(db, user, now=NOW)
    await revoke_token(db, first.token, now=NOW)

    assert await revoke_all_for_user(db, user.id, now=NOW) == 1
    assert await revoke_all_for_user(db, user.id, now=NOW) == 0


# --- housekeeping ------------------------------------------------------------------


async def test_purge_removes_only_sessions_finished_long_ago(
    db: AsyncSession, user: User
) -> None:
    long_expired = await create_session(
        db, user, now=NOW - timedelta(days=100)
    )  # expired 70 days ago
    long_revoked = await create_session(db, user, now=NOW - timedelta(days=5))
    await revoke_token(db, long_revoked.token, now=NOW - timedelta(days=60))
    recently_expired = await create_session(
        db, user, now=NOW - timedelta(days=40)
    )  # expired 10 days ago
    recently_revoked = await create_session(db, user, now=NOW - timedelta(days=5))
    await revoke_token(db, recently_revoked.token, now=NOW - timedelta(days=2))
    active = await create_session(db, user, now=NOW)

    removed = await purge_finished_sessions(db, now=NOW)

    assert removed == 2
    remaining = set((await db.scalars(select(AuthSession.id))).all())
    assert remaining == {
        recently_expired.session.id,
        recently_revoked.session.id,
        active.session.id,
    }
    assert long_expired.session.id not in remaining
    assert long_revoked.session.id not in remaining
