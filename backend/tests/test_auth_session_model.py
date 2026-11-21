"""Tests for the AuthSession model, run against a real PostgreSQL (see conftest.py)."""

import hashlib
import secrets
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import delete, func, select, text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from app.db import create_session_factory
from app.models import AuthSession, User

pytestmark = [pytest.mark.anyio, pytest.mark.usefixtures("empty_tables")]


@pytest.fixture
async def session(engine: AsyncEngine) -> AsyncIterator[AsyncSession]:
    async with create_session_factory(engine)() as session:
        yield session


@pytest.fixture
async def user(session: AsyncSession) -> User:
    user = User(email="ada@example.com")
    session.add(user)
    await session.commit()
    return user


def new_token_hash() -> bytes:
    """A realistic token hash: SHA-256 of a random token, as the real code will store."""
    return hashlib.sha256(secrets.token_bytes(32)).digest()


def make_session(user_id: uuid.UUID, **overrides: object) -> AuthSession:
    fields: dict[str, object] = {
        "user_id": user_id,
        "token_hash": new_token_hash(),
        "expires_at": datetime.now(UTC) + timedelta(days=30),
    }
    fields.update(overrides)
    return AuthSession(**fields)


async def save(session: AsyncSession, auth_session: AuthSession) -> AuthSession:
    session.add(auth_session)
    await session.commit()
    return auth_session


async def count_sessions(session: AsyncSession) -> int:
    return await session.scalar(select(func.count()).select_from(AuthSession)) or 0


async def test_new_session_gets_defaults(session: AsyncSession, user: User) -> None:
    auth_session = await save(session, make_session(user.id))

    assert isinstance(auth_session.id, uuid.UUID)
    assert auth_session.created_at.tzinfo is not None
    assert auth_session.last_seen_at.tzinfo is not None
    assert auth_session.revoked_at is None
    assert auth_session.user_agent is None


async def test_token_hash_must_be_unique(session: AsyncSession, user: User) -> None:
    shared_hash = new_token_hash()
    await save(session, make_session(user.id, token_hash=shared_hash))

    with pytest.raises(IntegrityError, match="uq_auth_sessions_token_hash"):
        await save(session, make_session(user.id, token_hash=shared_hash))


@pytest.mark.parametrize("length", [0, 16, 31, 33, 64])
async def test_token_hash_must_be_exactly_32_bytes(
    session: AsyncSession, user: User, length: int
) -> None:
    """Guards against storing a raw token, or a hash of the wrong kind, by mistake."""
    with pytest.raises(IntegrityError, match="ck_auth_sessions_token_hash_is_sha256"):
        await save(session, make_session(user.id, token_hash=b"x" * length))


async def test_session_cannot_expire_before_it_was_created(
    session: AsyncSession, user: User
) -> None:
    already_expired = datetime.now(UTC) - timedelta(hours=1)

    with pytest.raises(IntegrityError, match="ck_auth_sessions_expires_after_creation"):
        await save(session, make_session(user.id, expires_at=already_expired))


async def test_session_requires_an_existing_user(session: AsyncSession) -> None:
    with pytest.raises(IntegrityError, match="fk_auth_sessions_user_id_users"):
        await save(session, make_session(uuid.uuid4()))


async def test_deleting_a_user_deletes_their_sessions(
    session: AsyncSession, user: User
) -> None:
    await save(session, make_session(user.id))
    await save(session, make_session(user.id))
    assert await count_sessions(session) == 2

    await session.execute(delete(User).where(User.id == user.id))
    await session.commit()

    assert await count_sessions(session) == 0


async def test_deleting_one_user_leaves_other_users_sessions(
    session: AsyncSession, user: User
) -> None:
    other = User(email="grace@example.com")
    session.add(other)
    await session.commit()
    await save(session, make_session(user.id))
    survivor = await save(session, make_session(other.id))

    await session.execute(delete(User).where(User.id == user.id))
    await session.commit()

    remaining = (await session.scalars(select(AuthSession))).all()
    assert [s.id for s in remaining] == [survivor.id]


async def test_signing_out_keeps_the_row(session: AsyncSession, user: User) -> None:
    auth_session = await save(session, make_session(user.id))

    auth_session.revoked_at = datetime.now(UTC)
    await session.commit()

    stored = await session.scalar(
        select(AuthSession).where(AuthSession.id == auth_session.id)
    )
    assert stored is not None
    assert stored.revoked_at is not None


async def test_last_seen_can_be_updated(session: AsyncSession, user: User) -> None:
    auth_session = await save(session, make_session(user.id))
    later = auth_session.last_seen_at + timedelta(minutes=5)

    auth_session.last_seen_at = later
    await session.commit()
    await session.refresh(auth_session)

    assert auth_session.last_seen_at == later


async def test_user_agent_is_limited_in_length(
    session: AsyncSession, user: User
) -> None:
    await save(session, make_session(user.id, user_agent="a" * 512))

    with pytest.raises(DBAPIError):
        await save(session, make_session(user.id, user_agent="a" * 513))


async def test_sessions_are_findable_by_user_through_an_index(
    engine: AsyncEngine,
) -> None:
    async with engine.connect() as connection:
        names = (
            (
                await connection.execute(
                    text(
                        "SELECT indexname FROM pg_indexes WHERE tablename = 'auth_sessions'"
                    )
                )
            )
            .scalars()
            .all()
        )

    assert "ix_auth_sessions_user_id" in names


async def test_repr_shows_only_the_session_id(
    session: AsyncSession, user: User
) -> None:
    auth_session = await save(session, make_session(user.id))

    text_form = repr(auth_session)

    assert str(auth_session.id) in text_form
    assert str(user.id) not in text_form
    assert auth_session.token_hash.hex() not in text_form
