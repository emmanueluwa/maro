"""Tests for the User model, run against a real PostgreSQL (see conftest.py)."""

import asyncio
import uuid
from collections.abc import AsyncIterator

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from app.db import Base, create_session_factory
from app.models import User

pytestmark = pytest.mark.anyio


@pytest.fixture(scope="module")
async def users_table(engine: AsyncEngine) -> None:
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)


@pytest.fixture(autouse=True)
async def empty_users_table(engine: AsyncEngine, users_table: None) -> None:
    """Every test starts with no users."""
    async with engine.begin() as connection:
        await connection.execute(text("TRUNCATE users"))


@pytest.fixture
async def session(engine: AsyncEngine) -> AsyncIterator[AsyncSession]:
    factory: async_sessionmaker[AsyncSession] = create_session_factory(engine)
    async with factory() as session:
        yield session


async def save(session: AsyncSession, **fields: str) -> User:
    user = User(**fields)
    session.add(user)
    await session.commit()
    return user


async def test_new_user_gets_defaults(session: AsyncSession) -> None:
    user = await save(session, email="ada@example.com")

    assert isinstance(user.id, uuid.UUID)
    assert user.is_active is True
    assert user.display_name is None
    assert user.created_at.tzinfo is not None
    assert user.updated_at.tzinfo is not None


async def test_ids_are_random_version_4_uuids(session: AsyncSession) -> None:
    first = await save(session, email="one@example.com")
    second = await save(session, email="two@example.com")

    assert first.id != second.id
    assert first.id.version == 4


async def test_email_is_normalised_when_saved(session: AsyncSession) -> None:
    user = await save(session, email="  Ada@Example.COM ")

    assert user.email == "ada@example.com"
    stored = await session.scalar(select(User.email))
    assert stored == "ada@example.com"


async def test_duplicate_email_is_rejected(session: AsyncSession) -> None:
    await save(session, email="ada@example.com")

    with pytest.raises(IntegrityError, match="uq_users_email"):
        await save(session, email="ada@example.com")


async def test_email_differing_only_by_case_or_spaces_is_a_duplicate(
    session: AsyncSession,
) -> None:
    await save(session, email="ada@example.com")

    with pytest.raises(IntegrityError, match="uq_users_email"):
        await save(session, email="  ADA@Example.com ")


async def test_database_itself_rejects_uppercase_email(engine: AsyncEngine) -> None:
    """The safety net: even raw SQL that skips the model cannot store a mixed-case email."""
    async with engine.connect() as connection:
        with pytest.raises(IntegrityError, match="ck_users_email_is_lowercase"):
            await connection.execute(
                text("INSERT INTO users (email) VALUES ('UPPER@example.com')")
            )


async def test_database_rejects_trivially_short_email(engine: AsyncEngine) -> None:
    async with engine.connect() as connection:
        with pytest.raises(IntegrityError, match="ck_users_email_is_not_trivial"):
            await connection.execute(text("INSERT INTO users (email) VALUES ('a@b')"))


async def test_overlong_email_is_rejected(session: AsyncSession) -> None:
    with pytest.raises(DBAPIError):
        await save(session, email="a" * 320 + "@example.com")


async def test_raw_insert_receives_database_defaults(engine: AsyncEngine) -> None:
    """Rows created by other tools still get an id, active status and timestamps."""
    async with engine.begin() as connection:
        row = (
            await connection.execute(
                text(
                    "INSERT INTO users (email) VALUES ('raw@example.com') RETURNING id, is_active, created_at"
                )
            )
        ).one()

    assert row.id is not None
    assert row.is_active is True
    assert row.created_at is not None


async def test_updated_at_advances_when_a_user_changes(session: AsyncSession) -> None:
    user = await save(session, email="ada@example.com")
    created, first_updated = user.created_at, user.updated_at

    await asyncio.sleep(0.05)
    user.display_name = "Ada"
    await session.commit()
    await session.refresh(user)

    assert user.updated_at > first_updated
    assert user.created_at == created


async def test_deactivating_a_user_keeps_the_row(session: AsyncSession) -> None:
    user = await save(session, email="ada@example.com")

    user.is_active = False
    await session.commit()

    stored = await session.scalar(select(User).where(User.id == user.id))
    assert stored is not None
    assert stored.is_active is False


async def test_repr_never_contains_the_email(session: AsyncSession) -> None:
    user = await save(session, email="ada@example.com")

    assert str(user.id) in repr(user)
    assert "ada" not in repr(user)
    assert "example.com" not in repr(user)
