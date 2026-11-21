"""Tests for the LoginCode model, run against a real PostgreSQL (see conftest.py)."""

import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import delete, func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from app.models import LoginCode, User

pytestmark = pytest.mark.anyio


@pytest.fixture
async def user(db: AsyncSession) -> User:
    user = User(email="ada@example.com")
    db.add(user)
    await db.commit()
    return user


async def make_user(db: AsyncSession, email: str) -> User:
    user = User(email=email)
    db.add(user)
    await db.commit()
    return user


def new_hash() -> bytes:
    """A stand-in for the real keyed hash: any 32 bytes will do for storage tests."""
    return hashlib.sha256(secrets.token_bytes(8)).digest()


def make_code(user_id: uuid.UUID, **overrides: object) -> LoginCode:
    fields: dict[str, object] = {
        "user_id": user_id,
        "code_hash": new_hash(),
        "expires_at": datetime.now(UTC) + timedelta(minutes=10),
    }
    fields.update(overrides)
    return LoginCode(**fields)


async def save(db: AsyncSession, code: LoginCode) -> LoginCode:
    db.add(code)
    await db.commit()
    return code


async def count_codes(db: AsyncSession) -> int:
    return await db.scalar(select(func.count()).select_from(LoginCode)) or 0


async def test_new_code_gets_defaults(db: AsyncSession, user: User) -> None:
    code = await save(db, make_code(user.id))

    assert isinstance(code.id, uuid.UUID)
    assert code.attempts == 0
    assert code.consumed_at is None
    assert code.created_at.tzinfo is not None


@pytest.mark.parametrize("length", [0, 6, 16, 31, 33, 64])
async def test_code_hash_must_be_exactly_32_bytes(
    db: AsyncSession, user: User, length: int
) -> None:
    """Guards against storing the six digits themselves, or the wrong kind of hash."""
    with pytest.raises(IntegrityError, match="ck_login_codes_code_hash_is_hmac_sha256"):
        await save(db, make_code(user.id, code_hash=b"1" * length))


async def test_code_cannot_expire_before_it_was_created(
    db: AsyncSession, user: User
) -> None:
    with pytest.raises(IntegrityError, match="ck_login_codes_expires_after_creation"):
        await save(
            db, make_code(user.id, expires_at=datetime.now(UTC) - timedelta(minutes=1))
        )


async def test_attempts_cannot_be_negative(db: AsyncSession, user: User) -> None:
    with pytest.raises(IntegrityError, match="ck_login_codes_attempts_not_negative"):
        await save(db, make_code(user.id, attempts=-1))


async def test_wrong_guesses_can_be_counted(db: AsyncSession, user: User) -> None:
    code = await save(db, make_code(user.id))

    code.attempts += 1
    code.attempts += 1
    await db.commit()
    await db.refresh(code)

    assert code.attempts == 2


async def test_code_requires_an_existing_user(db: AsyncSession) -> None:
    with pytest.raises(IntegrityError, match="fk_login_codes_user_id_users"):
        await save(db, make_code(uuid.uuid4()))


async def test_deleting_a_user_deletes_only_their_codes(
    db: AsyncSession, user: User
) -> None:
    other = await make_user(db, "grace@example.com")
    await save(db, make_code(user.id))
    survivor = await save(db, make_code(other.id))

    await db.execute(delete(User).where(User.id == user.id))
    await db.commit()

    remaining = (await db.scalars(select(LoginCode))).all()
    assert [code.id for code in remaining] == [survivor.id]


async def test_a_user_can_have_only_one_live_code(db: AsyncSession, user: User) -> None:
    await save(db, make_code(user.id))

    with pytest.raises(IntegrityError, match="uq_login_codes_one_live_code_per_user"):
        await save(db, make_code(user.id))


async def test_a_new_code_is_allowed_once_the_old_one_is_used(
    db: AsyncSession, user: User
) -> None:
    first = await save(db, make_code(user.id))
    first.consumed_at = datetime.now(UTC)
    await db.commit()

    await save(db, make_code(user.id))

    assert await count_codes(db) == 2


async def test_any_number_of_used_codes_may_exist_beside_one_live_one(
    db: AsyncSession, user: User
) -> None:
    for _ in range(4):
        await save(db, make_code(user.id, consumed_at=datetime.now(UTC)))
    await save(db, make_code(user.id))

    assert await count_codes(db) == 5


async def test_different_users_can_each_have_a_live_code(
    db: AsyncSession, user: User
) -> None:
    other = await make_user(db, "grace@example.com")

    await save(db, make_code(user.id))
    await save(db, make_code(other.id))

    assert await count_codes(db) == 2


async def test_two_people_may_hold_the_same_code_hash_at_once(
    db: AsyncSession, user: User
) -> None:
    """Six digits collide by chance. That must never turn into an error for someone signing in."""
    other = await make_user(db, "grace@example.com")
    shared = new_hash()

    await save(db, make_code(user.id, code_hash=shared))
    await save(db, make_code(other.id, code_hash=shared))

    assert await count_codes(db) == 2


async def test_codes_are_findable_by_user_through_indexes(engine: AsyncEngine) -> None:
    async with engine.connect() as connection:
        rows = (
            await connection.execute(
                text(
                    "SELECT indexname, indexdef FROM pg_indexes WHERE tablename = 'login_codes'"
                )
            )
        ).all()
    definitions = {row.indexname: row.indexdef for row in rows}

    assert "ix_login_codes_user_id" in definitions
    assert "consumed_at IS NULL" in definitions["uq_login_codes_one_live_code_per_user"]


async def test_repr_shows_only_the_code_id(db: AsyncSession, user: User) -> None:
    code = await save(db, make_code(user.id))

    text_form = repr(code)

    assert str(code.id) in text_form
    assert str(user.id) not in text_form
    assert code.code_hash.hex() not in text_form
