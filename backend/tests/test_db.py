"""Tests for the database layer, run against a real PostgreSQL.

They use a separate throwaway database called `maro_test`, created on the same
server your app is configured for and deleted afterwards. Your own data is never
touched, and the tests refuse to run against any server that is not on this machine.

If no database is reachable the tests are skipped, with a hint. Set
MARO_REQUIRE_DATABASE=1 (for example in CI) to make that a failure instead.
"""

import os
import time
from collections.abc import AsyncIterator

import pytest
from fastapi import FastAPI
from sqlalchemy import (
    Column,
    Integer,
    MetaData,
    String,
    Table,
    func,
    insert,
    select,
    text,
)
from sqlalchemy.engine import URL, make_url
from sqlalchemy.exc import DBAPIError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from starlette.requests import Request

from app.config import Settings
from app.db import (
    NAMING_CONVENTION,
    Base,
    check_connection,
    create_engine,
    create_session_factory,
    get_session,
)

pytestmark = pytest.mark.anyio

TEST_DATABASE_NAME = "maro_test"
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


def build_test_database_url(developer_url: str) -> URL:
    """Point at the throwaway test database, and refuse anything that is not local."""
    url = make_url(developer_url)
    if url.host not in LOCAL_HOSTS:
        raise RuntimeError(
            f"Refusing to run database tests against non-local host {url.host!r}"
        )
    return url.set(database=TEST_DATABASE_NAME)


def settings_for(url: URL) -> Settings:
    return Settings(
        _env_file=None, database_url=url.render_as_string(hide_password=False)
    )


@pytest.fixture(scope="module")
async def test_url(developer_database_url: str) -> AsyncIterator[URL]:
    """Create a fresh test database for this module and drop it afterwards."""
    url = build_test_database_url(developer_database_url)
    admin = create_async_engine(
        url.set(database="postgres"), isolation_level="AUTOCOMMIT"
    )
    try:
        async with admin.connect() as connection:
            await connection.execute(
                text(f"DROP DATABASE IF EXISTS {TEST_DATABASE_NAME} WITH (FORCE)")
            )
            await connection.execute(text(f"CREATE DATABASE {TEST_DATABASE_NAME}"))
    except (SQLAlchemyError, OSError) as error:
        await admin.dispose()
        message = f"No database reachable ({type(error).__name__}). Start it with: docker compose up -d"
        if os.environ.get("MARO_REQUIRE_DATABASE"):
            pytest.fail(message)
        pytest.skip(message)

    yield url

    async with admin.connect() as connection:
        await connection.execute(
            text(f"DROP DATABASE IF EXISTS {TEST_DATABASE_NAME} WITH (FORCE)")
        )
    await admin.dispose()


@pytest.fixture(scope="module")
async def engine(test_url: URL) -> AsyncIterator[AsyncEngine]:
    engine = create_engine(settings_for(test_url), pool_size=2, max_overflow=0)
    yield engine
    await engine.dispose()


@pytest.fixture(scope="module")
async def things(engine: AsyncEngine) -> Table:
    """A small table built with the project's naming convention."""
    metadata = MetaData(naming_convention=Base.metadata.naming_convention)
    table = Table(
        "things",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("name", String, nullable=False, unique=True),
    )
    async with engine.begin() as connection:
        await connection.run_sync(metadata.create_all)
    return table


def test_refuses_non_local_database_servers() -> None:
    with pytest.raises(RuntimeError, match="non-local"):
        build_test_database_url(
            "postgresql+asyncpg://u:p@db.production.example:5432/maro"
        )


def test_test_database_is_never_the_developers_own() -> None:
    url = build_test_database_url("postgresql+asyncpg://maro:maro@localhost:5433/maro")
    assert url.database == TEST_DATABASE_NAME
    assert url.port == 5433


async def test_check_connection_succeeds(engine: AsyncEngine) -> None:
    assert await check_connection(engine) is True


async def test_check_connection_fails_when_database_is_unreachable() -> None:
    unreachable = Settings(
        _env_file=None, database_url="postgresql+asyncpg://u:p@127.0.0.1:1/none"
    )
    engine = create_engine(unreachable)
    try:
        assert await check_connection(engine) is False
    finally:
        await engine.dispose()


async def test_server_settings_are_applied(engine: AsyncEngine) -> None:
    async with engine.connect() as connection:

        async def show(name: str) -> str:
            return (await connection.execute(text(f"SHOW {name}"))).scalar_one()

        assert await show("application_name") == "maro-api"
        assert await show("TimeZone") == "UTC"
        assert await show("statement_timeout") == "30s"
        assert await show("idle_in_transaction_session_timeout") == "1min"


async def test_base_uses_the_naming_convention() -> None:
    assert Base.metadata.naming_convention == NAMING_CONVENTION


async def test_constraints_get_predictable_names(
    engine: AsyncEngine, things: Table
) -> None:
    query = text(
        "SELECT conname FROM pg_constraint WHERE conrelid = 'things'::regclass ORDER BY conname"
    )
    async with engine.connect() as connection:
        names = (await connection.execute(query)).scalars().all()
    assert names == ["pk_things", "uq_things_name"]


async def test_uncommitted_changes_are_rolled_back(
    engine: AsyncEngine, things: Table
) -> None:
    factory = create_session_factory(engine)
    async with factory() as session:
        await session.execute(insert(things).values(name="never-committed"))

    async with factory() as session:
        count = await session.scalar(
            select(func.count())
            .select_from(things)
            .where(things.c.name == "never-committed")
        )
    assert count == 0


async def test_committed_changes_persist(engine: AsyncEngine, things: Table) -> None:
    factory = create_session_factory(engine)
    async with factory() as session:
        await session.execute(insert(things).values(name="committed"))
        await session.commit()

    async with factory() as session:
        count = await session.scalar(
            select(func.count()).select_from(things).where(things.c.name == "committed")
        )
    assert count == 1


async def test_get_session_dependency_closes_and_rolls_back(
    engine: AsyncEngine, things: Table
) -> None:
    app = FastAPI()
    app.state.session_factory = create_session_factory(engine)
    request = Request({"type": "http", "app": app, "headers": []})

    dependency = get_session(request)
    session = await anext(dependency)
    await session.execute(insert(things).values(name="dependency-uncommitted"))
    assert engine.pool.checkedout() == 1  # type: ignore[attr-defined]

    # FastAPI finishes a dependency by resuming it after the `yield`, so run that part too.
    with pytest.raises(StopAsyncIteration):
        await anext(dependency)
    assert engine.pool.checkedout() == 0  # type: ignore[attr-defined]

    async with create_session_factory(engine)() as check:
        count = await check.scalar(
            select(func.count())
            .select_from(things)
            .where(things.c.name == "dependency-uncommitted")
        )
    assert count == 0


async def test_engine_recovers_after_connections_are_killed(
    engine: AsyncEngine, test_url: URL
) -> None:
    async with engine.connect() as connection:  # make sure the pool holds a connection
        await connection.execute(text("SELECT 1"))

    admin = create_async_engine(
        test_url.set(database="postgres"), isolation_level="AUTOCOMMIT"
    )
    try:
        async with admin.connect() as connection:
            await connection.execute(
                text(
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                    "WHERE datname = :name AND application_name = 'maro-api'"
                ),
                {"name": TEST_DATABASE_NAME},
            )
    finally:
        await admin.dispose()

    async with engine.connect() as connection:  # must succeed on a fresh connection
        assert (await connection.execute(text("SELECT 42"))).scalar_one() == 42


async def test_statement_timeout_is_enforced(test_url: URL) -> None:
    engine = create_engine(settings_for(test_url), statement_timeout_ms=300)
    try:
        started = time.perf_counter()
        async with engine.connect() as connection:
            with pytest.raises(DBAPIError):
                await connection.execute(text("SELECT pg_sleep(5)"))
        assert time.perf_counter() - started < 3
    finally:
        await engine.dispose()
