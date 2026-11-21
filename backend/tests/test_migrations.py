"""Tests that the migrations are correct, reversible, and agree with the models.

Each test builds a brand-new empty database, then runs the real `alembic` command
against it, exactly as a developer or a deployment would. Nothing here touches your
own data.
"""

import asyncio
import os
import subprocess
import sys
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.engine import URL
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import create_async_engine

pytestmark = pytest.mark.anyio

BACKEND_DIR = Path(__file__).resolve().parents[1]
MIGRATION_DATABASE_NAME = "maro_migration_test"


def run_alembic(url: URL, *args: str) -> subprocess.CompletedProcess[str]:
    """Run the real alembic command against the given database."""
    env = {
        **os.environ,
        "APP_ENVIRONMENT": "development",
        "APP_LOG_LEVEL": "INFO",
        "APP_ALLOWED_ORIGINS": '["http://localhost:3000"]',
        "APP_DATABASE_URL": url.render_as_string(hide_password=False),
    }
    return subprocess.run(
        [sys.executable, "-m", "alembic", *args],
        cwd=BACKEND_DIR,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


async def alembic(url: URL, *args: str) -> subprocess.CompletedProcess[str]:
    return await asyncio.to_thread(run_alembic, url, *args)


@pytest.fixture
async def empty_database(test_url: URL) -> AsyncIterator[URL]:
    """A brand-new, empty database. `test_url` guarantees the server is local and reachable."""
    url = test_url.set(database=MIGRATION_DATABASE_NAME)
    admin = create_async_engine(
        url.set(database="postgres"), isolation_level="AUTOCOMMIT"
    )
    async with admin.connect() as connection:
        await connection.execute(
            text(f"DROP DATABASE IF EXISTS {MIGRATION_DATABASE_NAME} WITH (FORCE)")
        )
        await connection.execute(text(f"CREATE DATABASE {MIGRATION_DATABASE_NAME}"))
    yield url
    async with admin.connect() as connection:
        await connection.execute(
            text(f"DROP DATABASE IF EXISTS {MIGRATION_DATABASE_NAME} WITH (FORCE)")
        )
    await admin.dispose()


async def query(url: URL, sql: str) -> list[str]:
    engine = create_async_engine(url)
    try:
        async with engine.connect() as connection:
            return [
                str(value)
                for value in (await connection.execute(text(sql))).scalars().all()
            ]
    finally:
        await engine.dispose()


async def users_table_exists(url: URL) -> bool:
    return (await query(url, "SELECT to_regclass('public.users')"))[0] != "None"


async def test_upgrade_creates_the_users_table(empty_database: URL) -> None:
    result = await alembic(empty_database, "upgrade", "head")

    assert result.returncode == 0, result.stderr
    assert await users_table_exists(empty_database)
    constraints = await query(
        empty_database,
        "SELECT conname FROM pg_constraint WHERE conrelid = 'users'::regclass ORDER BY conname",
    )
    assert constraints == [
        "ck_users_email_is_lowercase",
        "ck_users_email_is_not_trivial",
        "pk_users",
        "uq_users_email",
    ]


async def test_migration_can_be_reversed_and_reapplied(empty_database: URL) -> None:
    assert (await alembic(empty_database, "upgrade", "head")).returncode == 0
    assert await users_table_exists(empty_database)

    assert (await alembic(empty_database, "downgrade", "base")).returncode == 0
    assert not await users_table_exists(empty_database)

    assert (await alembic(empty_database, "upgrade", "head")).returncode == 0
    assert await users_table_exists(empty_database)


async def test_migrations_and_models_agree(empty_database: URL) -> None:
    """If someone changes a model without writing a migration, this fails."""
    assert (await alembic(empty_database, "upgrade", "head")).returncode == 0

    result = await alembic(empty_database, "check")

    assert result.returncode == 0, result.stderr


async def test_history_is_a_single_line_with_one_head(empty_database: URL) -> None:
    """Two migrations branching from the same parent would make upgrades ambiguous."""
    result = await alembic(empty_database, "heads")

    assert result.returncode == 0, result.stderr
    assert result.stdout.count("(head)") == 1


async def test_migrated_database_enforces_the_same_rules_as_the_model(
    empty_database: URL,
) -> None:
    assert (await alembic(empty_database, "upgrade", "head")).returncode == 0

    engine = create_async_engine(empty_database)
    try:
        async with engine.begin() as connection:
            await connection.execute(
                text("INSERT INTO users (email) VALUES ('ada@example.com')")
            )
        async with engine.connect() as connection:
            with pytest.raises(IntegrityError, match="uq_users_email"):
                await connection.execute(
                    text("INSERT INTO users (email) VALUES ('ada@example.com')")
                )
        async with engine.connect() as connection:
            with pytest.raises(IntegrityError, match="ck_users_email_is_lowercase"):
                await connection.execute(
                    text("INSERT INTO users (email) VALUES ('UPPER@example.com')")
                )
    finally:
        await engine.dispose()
