"""Alembic environment: connects migrations to the app's settings and models."""

from __future__ import annotations

import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import create_async_engine

import app.models  # noqa: F401  (importing it registers every model on Base.metadata)
from app.config import get_settings
from app.db import Base

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name, disable_existing_loggers=False)

# What `alembic revision --autogenerate` and `alembic check` compare the database against.
target_metadata = Base.metadata

# Fail fast instead of queueing behind a long-running query and blocking everyone
# else's access to the table while waiting for a lock.
LOCK_TIMEOUT = "10s"


def run_migrations_offline() -> None:
    """Write the SQL to the console instead of running it (`alembic upgrade head --sql`)."""
    context.configure(
        url=str(get_settings().database_url),
        target_metadata=target_metadata,
        literal_binds=True,
        compare_type=True,
        compare_server_default=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    # Postgres can undo schema changes, so a failed migration leaves nothing half-done.
    # Nothing may be executed on the connection before this point: that would open a
    # transaction Alembic does not own, and it would then never commit the migration.
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        compare_server_default=True,
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    # The address comes from the app settings, not alembic.ini, so the password is
    # never written to a config file. NullPool: a migration is one short-lived job.
    # The lock timeout is set when the connection opens, not with a SET command afterwards.
    engine = create_async_engine(
        str(get_settings().database_url),
        poolclass=pool.NullPool,
        connect_args={"server_settings": {"lock_timeout": LOCK_TIMEOUT}},
    )
    try:
        async with engine.connect() as connection:
            await connection.run_sync(do_run_migrations)
    finally:
        await engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
