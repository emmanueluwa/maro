"""Database connection layer: engine, session factory and base class for models.

Nothing here connects at import time. The engine is created when the application
starts and disposed when it stops, so tests and tooling can import this module
without needing a database.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator

from fastapi import Request
from sqlalchemy import MetaData, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from app.config import Settings

logger = logging.getLogger("app.db")

# Explicit constraint names make migrations deterministic and reviewable.
NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    """Base class for every database model."""

    metadata = MetaData(naming_convention=NAMING_CONVENTION)


def create_engine(
    settings: Settings,
    *,
    pool_size: int = 10,
    max_overflow: int = 10,
    statement_timeout_ms: int = 30_000,
    idle_in_transaction_timeout_ms: int = 60_000,
) -> AsyncEngine:
    """Build the connection pool.

    - pool_pre_ping discards dead connections instead of failing a request on them.
    - pool_recycle retires connections before cloud load balancers silently drop them.
    - The server-side timeouts stop a runaway query, or a transaction someone forgot
      to finish, from holding resources indefinitely.
    - Times are always stored and returned in UTC.
    """
    return create_async_engine(
        str(settings.database_url),
        pool_size=pool_size,
        max_overflow=max_overflow,
        pool_timeout=10,
        pool_pre_ping=True,
        pool_recycle=1800,
        connect_args={
            "server_settings": {
                "application_name": "maro-api",
                "statement_timeout": str(statement_timeout_ms),
                "idle_in_transaction_session_timeout": str(
                    idle_in_transaction_timeout_ms
                ),
                "timezone": "UTC",
            }
        },
    )


def create_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    # expire_on_commit=False keeps objects readable after commit, which async code needs.
    return async_sessionmaker(engine, expire_on_commit=False)


async def check_connection(engine: AsyncEngine) -> bool:
    """Return True if the database answers a trivial query. Used by the readiness check."""
    try:
        async with engine.connect() as connection:
            await connection.execute(text("SELECT 1"))
    except (SQLAlchemyError, OSError, TimeoutError) as error:
        # Log only the error type: messages can contain connection details.
        logger.warning("database check failed: %s", type(error).__name__)
        return False
    return True


async def get_session(request: Request) -> AsyncIterator[AsyncSession]:
    session_factory: async_sessionmaker[AsyncSession] = (
        request.app.state.session_factory
    )
    async with session_factory() as session:
        yield session
