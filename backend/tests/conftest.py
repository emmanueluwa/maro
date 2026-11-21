"""Shared test setup.

pytest loads this file before it imports any test module. That matters because
`app.main` builds the whole application when it is imported, and the application
reads its settings at that moment. Fixing the environment here guarantees that
a developer's local .env file or exported APP_ variables can never change how
the tests behave.
"""

import os
from collections.abc import AsyncIterator, Callable

import pytest
from dotenv import dotenv_values
from sqlalchemy import text
from sqlalchemy.engine import URL, make_url
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from app.config import DEV_DATABASE_URL, Settings
from app.db import create_engine

TEST_DATABASE_NAME = "maro_test"
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}

# Remember which database server the developer has configured, so the database
# tests can find it. Only the server is used: those tests always work in a
# separate throwaway database and never touch the developer's own data.
_DEVELOPER_DATABASE_URL: str = (
    os.environ.get("APP_DATABASE_URL")
    or dotenv_values(".env").get("APP_DATABASE_URL")
    or DEV_DATABASE_URL
)

# Remove anything the machine has configured, then set a known, safe baseline.
for _name in [name for name in os.environ if name.startswith("APP_")]:
    del os.environ[_name]

os.environ["APP_ENVIRONMENT"] = "development"
os.environ["APP_LOG_LEVEL"] = "INFO"
os.environ["APP_ALLOWED_ORIGINS"] = '["http://localhost:3000"]'
os.environ["APP_DATABASE_URL"] = DEV_DATABASE_URL


@pytest.fixture(scope="session")
def developer_database_url() -> str:
    return _DEVELOPER_DATABASE_URL


# --- Shared database fixtures -------------------------------------------------
# One throwaway database (`maro_test`) is created for the whole test run on the
# server the developer has configured, and dropped at the end. Your own data is
# never touched, and nothing runs against a server that is not on this machine.


def _build_test_database_url(developer_url: str) -> URL:
    """Point at the throwaway test database, and refuse anything that is not local."""
    url = make_url(developer_url)
    if url.host not in LOCAL_HOSTS:
        raise RuntimeError(
            f"Refusing to run database tests against non-local host {url.host!r}"
        )
    return url.set(database=TEST_DATABASE_NAME)


@pytest.fixture(scope="session")
def anyio_backend() -> str:
    # Lets async fixtures be shared across the whole test run.
    return "asyncio"


@pytest.fixture(scope="session")
def database_url_builder() -> Callable[[str], URL]:
    return _build_test_database_url


@pytest.fixture(scope="session")
async def test_url(developer_database_url: str) -> AsyncIterator[URL]:
    """Create the throwaway test database, and drop it when the run ends.

    If no database is reachable the tests are skipped, with a hint. Set
    MARO_REQUIRE_DATABASE=1 (for example in CI) to make that a failure instead.
    """
    url = _build_test_database_url(developer_database_url)
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


@pytest.fixture(scope="session")
async def engine(test_url: URL) -> AsyncIterator[AsyncEngine]:
    settings = Settings(
        _env_file=None, database_url=test_url.render_as_string(hide_password=False)
    )
    engine = create_engine(settings, pool_size=2, max_overflow=0)
    yield engine
    await engine.dispose()
