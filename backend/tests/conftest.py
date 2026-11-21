"""Shared test setup.

pytest loads this file before it imports any test module. That matters because
`app.main` builds the whole application when it is imported, and the application
reads its settings at that moment. Fixing the environment here guarantees that
a developer's local .env file or exported APP_ variables can never change how
the tests behave.
"""

import os

import pytest
from dotenv import dotenv_values

from app.config import DEV_DATABASE_URL

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
