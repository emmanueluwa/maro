"""Tests for app startup/shutdown and the /health and /ready endpoints.

Most of these need no database: the readiness check is replaced with a stand-in so
the endpoint's behaviour can be tested exactly. Two tests use the real check
against deliberately unreachable or unresponsive servers.
"""

import asyncio
from collections.abc import Iterator
from contextlib import contextmanager
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncEngine

from app.config import Settings, get_settings
from app.db import check_connection, create_engine
from app.main import create_app


@contextmanager
def running_app(monkeypatch: pytest.MonkeyPatch, **env: str) -> Iterator[TestClient]:
    """Start the app, including its startup and shutdown, and give back a client."""
    for name, value in env.items():
        monkeypatch.setenv(f"APP_{name.upper()}", value)
    get_settings.cache_clear()
    try:
        with TestClient(create_app()) as client:
            yield client
    finally:
        get_settings.cache_clear()


def stub_database_check(monkeypatch: pytest.MonkeyPatch, *, healthy: bool) -> None:
    async def fake_check(engine: AsyncEngine) -> bool:
        return healthy

    monkeypatch.setattr("app.main.check_connection", fake_check)


def test_ready_returns_200_when_database_is_healthy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stub_database_check(monkeypatch, healthy=True)
    with running_app(monkeypatch) as client:
        response = client.get("/ready")
    assert response.status_code == 200
    assert response.json() == {"status": "ready"}


def test_ready_returns_503_when_database_is_down(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stub_database_check(monkeypatch, healthy=False)
    with running_app(monkeypatch) as client:
        response = client.get("/ready")
    assert response.status_code == 503
    assert response.json() == {"status": "unavailable"}


def test_ready_response_reveals_nothing_about_the_database(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stub_database_check(monkeypatch, healthy=False)
    with running_app(monkeypatch) as client:
        body = client.get("/ready").text.lower()
    for secret in ("postgres", "maro", "localhost", "5432", "password"):
        assert secret not in body


def test_health_stays_ok_when_database_is_down(monkeypatch: pytest.MonkeyPatch) -> None:
    """Liveness must not depend on the database, or an outage would trigger restarts."""
    stub_database_check(monkeypatch, healthy=False)
    with running_app(monkeypatch) as client:
        assert client.get("/health").status_code == 200


def test_ready_responses_carry_security_headers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stub_database_check(monkeypatch, healthy=False)
    with running_app(monkeypatch) as client:
        response = client.get("/ready")
    assert "x-request-id" in response.headers
    assert response.headers["x-content-type-options"] == "nosniff"


def test_startup_creates_database_state_and_shutdown_closes_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_engine = MagicMock()
    fake_engine.dispose = AsyncMock()
    monkeypatch.setattr("app.main.create_engine", lambda settings: fake_engine)

    with running_app(monkeypatch) as client:
        assert client.app.state.engine is fake_engine
        assert client.app.state.session_factory is not None
        fake_engine.dispose.assert_not_awaited()

    fake_engine.dispose.assert_awaited_once()


def test_app_starts_and_reports_unavailable_when_database_is_unreachable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A down database must not stop the app starting; it just must not report ready."""
    unreachable = "postgresql+asyncpg://u:p@127.0.0.1:1/none"
    with running_app(monkeypatch, database_url=unreachable) as client:
        assert client.get("/health").status_code == 200
        assert client.get("/ready").status_code == 503


@pytest.mark.anyio
async def test_check_connection_gives_up_on_a_database_that_never_answers() -> None:
    """A server that accepts connections but stays silent must not hang the check."""

    async def stay_silent(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            await asyncio.sleep(3600)
        finally:
            writer.close()

    server = await asyncio.start_server(stay_silent, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    engine = create_engine(
        Settings(
            _env_file=None,
            database_url=f"postgresql+asyncpg://u:p@127.0.0.1:{port}/none",
        )
    )
    try:
        # The outer limit makes a regression fail quickly instead of hanging the test run.
        async with asyncio.timeout(5):
            started = asyncio.get_running_loop().time()
            result = await check_connection(engine, timeout=0.5)
            elapsed = asyncio.get_running_loop().time() - started
        assert result is False
        assert elapsed < 2
    finally:
        await engine.dispose()
        server.close()
