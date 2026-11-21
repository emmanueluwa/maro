"""Tests for sign-in over HTTP: the cookie, "who am I", and signing out.

Real requests go through the whole application against a real PostgreSQL.
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta

import httpx2
import pytest
from fastapi import Response
from sqlalchemy import select, text
from sqlalchemy.engine import URL
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from app.auth.dependencies import (
    COOKIE_NAME,
    PRODUCTION_COOKIE_NAME,
    clear_session_cookie,
    set_session_cookie,
)
from app.auth.sessions import (
    SESSION_LIFETIME,
    IssuedSession,
    create_session,
    revoke_token,
)
from app.config import Settings, get_settings
from app.db import Base, create_session_factory
from app.main import create_app
from app.models import AuthSession, User

pytestmark = pytest.mark.anyio

TRUSTED = {"origin": "http://localhost:3000"}
EVIL = {"origin": "https://evil.example"}
STALE_BODY = {"detail": "Not authenticated"}
PRODUCTION_URL = "postgresql+asyncpg://u:p@db.internal:5432/maro"


# --- fixtures and helpers ------------------------------------------------------


@pytest.fixture(scope="module")
async def tables(engine: AsyncEngine) -> None:
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)


@pytest.fixture
async def empty_tables(engine: AsyncEngine, tables: None) -> None:
    async with engine.begin() as connection:
        await connection.execute(text("TRUNCATE users CASCADE"))


@pytest.fixture
async def db(engine: AsyncEngine, empty_tables: None) -> AsyncIterator[AsyncSession]:
    async with create_session_factory(engine)() as session:
        yield session


@asynccontextmanager
async def running_client(
    monkeypatch: pytest.MonkeyPatch, test_url: URL, environment: str = "development"
) -> AsyncIterator[httpx2.AsyncClient]:
    """The whole app, started up and pointed at the test database, with a client for it."""
    monkeypatch.setenv("APP_ENVIRONMENT", environment)
    monkeypatch.setenv(
        "APP_DATABASE_URL", test_url.render_as_string(hide_password=False)
    )
    get_settings.cache_clear()
    app = create_app()
    try:
        async with app.router.lifespan_context(app):
            transport = httpx2.ASGITransport(app=app)
            async with httpx2.AsyncClient(
                transport=transport, base_url="http://test"
            ) as client:
                yield client
    finally:
        get_settings.cache_clear()


@pytest.fixture
async def client(
    monkeypatch: pytest.MonkeyPatch, test_url: URL, empty_tables: None
) -> AsyncIterator[httpx2.AsyncClient]:
    async with running_client(monkeypatch, test_url) as client:
        yield client


async def make_user(
    db: AsyncSession, email: str = "ada@example.com", *, active: bool = True
) -> User:
    user = User(email=email, display_name="Ada", is_active=active)
    db.add(user)
    await db.commit()
    return user


@pytest.fixture
async def user(db: AsyncSession) -> User:
    return await make_user(db)


async def sign_in(db: AsyncSession, user: User, **kwargs: object) -> IssuedSession:
    return await create_session(db, user, **kwargs)  # type: ignore[arg-type]


def cookie(token: str, name: str = COOKIE_NAME) -> dict[str, str]:
    return {"cookie": f"{name}={token}"}


async def revoked_at(db: AsyncSession, session_id: object) -> datetime | None:
    db.expire_all()
    return await db.scalar(
        select(AuthSession.revoked_at).where(AuthSession.id == session_id)
    )


# --- the cookie itself (no database needed) -------------------------------------


def settings_for(environment: str) -> Settings:
    return Settings(
        _env_file=None, environment=environment, database_url=PRODUCTION_URL
    )


def cookie_header(settings: Settings, *, clear: bool = False) -> str:
    response = Response()
    if clear:
        clear_session_cookie(response, settings)
    else:
        set_session_cookie(response, "the-token", settings)
    return response.headers["set-cookie"].lower()


def test_cookie_is_httponly_lax_and_site_wide_in_every_environment() -> None:
    for environment in ("development", "production"):
        header = cookie_header(settings_for(environment))
        assert "httponly" in header
        assert "samesite=lax" in header
        assert "path=/" in header
        assert "domain" not in header


def test_cookie_lasts_as_long_as_a_session() -> None:
    header = cookie_header(settings_for("development"))

    assert f"max-age={int(SESSION_LIFETIME.total_seconds())}" in header


def test_cookie_is_https_only_with_host_prefix_in_production_only() -> None:
    development = cookie_header(settings_for("development"))
    production = cookie_header(settings_for("production"))

    assert development.startswith(f"{COOKIE_NAME}=")
    assert "secure" not in development
    assert production.startswith(f"{PRODUCTION_COOKIE_NAME.lower()}=")
    assert "secure" in production


def test_clearing_the_cookie_uses_the_same_attributes_so_browsers_honour_it() -> None:
    for environment in ("development", "production"):
        settings = settings_for(environment)
        cleared = cookie_header(settings, clear=True)
        assert "max-age=0" in cleared
        assert "httponly" in cleared
        assert "samesite=lax" in cleared
        assert "path=/" in cleared
        assert ("secure" in cleared) == settings.is_production


# --- who am I ------------------------------------------------------------------


async def test_me_returns_the_signed_in_user(
    client: httpx2.AsyncClient, db: AsyncSession, user: User
) -> None:
    issued = await sign_in(db, user)

    response = await client.get("/auth/me", headers=cookie(issued.token))

    assert response.status_code == 200
    assert response.json() == {
        "id": str(user.id),
        "email": "ada@example.com",
        "display_name": "Ada",
    }


async def test_me_never_exposes_anything_secret(
    client: httpx2.AsyncClient, db: AsyncSession, user: User
) -> None:
    issued = await sign_in(db, user)

    response = await client.get("/auth/me", headers=cookie(issued.token))

    assert issued.token not in response.text
    assert issued.session.token_hash.hex() not in response.text
    assert response.headers["cache-control"] == "no-store"


async def test_me_requires_a_cookie(client: httpx2.AsyncClient) -> None:
    response = await client.get("/auth/me")

    assert response.status_code == 401
    assert response.json() == STALE_BODY


async def test_every_kind_of_failure_gives_the_same_answer(
    client: httpx2.AsyncClient, db: AsyncSession, user: User
) -> None:
    """Nothing about WHY a request failed may leak to whoever is asking."""
    expired = await sign_in(db, user, now=datetime.now(UTC) - timedelta(days=40))
    revoked = await sign_in(db, user)
    await revoke_token(db, revoked.token)
    inactive_user = await make_user(db, "grace@example.com", active=True)
    deactivated = await sign_in(db, inactive_user)
    inactive_user.is_active = False
    await db.commit()

    attempts = [
        {},
        cookie("garbage"),
        cookie("x" * 10_000),
        cookie(expired.token),
        cookie(revoked.token),
        cookie(deactivated.token),
    ]
    for headers in attempts:
        response = await client.get("/auth/me", headers=headers)
        assert response.status_code == 401
        assert response.json() == STALE_BODY


async def test_a_failed_check_tells_the_browser_to_drop_the_stale_cookie(
    client: httpx2.AsyncClient,
) -> None:
    response = await client.get("/auth/me", headers=cookie("garbage"))

    header = response.headers["set-cookie"].lower()
    assert header.startswith(f"{COOKIE_NAME}=")
    assert "max-age=0" in header


async def test_using_the_site_keeps_the_session_alive(
    client: httpx2.AsyncClient, db: AsyncSession, user: User
) -> None:
    an_hour_ago = datetime.now(UTC) - timedelta(hours=1)
    issued = await sign_in(db, user, now=an_hour_ago)

    await client.get("/auth/me", headers=cookie(issued.token))

    await db.refresh(issued.session)
    assert issued.session.last_seen_at > datetime.now(UTC) - timedelta(minutes=5)


async def test_reading_is_allowed_whatever_the_origin(
    client: httpx2.AsyncClient, db: AsyncSession, user: User
) -> None:
    """Origin checks guard changes only; a read changes nothing."""
    issued = await sign_in(db, user)

    response = await client.get("/auth/me", headers={**cookie(issued.token), **EVIL})

    assert response.status_code == 200


# --- signing out -----------------------------------------------------------------


async def test_logout_ends_the_session_and_clears_the_cookie(
    client: httpx2.AsyncClient, db: AsyncSession, user: User
) -> None:
    issued = await sign_in(db, user)

    response = await client.post(
        "/auth/logout", headers={**cookie(issued.token), **TRUSTED}
    )

    assert response.status_code == 204
    assert "max-age=0" in response.headers["set-cookie"].lower()
    assert await revoked_at(db, issued.session.id) is not None
    after = await client.get("/auth/me", headers=cookie(issued.token))
    assert after.status_code == 401


async def test_logout_always_succeeds_and_always_clears_the_cookie(
    client: httpx2.AsyncClient, db: AsyncSession, user: User
) -> None:
    issued = await sign_in(db, user)
    headers = {**cookie(issued.token), **TRUSTED}

    for request_headers in (
        headers,
        headers,
        TRUSTED,
        {**cookie("garbage"), **TRUSTED},
    ):
        response = await client.post("/auth/logout", headers=request_headers)
        assert response.status_code == 204
        assert "max-age=0" in response.headers["set-cookie"].lower()


async def test_logout_rejects_requests_from_other_sites(
    client: httpx2.AsyncClient, db: AsyncSession, user: User
) -> None:
    issued = await sign_in(db, user)

    for headers in (
        {**cookie(issued.token), **EVIL},
        cookie(issued.token),
        {**cookie(issued.token), "origin": "null"},
    ):
        response = await client.post("/auth/logout", headers=headers)
        assert response.status_code == 403

    assert await revoked_at(db, issued.session.id) is None
    still_valid = await client.get("/auth/me", headers=cookie(issued.token))
    assert still_valid.status_code == 200


# --- signing out everywhere --------------------------------------------------------


async def test_logout_all_ends_every_session_of_the_user_including_this_one(
    client: httpx2.AsyncClient, db: AsyncSession, user: User
) -> None:
    this_device = await sign_in(db, user)
    other_device = await sign_in(db, user)

    response = await client.post(
        "/auth/logout-all", headers={**cookie(this_device.token), **TRUSTED}
    )

    assert response.status_code == 200
    assert response.json() == {"signed_out": 2}
    assert "max-age=0" in response.headers["set-cookie"].lower()
    for issued in (this_device, other_device):
        assert (
            await client.get("/auth/me", headers=cookie(issued.token))
        ).status_code == 401


async def test_logout_all_leaves_other_peoples_sessions_alone(
    client: httpx2.AsyncClient, db: AsyncSession, user: User
) -> None:
    other_user = await make_user(db, "grace@example.com")
    mine = await sign_in(db, user)
    theirs = await sign_in(db, other_user)

    await client.post("/auth/logout-all", headers={**cookie(mine.token), **TRUSTED})

    assert (
        await client.get("/auth/me", headers=cookie(theirs.token))
    ).status_code == 200


async def test_logout_all_requires_being_signed_in(client: httpx2.AsyncClient) -> None:
    for headers in (TRUSTED, {**cookie("garbage"), **TRUSTED}):
        response = await client.post("/auth/logout-all", headers=headers)
        assert response.status_code == 401
        assert response.json() == STALE_BODY


async def test_logout_all_rejects_requests_from_other_sites(
    client: httpx2.AsyncClient, db: AsyncSession, user: User
) -> None:
    issued = await sign_in(db, user)

    for headers in ({**cookie(issued.token), **EVIL}, cookie(issued.token)):
        assert (
            await client.post("/auth/logout-all", headers=headers)
        ).status_code == 403

    assert (
        await client.get("/auth/me", headers=cookie(issued.token))
    ).status_code == 200


# --- production behaviour ------------------------------------------------------------


async def test_production_uses_the_host_prefixed_cookie_name(
    monkeypatch: pytest.MonkeyPatch, test_url: URL, db: AsyncSession, user: User
) -> None:
    issued = await sign_in(db, user)

    async with running_client(monkeypatch, test_url, "production") as client:
        wrong_name = await client.get(
            "/auth/me", headers=cookie(issued.token, COOKIE_NAME)
        )
        right_name = await client.get(
            "/auth/me", headers=cookie(issued.token, PRODUCTION_COOKIE_NAME)
        )
        logout = await client.post(
            "/auth/logout",
            headers={**cookie(issued.token, PRODUCTION_COOKIE_NAME), **TRUSTED},
        )

    assert wrong_name.status_code == 401
    assert right_name.status_code == 200
    header = logout.headers["set-cookie"].lower()
    assert header.startswith(f"{PRODUCTION_COOKIE_NAME.lower()}=")
    assert "secure" in header
