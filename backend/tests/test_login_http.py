"""Tests for signing in over HTTP with an emailed code.

Real requests go through the whole application against a real PostgreSQL. Emails are
captured in memory, so the tests read the code exactly as a person would read it.
"""

import json
import logging
import re
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta

import httpx2
import pytest
from sqlalchemy import func, select
from sqlalchemy.engine import URL
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import COOKIE_NAME, PRODUCTION_COOKIE_NAME
from app.auth.login_codes import (
    CODE_LIFETIME,
    MAX_ATTEMPTS_PER_CODE,
    RESEND_COOLDOWN,
    issue_login_code,
)
from app.config import Settings, get_settings
from app.email import EmailMessage
from app.main import create_app
from app.models import AuthSession, LoginCode, User

pytestmark = pytest.mark.anyio

ADA = "ada@example.com"
TRUSTED = {"origin": "http://localhost:3000"}
EVIL = {"origin": "https://evil.example"}
ACCEPTED = {"status": "ok"}
REFUSED = {"detail": "Invalid or expired code"}


# --- test doubles and helpers -------------------------------------------------------------


class Outbox:
    """Collects emails in memory instead of sending them."""

    def __init__(self) -> None:
        self.messages: list[EmailMessage] = []

    async def send(self, message: EmailMessage) -> None:
        self.messages.append(message)


class BrokenSender:
    """A mail server that fails, with an error message that contains private details."""

    async def send(self, message: EmailMessage) -> None:
        raise RuntimeError(
            f"smtp login failed for {message.to} with password hunter2hunter2"
        )


@asynccontextmanager
async def running_client(
    monkeypatch: pytest.MonkeyPatch,
    test_url: URL,
    sender: object,
    environment: str = "development",
) -> AsyncIterator[httpx2.AsyncClient]:
    monkeypatch.setenv("APP_ENVIRONMENT", environment)
    monkeypatch.setenv(
        "APP_DATABASE_URL", test_url.render_as_string(hide_password=False)
    )
    get_settings.cache_clear()
    app = create_app()
    try:
        async with app.router.lifespan_context(app):
            app.state.email_sender = sender  # replaces the real one for the test
            transport = httpx2.ASGITransport(app=app)
            async with httpx2.AsyncClient(
                transport=transport, base_url="http://test"
            ) as client:
                yield client
    finally:
        get_settings.cache_clear()


@pytest.fixture
def outbox() -> Outbox:
    return Outbox()


@pytest.fixture
async def client(
    monkeypatch: pytest.MonkeyPatch, test_url: URL, outbox: Outbox, empty_tables: None
) -> AsyncIterator[httpx2.AsyncClient]:
    async with running_client(monkeypatch, test_url, outbox) as client:
        yield client


async def make_user(db: AsyncSession, email: str = ADA, *, active: bool = True) -> User:
    user = User(email=email, display_name="Ada", is_active=active)
    db.add(user)
    await db.commit()
    return user


@pytest.fixture
async def ada(db: AsyncSession) -> User:
    return await make_user(db)


def code_in(message: EmailMessage) -> str:
    match = re.search(r"(\d{3}) (\d{3})", message.body)
    assert match, "expected a six-digit code in the email"
    return match.group(1) + match.group(2)


async def request_code(
    client: httpx2.AsyncClient, email: str = ADA, **headers: str
) -> httpx2.Response:
    return await client.post(
        "/auth/login/request", json={"email": email}, headers={**TRUSTED, **headers}
    )


async def enter_code(
    client: httpx2.AsyncClient, code: str, email: str = ADA, **headers: str
) -> httpx2.Response:
    return await client.post(
        "/auth/login/verify",
        json={"email": email, "code": code},
        headers={**TRUSTED, **headers},
    )


def wrong_code(real: str) -> str:
    return "000000" if real != "000000" else "000001"


async def count(db: AsyncSession, model: type) -> int:
    return await db.scalar(select(func.count()).select_from(model)) or 0


# --- the email -------------------------------------------------------------------------------


async def test_asking_for_a_code_sends_one_email_with_the_code(
    client: httpx2.AsyncClient, outbox: Outbox, ada: User
) -> None:
    response = await request_code(client)

    assert response.status_code == 202
    assert response.json() == ACCEPTED
    assert len(outbox.messages) == 1
    message = outbox.messages[0]
    assert message.to == ADA
    assert message.subject == "Your Maro sign-in code"
    assert re.fullmatch(r"\d{6}", code_in(message))


async def test_the_email_has_no_links_and_states_how_long_the_code_lasts(
    client: httpx2.AsyncClient, outbox: Outbox, ada: User
) -> None:
    await request_code(client)

    body = outbox.messages[0].body.lower()
    assert "http" not in body
    assert "www." not in body
    assert "<a" not in body
    assert f"{int(CODE_LIFETIME.total_seconds() // 60)} minutes" in body
    assert "did not ask for this" in body


# --- asking for a code never reveals who has an account ------------------------------------------


async def test_every_request_gets_the_same_answer_whether_or_not_there_is_an_account(
    client: httpx2.AsyncClient, outbox: Outbox, db: AsyncSession, ada: User
) -> None:
    await make_user(db, "closed@example.com", active=False)
    answers = []
    for email in (
        ADA,
        "stranger@example.com",
        "closed@example.com",
        "not an email",
        "",
        "x" * 300,
    ):
        response = await request_code(client, email)
        answers.append(
            (
                response.status_code,
                response.json(),
                dict(response.headers).keys() - {"x-request-id"},
            )
        )

    assert len({str(answer) for answer in answers}) == 1
    assert answers[0][0] == 202
    assert len(outbox.messages) == 1  # only the real, active account was emailed


async def test_asking_for_a_code_never_creates_an_account(
    client: httpx2.AsyncClient, outbox: Outbox, db: AsyncSession
) -> None:
    await request_code(client, "stranger@example.com")

    assert await count(db, User) == 0
    assert await count(db, LoginCode) == 0
    assert outbox.messages == []


async def test_asking_again_straight_away_gets_the_same_answer_but_no_second_email(
    client: httpx2.AsyncClient, outbox: Outbox, ada: User
) -> None:
    first = await request_code(client)
    second = await request_code(client)

    assert first.json() == second.json() == ACCEPTED
    assert second.status_code == 202
    assert len(outbox.messages) == 1  # the cooldown is invisible to whoever asks


async def test_a_failing_mail_server_changes_nothing_the_caller_can_see(
    monkeypatch: pytest.MonkeyPatch,
    test_url: URL,
    empty_tables: None,
    ada: User,
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.DEBUG):
        async with running_client(monkeypatch, test_url, BrokenSender()) as client:
            response = await request_code(client)

    assert response.status_code == 202
    assert response.json() == ACCEPTED
    assert (
        "sending a sign-in code failed: RuntimeError" in caplog.text
    )  # operators are told
    for private in ("hunter2hunter2", ADA):
        assert private not in caplog.text  # ...without the private details in the error


async def test_the_answer_goes_out_before_any_of_the_work_is_done(
    monkeypatch: pytest.MonkeyPatch,
    test_url: URL,
    empty_tables: None,
    outbox: Outbox,
    ada: User,
) -> None:
    """If the account lookup and the sending happened BEFORE answering, how long the answer takes
    would reveal whether an account exists. So the answer must be sent first, work second.
    """
    order: list[str] = []

    async def work_done_later(*args: object) -> None:
        order.append("work")

    monkeypatch.setattr("app.auth.login.issue_and_send", work_done_later)
    body = json.dumps({"email": ADA}).encode()
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/auth/login/request",
        "raw_path": b"/auth/login/request",
        "query_string": b"",
        "root_path": "",
        "server": ("test", 80),
        "client": ("127.0.0.1", 1234),
        "headers": [
            (b"host", b"test"),
            (b"origin", b"http://localhost:3000"),
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode()),
        ],
    }

    async def receive() -> dict:
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message: dict) -> None:
        if message["type"] == "http.response.body" and not message.get("more_body"):
            order.append("answer sent")

    async with running_client(monkeypatch, test_url, outbox) as client:
        await client._transport.app(
            scope, receive, send
        )  # the application itself, called directly

    assert order == ["answer sent", "work"]


# --- cross-site protection -------------------------------------------------------------------------


@pytest.mark.parametrize("headers", [{}, EVIL, {"origin": "null"}])
async def test_both_endpoints_refuse_requests_from_other_sites(
    monkeypatch: pytest.MonkeyPatch,
    test_url: URL,
    empty_tables: None,
    outbox: Outbox,
    db: AsyncSession,
    ada: User,
    headers: dict[str, str],
) -> None:
    issued = await issue_login_code(db, ADA, settings=Settings(_env_file=None))
    assert issued is not None
    async with running_client(monkeypatch, test_url, outbox) as client:
        asked = await client.post(
            "/auth/login/request", json={"email": ADA}, headers=headers
        )
        entered = await client.post(
            "/auth/login/verify",
            json={"email": ADA, "code": issued.code},
            headers=headers,
        )

    assert asked.status_code == 403
    assert entered.status_code == 403
    assert outbox.messages == []
    assert await count(db, AuthSession) == 0


# --- entering a code ----------------------------------------------------------------------------------


async def test_the_right_code_signs_you_in_with_a_secure_cookie(
    client: httpx2.AsyncClient, outbox: Outbox, ada: User
) -> None:
    await request_code(client)

    response = await enter_code(client, code_in(outbox.messages[0]))

    assert response.status_code == 200
    assert response.json() == {"id": str(ada.id), "email": ADA, "display_name": "Ada"}
    cookie = response.headers["set-cookie"].lower()
    assert cookie.startswith(f"{COOKIE_NAME}=")
    assert "httponly" in cookie
    assert "samesite=lax" in cookie
    assert "path=/" in cookie


async def test_the_whole_journey_from_asking_for_a_code_to_signing_out(
    client: httpx2.AsyncClient, outbox: Outbox, ada: User
) -> None:
    assert (await client.get("/auth/me")).status_code == 401  # nobody is signed in

    await request_code(client)
    signed_in = await enter_code(client, code_in(outbox.messages[0]))
    cookie = {"cookie": signed_in.headers["set-cookie"].split(";")[0]}

    assert (await client.get("/auth/me", headers=cookie)).json()["email"] == ADA
    assert (
        await client.post("/auth/logout", headers={**cookie, **TRUSTED})
    ).status_code == 204
    assert (await client.get("/auth/me", headers=cookie)).status_code == 401


async def test_the_session_remembers_which_browser_signed_in(
    client: httpx2.AsyncClient, outbox: Outbox, db: AsyncSession, ada: User
) -> None:
    await request_code(client)

    await enter_code(
        client, code_in(outbox.messages[0]), **{"user-agent": "Safari on iPad"}
    )

    assert await db.scalar(select(AuthSession.user_agent)) == "Safari on iPad"


async def test_a_code_works_only_once_through_the_endpoint(
    client: httpx2.AsyncClient, outbox: Outbox, ada: User
) -> None:
    await request_code(client)
    code = code_in(outbox.messages[0])

    assert (await enter_code(client, code)).status_code == 200
    assert (await enter_code(client, code)).status_code == 401


async def test_every_kind_of_failure_gets_one_fixed_refusal_and_no_cookie(
    client: httpx2.AsyncClient, outbox: Outbox, db: AsyncSession, ada: User
) -> None:
    await make_user(db, "closed@example.com", active=False)
    expired = await issue_login_code(
        db,
        "ada@example.com",
        settings=Settings(_env_file=None),
        now=datetime.now(UTC) - CODE_LIFETIME - timedelta(minutes=5),
    )
    assert expired is not None
    used = await request_code(client)  # a fresh code, which we then use up
    assert used.status_code == 202
    real = code_in(outbox.messages[0])
    await enter_code(client, real)

    attempts = [
        (ADA, wrong_code(real)),  # wrong
        (ADA, real),  # already used
        (ADA, expired.code),  # expired
        (ADA, "banana"),  # malformed
        (ADA, ""),
        ("stranger@example.com", real),  # unknown email
        ("closed@example.com", real),  # deactivated account
        ("", real),
    ]
    for email, code in attempts:
        response = await enter_code(client, code, email)
        assert response.status_code == 401, (email, code)
        assert response.json() == REFUSED, (email, code)
        assert "set-cookie" not in response.headers, (email, code)


async def test_five_wrong_guesses_through_the_endpoint_kill_the_code(
    client: httpx2.AsyncClient, outbox: Outbox, ada: User
) -> None:
    await request_code(client)
    real = code_in(outbox.messages[0])

    for _ in range(MAX_ATTEMPTS_PER_CODE):
        assert (await enter_code(client, wrong_code(real))).status_code == 401

    assert (await enter_code(client, real)).status_code == 401


async def test_the_code_works_however_it_is_typed(
    client: httpx2.AsyncClient, outbox: Outbox, ada: User
) -> None:
    await request_code(client)
    real = code_in(outbox.messages[0])

    response = await enter_code(
        client, f" {real[:3]} {real[3:]} ", "  ADA@Example.com "
    )

    assert response.status_code == 200


async def test_signing_in_twice_gives_two_independent_sessions(
    client: httpx2.AsyncClient, outbox: Outbox, db: AsyncSession, ada: User
) -> None:
    await request_code(client)
    first = await enter_code(client, code_in(outbox.messages[0]))
    # Move the cooldown out of the way by retiring the first code's record of creation.
    await db.execute(
        LoginCode.__table__.update().values(
            created_at=datetime.now(UTC) - RESEND_COOLDOWN * 2
        )
    )
    await db.commit()
    await request_code(client)
    second = await enter_code(client, code_in(outbox.messages[1]))

    cookies = [r.headers["set-cookie"].split(";")[0] for r in (first, second)]
    assert cookies[0] != cookies[1]
    for cookie in cookies:
        assert (
            await client.get("/auth/me", headers={"cookie": cookie})
        ).status_code == 200
    await client.post("/auth/logout", headers={"cookie": cookies[0], **TRUSTED})
    assert (
        await client.get("/auth/me", headers={"cookie": cookies[0]})
    ).status_code == 401
    assert (
        await client.get("/auth/me", headers={"cookie": cookies[1]})
    ).status_code == 200


# --- input handling -----------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"email": ADA},
        {"code": "123456"},
        {"email": ADA, "code": "123456", "extra": "field"},
        {"email": "x" * 400, "code": "123456"},
        {"email": ADA, "code": "1" * 100},
        {"email": 123, "code": "123456"},
        {"email": ADA, "code": None},
    ],
)
async def test_badly_shaped_requests_are_rejected_cleanly(
    client: httpx2.AsyncClient, payload: dict
) -> None:
    response = await client.post("/auth/login/verify", json=payload, headers=TRUSTED)

    assert response.status_code == 422
    assert "set-cookie" not in response.headers


async def test_junk_in_an_email_never_causes_a_server_error(
    client: httpx2.AsyncClient,
) -> None:
    json_headers = {**TRUSTED, "content-type": "application/json"}
    for junk in (
        "\x00",
        "ada@exam\x00ple.com",
        "\ud800",
        "'; DROP TABLE users;--",
        "ada\n@example.com",
    ):
        # Raw JSON text, the way an attacker would really send it: escapes like \ud800 are
        # valid JSON even though they cannot be turned back into real text.
        asked = await client.post(
            "/auth/login/request",
            content=json.dumps({"email": junk}),
            headers=json_headers,
        )
        entered = await client.post(
            "/auth/login/verify",
            content=json.dumps({"email": junk, "code": "123456"}),
            headers=json_headers,
        )

        assert asked.status_code in (202, 422), junk
        assert entered.status_code in (401, 422), junk


async def test_error_replies_say_which_field_is_wrong_but_never_repeat_what_was_sent(
    client: httpx2.AsyncClient,
) -> None:
    response = await client.post(
        "/auth/login/verify",
        json={"email": "x" * 400 + "SECRET-MARKER", "code": "123456-SECRET-MARKER" * 5},
        headers=TRUSTED,
    )

    assert response.status_code == 422
    assert "SECRET-MARKER" not in response.text
    problems = response.json()["detail"]
    assert {tuple(problem["loc"]) for problem in problems} == {
        ("body", "email"),
        ("body", "code"),
    }
    assert all(
        {"loc", "type", "msg"} == set(problem) for problem in problems
    )  # nothing else, such as "input"


# --- logs --------------------------------------------------------------------------------------------------------


async def test_logs_never_contain_the_code_or_the_email_during_a_whole_sign_in(
    client: httpx2.AsyncClient,
    outbox: Outbox,
    ada: User,
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.DEBUG):
        await request_code(client)
        real = code_in(outbox.messages[0])
        await enter_code(client, wrong_code(real))
        await enter_code(client, real)
        await request_code(client, "stranger@example.com")

    logged = caplog.text.replace(str(ada.id), "<user-id>")
    numbers = re.sub(r"[^0-9]+", " ", logged).split()
    assert real not in numbers
    assert wrong_code(real) not in numbers
    assert ADA not in logged
    assert "stranger@example.com" not in logged


# --- production ---------------------------------------------------------------------------------------------------


async def test_in_production_the_cookie_is_https_only_with_the_host_prefix(
    monkeypatch: pytest.MonkeyPatch,
    test_url: URL,
    empty_tables: None,
    outbox: Outbox,
    db: AsyncSession,
    ada: User,
) -> None:
    issued = await issue_login_code(db, ADA, settings=Settings(_env_file=None))
    assert issued is not None

    async with running_client(monkeypatch, test_url, outbox, "production") as client:
        response = await enter_code(client, issued.code)

    assert response.status_code == 200
    cookie = response.headers["set-cookie"].lower()
    assert cookie.startswith(f"{PRODUCTION_COOKIE_NAME.lower()}=")
    assert "secure" in cookie


async def test_without_a_real_email_sender_codes_are_never_printed_or_sent(
    monkeypatch: pytest.MonkeyPatch,
    test_url: URL,
    empty_tables: None,
    ada: User,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The default sender outside development refuses, so a code can never end up in production logs."""
    monkeypatch.setenv("APP_ENVIRONMENT", "staging")
    monkeypatch.setenv(
        "APP_DATABASE_URL", test_url.render_as_string(hide_password=False)
    )
    get_settings.cache_clear()
    app = create_app()
    try:
        with caplog.at_level(logging.DEBUG):
            async with app.router.lifespan_context(
                app
            ):  # the real sender, not a test double
                transport = httpx2.ASGITransport(app=app)
                async with httpx2.AsyncClient(
                    transport=transport, base_url="http://test"
                ) as client:
                    response = await request_code(client)
    finally:
        get_settings.cache_clear()

    assert response.status_code == 202  # the caller still sees nothing unusual
    assert "EmailNotConfiguredError" in caplog.text  # but operators are told, loudly
    assert "EMAIL (development only" not in caplog.text
    codes_printed = re.findall(r"\b\d{3} \d{3}\b", caplog.text)
    assert codes_printed == []
