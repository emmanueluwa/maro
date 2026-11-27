"""Tests for the login code service, run against a real PostgreSQL (see conftest.py).

Time is controlled by passing `now`, so expiry, cooldown and lockout rules are tested
without waiting.
"""

import asyncio
import hashlib
import logging
import re
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from app.auth import login_codes
from app.auth.login_codes import (
    CODE_LENGTH,
    CODE_LIFETIME,
    FAILURE_WINDOW,
    MAX_ATTEMPTS_PER_CODE,
    MAX_FAILURES_PER_WINDOW,
    RESEND_COOLDOWN,
    IssuedLoginCode,
    generate_code,
    hash_code,
    issue_login_code,
    normalise_code,
    verify_login_code,
)
from app.config import Settings
from app.db import create_session_factory
from app.models import LoginCode, User

pytestmark = pytest.mark.anyio

NOW = datetime(2026, 11, 21, 12, 0, tzinfo=UTC)
ADA = "ada@example.com"
GRACE = "grace@example.com"
SETTINGS = Settings(
    _env_file=None, secret_key="a-test-secret-key-that-is-long-enough-0123456789"
)
OTHER_KEY_SETTINGS = Settings(
    _env_file=None, secret_key="a-completely-different-secret-key-0123456789"
)


# --- helpers ------------------------------------------------------------------


async def make_user(db: AsyncSession, email: str, *, active: bool = True) -> User:
    user = User(email=email, is_active=active)
    db.add(user)
    await db.commit()
    return user


@pytest.fixture
async def ada(db: AsyncSession) -> User:
    return await make_user(db, ADA)


async def issue(
    db: AsyncSession, email: str = ADA, *, now: datetime = NOW, **kwargs: object
) -> IssuedLoginCode:
    issued = await issue_login_code(db, email, settings=SETTINGS, now=now, **kwargs)  # type: ignore[arg-type]
    assert issued is not None, "expected a code to be issued"
    return issued


async def verify(
    db: AsyncSession,
    code: str,
    email: str = ADA,
    *,
    now: datetime = NOW,
    **kwargs: object,
) -> User | None:
    return await verify_login_code(db, email, code, settings=SETTINGS, now=now, **kwargs)  # type: ignore[arg-type]


def wrong_code(real: str) -> str:
    return "000000" if real != "000000" else "000001"


async def live_code(db: AsyncSession, user: User) -> LoginCode | None:
    """The user's live code, freshly read from the database (not from the session's memory)."""
    return await db.scalar(
        select(LoginCode)
        .where(LoginCode.user_id == user.id, LoginCode.consumed_at.is_(None))
        .execution_options(populate_existing=True)
    )


async def count_live(db: AsyncSession) -> int:
    return (
        await db.scalar(
            select(func.count())
            .select_from(LoginCode)
            .where(LoginCode.consumed_at.is_(None))
        )
        or 0
    )


async def total_codes(db: AsyncSession) -> int:
    return await db.scalar(select(func.count()).select_from(LoginCode)) or 0


# --- the code itself (no database needed) -------------------------------------------


def test_codes_are_six_digits_and_really_random() -> None:
    codes = [generate_code() for _ in range(2000)]

    assert all(
        len(code) == CODE_LENGTH and code.isascii() and code.isdigit() for code in codes
    )
    assert len(set(codes)) > 1900  # a million possibilities, so repeats are rare
    assert any(code.startswith("0") for code in codes)  # leading zeros survive
    assert {code[0] for code in codes} == set("0123456789")


def test_codes_come_from_the_operating_systems_secure_random_source(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ordinary random numbers are predictable. Only `secrets` is safe for anything security-related."""
    monkeypatch.setattr(login_codes.secrets, "randbelow", lambda limit: 42)

    assert (
        generate_code() == "000042"
    )  # also shows short numbers are padded to six digits


@pytest.mark.parametrize(
    ("typed", "expected"),
    [
        ("123456", "123456"),
        (" 123456 ", "123456"),
        ("123 456", "123456"),
        ("123-456", "123456"),
        ("123456\n", "123456"),
        ("000123", "000123"),
    ],
)
def test_normalise_accepts_how_people_really_type_codes(
    typed: str, expected: str
) -> None:
    assert normalise_code(typed) == expected


@pytest.mark.parametrize(
    "typed",
    [
        "",
        " ",
        "12345",
        "1234567",
        "12345a",
        "abcdef",
        "12.456",
        "１２３４５６",
        "١٢٣٤٥٦",
        "123456" * 10,
        "x" * 1000,
        "1 2 3 4 5 6 7",
    ],
)
def test_normalise_rejects_everything_that_cannot_be_a_code(typed: str) -> None:
    assert normalise_code(typed) is None


def test_hash_is_keyed_per_user_and_per_code() -> None:
    ada_id, grace_id = uuid.uuid4(), uuid.uuid4()
    base = hash_code("123456", ada_id, SETTINGS)

    assert len(base) == 32
    assert base == hash_code("123456", ada_id, SETTINGS)
    assert base != hash_code("123457", ada_id, SETTINGS)  # different code
    assert base != hash_code(
        "123456", grace_id, SETTINGS
    )  # same code, different person
    assert base != hash_code(
        "123456", ada_id, OTHER_KEY_SETTINGS
    )  # different secret key


def test_hash_is_not_a_plain_unkeyed_hash() -> None:
    """A plain SHA-256 of six digits can be reversed instantly, so it must never be used."""
    user_id = uuid.uuid4()
    stored = hash_code("123456", user_id, SETTINGS)

    assert stored != hashlib.sha256(b"123456").digest()
    assert stored != hashlib.sha256(user_id.bytes + b"123456").digest()


# --- issuing codes ---------------------------------------------------------------------


async def test_issuing_gives_a_code_that_is_stored_only_as_a_keyed_hash(
    db: AsyncSession, ada: User
) -> None:
    issued = await issue(db)

    row = await live_code(db, ada)
    assert row is not None
    assert row.code_hash == hash_code(issued.code, ada.id, SETTINGS)
    assert row.code_hash != issued.code.encode()
    assert row.code_hash != hashlib.sha256(issued.code.encode()).digest()


async def test_a_code_expires_ten_minutes_after_it_is_issued(
    db: AsyncSession, ada: User
) -> None:
    issued = await issue(db)

    assert issued.expires_at == NOW + CODE_LIFETIME
    assert CODE_LIFETIME == timedelta(minutes=10)
    row = await live_code(db, ada)
    assert row is not None
    assert row.created_at == NOW
    assert row.expires_at == NOW + CODE_LIFETIME


async def test_an_issued_code_never_prints_itself(db: AsyncSession, ada: User) -> None:
    issued = await issue(db)

    assert issued.code not in repr(issued)
    assert issued.code not in str(issued)


async def test_no_code_is_issued_for_an_unknown_email_and_nothing_is_created(
    db: AsyncSession,
) -> None:
    result = await issue_login_code(
        db, "stranger@example.com", settings=SETTINGS, now=NOW
    )

    assert result is None
    assert await total_codes(db) == 0
    assert (
        await db.scalar(select(func.count()).select_from(User)) == 0
    )  # signing in never creates accounts


async def test_no_code_is_issued_for_a_deactivated_user(db: AsyncSession) -> None:
    await make_user(db, ADA, active=False)

    assert await issue_login_code(db, ADA, settings=SETTINGS, now=NOW) is None
    assert await total_codes(db) == 0


@pytest.mark.parametrize(
    "typed", ["ADA@example.com", "  ada@example.com  ", "Ada@Example.COM"]
)
async def test_the_email_is_matched_however_it_is_capitalised_or_spaced(
    db: AsyncSession, ada: User, typed: str
) -> None:
    issued = await issue(db, typed)

    assert issued.user_id == ada.id
    assert issued.email == ADA


@pytest.mark.parametrize(
    "junk",
    [
        "",
        " ",
        "x" * 5000,
        "not an email",
        "'; DROP TABLE users;--",
        "\x00",
        "ada@exam\x00ple.com",
        "\ud800",
        "ada\n@example.com",
    ],
)
async def test_junk_emails_are_refused_without_errors(
    db: AsyncSession, ada: User, junk: str
) -> None:
    assert await issue_login_code(db, junk, settings=SETTINGS, now=NOW) is None
    assert (
        await verify_login_code(db, junk, "123456", settings=SETTINGS, now=NOW) is None
    )


async def test_asking_again_too_soon_sends_nothing_and_keeps_the_first_code(
    db: AsyncSession, ada: User
) -> None:
    first = await issue(db)

    too_soon = NOW + RESEND_COOLDOWN - timedelta(seconds=1)
    assert await issue_login_code(db, ADA, settings=SETTINGS, now=too_soon) is None

    assert await verify(db, first.code, now=too_soon) is not None


async def test_a_new_code_retires_the_old_one(db: AsyncSession, ada: User) -> None:
    first = await issue(db)
    second = await issue(db, now=NOW + RESEND_COOLDOWN)
    moment = NOW + RESEND_COOLDOWN + timedelta(seconds=5)

    assert await verify(db, first.code, now=moment) is None
    assert await verify(db, second.code, now=moment) is not None
    assert await count_live(db) == 0  # the successful sign-in used the only live code


async def test_only_one_code_is_ever_live_per_user(db: AsyncSession, ada: User) -> None:
    for minute in range(5):
        await issue(db, now=NOW + timedelta(minutes=minute * 2))

    assert await count_live(db) == 1
    assert await total_codes(db) == 5


# --- checking codes ---------------------------------------------------------------------------


async def test_the_right_code_signs_the_user_in(db: AsyncSession, ada: User) -> None:
    issued = await issue(db)

    signed_in = await verify(db, issued.code, now=NOW + timedelta(minutes=1))

    assert signed_in is not None
    assert signed_in.id == ada.id


@pytest.mark.parametrize(
    "format_",
    [
        lambda c: c,
        lambda c: f"{c[:3]} {c[3:]}",
        lambda c: f"{c[:3]}-{c[3:]}",
        lambda c: f" {c} ",
    ],
)
async def test_the_code_works_however_it_was_typed(
    db: AsyncSession, ada: User, format_
) -> None:
    issued = await issue(db)

    assert await verify(db, format_(issued.code)) is not None


async def test_a_code_works_only_once(db: AsyncSession, ada: User) -> None:
    issued = await issue(db)

    assert await verify(db, issued.code) is not None
    assert await verify(db, issued.code) is None


async def test_a_wrong_code_is_rejected_and_counted(
    db: AsyncSession, ada: User
) -> None:
    issued = await issue(db)

    assert await verify(db, wrong_code(issued.code)) is None

    row = await live_code(db, ada)
    assert row is not None
    assert row.attempts == 1


async def test_one_typo_does_not_ruin_the_code(db: AsyncSession, ada: User) -> None:
    issued = await issue(db)

    await verify(db, wrong_code(issued.code))

    assert await verify(db, issued.code) is not None


async def test_a_code_dies_after_five_wrong_guesses_even_if_the_right_one_follows(
    db: AsyncSession, ada: User
) -> None:
    issued = await issue(db)

    for _ in range(MAX_ATTEMPTS_PER_CODE):
        assert await verify(db, wrong_code(issued.code)) is None

    assert await verify(db, issued.code) is None
    assert await live_code(db, ada) is None  # burned


async def test_four_wrong_guesses_leave_the_code_alive(
    db: AsyncSession, ada: User
) -> None:
    issued = await issue(db)

    for _ in range(MAX_ATTEMPTS_PER_CODE - 1):
        await verify(db, wrong_code(issued.code))

    assert await verify(db, issued.code) is not None


async def test_an_expired_code_is_rejected_and_retired(
    db: AsyncSession, ada: User
) -> None:
    issued = await issue(db)

    assert (
        await verify(db, issued.code, now=NOW + CODE_LIFETIME + timedelta(seconds=1))
        is None
    )
    assert await live_code(db, ada) is None


async def test_the_expiry_moment_itself_is_already_too_late(
    db: AsyncSession, ada: User
) -> None:
    issued = await issue(db)

    assert (
        await verify(db, issued.code, now=NOW + CODE_LIFETIME - timedelta(seconds=1))
        is not None
    )
    second = await issue(db, now=NOW + timedelta(hours=3))
    assert (
        await verify(db, second.code, now=NOW + timedelta(hours=3) + CODE_LIFETIME)
        is None
    )


@pytest.mark.parametrize(
    "junk",
    [
        "",
        "abc",
        "12345",
        "1234567",
        "'; DROP TABLE login_codes;--",
        "１２３４５６",
        "x" * 10_000,
    ],
)
async def test_malformed_codes_are_rejected_and_never_count_as_guesses(
    db: AsyncSession, ada: User, junk: str
) -> None:
    issued = await issue(db)

    assert await verify(db, junk) is None

    row = await live_code(db, ada)
    assert row is not None
    assert row.attempts == 0
    assert await verify(db, issued.code) is not None


async def test_a_code_belongs_to_one_person_only(db: AsyncSession, ada: User) -> None:
    grace = await make_user(db, GRACE)
    ada_code = await issue(db, ADA)
    grace_code = await issue(db, GRACE)

    assert (
        await verify(db, ada_code.code, GRACE) is None
    )  # Ada's code against Grace's account
    assert (
        await verify(db, grace_code.code, ADA) is None
    )  # Grace's code against Ada's account
    assert await verify(db, ada_code.code, ADA) is not None
    assert await verify(db, grace_code.code, GRACE) is not None
    assert grace.id != ada.id


async def test_a_code_does_not_work_for_an_unknown_email(
    db: AsyncSession, ada: User
) -> None:
    issued = await issue(db)

    assert await verify(db, issued.code, "stranger@example.com") is None
    assert await verify(db, issued.code) is not None  # and Ada's code is unharmed


async def test_a_code_stops_working_if_the_user_is_deactivated(
    db: AsyncSession, ada: User
) -> None:
    issued = await issue(db)
    ada.is_active = False
    await db.commit()

    assert await verify(db, issued.code) is None


async def test_the_email_is_matched_when_signing_in_too(
    db: AsyncSession, ada: User
) -> None:
    issued = await issue(db)

    assert await verify(db, issued.code, "  ADA@Example.com ") is not None


async def test_changing_the_secret_key_invalidates_pending_codes(
    db: AsyncSession, ada: User
) -> None:
    issued = await issue(db)

    assert (
        await verify_login_code(
            db, ADA, issued.code, settings=OTHER_KEY_SETTINGS, now=NOW
        )
        is None
    )
    assert await verify(db, issued.code) is not None  # the original key still works


# --- the account-wide limit on wrong guesses ----------------------------------------------------


async def guess_wrongly(
    db: AsyncSession, issued: IssuedLoginCode, times: int, *, now: datetime = NOW
) -> None:
    for _ in range(times):
        await verify(db, wrong_code(issued.code), now=now, max_attempts=100)


async def test_after_ten_wrong_guesses_even_the_right_code_is_refused(
    db: AsyncSession, ada: User
) -> None:
    issued = await issue(db)
    await guess_wrongly(db, issued, MAX_FAILURES_PER_WINDOW)

    assert await verify(db, issued.code, max_attempts=100) is None

    await db.refresh(
        ada
    )  # the refusal rolled back, which makes this shared session forget `ada`
    row = await live_code(db, ada)
    assert row is not None
    assert (
        row.attempts == MAX_FAILURES_PER_WINDOW
    )  # a refused attempt is not counted again


async def test_nine_wrong_guesses_do_not_lock_the_account(
    db: AsyncSession, ada: User
) -> None:
    issued = await issue(db)
    await guess_wrongly(db, issued, MAX_FAILURES_PER_WINDOW - 1)

    assert await verify(db, issued.code, max_attempts=100) is not None


async def test_asking_for_fresh_codes_cannot_dodge_the_limit(
    db: AsyncSession, ada: User
) -> None:
    """Two codes' worth of wrong guesses locks the account, so an attacker cannot keep resetting it."""
    clock = NOW
    for _ in range(MAX_FAILURES_PER_WINDOW // MAX_ATTEMPTS_PER_CODE):
        issued = await issue(db, now=clock)
        await guess_wrongly(db, issued, MAX_ATTEMPTS_PER_CODE, now=clock)
        clock += RESEND_COOLDOWN + timedelta(seconds=1)

    assert await issue_login_code(db, ADA, settings=SETTINGS, now=clock) is None


async def test_the_limit_lifts_once_the_window_has_passed(
    db: AsyncSession, ada: User
) -> None:
    issued = await issue(db)
    await guess_wrongly(db, issued, MAX_FAILURES_PER_WINDOW)
    assert (
        await issue_login_code(
            db, ADA, settings=SETTINGS, now=NOW + timedelta(minutes=30)
        )
        is None
    )

    later = NOW + FAILURE_WINDOW + timedelta(minutes=1)
    fresh = await issue(db, now=later)

    assert await verify(db, fresh.code, now=later) is not None


async def test_old_wrong_guesses_stop_counting(db: AsyncSession, ada: User) -> None:
    clock = NOW
    for _ in range(2):
        issued = await issue(db, now=clock)
        await guess_wrongly(db, issued, MAX_ATTEMPTS_PER_CODE, now=clock)
        clock += timedelta(minutes=2)

    just_after_the_window = NOW + FAILURE_WINDOW + timedelta(minutes=3)

    assert (
        await issue_login_code(db, ADA, settings=SETTINGS, now=just_after_the_window)
        is not None
    )


async def test_one_persons_wrong_guesses_never_lock_another(
    db: AsyncSession, ada: User
) -> None:
    await make_user(db, GRACE)
    ada_code = await issue(db, ADA)
    await guess_wrongly(db, ada_code, MAX_FAILURES_PER_WINDOW)

    assert await issue_login_code(db, GRACE, settings=SETTINGS, now=NOW) is not None


# --- simultaneous requests -----------------------------------------------------------------------------


async def test_simultaneous_wrong_guesses_are_all_counted(
    engine: AsyncEngine, db: AsyncSession, ada: User
) -> None:
    """Without row locking, two guesses at the same instant can both read '0' and record '1',
    letting an attacker make more guesses than the limit allows."""
    factory = create_session_factory(engine)

    async def guess(code: str, clock: datetime) -> None:
        async with factory() as session:
            await verify_login_code(session, ADA, code, settings=SETTINGS, now=clock)

    for round_number in range(12):
        clock = NOW + timedelta(
            hours=round_number * 2
        )  # far apart, so the hourly limit never interferes
        issued = await issue(db, now=clock)
        await db.commit()
        await asyncio.gather(
            guess(wrong_code(issued.code), clock), guess(wrong_code(issued.code), clock)
        )

        row = await live_code(db, ada)
        assert row is not None
        assert row.attempts == 2, f"lost update in round {round_number}"
        await db.commit()


async def test_simultaneous_requests_for_a_code_produce_exactly_one_live_code(
    engine: AsyncEngine, db: AsyncSession, ada: User
) -> None:
    factory = create_session_factory(engine)

    async def request() -> IssuedLoginCode | None:
        async with factory() as session:
            return await issue_login_code(session, ADA, settings=SETTINGS, now=NOW)

    results = await asyncio.gather(request(), request())

    assert sum(result is not None for result in results) == 1
    assert await count_live(db) == 1


# --- logs ---------------------------------------------------------------------------------------------------


async def test_logs_never_contain_any_code_the_email_or_the_hash(
    db: AsyncSession, ada: User, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.INFO, logger="app.auth"):
        issued = await issue(db)
        guess = wrong_code(issued.code)
        await verify(db, guess)
        await verify(db, "banana")
        await verify(db, issued.code, "stranger@example.com")
        await verify(db, issued.code)
        await issue_login_code(db, "stranger@example.com", settings=SETTINGS, now=NOW)

    logged = caplog.text.replace(
        str(ada.id), "<user-id>"
    )  # ids are hex and could contain digits by chance
    assert logged.strip(), "expected the service to log what happened"
    numbers_in_the_log = re.sub(r"[^0-9]+", " ", logged).split()
    assert issued.code not in numbers_in_the_log  # the real code
    assert guess not in numbers_in_the_log  # and what someone typed, right or wrong
    for secret in (
        ADA,
        "stranger@example.com",
        hash_code(issued.code, ada.id, SETTINGS).hex(),
    ):
        assert secret not in logged


# --- regressions: bugs found while writing these tests ----------------------------------------


async def test_a_locked_out_account_is_refused_calmly_and_can_try_again_later(
    db: AsyncSession, ada: User
) -> None:
    """Once crashed with a database-session error at exactly the moment someone was locked out."""
    issued = await issue(db)
    await guess_wrongly(db, issued, MAX_FAILURES_PER_WINDOW)

    for _ in range(3):  # repeated attempts while locked: every one is a clean refusal
        assert await verify(db, issued.code, max_attempts=100) is None
        assert (
            await issue_login_code(
                db, ADA, settings=SETTINGS, now=NOW + timedelta(minutes=5)
            )
            is None
        )

    later = NOW + FAILURE_WINDOW + timedelta(minutes=1)
    fresh = await issue(db, now=later)
    assert await verify(db, fresh.code, now=later) is not None


async def test_simultaneous_requests_never_leave_one_person_holding_a_dead_code(
    engine: AsyncEngine, db: AsyncSession, ada: User
) -> None:
    """Two requests at once used to both succeed, the second silently killing the first code."""
    factory = create_session_factory(engine)

    async def request() -> IssuedLoginCode | None:
        async with factory() as session:
            return await issue_login_code(session, ADA, settings=SETTINGS, now=NOW)

    for round_number in range(8):
        results = await asyncio.gather(request(), request())
        issued = [result for result in results if result is not None]

        assert len(issued) == 1, f"round {round_number}: {len(issued)} codes were sent"
        assert (
            await verify(db, issued[0].code, now=NOW + timedelta(seconds=5)) is not None
        )  # the one sent works
        await db.commit()
        await asyncio.gather(
            *[_wipe_codes(factory)]  # next round starts from a clean slate
        )


async def _wipe_codes(factory) -> None:
    async with factory() as session:
        await session.execute(LoginCode.__table__.delete())
        await session.commit()


async def test_a_refused_request_does_not_keep_the_users_record_locked(
    engine: AsyncEngine, db: AsyncSession, ada: User
) -> None:
    """Refusals (cooldown, lockout) must release their lock, or the next request would hang."""
    ada_id = (
        ada.id
    )  # read now: the refusal below rolls back and the session forgets `ada`
    await issue(db)
    assert (
        await issue_login_code(
            db, ADA, settings=SETTINGS, now=NOW + timedelta(seconds=1)
        )
        is None
    )  # cooldown

    async def other_session_updates_the_user() -> None:
        async with create_session_factory(engine)() as session:
            await session.execute(
                User.__table__.update()
                .where(User.id == ada_id)
                .values(display_name="Ada L.")
            )
            await session.commit()

    await asyncio.wait_for(other_session_updates_the_user(), timeout=3)


# --- the locks, proven directly -------------------------------------------------------------------------
# Simultaneous requests are hard to line up by luck. These tests instead HOLD the lock themselves,
# standing in for a request that is halfway through, and check that the service really waits.


async def test_issuing_waits_for_a_request_already_in_progress_for_the_same_person(
    engine: AsyncEngine, db: AsyncSession, ada: User
) -> None:
    ada_id = ada.id
    factory = create_session_factory(engine)

    async def request() -> IssuedLoginCode | None:
        async with factory() as session:
            return await issue_login_code(session, ADA, settings=SETTINGS, now=NOW)

    async with factory() as in_progress:
        # The same kind of lock the service takes, and no stronger: a stronger one would also stall
        # the 'does this user exist' check of an insert, and the test could not tell the difference.
        await in_progress.scalar(
            select(User).where(User.id == ada_id).with_for_update(key_share=True)
        )
        waiting = asyncio.create_task(request())
        finished, _ = await asyncio.wait({waiting}, timeout=0.5)
        assert not finished, "issuing did not wait for the request already in progress"
        await in_progress.rollback()

    assert await asyncio.wait_for(waiting, timeout=5) is not None


async def test_issuing_for_one_person_does_not_wait_for_another(
    engine: AsyncEngine, db: AsyncSession, ada: User
) -> None:
    grace = await make_user(db, GRACE)
    grace_id = grace.id
    factory = create_session_factory(engine)

    async with factory() as in_progress:
        await in_progress.scalar(
            select(User).where(User.id == grace_id).with_for_update(key_share=True)
        )  # Grace is busy
        async with factory() as session:
            result = await asyncio.wait_for(
                issue_login_code(session, ADA, settings=SETTINGS, now=NOW), timeout=3
            )

    assert result is not None


async def test_wrong_guesses_are_counted_one_at_a_time(
    engine: AsyncEngine, db: AsyncSession, ada: User
) -> None:
    """A guess arriving while another is being counted must wait, then add to it, not overwrite it."""
    issued = await issue(db)
    row = await live_code(db, ada)
    assert row is not None
    row_id = row.id
    await db.commit()  # release this session's connection
    factory = create_session_factory(engine)

    async def guess() -> None:
        async with factory() as session:
            await verify_login_code(
                session, ADA, wrong_code(issued.code), settings=SETTINGS, now=NOW
            )

    async with factory() as in_progress:
        counting = await in_progress.scalar(
            select(LoginCode).where(LoginCode.id == row_id).with_for_update()
        )
        assert counting is not None
        waiting = asyncio.create_task(guess())
        finished, _ = await asyncio.wait({waiting}, timeout=0.5)
        assert not finished, "a guess did not wait for the one being counted"
        counting.attempts += 1  # the guess in progress is recorded...
        await in_progress.commit()

    await asyncio.wait_for(waiting, timeout=5)  # ...then the waiting guess adds its own

    final = await live_code(db, ada)
    assert final is not None
    assert final.attempts == 2


async def test_guesses_are_compared_in_constant_time(
    db: AsyncSession, ada: User, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A plain == can leak, through tiny timing differences, how many leading digits were right."""
    calls: list[tuple[bytes, bytes]] = []
    real_compare = login_codes.hmac.compare_digest

    def spy(a: bytes, b: bytes) -> bool:
        calls.append((a, b))
        return real_compare(a, b)

    monkeypatch.setattr(login_codes.hmac, "compare_digest", spy)
    issued = await issue(db)

    assert await verify(db, issued.code) is not None
    assert len(calls) == 1
