"""Signing in with an emailed code: ask for a code, then enter it.

Two rules shape these endpoints:

  1. Asking for a code ALWAYS gets the same instant answer, whether or not the email has an
     account. The real work (looking up the account, creating the code, sending the email)
     happens after the answer has gone out, so even how long the answer takes reveals nothing.
  2. Entering a code either signs you in or gets one fixed refusal. It never says why.
"""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    HTTPException,
    Request,
    Response,
    status,
)
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.auth.dependencies import require_trusted_origin, set_session_cookie
from app.auth.login_codes import (
    CODE_LIFETIME,
    IssuedLoginCode,
    issue_login_code,
    verify_login_code,
)
from app.auth.router import UserOut
from app.auth.sessions import create_session
from app.config import Settings, get_settings
from app.db import get_session
from app.email import EmailMessage, EmailSender

logger = logging.getLogger("app.auth")

router = APIRouter(prefix="/auth/login", tags=["auth"])

Database = Annotated[AsyncSession, Depends(get_session)]
AppSettings = Annotated[Settings, Depends(get_settings)]


class RequestCode(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: str = Field(max_length=320)


class EnterCode(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: str = Field(max_length=320)
    code: str = Field(max_length=32)


class Accepted(BaseModel):
    status: str = "ok"


def build_login_code_message(issued: IssuedLoginCode) -> EmailMessage:
    """Plain text, and deliberately no links: nothing in this email can be clicked, so it
    cannot be copied into a convincing phishing email."""
    spaced = f"{issued.code[:3]} {issued.code[3:]}"
    minutes = int(CODE_LIFETIME.total_seconds() // 60)
    body = (
        f"Your Maro sign-in code is {spaced}\n"
        f"\n"
        f"It works once and expires in {minutes} minutes.\n"
        f"\n"
        f"If you did not ask for this, ignore this email. Nobody can sign in without the code,\n"
        f"and Maro will never ask you to tell it to anyone.\n"
    )
    return EmailMessage(to=issued.email, subject="Your Maro sign-in code", body=body)


async def issue_and_send(
    session_factory: async_sessionmaker[AsyncSession],
    sender: EmailSender,
    settings: Settings,
    email: str,
) -> None:
    """Runs after the response has been sent, with its own database session."""
    try:
        async with session_factory() as db:
            issued = await issue_login_code(db, email, settings=settings)
        if issued is not None:
            await sender.send(build_login_code_message(issued))
    except (
        Exception
    ) as error:  # noqa: BLE001  nobody is waiting to receive this error, and it must not escape
        # Only the type of error is logged: messages from mail servers can contain addresses.
        logger.error("sending a sign-in code failed: %s", type(error).__name__)


@router.post("/request", response_model=Accepted, status_code=status.HTTP_202_ACCEPTED)
async def request_code(
    body: RequestCode,
    request: Request,
    background: BackgroundTasks,
    settings: AppSettings,
) -> Accepted:
    require_trusted_origin(request, settings)
    state = request.app.state
    background.add_task(
        issue_and_send, state.session_factory, state.email_sender, settings, body.email
    )
    return Accepted()


@router.post("/verify", response_model=UserOut)
async def enter_code(
    body: EnterCode,
    request: Request,
    response: Response,
    db: Database,
    settings: AppSettings,
) -> UserOut:
    require_trusted_origin(request, settings)
    user = await verify_login_code(db, body.email, body.code, settings=settings)
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired code")
    issued = await create_session(
        db, user, user_agent=request.headers.get("user-agent")
    )
    set_session_cookie(response, issued.token, settings)
    return UserOut.model_validate(user)
