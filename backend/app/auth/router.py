"""Endpoints for the signed-in user: who am I, sign out, sign out everywhere.

Signing IN is added with the sign-in methods themselves (passkeys and login links).
Those will create a session and attach it with `set_session_cookie`.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import (
    CurrentAuth,
    CurrentUser,
    clear_session_cookie,
    cookie_name,
    require_trusted_origin,
)
from app.auth.sessions import revoke_all_for_user, revoke_token
from app.config import Settings, get_settings
from app.db import get_session

router = APIRouter(prefix="/auth", tags=["auth"])

Database = Annotated[AsyncSession, Depends(get_session)]
AppSettings = Annotated[Settings, Depends(get_settings)]


class UserOut(BaseModel):
    """What the browser may know about the signed-in user. Nothing else is ever sent."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: str
    display_name: str | None


class SignedOut(BaseModel):
    signed_out: int


@router.get("/me", response_model=UserOut)
async def me(user: CurrentUser) -> UserOut:
    return UserOut.model_validate(user)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    request: Request, response: Response, db: Database, settings: AppSettings
) -> None:
    """Sign out this browser. Always succeeds and always clears the cookie, even if the
    session was already gone, so a stale cookie can never get stuck."""
    require_trusted_origin(request, settings)
    token = request.cookies.get(cookie_name(settings))
    if token:
        await revoke_token(db, token)
    clear_session_cookie(response, settings)


@router.post("/logout-all", response_model=SignedOut)
async def logout_all(
    auth: CurrentAuth, response: Response, db: Database, settings: AppSettings
) -> SignedOut:
    """Sign out every browser and device, including this one."""
    ended = await revoke_all_for_user(db, auth.user.id)
    clear_session_cookie(response, settings)
    return SignedOut(signed_out=ended)
