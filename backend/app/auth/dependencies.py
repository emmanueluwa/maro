"""HTTP plumbing for authentication: the session cookie, and the checks that guard routes.

Two protections work together against cross-site request forgery (CSRF), where another
website tricks a signed-in browser into sending a request:
  1. The cookie is SameSite=Lax, so browsers withhold it from cross-site POSTs.
  2. Every request that changes anything (anything but GET/HEAD/OPTIONS) must carry an
     Origin header naming one of our own sites. This is enforced inside `get_current_auth`,
     so a route that requires a signed-in user cannot forget it.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, HTTPException, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.sessions import (
    SESSION_LIFETIME,
    Authenticated,
    get_valid_session,
    touch_session,
)
from app.config import Settings, get_settings
from app.db import get_session
from app.models import User

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
COOKIE_NAME = "maro_session"
# The __Host- prefix makes browsers refuse the cookie unless it is Secure, set for the
# whole site, and not shared with subdomains. It only works over HTTPS, so production only.
PRODUCTION_COOKIE_NAME = "__Host-maro_session"


def cookie_name(settings: Settings) -> str:
    return PRODUCTION_COOKIE_NAME if settings.is_production else COOKIE_NAME


def set_session_cookie(response: Response, token: str, settings: Settings) -> None:
    response.set_cookie(
        key=cookie_name(settings),
        value=token,
        max_age=int(SESSION_LIFETIME.total_seconds()),
        path="/",
        httponly=True,  # invisible to JavaScript, so injected scripts cannot steal it
        secure=settings.is_production,  # HTTPS only (browsers allow plain http on localhost for development)
        samesite="lax",
    )


def clear_session_cookie(response: Response, settings: Settings) -> None:
    response.delete_cookie(
        key=cookie_name(settings),
        path="/",
        httponly=True,
        secure=settings.is_production,
        samesite="lax",
    )


def require_trusted_origin(request: Request, settings: Settings) -> None:
    """Reject state-changing requests that do not come from one of our own sites."""
    if request.method in SAFE_METHODS:
        return
    origin = request.headers.get("origin")
    if origin is None or origin not in settings.allowed_origins:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Origin not allowed")


def _not_authenticated(settings: Settings) -> HTTPException:
    """One identical answer for every kind of failure, so nothing is revealed about why.

    It also tells the browser to throw away the stale cookie.
    """
    expired_cookie = Response()
    clear_session_cookie(expired_cookie, settings)
    return HTTPException(
        status.HTTP_401_UNAUTHORIZED,
        "Not authenticated",
        headers={"set-cookie": expired_cookie.headers["set-cookie"]},
    )


async def get_current_auth(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> Authenticated:
    """The signed-in user and their session, or a 401."""
    require_trusted_origin(request, settings)
    token = request.cookies.get(cookie_name(settings))
    auth = await get_valid_session(db, token) if token else None
    if auth is None:
        raise _not_authenticated(settings)
    await touch_session(db, auth.session)
    return auth


async def get_current_user(
    auth: Annotated[Authenticated, Depends(get_current_auth)],
) -> User:
    return auth.user


CurrentAuth = Annotated[Authenticated, Depends(get_current_auth)]
CurrentUser = Annotated[User, Depends(get_current_user)]
