"""Application entry point.

Run locally (from the `backend` folder):
    uvicorn app.main:app --reload
"""

from __future__ import annotations

import logging
import time
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.auth.login import router as login_router
from app.auth.router import router as auth_router
from app.config import get_settings
from app.db import check_connection, create_engine, create_session_factory
from app.email import create_email_sender

logger = logging.getLogger("app")


class RequestContextMiddleware:
    """Adds a request ID and security headers to every response, and logs each request.

    Written as plain ASGI middleware (not BaseHTTPMiddleware) so it adds no
    overhead to streaming responses and cannot interfere with background tasks.
    Only the path is logged, never the query string, in case it holds sensitive data.
    """

    def __init__(self, app: ASGIApp, *, enable_hsts: bool) -> None:
        self.app = app
        self.enable_hsts = enable_hsts

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_id = uuid.uuid4().hex
        scope.setdefault("state", {})["request_id"] = request_id
        started = time.perf_counter()
        status_code = 500

        async def send_with_headers(message: Message) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
                headers = MutableHeaders(scope=message)
                headers["X-Request-ID"] = request_id
                headers["X-Content-Type-Options"] = "nosniff"
                headers["X-Frame-Options"] = "DENY"
                headers["Referrer-Policy"] = "no-referrer"
                headers["Cache-Control"] = "no-store"
                if self.enable_hsts:
                    headers["Strict-Transport-Security"] = (
                        "max-age=63072000; includeSubDomains"
                    )
            await send(message)

        try:
            await self.app(scope, receive, send_with_headers)
        finally:
            logger.info(
                "request method=%s path=%s status=%s duration_ms=%.1f request_id=%s",
                scope["method"],
                scope["path"],
                status_code,
                (time.perf_counter() - started) * 1000,
                request_id,
            )


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Create the database connection pool at startup and close it at shutdown.

    Startup does not wait for the database. If it is down, the app still starts and
    /ready reports unavailable until it recovers, so the service never crash-loops.
    """
    engine = create_engine(get_settings())
    app.state.engine = engine
    app.state.session_factory = create_session_factory(engine)
    app.state.email_sender = create_email_sender(get_settings())
    logger.info("database connection pool created")
    try:
        yield
    finally:
        await engine.dispose()
        logger.info("database connection pool closed")


async def validation_error_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    """Say WHICH field is wrong, never repeat WHAT was sent.

    FastAPI's default reply echoes the offending input back. That repeats whatever a person
    typed (possibly a code or a password) and, for text that cannot be encoded such as a lone
    surrogate character, crashes with a 500 that anyone could trigger.
    """
    problems = [
        {"loc": list(error["loc"]), "type": error["type"], "msg": error["msg"]}
        for error in exc.errors()
    ]
    return JSONResponse(status_code=422, content={"detail": problems})


def create_app() -> FastAPI:
    settings = get_settings()
    logging.basicConfig(
        level=settings.log_level,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    app = FastAPI(
        title="Maro API",
        lifespan=lifespan,
        # API docs are useful while building but are not exposed in production.
        docs_url=None if settings.is_production else "/docs",
        redoc_url=None,
        openapi_url=None if settings.is_production else "/openapi.json",
    )

    app.add_exception_handler(RequestValidationError, validation_error_handler)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["Content-Type", "Authorization"],
    )
    # Added last so it is the outermost layer and covers every response.
    app.add_middleware(RequestContextMiddleware, enable_hsts=settings.is_production)

    @app.get("/health", tags=["system"])
    async def health() -> dict[str, str]:
        return {"status": "ok", "environment": settings.environment}

    @app.get("/ready", tags=["system"])
    async def ready(request: Request, response: Response) -> dict[str, str]:
        """Readiness: can this instance serve real traffic? Unlike /health, it needs the database."""
        if await check_connection(request.app.state.engine):
            return {"status": "ready"}
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {"status": "unavailable"}

    app.include_router(auth_router)
    app.include_router(login_router)

    return app


app = create_app()
