"""Application entry point.

Run locally (from the `backend` folder):
    uvicorn app.main:app --reload
"""

from __future__ import annotations

import logging
import time
import uuid
from functools import lru_cache
from typing import Literal

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic_settings import BaseSettings, SettingsConfigDict
from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

logger = logging.getLogger("app")


class Settings(BaseSettings):
    """Configuration, read from environment variables prefixed with APP_."""

    model_config = SettingsConfigDict(env_prefix="APP_", env_file=".env", extra="ignore")

    environment: Literal["development", "staging", "production"] = "development"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    allowed_origins: list[str] = ["http://localhost:3000"]

    @property
    def is_production(self) -> bool:
        return self.environment == "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()


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
                    headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
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


def create_app() -> FastAPI:
    settings = get_settings()
    logging.basicConfig(
        level=settings.log_level,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    app = FastAPI(
        title="Research Companion API",
        # API docs are useful while building but are not exposed in production.
        docs_url=None if settings.is_production else "/docs",
        redoc_url=None,
        openapi_url=None if settings.is_production else "/openapi.json",
    )

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

    return app


app = create_app()
