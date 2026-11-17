"""Tests for the application foundation: health, security headers, CORS and settings."""

from collections.abc import Callable, Iterator

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.main import create_app, get_settings

AppFactory = Callable[..., TestClient]


@pytest.fixture
def make_client(monkeypatch: pytest.MonkeyPatch) -> Iterator[AppFactory]:
    """Build a fresh app under a chosen environment, without leaking settings between tests."""

    def _make(environment: str = "development") -> TestClient:
        monkeypatch.setenv("APP_ENVIRONMENT", environment)
        get_settings.cache_clear()
        return TestClient(create_app())

    yield _make
    get_settings.cache_clear()


def test_health_returns_ok(make_client: AppFactory) -> None:
    response = make_client().get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "environment": "development"}


def test_security_headers_present(make_client: AppFactory) -> None:
    headers = make_client().get("/health").headers
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["x-frame-options"] == "DENY"
    assert headers["referrer-policy"] == "no-referrer"
    assert headers["cache-control"] == "no-store"


def test_security_headers_also_on_errors(make_client: AppFactory) -> None:
    response = make_client().get("/does-not-exist")
    assert response.status_code == 404
    assert "x-request-id" in response.headers
    assert response.headers["x-content-type-options"] == "nosniff"


def test_each_request_gets_a_unique_id(make_client: AppFactory) -> None:
    client = make_client()
    first = client.get("/health").headers["x-request-id"]
    second = client.get("/health").headers["x-request-id"]
    assert first != second


def test_cors_allows_configured_origin(make_client: AppFactory) -> None:
    response = make_client().options(
        "/health",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert response.headers["access-control-allow-origin"] == "http://localhost:3000"


def test_cors_rejects_unknown_origin(make_client: AppFactory) -> None:
    response = make_client().options(
        "/health",
        headers={
            "Origin": "http://evil.example",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert "access-control-allow-origin" not in response.headers


def test_hsts_only_in_production(make_client: AppFactory) -> None:
    assert (
        "strict-transport-security"
        not in make_client("development").get("/health").headers
    )
    assert (
        "strict-transport-security" in make_client("production").get("/health").headers
    )


def test_api_docs_hidden_in_production(make_client: AppFactory) -> None:
    assert make_client("development").get("/docs").status_code == 200
    production = make_client("production")
    assert production.get("/docs").status_code == 404
    assert production.get("/openapi.json").status_code == 404


def test_invalid_environment_fails_at_startup(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APP_ENVIRONMENT", "prodution")  # deliberate typo
    get_settings.cache_clear()
    with pytest.raises(ValidationError):
        create_app()
    get_settings.cache_clear()
