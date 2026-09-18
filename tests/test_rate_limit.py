import asyncio

import pytest

import app.core.rate_limit as rate_limit
from app.core.config import get_settings
from app.core.rate_limit import RateLimitExceededError, enforce_rate_limit


@pytest.fixture(autouse=True)
def _reset_rate_limit_state():
    rate_limit._requests.clear()
    yield
    rate_limit._requests.clear()


def _set_limit(monkeypatch: pytest.MonkeyPatch, value: int) -> None:
    monkeypatch.setenv("RATE_LIMIT_PER_HOUR", str(value))
    get_settings.cache_clear()


def test_enforce_rate_limit_allows_requests_under_the_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_limit(monkeypatch, 3)
    try:
        for _ in range(3):
            asyncio.run(enforce_rate_limit("user-a"))
    finally:
        get_settings.cache_clear()


def test_enforce_rate_limit_blocks_once_limit_is_reached(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_limit(monkeypatch, 2)
    try:
        asyncio.run(enforce_rate_limit("user-b"))
        asyncio.run(enforce_rate_limit("user-b"))

        with pytest.raises(RateLimitExceededError) as exc_info:
            asyncio.run(enforce_rate_limit("user-b"))
    finally:
        get_settings.cache_clear()

    assert exc_info.value.retry_after_seconds > 0


def test_enforce_rate_limit_tracks_users_independently(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_limit(monkeypatch, 1)
    try:
        asyncio.run(enforce_rate_limit("user-c"))

        with pytest.raises(RateLimitExceededError):
            asyncio.run(enforce_rate_limit("user-c"))

        # otro usuario no debe verse afectado por el consumo de user-c
        asyncio.run(enforce_rate_limit("user-d"))
    finally:
        get_settings.cache_clear()


def test_enforce_rate_limit_prunes_requests_outside_the_window(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_limit(monkeypatch, 1)
    try:
        asyncio.run(enforce_rate_limit("user-e"))
        # Simula que la única request registrada ya salió de la ventana de 1 hora.
        rate_limit._requests["user-e"][0] -= rate_limit._WINDOW_SECONDS + 1

        asyncio.run(enforce_rate_limit("user-e"))  # no debería lanzar
    finally:
        get_settings.cache_clear()
