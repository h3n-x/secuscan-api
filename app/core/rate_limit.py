import asyncio
import time
from collections import defaultdict

from app.core.config import get_settings

_WINDOW_SECONDS = 3600

# Contador en memoria del proceso, por user_id: MVP de una sola instancia.
_lock = asyncio.Lock()
_requests: dict[str, list[float]] = defaultdict(list)


class RateLimitExceededError(Exception):
    def __init__(self, retry_after_seconds: int) -> None:
        self.retry_after_seconds = retry_after_seconds
        super().__init__(f"Límite de escaneos por hora excedido. Reintenta en {retry_after_seconds}s.")


async def enforce_rate_limit(user_id: str) -> None:
    limit = get_settings().rate_limit_per_hour
    now = time.monotonic()

    async with _lock:
        timestamps = _requests[user_id]
        cutoff = now - _WINDOW_SECONDS
        while timestamps and timestamps[0] < cutoff:
            timestamps.pop(0)

        if len(timestamps) >= limit:
            retry_after = int(timestamps[0] + _WINDOW_SECONDS - now) + 1
            raise RateLimitExceededError(retry_after)

        timestamps.append(now)
