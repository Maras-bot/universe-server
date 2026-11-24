"""Retry con backoff lineare. Solo per errori marcati come ritentabili."""

from __future__ import annotations

import asyncio
from typing import Awaitable, Callable, TypeVar

from universe.errors import ErrorCode, UniverseError
from universe.models import RetryConfig

T = TypeVar("T")


def should_retry(exc: BaseException, retry_on: list[str]) -> bool:
    if isinstance(exc, UniverseError):
        if not exc.retryable:
            return False
        if exc.code == ErrorCode.TIMEOUT and "timeout" in retry_on:
            return True
        if exc.code in retry_on:
            return True
        if str(exc.details.get("http_status")) in retry_on:
            return True
        return exc.retryable and ("timeout" in retry_on or "503" in retry_on)
    return False


async def with_retry(func: Callable[[], Awaitable[T]], config: RetryConfig, sleeper=None) -> T:
    sleeper = sleeper or asyncio.sleep
    attempts = max(1, config.max_attempts)
    last: BaseException | None = None
    for i in range(attempts):
        try:
            return await func()
        except Exception as exc:  # noqa: BLE001
            last = exc
            if i >= attempts - 1 or not should_retry(exc, config.retry_on):
                raise
            await sleeper(config.backoff_seconds * (i + 1))
    assert last is not None
    raise last
