"""Rate limit in memoria, per target."""

from __future__ import annotations

import time
from collections import defaultdict, deque

from universe.errors import ErrorCode, UniverseError


class RateLimiter:
    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def check(self, key: str, requests_per_minute: int, now: float | None = None) -> None:
        now = time.time() if now is None else now
        window = 60.0
        q = self._hits[key]
        while q and now - q[0] > window:
            q.popleft()
        if len(q) >= requests_per_minute:
            raise UniverseError(
                ErrorCode.RATE_LIMITED,
                f"Rate limit raggiunto per {key} ({requests_per_minute}/min)",
                retryable=True,
            )
        q.append(now)
