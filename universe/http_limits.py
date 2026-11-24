"""Limite dimensione richiesta e rate limit HTTP, senza dati sensibili."""

from __future__ import annotations

import json
import time
from collections import defaultdict, deque

from starlette.types import ASGIApp, Receive, Scope, Send


class HttpRateLimiter:
    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str, limit: int, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        q = self._hits[key]
        while q and now - q[0] > 60.0:
            q.popleft()
        if len(q) >= limit:
            return False
        q.append(now)
        return True


class MaxBodySizeMiddleware:
    """Rifiuta body oltre max_bytes con 413. Legge al massimo max_bytes+1."""

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = {k.lower(): v for k, v in scope.get("headers") or []}
        raw_len = headers.get(b"content-length")
        if raw_len:
            try:
                length = int(raw_len.decode("latin-1"))
            except ValueError:
                await _send_json(send, 400, {"detail": "invalid content-length"})
                return
            if length > self.max_bytes:
                await _send_json(send, 413, {"detail": "payload too large"})
                return

        body = bytearray()
        while True:
            message = await receive()
            if message.get("type") == "http.disconnect":
                return
            if message.get("type") != "http.request":
                continue
            chunk = message.get("body") or b""
            body.extend(chunk)
            if len(body) > self.max_bytes:
                await _send_json(send, 413, {"detail": "payload too large"})
                return
            if not message.get("more_body"):
                break

        payload = bytes(body)
        seen = False

        async def replay() -> dict:
            nonlocal seen
            if seen:
                return {"type": "http.request", "body": b"", "more_body": False}
            seen = True
            return {"type": "http.request", "body": payload, "more_body": False}

        await self.app(scope, replay, send)


async def _send_json(send: Send, status: int, payload: dict) -> None:
    data = json.dumps(payload).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(data)).encode("latin-1")),
            ],
        }
    )
    await send({"type": "http.response.body", "body": data})


def ip_from_headers(header_map: dict[str, str], client_host: str | None = None) -> str:
    """IP per il rate limit. Preferisce CF-Connecting-IP."""
    headers = {str(k).lower(): str(v) for k, v in header_map.items()}
    for name in ("cf-connecting-ip", "x-real-ip"):
        val = headers.get(name)
        if val:
            return val.split(",")[0].strip()
    forwarded = headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return client_host or "unknown"
