"""Hub WebSocket per il telefono (ex relay Phone Control), indurito.

Il telefono si collega a /phone. Autenticazione: header Authorization Bearer
oppure primo messaggio {"type":"hello","token":"..."}.
Il token non va nella query string: se c'è, la connessione viene chiusa.
I token non vengono loggati.

Su Render Free l'istanza va in sleep dopo 15 minuti senza richieste HTTP
né messaggi WebSocket in ingresso. Un ping inviato dal server non basta.
Il telefono deve inviare almeno ogni 5 minuti un messaggio applicativo
{"type":"ping"} (senza token). Il server risponde {"type":"pong"}.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from typing import Any, Optional

from fastapi import WebSocket, WebSocketDisconnect
from starlette.websockets import WebSocketState

from universe.auth import TokenStore, extract_bearer

log = logging.getLogger("universe.phone")

CLOSE_POLICY = 1008


class PhoneHub:
    """Tiene al più una connessione telefono e le richieste in attesa."""

    def __init__(self, command_timeout: float = 30.0) -> None:
        self.phone: Optional[WebSocket] = None
        self.pending: dict[str, asyncio.Future] = {}
        self.command_timeout = command_timeout
        self.lock = asyncio.Lock()

    def phone_online(self) -> bool:
        return self.phone is not None

    async def attach(self, ws: WebSocket) -> None:
        async with self.lock:
            old = self.phone
            self.phone = ws
        if old is not None and old is not ws:
            try:
                if old.client_state == WebSocketState.CONNECTED:
                    await old.close(code=1012)
            except Exception:
                pass
        log.info("phone_ws event=attached")
        try:
            while True:
                raw = await ws.receive_text()
                try:
                    reply = json.loads(raw)
                except Exception:
                    continue
                if not isinstance(reply, dict):
                    continue
                if reply.get("type") in {"ping", "keepalive"}:
                    try:
                        await ws.send_text(json.dumps({"type": "pong"}))
                    except Exception:
                        pass
                    continue
                self.resolve(reply)
        except WebSocketDisconnect:
            pass
        finally:
            async with self.lock:
                if self.phone is ws:
                    self.phone = None
            log.info("phone_ws event=detached")

    async def send_to_phone(self, cmd: dict[str, Any]) -> dict[str, Any]:
        if self.phone is None:
            raise RuntimeError("Telefono non connesso")
        cmd_id = cmd.get("id") or uuid.uuid4().hex
        cmd["id"] = cmd_id
        loop = asyncio.get_running_loop()
        fut: asyncio.Future = loop.create_future()
        self.pending[cmd_id] = fut
        await self.phone.send_text(json.dumps(cmd))
        try:
            return await asyncio.wait_for(fut, timeout=self.command_timeout)
        except asyncio.TimeoutError:
            return {"id": cmd_id, "ok": False, "error": "timeout risposta telefono"}
        finally:
            self.pending.pop(cmd_id, None)

    def resolve(self, reply: dict[str, Any]) -> None:
        cmd_id = reply.get("id")
        fut = self.pending.get(cmd_id) if cmd_id else None
        if fut and not fut.done():
            fut.set_result(reply)


async def reject(ws: WebSocket, reason: str) -> None:
    # reason è un codice interno, non un token. Non includerlo se lungo.
    log.info("phone_ws event=rejected reason=%s", reason)
    try:
        if ws.client_state == WebSocketState.CONNECTED:
            await ws.close(code=CLOSE_POLICY)
        elif ws.application_state == WebSocketState.CONNECTING:
            await ws.close(code=CLOSE_POLICY)
    except Exception:
        pass


async def authenticate_phone_ws(ws: WebSocket, store: TokenStore, hello_timeout: float) -> bool:
    """True se autenticato e la socket è già accept. Altrimenti chiude e torna False."""
    if "token" in ws.query_params:
        await reject(ws, "token_in_query")
        return False

    header_token = extract_bearer(ws.headers.get("authorization"))
    if header_token is not None:
        if not store.verify_phone(header_token):
            await reject(ws, "bad_header")
            return False
        await ws.accept()
        return True

    await ws.accept()
    try:
        first = await asyncio.wait_for(ws.receive_text(), timeout=hello_timeout)
    except asyncio.TimeoutError:
        await reject(ws, "hello_timeout")
        return False
    except WebSocketDisconnect:
        return False
    except Exception:
        await reject(ws, "hello_error")
        return False

    try:
        msg = json.loads(first)
    except Exception:
        await reject(ws, "hello_not_json")
        return False
    if not isinstance(msg, dict) or msg.get("type") != "hello":
        await reject(ws, "hello_missing")
        return False
    token = msg.get("token")
    if not isinstance(token, str) or not store.verify_phone(token):
        await reject(ws, "bad_hello")
        return False
    return True
