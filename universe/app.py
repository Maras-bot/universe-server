"""API FastAPI di Universe + relay Phone Control montato.

Di default i target Universe restano in dry-run (UNIVERSE_ALLOW_LIVE=false).
Il relay Phone Control (/phone, /command con RELAY_TOKEN, /control, /ring)
inoltra al telefono connesso via WebSocket; sul telefono resta sempre attivo
il Guard per app protette, pagamenti ed eSIM.

Indurita per esposizione su internet: token per-bot, hash a tempo costante,
rate limit, limite body, CORS spento, /docs disabilitati, /health minimo,
audit HTTP senza segreti, WebSocket /phone e /control dietro TLS.
"""

from __future__ import annotations

import asyncio
import hmac
import json
import logging
import os
import re
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ValidationError

from universe.audit import AuditLog
from universe.auth import AuthError, TokenStore, UNAUTHORIZED_DETAIL, extract_bearer, hash_token
from universe.http_limits import HttpRateLimiter, MaxBodySizeMiddleware, ip_from_headers
from universe.models import Command
from universe.phone_hub import PhoneHub, authenticate_phone_ws, reject
from universe.relay_routing import Account, Registry, RouteError
from universe.router import build_default_router
from universe.settings import Settings

log = logging.getLogger("universe.http")

HEALTH_BODY = {"ok": True}
SERVER_VERSION = "0.2.0"
_COMMIT_RE = re.compile(r"^[0-9a-f]{7,40}$")


def _short_commit() -> str | None:
    """Commit del deploy (Render imposta RENDER_GIT_COMMIT). Solo hash esadecimale, max 7 caratteri."""
    raw = (os.environ.get("RENDER_GIT_COMMIT") or "").strip().lower()
    return raw[:7] if _COMMIT_RE.match(raw) else None


def health_payload(started_mono: float, started_wall: datetime, now_mono: float | None = None) -> dict[str, Any]:
    """Risposta pubblica di /health: niente segreti, niente target, niente flag."""
    now = time.monotonic() if now_mono is None else now_mono
    body: dict[str, Any] = dict(HEALTH_BODY)
    body["version"] = SERVER_VERSION
    commit = _short_commit()
    if commit:
        body["commit"] = commit
    body["started_at"] = started_wall.astimezone(timezone.utc).isoformat(timespec="seconds")
    body["uptime_s"] = max(0, int(now - started_mono))
    return body


SENSITIVE_HEALTH_KEYS = {
    "allow_live",
    "dry_run",
    "targets",
    "token",
    "tokens",
    "phone_online",
    "client_ids",
    "auth",
}


class ConfirmBody(BaseModel):
    approved: bool
    approver: str = "maras"


def load_token_store(settings: Settings) -> TokenStore:
    return TokenStore.from_settings_and_env(
        tokens_file=settings.bot_tokens_file,
        bot_tokens_json=settings.bot_tokens,
        phone_token=settings.phone_token,
    )


def forwarded_proto(request_headers: dict[str, str]) -> str:
    headers = {k.lower(): v for k, v in request_headers.items()}
    proto = (headers.get("x-forwarded-proto") or "").split(",")[0].strip().lower()
    if proto:
        return proto
    visitor = headers.get("cf-visitor") or ""
    if "https" in visitor.lower():
        return "https"
    return ""


def _enforce_tls_http(settings: Settings, request: Request) -> None:
    if not settings.require_tls:
        return
    proto = forwarded_proto(dict(request.headers))
    if proto and proto != "https":
        raise HTTPException(status_code=400, detail="https required")


def _client_ip(request: Request) -> str:
    host = request.client.host if request.client else None
    return ip_from_headers(dict(request.headers), host)


def create_app(
    settings: Settings | None = None,
    token_store: TokenStore | None = None,
    *,
    require_tokens: bool = True,
    router: Any = None,
) -> FastAPI:
    settings = settings or Settings()
    store = token_store if token_store is not None else load_token_store(settings)
    http_limiter = HttpRateLimiter()
    cmd_timeout = settings.effective_relay_command_timeout()
    phone_hub = PhoneHub(command_timeout=cmd_timeout)
    audit = AuditLog(settings.audit_path)

    relay_token_raw = settings.effective_relay_token()
    relay_token_hash: str | None = hash_token(relay_token_raw) if relay_token_raw else None
    del relay_token_raw

    accounts_file = settings.effective_relay_accounts_file()
    registry: Registry | None = None
    if accounts_file:
        registry = Registry.from_json(Path(accounts_file).read_text(encoding="utf-8"))
    device_hubs: dict[tuple[str, str], PhoneHub] = {}

    def is_relay_token(token: str | None) -> bool:
        if not token or relay_token_hash is None:
            return False
        return hmac.compare_digest(hash_token(token), relay_token_hash)

    async def ring_targets(acc: Account, target: str, from_device: str | None) -> dict[str, Any]:
        assert registry is not None
        devs = registry.resolve_ring(acc, target, from_device)
        registry.check_ring_rate(acc.id)
        cmd = registry.ring_command(acc, from_device)
        results = {}
        for d in devs:
            h = device_hubs.get((acc.id, d))
            if h is None:
                continue
            results[d] = await h.send_to_phone(dict(cmd, id=uuid.uuid4().hex))
        return {"ok": True, "rang": list(results.keys())}

    async def heartbeat_watch() -> None:
        while True:
            await asyncio.sleep(60)
            if registry is None:
                continue
            for a, d, others in registry.stale_alerts():
                acc = registry.accounts.get(a)
                for o in others:
                    h = device_hubs.get((a, o))
                    if acc is not None and h is not None:
                        asyncio.create_task(
                            h.send_to_phone(dict(registry.a11y_off_command(acc, d), id=uuid.uuid4().hex))
                        )

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        has_relay = (relay_token_hash is not None) or (registry is not None)
        if require_tokens and not has_relay:
            if not store.has_bots():
                raise RuntimeError(
                    "Avvio rifiutato: nessun token bot configurato. "
                    "Imposta UNIVERSE_BOT_TOKENS_FILE, UNIVERSE_BOT_TOKENS o RELAY_TOKEN."
                )
            if not store.has_phone():
                raise RuntimeError(
                    "Avvio rifiutato: manca il token del telefono. "
                    "Imposta UNIVERSE_PHONE_TOKEN, RELAY_TOKEN o il campo 'phone' nel file token."
                )
        if settings.allow_live:
            log.warning("allow_live è acceso: il processo può uscire dal dry-run")
        hb_task: asyncio.Task[None] | None = None
        if registry is not None:
            hb_task = asyncio.create_task(heartbeat_watch())
        try:
            yield
        finally:
            if hb_task is not None:
                hb_task.cancel()
                try:
                    await hb_task
                except asyncio.CancelledError:
                    pass

    docs_url = "/docs" if settings.enable_docs else None
    redoc_url = "/redoc" if settings.enable_docs else None
    openapi_url = "/openapi.json" if settings.enable_docs else None

    app = FastAPI(
        title="Connessione Universale",
        version=SERVER_VERSION,
        docs_url=docs_url,
        redoc_url=redoc_url,
        openapi_url=openapi_url,
        lifespan=lifespan,
    )
    # CORS: nessun middleware CORS. I browser non ricevono Access-Control-Allow-Origin.
    app.add_middleware(MaxBodySizeMiddleware, max_bytes=settings.max_request_bytes)

    app.state.settings = settings
    app.state.token_store = store
    app.state.phone_hub = phone_hub
    app.state.http_limiter = http_limiter
    app.state.audit = audit
    app.state.command_router = router
    app.state.relay_registry = registry
    app.state.device_hubs = device_hubs

    def get_router():
        if app.state.command_router is None:
            app.state.command_router = build_default_router(settings.configs_dir, settings)
            # Allinea l'audit HTTP e quello dei comandi sullo stesso file.
            app.state.command_router.audit = audit
        return app.state.command_router

    def record_http(
        *,
        method: str,
        path: str,
        status: int,
        client_id: str | None = None,
        reason: str | None = None,
        ip: str | None = None,
    ) -> None:
        entry = {
            "type": "http",
            "method": method,
            "path": path,
            "status": status,
            "client_id": client_id,
            "reason": reason,
            "ip": ip,
        }
        line = {
            "ts": datetime.now(timezone.utc).isoformat(),
            **entry,
        }
        audit.path.parent.mkdir(parents=True, exist_ok=True)
        with audit.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(line, ensure_ascii=False) + "\n")
        audit._memory.append(line)

    def authenticate(authorization: str | None) -> str:
        try:
            return store.authenticate_bot(extract_bearer(authorization))
        except AuthError as exc:
            raise HTTPException(status_code=401, detail=UNAUTHORIZED_DETAIL) from exc

    def check_http_rate(request: Request, client_id: str | None) -> None:
        ip = _client_ip(request)
        if client_id is None:
            key = f"unauth:{ip}"
            limit = settings.http_rate_limit_unauth_per_minute
        else:
            key = f"bot:{client_id}"
            limit = settings.http_rate_limit_per_minute
        if not http_limiter.allow(key, limit):
            raise HTTPException(status_code=429, detail="rate limit", headers={"Retry-After": "60"})

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        # /health è l'unico percorso senza auth e senza rate limit stretto.
        path = request.url.path
        if path != "/health" and settings.require_tls:
            try:
                _enforce_tls_http(settings, request)
            except HTTPException as exc:
                return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        return response

    started_mono = time.monotonic()
    started_wall = datetime.now(timezone.utc)

    @app.get("/health")
    async def health() -> dict[str, Any]:
        return health_payload(started_mono, started_wall)

    @app.get("/capabilities")
    async def capabilities(
        request: Request, authorization: str | None = Header(default=None)
    ) -> dict[str, Any]:
        try:
            if not extract_bearer(authorization):
                check_http_rate(request, None)
            client_id = authenticate(authorization)
            check_http_rate(request, client_id)
        except HTTPException as exc:
            record_http(
                method="GET",
                path="/capabilities",
                status=exc.status_code,
                reason="unauthorized" if exc.status_code == 401 else "rate_limit",
                ip=_client_ip(request),
            )
            raise
        record_http(method="GET", path="/capabilities", status=200, client_id=client_id, ip=_client_ip(request))
        return {"ok": True, "capabilities": get_router().registry.capabilities_public()}

    @app.post("/command")
    async def command(
        request: Request, authorization: str | None = Header(default=None)
    ) -> Any:
        raw_token = extract_bearer(authorization)

        # 1) Modalità relay multi-account (se configurato RELAY_ACCOUNTS_FILE).
        if registry is not None and raw_token:
            acc: Account | None = None
            try:
                acc = registry.account_for_token(raw_token)
            except RouteError:
                acc = None
            if acc is not None:
                try:
                    check_http_rate(request, f"acct:{acc.id}")
                except HTTPException as exc:
                    record_http(
                        method="POST",
                        path="/command",
                        status=exc.status_code,
                        client_id=f"acct:{acc.id}",
                        reason="rate_limit",
                        ip=_client_ip(request),
                    )
                    raise
                try:
                    payload = await request.json()
                except Exception:
                    record_http(method="POST", path="/command", status=400, client_id=f"acct:{acc.id}", reason="bad_json", ip=_client_ip(request))
                    raise HTTPException(status_code=400, detail="invalid json")
                if not isinstance(payload, dict):
                    raise HTTPException(status_code=422, detail="command must be an object")
                try:
                    dev, out = registry.route_command(acc, payload)
                except RouteError as exc:
                    record_http(method="POST", path="/command", status=exc.code, client_id=f"acct:{acc.id}", reason="route_error", ip=_client_ip(request))
                    return JSONResponse(status_code=exc.code, content={"ok": False, "error": exc.msg})
                hub = device_hubs.get((acc.id, dev))
                if hub is None or not hub.phone_online():
                    record_http(method="POST", path="/command", status=503, client_id=f"acct:{acc.id}", reason="phone_offline", ip=_client_ip(request))
                    return JSONResponse(status_code=503, content={"ok": False, "error": "dispositivo non connesso"})
                try:
                    reply = await hub.send_to_phone(out)
                except Exception:
                    record_http(method="POST", path="/command", status=503, client_id=f"acct:{acc.id}", reason="phone_disconnected", ip=_client_ip(request))
                    return JSONResponse(status_code=503, content={"ok": False, "error": "telefono non connesso"})
                record_http(method="POST", path="/command", status=200, client_id=f"acct:{acc.id}", reason="relay_ok", ip=_client_ip(request))
                return reply

        # 2) Modalità relay singolo (RELAY_TOKEN): inoltro diretto al telefono su /phone.
        if is_relay_token(raw_token):
            try:
                check_http_rate(request, "relay")
            except HTTPException as exc:
                record_http(method="POST", path="/command", status=exc.status_code, client_id="relay", reason="rate_limit", ip=_client_ip(request))
                raise
            try:
                payload = await request.json()
            except Exception:
                record_http(method="POST", path="/command", status=400, client_id="relay", reason="bad_json", ip=_client_ip(request))
                raise HTTPException(status_code=400, detail="invalid json")
            if not isinstance(payload, dict):
                raise HTTPException(status_code=422, detail="command must be an object")
            if not phone_hub.phone_online():
                record_http(method="POST", path="/command", status=503, client_id="relay", reason="phone_offline", ip=_client_ip(request))
                return JSONResponse(status_code=503, content={"ok": False, "error": "telefono non connesso"})
            try:
                reply = await phone_hub.send_to_phone(payload)
            except Exception:
                record_http(method="POST", path="/command", status=503, client_id="relay", reason="phone_disconnected", ip=_client_ip(request))
                return JSONResponse(status_code=503, content={"ok": False, "error": "telefono non connesso"})
            record_http(
                method="POST",
                path="/command",
                status=200,
                client_id="relay",
                reason="relay_ok" if isinstance(reply, dict) and reply.get("ok") else "relay_reply",
                ip=_client_ip(request),
            )
            return reply

        # 3) Modalità Universe bot (UNIVERSE_BOT_TOKENS): envelope Command + Router (dry-run di default).
        try:
            if not raw_token:
                check_http_rate(request, None)
            try:
                client_id = authenticate(authorization)
            except HTTPException:
                if raw_token:
                    check_http_rate(request, None)
                raise
            check_http_rate(request, client_id)
        except HTTPException as exc:
            record_http(
                method="POST",
                path="/command",
                status=exc.status_code,
                reason="unauthorized" if exc.status_code == 401 else "rate_limit",
                ip=_client_ip(request),
            )
            raise

        try:
            payload = await request.json()
        except Exception:
            record_http(method="POST", path="/command", status=400, client_id=client_id, reason="bad_json", ip=_client_ip(request))
            raise HTTPException(status_code=400, detail="invalid json")
        if not isinstance(payload, dict):
            raise HTTPException(status_code=422, detail="command must be an object")
        try:
            cmd = Command.model_validate(payload)
        except ValidationError as exc:
            record_http(method="POST", path="/command", status=422, client_id=client_id, reason="validation", ip=_client_ip(request))
            raise HTTPException(status_code=422, detail="invalid command") from exc

        result = await get_router().dispatch(cmd)
        record_http(
            method="POST",
            path="/command",
            status=200,
            client_id=client_id,
            reason=result.status.value if result.status else None,
            ip=_client_ip(request),
        )
        data = result.model_dump(mode="json")
        data["auth_client"] = client_id
        return data

    @app.post("/ring")
    async def ring(
        request: Request, authorization: str | None = Header(default=None)
    ) -> Any:
        """Trova telefono: richiede token valido. Multi-account se RELAY_ACCOUNTS_FILE è attivo."""
        raw_token = extract_bearer(authorization)
        if registry is not None:
            try:
                acc = registry.account_for_token(raw_token)
            except RouteError:
                check_http_rate(request, None)
                record_http(method="POST", path="/ring", status=401, reason="unauthorized", ip=_client_ip(request))
                raise HTTPException(status_code=401, detail=UNAUTHORIZED_DETAIL)
            check_http_rate(request, f"acct:{acc.id}")
            try:
                body = await request.json()
            except Exception:
                raise HTTPException(status_code=400, detail="invalid json")
            if not isinstance(body, dict):
                raise HTTPException(status_code=422, detail="body must be an object")
            try:
                res = await ring_targets(acc, str(body.get("target", "")), None)
                record_http(method="POST", path="/ring", status=200, client_id=f"acct:{acc.id}", ip=_client_ip(request))
                return res
            except RouteError as exc:
                record_http(method="POST", path="/ring", status=exc.code, client_id=f"acct:{acc.id}", ip=_client_ip(request))
                return JSONResponse(status_code=exc.code, content={"ok": False, "error": exc.msg})

        if not is_relay_token(raw_token):
            check_http_rate(request, None)
            record_http(method="POST", path="/ring", status=401, reason="unauthorized", ip=_client_ip(request))
            raise HTTPException(status_code=401, detail=UNAUTHORIZED_DETAIL)
        check_http_rate(request, "relay")
        return JSONResponse(status_code=404, content={"ok": False, "error": "multi-account non configurato"})

    @app.post("/confirm/{confirmation_id}")
    async def confirm(
        confirmation_id: str,
        body: ConfirmBody,
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        try:
            if not extract_bearer(authorization):
                check_http_rate(request, None)
            client_id = authenticate(authorization)
            check_http_rate(request, client_id)
        except HTTPException as exc:
            record_http(
                method="POST",
                path="/confirm",
                status=exc.status_code,
                reason="unauthorized" if exc.status_code == 401 else "rate_limit",
                ip=_client_ip(request),
            )
            raise
        store_conf = get_router().confirmations
        try:
            item = store_conf.decide(confirmation_id, body.approved, approver=body.approver)
        except KeyError:
            raise HTTPException(status_code=404, detail="conferma sconosciuta")
        record_http(method="POST", path="/confirm", status=200, client_id=client_id, ip=_client_ip(request))
        return {
            "ok": True,
            "confirmation_id": item.id,
            "decision": item.decision,
            "command_id": item.command_id,
            "note": "Se approvato, rinvia lo stesso comando con la stessa idempotency_key.",
        }

    async def _multi_phone(ws: WebSocket, msg: dict[str, Any]) -> None:
        assert registry is not None
        if msg.get("type") != "hello":
            await reject(ws, "hello_missing")
            return
        try:
            acc, dev = registry.register_phone(
                msg.get("token"),
                msg.get("device_id"),
                ws,
                msg.get("account"),
            )
        except RouteError:
            await reject(ws, "bad_multi_hello")
            return
        h = PhoneHub(command_timeout=cmd_timeout)
        h.phone = ws
        device_hubs[(acc.id, dev.device_id)] = h
        try:
            while True:
                raw = await ws.receive_text()
                try:
                    m = json.loads(raw)
                except Exception:
                    continue
                if not isinstance(m, dict):
                    continue
                mtype = m.get("type")
                if mtype in {"ping", "keepalive"}:
                    try:
                        await ws.send_text(json.dumps({"type": "pong"}))
                    except Exception:
                        pass
                    continue
                if mtype == "ring":
                    try:
                        res = await ring_targets(acc, str(m.get("target", "")), dev.device_id)
                    except RouteError as exc:
                        res = {"ok": False, "error": exc.msg}
                    await ws.send_text(json.dumps({"type": "ring_result", "id": m.get("id"), **res}))
                    continue
                if mtype == "alive":
                    registry.heartbeat(acc.id, dev.device_id, bool(m.get("alert_others", False)))
                    continue
                if mtype == "alive_stop":
                    registry.heartbeat_stop(acc.id, dev.device_id)
                    continue
                if mtype == "night_alarm":
                    cmd = registry.alert_command(acc, dev.device_id, m)
                    for d in registry.alert_targets(acc, dev.device_id):
                        other = device_hubs.get((acc.id, d))
                        if other is not None:
                            asyncio.create_task(other.send_to_phone(dict(cmd, id=uuid.uuid4().hex)))
                    continue
                h.resolve(m)
        except WebSocketDisconnect:
            pass
        finally:
            registry.unregister(acc.id, dev.device_id, ws)
            if device_hubs.get((acc.id, dev.device_id)) is h:
                device_hubs.pop((acc.id, dev.device_id), None)

    @app.websocket("/phone")
    async def phone_ws(ws: WebSocket) -> None:
        if settings.require_tls:
            proto = forwarded_proto(dict(ws.headers))
            if proto and proto != "https":
                await ws.close(code=1008)
                return
        if "token" in ws.query_params:
            await reject(ws, "token_in_query")
            return
        if registry is not None:
            await ws.accept()
            try:
                first = await asyncio.wait_for(ws.receive_text(), timeout=settings.phone_hello_timeout_seconds)
                msg = json.loads(first)
            except Exception:
                await reject(ws, "multi_hello_error")
                return
            if not isinstance(msg, dict):
                await reject(ws, "multi_hello_not_dict")
                return
            await _multi_phone(ws, msg)
            return
        ok = await authenticate_phone_ws(
            ws,
            store,
            settings.phone_hello_timeout_seconds,
            relay_token_hash=relay_token_hash,
        )
        if not ok:
            return
        await phone_hub.attach(ws)

    @app.websocket("/control")
    async def control_ws(ws: WebSocket) -> None:
        if settings.require_tls:
            proto = forwarded_proto(dict(ws.headers))
            if proto and proto != "https":
                await ws.close(code=1008)
                return
        if "token" in ws.query_params:
            await reject(ws, "token_in_query")
            return
        await ws.accept()
        try:
            first = await asyncio.wait_for(ws.receive_text(), timeout=settings.phone_hello_timeout_seconds)
            msg = json.loads(first)
        except Exception:
            await reject(ws, "control_hello_error")
            return
        if not isinstance(msg, dict) or not is_relay_token(msg.get("token") if isinstance(msg.get("token"), str) else None):
            await reject(ws, "control_bad_token")
            return
        await ws.send_text(json.dumps({"ok": True, "phone_online": phone_hub.phone_online()}))
        try:
            while True:
                raw = await ws.receive_text()
                try:
                    cmd = json.loads(raw)
                except Exception:
                    await ws.send_text(json.dumps({"ok": False, "error": "JSON non valido"}))
                    continue
                if not isinstance(cmd, dict):
                    await ws.send_text(json.dumps({"ok": False, "error": "JSON non valido"}))
                    continue
                if not phone_hub.phone_online():
                    await ws.send_text(json.dumps({"ok": False, "error": "telefono non connesso"}))
                    continue
                try:
                    reply = await phone_hub.send_to_phone(cmd)
                except Exception:
                    reply = {"ok": False, "error": "telefono non connesso"}
                await ws.send_text(json.dumps(reply))
        except WebSocketDisconnect:
            pass

    return app


# Istanza di default per uvicorn universe.app:app
# I token vengono letti da env/file. Senza token l'avvio (lifespan) fallisce.
app = create_app()
