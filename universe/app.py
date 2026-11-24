"""API FastAPI di Universe. Di default tutto resta in dry-run.

Indurita per esposizione su internet: token per-bot, hash a tempo costante,
rate limit, limite body, CORS spento, /docs disabilitati, /health minimo,
audit HTTP senza segreti, WebSocket /phone dietro TLS.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request, WebSocket
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ValidationError

from universe.audit import AuditLog
from universe.auth import AuthError, TokenStore, UNAUTHORIZED_DETAIL, extract_bearer
from universe.http_limits import HttpRateLimiter, MaxBodySizeMiddleware, ip_from_headers
from universe.models import Command
from universe.phone_hub import PhoneHub, authenticate_phone_ws
from universe.router import build_default_router
from universe.settings import Settings

log = logging.getLogger("universe.http")

HEALTH_BODY = {"ok": True}
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
    phone_hub = PhoneHub()
    audit = AuditLog(settings.audit_path)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if require_tokens and not store.has_bots():
            raise RuntimeError(
                "Avvio rifiutato: nessun token bot configurato. "
                "Imposta UNIVERSE_BOT_TOKENS_FILE o UNIVERSE_BOT_TOKENS."
            )
        if require_tokens and not store.has_phone():
            raise RuntimeError(
                "Avvio rifiutato: manca il token del telefono. "
                "Imposta UNIVERSE_PHONE_TOKEN o il campo 'phone' nel file token."
            )
        if settings.allow_live:
            log.warning("allow_live è acceso: il processo può uscire dal dry-run")
        yield

    docs_url = "/docs" if settings.enable_docs else None
    redoc_url = "/redoc" if settings.enable_docs else None
    openapi_url = "/openapi.json" if settings.enable_docs else None

    app = FastAPI(
        title="Connessione Universale",
        version="0.2.0",
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
        # AuditLog.record è pensato per i comandi; qui appendiamo una riga HTTP.
        from datetime import datetime, timezone
        import json as _json

        line = {
            "ts": datetime.now(timezone.utc).isoformat(),
            **entry,
        }
        audit.path.parent.mkdir(parents=True, exist_ok=True)
        with audit.path.open("a", encoding="utf-8") as fh:
            fh.write(_json.dumps(line, ensure_ascii=False) + "\n")
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
        # Nessun header CORS. Togli eventuale server leakage già gestito da uvicorn.
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/health")
    async def health() -> dict[str, Any]:
        return dict(HEALTH_BODY)

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
    ) -> dict[str, Any]:
        # Autenticazione prima di parsare il body in dettaglio, ma il body
        # è già cappato dal middleware. Se manca il token: 401 identico.
        raw_token = extract_bearer(authorization)
        try:
            if not raw_token:
                check_http_rate(request, None)
            client_id = authenticate(authorization)
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

    @app.websocket("/phone")
    async def phone_ws(ws: WebSocket) -> None:
        if settings.require_tls:
            proto = forwarded_proto(dict(ws.headers))
            if proto and proto != "https":
                await ws.close(code=1008)
                return
        ok = await authenticate_phone_ws(ws, store, settings.phone_hello_timeout_seconds)
        if not ok:
            return
        await phone_hub.attach(ws)

    return app


# Istanza di default per uvicorn universe.app:app
# I token vengono letti da env/file. Senza token l'avvio (lifespan) fallisce.
app = create_app()
