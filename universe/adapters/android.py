"""Adapter verso Phone Control: POST /command sul relay FastAPI esistente.

Non sostituisce il Guard sul telefono. Lo precede: Universe può chiedere
conferma prima di mandare il comando. Per le app protette il telefono
chiede di nuovo Conferma/Rifiuta.

In dry-run non apre connessioni e non chiama il relay.
"""

from __future__ import annotations

from typing import Any

import httpx

from universe.adapters.base import Adapter, ExecContext
from universe.errors import ErrorCode, UniverseError
from universe.models import Command, Result, TargetConfig
from universe.secrets import resolve_env


class AndroidAdapter(Adapter):
    kind = "android"

    def __init__(self, config: TargetConfig, client: httpx.AsyncClient | None = None) -> None:
        super().__init__(config)
        self._client = client

    def _raw_base_url(self) -> str:
        return str((self.config.endpoint or {}).get("base_url") or "http://127.0.0.1:8080")

    def _base_url(self) -> str:
        from universe.secrets import maybe_resolve

        return str(maybe_resolve(self._raw_base_url())).rstrip("/")

    def _command_path(self) -> str:
        return (self.config.endpoint or {}).get("command_path") or "/command"

    def _health_path(self) -> str:
        return (self.config.endpoint or {}).get("health_path") or "/health"

    def planned_payload(self, command: Command) -> dict[str, Any]:
        body = {"id": command.id, "action": command.action}
        body.update(command.params)
        return {
            "method": "POST",
            "url": f"{self._raw_base_url().rstrip('/')}{self._command_path()}",
            "headers": {"Authorization": "Bearer [REDATTO]", "Content-Type": "application/json"},
            "body_keys": sorted(body.keys()),
            "action": command.action,
        }

    async def execute(self, command: Command, ctx: ExecContext) -> Result:
        planned = self.planned_payload(command)
        if ctx.dry_run:
            return Result.success(
                command,
                ctx.risk,
                result={"message": "Dry-run: nessuna chiamata al relay Phone Control."},
                dry_run=True,
                planned=planned,
            )

        token = resolve_env(self.config.auth.token_env or "RELAY_TOKEN")
        body = {"id": command.id, "action": command.action}
        body.update(command.params)
        timeout = command.timeout_seconds or self.config.timeout_seconds
        url = f"{self._base_url()}{self._command_path()}"
        client = self._client or httpx.AsyncClient(timeout=timeout)
        owns = self._client is None
        try:
            resp = await client.post(
                url,
                json=body,
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            )
        except httpx.TimeoutException as exc:
            raise UniverseError(ErrorCode.TIMEOUT, "Timeout verso il relay Phone Control", retryable=True) from exc
        except httpx.HTTPError as exc:
            raise UniverseError(ErrorCode.TARGET_OFFLINE, "Relay Phone Control non raggiungibile", retryable=True) from exc
        finally:
            if owns:
                await client.aclose()

        if resp.status_code == 401:
            raise UniverseError(ErrorCode.AUTH, "Token relay non accettato")
        if resp.status_code == 503:
            raise UniverseError(
                ErrorCode.TARGET_OFFLINE,
                "Telefono non connesso al relay",
                retryable=True,
                details={"http_status": "503"},
            )
        if resp.status_code >= 500:
            raise UniverseError(
                ErrorCode.ADAPTER,
                f"Relay ha risposto {resp.status_code}",
                retryable=True,
                details={"http_status": str(resp.status_code)},
            )
        if resp.status_code >= 400:
            raise UniverseError(ErrorCode.ADAPTER, f"Relay ha rifiutato il comando ({resp.status_code})")

        try:
            data = resp.json()
        except ValueError as exc:
            raise UniverseError(ErrorCode.ADAPTER, "Risposta relay non JSON") from exc

        ok = bool(data.get("ok", False))
        if not ok:
            # Non inoltrare eventuali campi sensibili: solo 'error' testuale atteso.
            err = str(data.get("error") or "Comando rifiutato dal telefono")
            return Result.fail(command, ctx.risk, err, ErrorCode.ADAPTER, retryable=False)
        return Result.success(command, ctx.risk, result=data.get("result", data), dry_run=False)

    async def health(self) -> dict[str, Any]:
        if self._client is None:
            return {
                "target": self.config.id,
                "kind": self.kind,
                "ok": True,
                "checked": False,
                "note": "Nessuna chiamata in dry-run / senza client.",
            }
        try:
            resp = await self._client.get(f"{self._base_url()}{self._health_path()}")
            data = resp.json()
            return {
                "target": self.config.id,
                "kind": self.kind,
                "ok": bool(data.get("ok")),
                "phone_online": data.get("phone_online"),
            }
        except httpx.HTTPError:
            return {"target": self.config.id, "kind": self.kind, "ok": False, "phone_online": False}
