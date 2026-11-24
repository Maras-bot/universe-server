"""Adapter REST generico. L'azione corrisponde a una voce in config.actions.

In dry-run non viene fatta nessuna richiesta HTTP.
I segreti arrivano solo da variabili d'ambiente.
"""

from __future__ import annotations

from typing import Any

import httpx

from universe.adapters.base import Adapter, ExecContext
from universe.errors import ErrorCode, UniverseError
from universe.models import Command, Result, TargetConfig
from universe.secrets import maybe_resolve, resolve_env


class RestApiAdapter(Adapter):
    kind = "rest_api"

    def __init__(self, config: TargetConfig, client: httpx.AsyncClient | None = None) -> None:
        super().__init__(config)
        self._client = client

    def _raw_base_url(self) -> str:
        raw = (self.config.endpoint or {}).get("base_url") or ""
        if not raw:
            raise UniverseError(ErrorCode.VALIDATION, f"base_url mancante per {self.config.id}")
        return str(raw).rstrip("/")

    def _base_url(self) -> str:
        return str(maybe_resolve(self._raw_base_url())).rstrip("/")

    def _spec(self, action: str) -> dict[str, Any]:
        spec = (self.config.actions or {}).get(action)
        if not spec:
            raise UniverseError(ErrorCode.UNKNOWN_ACTION, f"Azione REST sconosciuta: {action}")
        return spec

    def _path(self, spec: dict[str, Any], params: dict[str, Any]) -> str:
        path = spec.get("path") or "/"
        try:
            return path.format(**params)
        except KeyError as exc:
            raise UniverseError(ErrorCode.VALIDATION, f"Parametro di path mancante: {exc}") from exc

    def planned(self, command: Command) -> dict[str, Any]:
        spec = self._spec(command.action)
        method = str(spec.get("method") or "GET").upper()
        path = self._path(spec, command.params)
        return {
            "method": method,
            "url": f"{self._raw_base_url()}{path}",
            "query_keys": list((spec.get("query_from") or [])),
            "body": bool(spec.get("body_from_params")),
            "auth": self.config.auth.type,
        }

    def _auth_headers(self) -> dict[str, str]:
        auth = self.config.auth
        if auth.type in ("none", "", None):
            return {}
        if auth.type == "bearer":
            token = resolve_env(auth.token_env or "REST_API_TOKEN")
            return {"Authorization": f"Bearer {token}"}
        if auth.type == "header":
            token = resolve_env(auth.token_env or "REST_API_TOKEN")
            name = auth.header_name or "X-Api-Key"
            return {name: token}
        raise UniverseError(ErrorCode.AUTH, f"Tipo auth REST non supportato: {auth.type}")

    async def execute(self, command: Command, ctx: ExecContext) -> Result:
        planned = self.planned(command)
        if ctx.dry_run:
            return Result.success(
                command,
                ctx.risk,
                result={"message": "Dry-run: nessuna chiamata HTTP in uscita."},
                dry_run=True,
                planned=planned,
            )

        spec = self._spec(command.action)
        method = str(spec.get("method") or "GET").upper()
        url = f"{self._base_url()}{self._path(spec, command.params)}"
        query: dict[str, Any] = {}
        for key in spec.get("query_from") or []:
            if key in command.params:
                query[key] = command.params[key]
        json_body = None
        if spec.get("body_from_params"):
            skip = set(spec.get("path_params") or [])
            json_body = {k: v for k, v in command.params.items() if k not in skip}

        timeout = command.timeout_seconds or self.config.timeout_seconds
        client = self._client or httpx.AsyncClient(timeout=timeout)
        owns = self._client is None
        try:
            resp = await client.request(
                method,
                url,
                params=query or None,
                json=json_body,
                headers=self._auth_headers(),
            )
        except httpx.TimeoutException as exc:
            raise UniverseError(ErrorCode.TIMEOUT, "Timeout verso l'API REST", retryable=True) from exc
        except httpx.HTTPError as exc:
            raise UniverseError(ErrorCode.TARGET_OFFLINE, "API REST non raggiungibile", retryable=True) from exc
        finally:
            if owns:
                await client.aclose()

        if resp.status_code == 401 or resp.status_code == 403:
            raise UniverseError(ErrorCode.AUTH, "Autenticazione API rifiutata")
        if resp.status_code == 429:
            raise UniverseError(ErrorCode.RATE_LIMITED, "Rate limit dell'API remota", retryable=True)
        if resp.status_code >= 500:
            raise UniverseError(
                ErrorCode.ADAPTER,
                f"API remota ha risposto {resp.status_code}",
                retryable=True,
                details={"http_status": str(resp.status_code)},
            )
        if resp.status_code >= 400:
            raise UniverseError(ErrorCode.ADAPTER, f"API remota ha rifiutato ({resp.status_code})")

        try:
            data = resp.json()
        except ValueError:
            data = {"text_length": len(resp.text)}
        return Result.success(command, ctx.risk, result=data, dry_run=False)

    async def health(self) -> dict[str, Any]:
        return {"target": self.config.id, "kind": self.kind, "ok": True, "checked": False}
