"""Dispatcher: valida, classifica, chiede conferma, applica limiti, instrada."""

from __future__ import annotations

from typing import Any

from universe.adapters.android import AndroidAdapter
from universe.adapters.base import Adapter, ExecContext
from universe.adapters.rest_api import RestApiAdapter
from universe.audit import AuditLog
from universe.confirm import ConfirmationStore
from universe.errors import ErrorCode, UniverseError
from universe.models import Command, CommandStatus, Result, RiskLevel, TargetConfig
from universe.ratelimit import RateLimiter
from universe.registry import CapabilityRegistry
from universe.retry import with_retry
from universe.risk import classify, must_confirm
from universe.settings import Settings


ADAPTERS = {
    "android": AndroidAdapter,
    "rest_api": RestApiAdapter,
}


class Router:
    def __init__(
        self,
        registry: CapabilityRegistry,
        settings: Settings | None = None,
        audit: AuditLog | None = None,
        confirmations: ConfirmationStore | None = None,
        adapters: dict[str, Adapter] | None = None,
    ) -> None:
        self.registry = registry
        self.settings = settings or Settings()
        self.audit = audit or AuditLog(self.settings.audit_path)
        self.confirmations = confirmations or ConfirmationStore(
            timeout_seconds=self.settings.confirmation_timeout_seconds
        )
        self.limiter = RateLimiter()
        self._adapters = adapters or {}
        self._idem: dict[str, Result] = {}

    def register_adapter(self, adapter: Adapter) -> None:
        self._adapters[adapter.config.id] = adapter

    def adapter_for(self, target: TargetConfig) -> Adapter:
        if target.id in self._adapters:
            return self._adapters[target.id]
        factory = ADAPTERS.get(target.kind)
        if factory is None:
            raise UniverseError(
                ErrorCode.ADAPTER,
                f"Nessun adapter nello scheletro per kind={target.kind}. Vedi il documento di progetto.",
            )
        adapter = factory(target)
        self._adapters[target.id] = adapter
        return adapter

    async def dispatch(self, command: Command) -> Result:
        risk = RiskLevel.MEDIUM
        sensitive: list[str] = []
        try:
            target = self.registry.get(command.target)
            if not target.enabled:
                raise UniverseError(ErrorCode.TARGET_DISABLED, f"Target disabilitato: {target.id}")

            cap = self.registry.resolve_capability(target, command.action)
            if cap is None and target.kind in {"rest_api", "zapier", "mcp"} and not target.actions:
                pass
            if cap is None and target.kind in {"rest_api", "zapier", "mcp"}:
                # android/browser hanno la lista capabilities; rest usa actions.
                if target.capability(command.action) is None and command.action not in (target.actions or {}):
                    raise UniverseError(ErrorCode.UNKNOWN_ACTION, f"Azione sconosciuta per {target.id}: {command.action}")
            if cap is not None and not cap.enabled:
                raise UniverseError(ErrorCode.UNKNOWN_ACTION, f"Azione disabilitata: {command.action}")
            if cap is None and target.kind == "android":
                # Accettiamo le azioni dichiarate in capabilities. Se manca, rifiutiamo.
                raise UniverseError(ErrorCode.UNKNOWN_ACTION, f"Azione Android sconosciuta: {command.action}")
            if cap is None and target.kind == "browser":
                raise UniverseError(ErrorCode.UNKNOWN_ACTION, f"Azione browser sconosciuta: {command.action}")

            sensitive = list(cap.sensitive_params) if cap else []
            risk = classify(command, target, cap)

            cached = self._idem.get(command.idempotency_key)
            if cached is not None and cached.status in {CommandStatus.COMPLETED, CommandStatus.DRY_RUN}:
                return cached

            if must_confirm(command, risk, cap):
                pending = self.confirmations.request(command, risk, sensitive)
                if pending.decision == "timeout":
                    result = Result.fail(
                        command,
                        risk,
                        "Conferma scaduta: comando non eseguito.",
                        ErrorCode.CONFIRMATION_TIMEOUT,
                        status=CommandStatus.DENIED,
                    )
                    self.audit.record(command, result, risk, sensitive_params=sensitive)
                    return result
                if pending.decision == "denied":
                    result = Result.fail(
                        command,
                        risk,
                        "Maras ha rifiutato la conferma. Comando non eseguito.",
                        ErrorCode.CONFIRMATION_DENIED,
                        status=CommandStatus.DENIED,
                    )
                    self.audit.record(command, result, risk, sensitive_params=sensitive)
                    return result
                if pending.decision != "approved":
                    result = Result.needs_confirm(command, risk, pending.id)
                    self.audit.record(command, result, risk, sensitive_params=sensitive)
                    return result

            self.limiter.check(target.id, target.rate_limit.requests_per_minute)

            dry_run = self.settings.effective_dry_run(command.dry_run)
            if not dry_run and not self.settings.allow_live:
                dry_run = True

            # Browser/zapier/mcp: scheletro non li esegue ancora.
            if target.kind not in ADAPTERS:
                if dry_run:
                    result = Result.success(
                        command,
                        risk,
                        result={"message": f"Adapter {target.kind} previsto, non nello scheletro. Nessuna esecuzione."},
                        dry_run=True,
                        planned={"target": target.id, "kind": target.kind, "action": command.action},
                    )
                    self.audit.record(command, result, risk, sensitive_params=sensitive)
                    self._idem[command.idempotency_key] = result
                    return result
                raise UniverseError(
                    ErrorCode.ADAPTER,
                    f"Adapter {target.kind} non implementato nello scheletro. Live non disponibile.",
                )

            adapter = self.adapter_for(target)
            ctx = ExecContext(settings=self.settings, dry_run=dry_run, risk=risk, sensitive_params=sensitive)

            async def _run() -> Result:
                return await adapter.execute(command, ctx)

            if dry_run:
                result = await _run()
            else:
                result = await with_retry(_run, target.retry, sleeper=_no_sleep if target.retry.backoff_seconds == 0 else None)

            self.audit.record(command, result, risk, sensitive_params=sensitive)
            if result.ok:
                self._idem[command.idempotency_key] = result
            return result

        except UniverseError as exc:
            result = Result.fail(command, risk, exc.message, exc.code, retryable=exc.retryable)
            self.audit.record(command, result, risk, sensitive_params=sensitive)
            return result
        except Exception:  # noqa: BLE001
            result = Result.fail(command, risk, "Errore interno del router", ErrorCode.UNKNOWN)
            self.audit.record(command, result, risk, sensitive_params=sensitive)
            return result


async def _no_sleep(_: float) -> None:
    return None


def build_default_router(configs_dir: str, settings: Settings | None = None) -> Router:
    settings = settings or Settings(configs_dir=configs_dir)
    registry = CapabilityRegistry()
    registry.load_dir(configs_dir)
    return Router(registry, settings=settings)
