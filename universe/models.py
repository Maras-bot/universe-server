"""Envelope del comando, risultato e livelli di rischio."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _hex_id() -> str:
    return uuid.uuid4().hex


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    def rank(self) -> int:
        return {self.LOW: 0, self.MEDIUM: 1, self.HIGH: 2, self.CRITICAL: 3}[self]

    def needs_confirmation(self) -> bool:
        return self in (RiskLevel.HIGH, RiskLevel.CRITICAL)


class CommandStatus(str, Enum):
    COMPLETED = "completed"
    DRY_RUN = "dry_run"
    CONFIRMATION_REQUIRED = "confirmation_required"
    DENIED = "denied"
    ERROR = "error"


class Command(BaseModel):
    """Busta standard di un comando in ingresso (Ara, bot, CLI, MCP)."""

    id: str = Field(default_factory=_hex_id)
    source: str = Field(..., min_length=1, description="Chi invia: ara, bot, cli, mcp, ...")
    target: str = Field(..., min_length=1, description="Id del target, es. android.phone")
    action: str = Field(..., min_length=1)
    params: dict[str, Any] = Field(default_factory=dict)
    risk: RiskLevel | None = None
    requires_confirmation: bool = False
    idempotency_key: str = Field(default_factory=_hex_id)
    dry_run: bool = True
    timeout_seconds: float | None = None
    created_at: datetime = Field(default_factory=_now)

    @field_validator("source", "target", "action")
    @classmethod
    def _strip_nonempty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("campo vuoto")
        return v


class Result(BaseModel):
    ok: bool
    id: str
    status: CommandStatus
    risk: RiskLevel = RiskLevel.MEDIUM
    result: Any = None
    error: str | None = None
    error_code: str | None = None
    retryable: bool = False
    dry_run: bool = False
    planned: Any = None
    confirmation_id: str | None = None
    target: str | None = None
    action: str | None = None

    @classmethod
    def success(
        cls,
        command: Command,
        risk: RiskLevel,
        result: Any = None,
        *,
        dry_run: bool = False,
        planned: Any = None,
    ) -> "Result":
        return cls(
            ok=True,
            id=command.id,
            status=CommandStatus.DRY_RUN if dry_run else CommandStatus.COMPLETED,
            risk=risk,
            result=result,
            dry_run=dry_run,
            planned=planned,
            target=command.target,
            action=command.action,
        )

    @classmethod
    def needs_confirm(cls, command: Command, risk: RiskLevel, confirmation_id: str) -> "Result":
        return cls(
            ok=False,
            id=command.id,
            status=CommandStatus.CONFIRMATION_REQUIRED,
            risk=risk,
            error="Serve la conferma esplicita di Maras prima di eseguire.",
            error_code="CONFIRMATION_REQUIRED",
            confirmation_id=confirmation_id,
            target=command.target,
            action=command.action,
        )

    @classmethod
    def fail(
        cls,
        command: Command,
        risk: RiskLevel,
        message: str,
        code: str,
        *,
        retryable: bool = False,
        status: CommandStatus = CommandStatus.ERROR,
    ) -> "Result":
        return cls(
            ok=False,
            id=command.id,
            status=status,
            risk=risk,
            error=message,
            error_code=code,
            retryable=retryable,
            dry_run=command.dry_run,
            target=command.target,
            action=command.action,
        )


class Capability(BaseModel):
    action: str
    risk: RiskLevel = RiskLevel.MEDIUM
    requires_confirmation: bool = False
    sensitive_params: list[str] = Field(default_factory=list)
    description: str = ""
    enabled: bool = True


class AuthConfig(BaseModel):
    type: str = "none"
    token_env: str | None = None
    header_name: str | None = None
    username_env: str | None = None
    password_env: str | None = None


class RateLimitConfig(BaseModel):
    requests_per_minute: int = 60


class RetryConfig(BaseModel):
    max_attempts: int = 2
    backoff_seconds: float = 1.0
    retry_on: list[str] = Field(default_factory=lambda: ["timeout", "503"])


class TargetConfig(BaseModel):
    id: str
    kind: str
    enabled: bool = True
    description: str = ""
    endpoint: dict[str, Any] = Field(default_factory=dict)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    timeout_seconds: float = 30.0
    rate_limit: RateLimitConfig = Field(default_factory=RateLimitConfig)
    retry: RetryConfig = Field(default_factory=RetryConfig)
    capabilities: list[Capability] = Field(default_factory=list)
    confirmation: dict[str, Any] = Field(default_factory=dict)
    protected_packages: list[str] = Field(default_factory=list)
    allowed_origins: list[str] = Field(default_factory=list)
    actions: dict[str, Any] = Field(default_factory=dict)
    mcp: dict[str, Any] = Field(default_factory=dict)
    playwright: dict[str, Any] = Field(default_factory=dict)

    def capability(self, action: str) -> Capability | None:
        for cap in self.capabilities:
            if cap.action == action:
                return cap
        return None
