"""Interfaccia comune di ogni adapter."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from universe.models import Command, Result, RiskLevel, TargetConfig
from universe.settings import Settings


@dataclass
class ExecContext:
    settings: Settings
    dry_run: bool
    risk: RiskLevel
    sensitive_params: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)


class Adapter(ABC):
    kind: str = ""

    def __init__(self, config: TargetConfig) -> None:
        self.config = config

    def can_handle(self, command: Command) -> bool:
        return command.target == self.config.id and self.config.kind == self.kind

    @abstractmethod
    async def execute(self, command: Command, ctx: ExecContext) -> Result:
        raise NotImplementedError

    async def health(self) -> dict[str, Any]:
        return {"target": self.config.id, "kind": self.kind, "ok": True, "dry_run": True}
