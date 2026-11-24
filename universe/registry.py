"""Carica un file YAML per target e tiene il registro delle capability."""

from __future__ import annotations

from pathlib import Path

import yaml

from universe.errors import ErrorCode, UniverseError
from universe.models import Capability, TargetConfig


class CapabilityRegistry:
    def __init__(self) -> None:
        self._targets: dict[str, TargetConfig] = {}

    def load_dir(self, directory: str | Path) -> None:
        path = Path(directory)
        if not path.is_dir():
            raise UniverseError(ErrorCode.VALIDATION, f"Cartella config assente: {directory}")
        for file in sorted(path.glob("*.yaml")):
            self.load_file(file)

    def load_file(self, file: str | Path) -> TargetConfig:
        path = Path(file)
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if not isinstance(raw, dict):
            raise UniverseError(ErrorCode.VALIDATION, f"YAML non valido: {path.name}")
        cfg = TargetConfig.model_validate(raw)
        self._targets[cfg.id] = cfg
        return cfg

    def add(self, cfg: TargetConfig) -> None:
        self._targets[cfg.id] = cfg

    def get(self, target_id: str) -> TargetConfig:
        if target_id not in self._targets:
            raise UniverseError(ErrorCode.UNKNOWN_TARGET, f"Target sconosciuto: {target_id}")
        return self._targets[target_id]

    def all(self) -> list[TargetConfig]:
        return list(self._targets.values())

    def capabilities_public(self) -> list[dict]:
        out: list[dict] = []
        for cfg in self.all():
            for cap in cfg.capabilities:
                if not cap.enabled:
                    continue
                out.append(
                    {
                        "target": cfg.id,
                        "kind": cfg.kind,
                        "enabled": cfg.enabled,
                        "action": cap.action,
                        "risk": cap.risk.value,
                        "requires_confirmation": cap.requires_confirmation or cap.risk.needs_confirmation(),
                        "description": cap.description,
                    }
                )
        return out

    def resolve_capability(self, target: TargetConfig, action: str) -> Capability | None:
        cap = target.capability(action)
        if cap:
            return cap
        # REST/Zapier/MCP possono definire azioni nella mappa 'actions'.
        if action in (target.actions or {}):
            spec = target.actions[action] or {}
            from universe.models import RiskLevel

            risk = RiskLevel(spec.get("risk", "medium"))
            return Capability(
                action=action,
                risk=risk,
                requires_confirmation=bool(spec.get("requires_confirmation", risk.needs_confirmation())),
                sensitive_params=list(spec.get("sensitive_params") or []),
                description=spec.get("description") or "",
            )
        return None
