"""Audit append-only in JSONL. Mai dati sensibili."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from universe.models import Command, Result, RiskLevel
from universe.secrets import redact


class AuditLog:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._memory: list[dict[str, Any]] = []

    def record(
        self,
        command: Command,
        result: Result,
        risk: RiskLevel,
        *,
        sensitive_params: list[str] | None = None,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "id": command.id,
            "idempotency_key": command.idempotency_key,
            "source": command.source,
            "target": command.target,
            "action": command.action,
            "risk": risk.value,
            "dry_run": result.dry_run or command.dry_run,
            "status": result.status.value,
            "ok": result.ok,
            "error_code": result.error_code,
            "params": redact(command.params, sensitive_params),
            "confirmation_id": result.confirmation_id,
        }
        if extra:
            entry["extra"] = redact(extra)
        line = json.dumps(entry, ensure_ascii=False, default=str)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        self._memory.append(entry)
        return entry

    def entries(self) -> list[dict[str, Any]]:
        return list(self._memory)
