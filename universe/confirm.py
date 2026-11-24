"""Coda di conferme. Timeout = rifiuto. Nessun dato sensibile nel testo mostrato."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Literal

from universe.models import Command, RiskLevel
from universe.secrets import redact

Decision = Literal["pending", "approved", "denied", "timeout"]


@dataclass
class PendingConfirmation:
    id: str
    command_id: str
    idempotency_key: str
    target: str
    action: str
    risk: RiskLevel
    source: str
    summary: str
    created_at: float
    timeout_seconds: int
    decision: Decision = "pending"
    decided_at: float | None = None
    approver: str | None = None

    def expired(self, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        return (now - self.created_at) >= self.timeout_seconds


class ConfirmationStore:
    """Store in memoria. Va bene per lo scheletro e per i test."""

    def __init__(self, timeout_seconds: int = 60) -> None:
        self.timeout_seconds = timeout_seconds
        self._items: dict[str, PendingConfirmation] = {}
        self._by_command: dict[str, str] = {}
        self._by_idem: dict[str, str] = {}

    def request(self, command: Command, risk: RiskLevel, sensitive_params: list[str] | None = None) -> PendingConfirmation:
        existing_id = self._by_idem.get(command.idempotency_key) or self._by_command.get(command.id)
        if existing_id and existing_id in self._items:
            item = self._items[existing_id]
            self._refresh_timeout(item)
            return item

        # Il riassunto non contiene parametri sensibili.
        safe_params = redact(command.params, sensitive_params)
        summary = f"{command.action} su {command.target} (rischio {risk.value})"
        item = PendingConfirmation(
            id=uuid.uuid4().hex,
            command_id=command.id,
            idempotency_key=command.idempotency_key,
            target=command.target,
            action=command.action,
            risk=risk,
            source=command.source,
            summary=summary,
            created_at=time.time(),
            timeout_seconds=self.timeout_seconds,
        )
        # safe_params è calcolato per garantire che non resti in chiaro in quest'oggetto
        item.summary = f"{summary}. Parametri: {safe_params}"
        self._items[item.id] = item
        self._by_command[command.id] = item.id
        self._by_idem[command.idempotency_key] = item.id
        return item

    def _refresh_timeout(self, item: PendingConfirmation) -> None:
        if item.decision == "pending" and item.expired():
            item.decision = "timeout"
            item.decided_at = time.time()

    def get(self, confirmation_id: str) -> PendingConfirmation | None:
        item = self._items.get(confirmation_id)
        if item:
            self._refresh_timeout(item)
        return item

    def get_for_command(self, command: Command) -> PendingConfirmation | None:
        cid = self._by_idem.get(command.idempotency_key) or self._by_command.get(command.id)
        return self.get(cid) if cid else None

    def decide(self, confirmation_id: str, approved: bool, approver: str = "maras") -> PendingConfirmation:
        item = self.get(confirmation_id)
        if item is None:
            raise KeyError("conferma sconosciuta")
        if item.decision == "timeout":
            return item
        if item.decision != "pending":
            return item
        item.decision = "approved" if approved else "denied"
        item.decided_at = time.time()
        item.approver = approver
        return item

    def is_approved(self, command: Command) -> bool:
        item = self.get_for_command(command)
        return bool(item and item.decision == "approved")
