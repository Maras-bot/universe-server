"""Modello errori condiviso. I messaggi non contengono dati sensibili."""

from __future__ import annotations


class ErrorCode:
    VALIDATION = "VALIDATION"
    AUTH = "AUTH"
    UNKNOWN_TARGET = "UNKNOWN_TARGET"
    UNKNOWN_ACTION = "UNKNOWN_ACTION"
    TARGET_DISABLED = "TARGET_DISABLED"
    TARGET_OFFLINE = "TARGET_OFFLINE"
    RISK_BLOCKED = "RISK_BLOCKED"
    CONFIRMATION_REQUIRED = "CONFIRMATION_REQUIRED"
    CONFIRMATION_DENIED = "CONFIRMATION_DENIED"
    CONFIRMATION_TIMEOUT = "CONFIRMATION_TIMEOUT"
    RATE_LIMITED = "RATE_LIMITED"
    TIMEOUT = "TIMEOUT"
    ADAPTER = "ADAPTER"
    LIVE_DISABLED = "LIVE_DISABLED"
    UNKNOWN = "UNKNOWN"


RETRYABLE = {ErrorCode.TIMEOUT, ErrorCode.TARGET_OFFLINE, ErrorCode.RATE_LIMITED}


class UniverseError(Exception):
    def __init__(
        self,
        code: str,
        message: str,
        retryable: bool | None = None,
        details: dict | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.retryable = RETRYABLE.__contains__(code) if retryable is None else retryable
        self.details = details or {}

    def to_dict(self) -> dict:
        return {
            "ok": False,
            "error": self.message,
            "error_code": self.code,
            "retryable": self.retryable,
        }
