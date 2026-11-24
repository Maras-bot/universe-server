"""Risoluzione segreti da variabili d'ambiente. Mai valori in chiaro nei log."""

from __future__ import annotations

import os
import re
from typing import Any

from universe.errors import ErrorCode, UniverseError

# Nomi (minuscoli) considerati sempre sensibili, anche nidificati.
SENSITIVE_KEYS = {
    "token",
    "password",
    "authorization",
    "api_key",
    "apikey",
    "secret",
    "activation_code",
    "confirmation_code",
    "cookie",
    "cookies",
    "access_token",
    "refresh_token",
    "private_key",
    "bearer",
    "relay_token",
    "webhook_secret",
    "qr_image_base64",
    "auth",
    "credentials",
    "pin",
    "otp",
    "ssn",
    "card",
    "card_number",
    "cvv",
    "iban",
}

ENV_REF = re.compile(r"^\$\{([A-Z][A-Z0-9_]*)\}$")
REDACTED = "[REDATTO]"


def is_sensitive_key(key: str) -> bool:
    k = key.lower().replace("-", "_")
    if k in SENSITIVE_KEYS:
        return True
    return any(part in SENSITIVE_KEYS for part in k.split("_") if part in SENSITIVE_KEYS) or (
        "token" in k or "secret" in k or "password" in k or "api_key" in k
    )


def resolve_env(ref: str | None) -> str:
    """Accetta 'RELAY_TOKEN' oppure '${RELAY_TOKEN}'. Non logga il valore."""
    if not ref:
        raise UniverseError(ErrorCode.AUTH, "Riferimento segreto mancante")
    ref = ref.strip()
    m = ENV_REF.match(ref)
    name = m.group(1) if m else ref
    if not re.fullmatch(r"[A-Z][A-Z0-9_]*", name):
        raise UniverseError(ErrorCode.AUTH, "Nome variabile d'ambiente non valido")
    value = os.environ.get(name, "")
    if not value:
        raise UniverseError(ErrorCode.AUTH, f"Variabile d'ambiente {name} non impostata")
    return value


def maybe_resolve(value: Any) -> Any:
    """Se è un riferimento ${ENV}, lo risolve. Altrimenti lascia com'è."""
    if isinstance(value, str) and ENV_REF.match(value.strip()):
        return resolve_env(value)
    return value


def redact(data: Any, extra_keys: list[str] | None = None) -> Any:
    """Copia redattata, ricorsiva. I valori sensibili diventano [REDATTO]."""
    extra = {k.lower() for k in (extra_keys or [])}

    def _walk(obj: Any, key: str | None = None) -> Any:
        if key and (is_sensitive_key(key) or key.lower() in extra):
            return REDACTED
        if isinstance(obj, dict):
            return {k: _walk(v, k) for k, v in obj.items()}
        if isinstance(obj, list):
            return [_walk(v, key) for v in obj]
        if isinstance(obj, str) and ENV_REF.match(obj.strip()):
            return obj  # è un nome, non un valore
        return obj

    return _walk(data)
