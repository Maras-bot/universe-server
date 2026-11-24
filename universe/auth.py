"""Autenticazione a token per-bot. Confronto su hash, tempo costante.

I token in chiaro vivono solo il tempo del caricamento, poi restano gli hash.
Mai loggare il valore di un token.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import stat
from pathlib import Path
from typing import Any


MIN_TOKEN_LENGTH = 24
HASH_PREFIX = "sha256:"
UNAUTHORIZED_DETAIL = "unauthorized"


class AuthError(Exception):
    """Token mancante o non valido. Il messaggio non distingue i due casi."""

    def __init__(self, message: str = UNAUTHORIZED_DETAIL) -> None:
        super().__init__(message)
        self.message = message


def hash_token(token: str) -> str:
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return f"{HASH_PREFIX}{digest}"


def _digest_equal(left: str, right: str) -> bool:
    return hmac.compare_digest(left, right)


def extract_bearer(authorization: str | None) -> str | None:
    if not authorization:
        return None
    parts = authorization.strip().split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    token = parts[1].strip()
    return token or None


class TokenStore:
    """Registro di token bot (client_id distinti) e del token del telefono."""

    def __init__(self) -> None:
        self._bots: list[tuple[str, str]] = []  # (client_id, hash)
        self._phone_hash: str | None = None

    def has_any(self) -> bool:
        return bool(self._bots) or self._phone_hash is not None

    def has_bots(self) -> bool:
        return bool(self._bots)

    def has_phone(self) -> bool:
        return self._phone_hash is not None

    def client_ids(self) -> list[str]:
        return [cid for cid, _ in self._bots]

    def add_bot(self, client_id: str, token: str) -> None:
        client_id = (client_id or "").strip()
        token = token or ""
        if not client_id:
            raise ValueError("client_id vuoto")
        if len(token) < MIN_TOKEN_LENGTH:
            raise ValueError("token bot troppo corto")
        self._bots.append((client_id, hash_token(token)))

    def set_phone(self, token: str) -> None:
        if len(token or "") < MIN_TOKEN_LENGTH:
            raise ValueError("token telefono troppo corto")
        self._phone_hash = hash_token(token)

    def authenticate_bot(self, token: str | None) -> str:
        """Restituisce il client_id oppure solleva AuthError. Sempre 401 all'esterno."""
        if not token:
            # Confronto fittizio per non accorciare troppo il percorso "mancante".
            _digest_equal(hash_token("0" * MIN_TOKEN_LENGTH), hash_token("1" * MIN_TOKEN_LENGTH))
            raise AuthError()
        provided = hash_token(token)
        matched: str | None = None
        for client_id, stored in self._bots:
            if _digest_equal(provided, stored):
                matched = client_id
        if matched is None:
            raise AuthError()
        return matched

    def verify_phone(self, token: str | None) -> bool:
        if not token or self._phone_hash is None:
            if self._phone_hash is not None:
                _digest_equal(hash_token(token or ("0" * MIN_TOKEN_LENGTH)), self._phone_hash)
            return False
        return _digest_equal(hash_token(token), self._phone_hash)

    @classmethod
    def from_mapping(
        cls,
        bots: dict[str, str] | None = None,
        phone_token: str | None = None,
    ) -> "TokenStore":
        store = cls()
        for client_id, token in (bots or {}).items():
            store.add_bot(client_id, token)
        if phone_token:
            store.set_phone(phone_token)
        return store

    @classmethod
    def from_settings_and_env(
        cls,
        tokens_file: str = "",
        bot_tokens_json: str = "",
        phone_token: str = "",
    ) -> "TokenStore":
        store = cls()
        if tokens_file:
            data = load_tokens_file(tokens_file)
            for client_id, token in (data.get("bots") or {}).items():
                store.add_bot(str(client_id), str(token))
            file_phone = data.get("phone")
            if file_phone:
                store.set_phone(str(file_phone))
        if bot_tokens_json:
            parsed = json.loads(bot_tokens_json)
            if not isinstance(parsed, dict):
                raise ValueError("UNIVERSE_BOT_TOKENS deve essere un oggetto JSON")
            for client_id, token in parsed.items():
                store.add_bot(str(client_id), str(token))
        env_phone = phone_token or os.environ.get("UNIVERSE_PHONE_TOKEN", "")
        if env_phone and not store.has_phone():
            store.set_phone(env_phone)
        return store


def load_tokens_file(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"file token assente: {p}")
    mode = p.stat().st_mode
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise PermissionError(f"file token troppo aperto (atteso 0600): {p}")
    data = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("file token: JSON non oggetto")
    bots = data.get("bots")
    if bots is not None and not isinstance(bots, dict):
        raise ValueError("file token: 'bots' deve essere un oggetto")
    return data
