import hmac
import json
import os
from pathlib import Path

import pytest

from universe.auth import (
    AuthError,
    MIN_TOKEN_LENGTH,
    TokenStore,
    extract_bearer,
    hash_token,
    load_tokens_file,
)

BOT_A = "a" * 32
BOT_B = "b" * 32
PHONE = "p" * 32


def test_extract_bearer():
    assert extract_bearer(None) is None
    assert extract_bearer("") is None
    assert extract_bearer("Bearer") is None
    assert extract_bearer("Basic abc") is None
    assert extract_bearer("Bearer " + BOT_A) == BOT_A
    assert extract_bearer("bearer " + BOT_A) == BOT_A
    assert extract_bearer("BEARER  " + BOT_A) == BOT_A


def test_hash_is_stable_and_not_plaintext():
    h = hash_token(BOT_A)
    assert h == hash_token(BOT_A)
    assert BOT_A not in h
    assert h.startswith("sha256:")
    assert hash_token(BOT_A) != hash_token(BOT_B)


def test_per_bot_tokens_and_unknown_rejected():
    store = TokenStore.from_mapping({"test-client": BOT_A, "other": BOT_B}, phone_token=PHONE)
    assert store.authenticate_bot(BOT_A) == "test-client"
    assert store.authenticate_bot(BOT_B) == "other"
    with pytest.raises(AuthError):
        store.authenticate_bot(None)
    with pytest.raises(AuthError):
        store.authenticate_bot("")
    with pytest.raises(AuthError):
        store.authenticate_bot("z" * 32)
    with pytest.raises(AuthError):
        store.authenticate_bot(PHONE)  # il token telefono non vale come bot


def test_missing_and_invalid_have_same_message():
    store = TokenStore.from_mapping({"test-client": BOT_A})
    with pytest.raises(AuthError) as missing:
        store.authenticate_bot(None)
    with pytest.raises(AuthError) as invalid:
        store.authenticate_bot("z" * 32)
    assert missing.value.message == invalid.value.message == "unauthorized"


def test_verify_phone():
    store = TokenStore.from_mapping({"test-client": BOT_A}, phone_token=PHONE)
    assert store.verify_phone(PHONE) is True
    assert store.verify_phone(BOT_A) is False
    assert store.verify_phone(None) is False
    assert store.verify_phone("") is False


def test_short_token_rejected_at_load():
    store = TokenStore()
    with pytest.raises(ValueError):
        store.add_bot("test-client", "short")
    with pytest.raises(ValueError):
        store.set_phone("short")


def test_authenticate_uses_compare_digest(monkeypatch):
    called = {"n": 0}
    real = hmac.compare_digest

    def wrapper(a, b):
        called["n"] += 1
        return real(a, b)

    monkeypatch.setattr("universe.auth.hmac.compare_digest", wrapper)
    store = TokenStore.from_mapping({"test-client": BOT_A, "other": BOT_B})
    assert store.authenticate_bot(BOT_A) == "test-client"
    # Un confronto per ogni bot, in modo da non uscire prima sul match.
    assert called["n"] >= 2


def test_load_tokens_file_requires_0600(tmp_path: Path):
    path = tmp_path / "tokens.json"
    path.write_text(json.dumps({"bots": {"test-client": BOT_A}, "phone": PHONE}))
    os.chmod(path, 0o644)
    with pytest.raises(PermissionError):
        load_tokens_file(path)
    os.chmod(path, 0o600)
    data = load_tokens_file(path)
    assert "test-client" in data["bots"]


def test_from_settings_and_env_file(tmp_path: Path):
    path = tmp_path / "tokens.json"
    path.write_text(json.dumps({"bots": {"test-client": BOT_A}, "phone": PHONE}))
    os.chmod(path, 0o600)
    store = TokenStore.from_settings_and_env(tokens_file=str(path))
    assert store.authenticate_bot(BOT_A) == "test-client"
    assert store.verify_phone(PHONE)
