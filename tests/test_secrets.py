import os

import pytest

from universe.errors import UniverseError
from universe.secrets import REDACTED, redact, resolve_env


def test_resolve_env_and_placeholder(monkeypatch):
    monkeypatch.setenv("RELAY_TOKEN", "super-segreto")
    assert resolve_env("RELAY_TOKEN") == "super-segreto"
    assert resolve_env("${RELAY_TOKEN}") == "super-segreto"


def test_missing_env_fails(monkeypatch):
    monkeypatch.delenv("MISSING_SECRET_X", raising=False)
    with pytest.raises(UniverseError):
        resolve_env("MISSING_SECRET_X")


def test_redact_nested_and_extra_keys():
    data = {
        "action": "type",
        "token": "abc",
        "params": {"text": "ciao", "package": "com.whatsapp", "activation_code": "LPA:1$x$y"},
        "nested": {"authorization": "Bearer zzz"},
    }
    out = redact(data, extra_keys=["text"])
    assert out["token"] == REDACTED
    assert out["params"]["activation_code"] == REDACTED
    assert out["params"]["text"] == REDACTED
    assert out["params"]["package"] == "com.whatsapp"
    assert out["nested"]["authorization"] == REDACTED
    assert out["action"] == "type"
    # l'originale non è toccato
    assert data["token"] == "abc"
