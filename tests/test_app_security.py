from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from universe.app import SENSITIVE_HEALTH_KEYS, create_app
from universe.auth import TokenStore, UNAUTHORIZED_DETAIL
from universe.settings import Settings

BOT = "test-client-token-00000000000000000001"
PHONE = "phone-device-token-0000000000000000002"
OTHER = "other-client-token-00000000000000000003"


def _settings(tmp_path: Path, **kw) -> Settings:
    defaults = dict(
        dry_run=True,
        allow_live=False,
        configs_dir=str(Path(__file__).resolve().parents[1] / "configs"),
        audit_path=str(tmp_path / "audit.jsonl"),
        enable_docs=False,
        require_tls=False,
        max_request_bytes=1024,
        http_rate_limit_per_minute=60,
        http_rate_limit_unauth_per_minute=20,
    )
    defaults.update(kw)
    return Settings(**defaults)


def _store() -> TokenStore:
    return TokenStore.from_mapping({"test-client": BOT, "other": OTHER}, phone_token=PHONE)


def _client(tmp_path: Path, **kw) -> TestClient:
    app = create_app(settings=_settings(tmp_path, **kw), token_store=_store(), require_tokens=True)
    return TestClient(app)


def test_health_200_no_auth_no_secrets(tmp_path):
    with _client(tmp_path) as c:
        r = c.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body == {"ok": True}
    for key in SENSITIVE_HEALTH_KEYS:
        assert key not in body
    assert "token" not in r.text.lower() or "token" not in body
    # nessun elenco target, nessun flag live
    assert "android" not in r.text
    assert "allow_live" not in r.text


def test_command_missing_token_401(tmp_path):
    with _client(tmp_path) as c:
        r = c.post("/command", json={"source": "test-client", "target": "android.phone", "action": "dump_screen"})
    assert r.status_code == 401
    assert r.json()["detail"] == UNAUTHORIZED_DETAIL


def test_command_invalid_token_401(tmp_path):
    with _client(tmp_path) as c:
        r = c.post(
            "/command",
            json={"source": "test-client", "target": "android.phone", "action": "dump_screen"},
            headers={"Authorization": "Bearer " + ("z" * 32)},
        )
    assert r.status_code == 401
    assert r.json()["detail"] == UNAUTHORIZED_DETAIL


def test_command_phone_token_not_accepted_as_bot(tmp_path):
    with _client(tmp_path) as c:
        r = c.post(
            "/command",
            json={"source": "test-client", "target": "android.phone", "action": "dump_screen"},
            headers={"Authorization": f"Bearer {PHONE}"},
        )
    assert r.status_code == 401


def test_command_valid_token_dry_run_returns_plan(tmp_path):
    with _client(tmp_path) as c:
        r = c.post(
            "/command",
            json={
                "source": "test-client",
                "target": "android.phone",
                "action": "dump_screen",
                "dry_run": True,
            },
            headers={"Authorization": f"Bearer {BOT}"},
        )
    assert r.status_code == 200
    data = r.json()
    assert data["ok"] is True
    assert data["dry_run"] is True
    assert data["planned"]["action"] == "dump_screen"
    assert data["auth_client"] == "test-client"
    assert "Bearer [REDATTO]" in data["planned"]["headers"]["Authorization"]
    assert BOT not in r.text
    assert PHONE not in r.text


def test_allow_live_stays_off_even_if_command_asks_live(tmp_path):
    with _client(tmp_path) as c:
        r = c.post(
            "/command",
            json={
                "source": "test-client",
                "target": "android.phone",
                "action": "dump_screen",
                "dry_run": False,
            },
            headers={"Authorization": f"Bearer {BOT}"},
        )
    assert r.status_code == 200
    assert r.json()["dry_run"] is True


def test_docs_disabled_in_prod(tmp_path):
    with _client(tmp_path, enable_docs=False) as c:
        assert c.get("/docs").status_code == 404
        assert c.get("/redoc").status_code == 404
        assert c.get("/openapi.json").status_code == 404


def test_docs_can_be_enabled_explicitly(tmp_path):
    with _client(tmp_path, enable_docs=True) as c:
        assert c.get("/openapi.json").status_code == 200


def test_cors_off(tmp_path):
    with _client(tmp_path) as c:
        r = c.get("/health", headers={"Origin": "https://evil.example"})
        assert "access-control-allow-origin" not in {k.lower() for k in r.headers}
        r2 = c.options(
            "/command",
            headers={
                "Origin": "https://evil.example",
                "Access-Control-Request-Method": "POST",
            },
        )
    assert "access-control-allow-origin" not in {k.lower() for k in r2.headers}


def test_payload_too_large_413(tmp_path):
    with _client(tmp_path, max_request_bytes=256) as c:
        r = c.post(
            "/command",
            data=b"{" + b"x" * 2000 + b"}",
            headers={
                "Authorization": f"Bearer {BOT}",
                "Content-Type": "application/json",
            },
        )
    assert r.status_code == 413


def test_http_rate_limit_unauth_429(tmp_path):
    with _client(tmp_path, http_rate_limit_unauth_per_minute=2) as c:
        r1 = c.post("/command", json={"source": "x", "target": "y", "action": "z"})
        r2 = c.post("/command", json={"source": "x", "target": "y", "action": "z"})
        r3 = c.post("/command", json={"source": "x", "target": "y", "action": "z"})
    assert r1.status_code == 401
    assert r2.status_code == 401
    assert r3.status_code == 429


def test_http_rate_limit_per_bot_429(tmp_path):
    with _client(tmp_path, http_rate_limit_per_minute=2) as c:
        body = {"source": "test-client", "target": "android.phone", "action": "dump_screen"}
        headers = {"Authorization": f"Bearer {BOT}"}
        statuses = [c.post("/command", json=body, headers=headers).status_code for _ in range(3)]
    assert statuses[0] == 200
    assert statuses[1] == 200
    assert statuses[2] == 429


def test_audit_does_not_contain_tokens(tmp_path):
    with _client(tmp_path) as c:
        c.post(
            "/command",
            json={"source": "test-client", "target": "android.phone", "action": "dump_screen"},
            headers={"Authorization": f"Bearer {BOT}"},
        )
        c.post(
            "/command",
            json={"source": "test-client", "target": "android.phone", "action": "dump_screen"},
            headers={"Authorization": "Bearer " + ("z" * 32)},
        )
    raw = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    assert BOT not in raw
    assert OTHER not in raw
    assert PHONE not in raw
    assert "z" * 32 not in raw
    assert "Authorization" not in raw
    # c'è traccia dell'evento, senza segreti
    assert "/command" in raw


def test_require_tls_rejects_forwarded_http(tmp_path):
    with _client(tmp_path, require_tls=True) as c:
        r = c.get("/health")  # health resta raggiungibile anche senza proto
        assert r.status_code == 200
        r2 = c.post(
            "/command",
            json={"source": "test-client", "target": "android.phone", "action": "dump_screen"},
            headers={"Authorization": f"Bearer {BOT}", "X-Forwarded-Proto": "http"},
        )
    assert r2.status_code == 400
    assert r2.json()["detail"] == "https required"


def test_capabilities_requires_auth(tmp_path):
    with _client(tmp_path) as c:
        assert c.get("/capabilities").status_code == 401
        r = c.get("/capabilities", headers={"Authorization": f"Bearer {BOT}"})
    assert r.status_code == 200
    assert r.json()["ok"] is True


def test_startup_requires_tokens(tmp_path):
    app = create_app(
        settings=_settings(tmp_path),
        token_store=TokenStore(),
        require_tokens=True,
    )
    with pytest.raises(RuntimeError):
        with TestClient(app):
            pass
