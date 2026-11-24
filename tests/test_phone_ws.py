from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from universe.app import create_app
from universe.auth import TokenStore
from universe.settings import Settings

BOT = "test-client-token-00000000000000000001"
PHONE = "phone-device-token-0000000000000000002"


def _app(tmp_path: Path, **kw):
    settings = Settings(
        dry_run=True,
        allow_live=False,
        configs_dir=str(Path(__file__).resolve().parents[1] / "configs"),
        audit_path=str(tmp_path / "audit.jsonl"),
        enable_docs=False,
        require_tls=False,
        phone_hello_timeout_seconds=1.0,
        **kw,
    )
    store = TokenStore.from_mapping({"test-client": BOT}, phone_token=PHONE)
    return create_app(settings=settings, token_store=store, require_tokens=True)


def test_phone_ws_with_header_token_succeeds(tmp_path):
    with TestClient(_app(tmp_path)) as c:
        with c.websocket_connect("/phone", headers={"Authorization": f"Bearer {PHONE}"}) as ws:
            # Connessione autenticata: un messaggio non-hello viene ignorato, la socket resta aperta.
            ws.send_json({"id": "nope", "ok": True})


def test_phone_ws_hello_token_succeeds(tmp_path):
    with TestClient(_app(tmp_path)) as c:
        with c.websocket_connect("/phone") as ws:
            ws.send_json({"type": "hello", "token": PHONE})
            ws.send_json({"id": "x", "ok": True})


def test_phone_ws_without_token_rejected(tmp_path):
    with TestClient(_app(tmp_path)) as c:
        with c.websocket_connect("/phone") as ws:
            with pytest.raises(WebSocketDisconnect) as exc:
                ws.send_json({"type": "hello"})
                ws.receive_text()
            assert exc.value.code == 1008


def test_phone_ws_bad_hello_rejected(tmp_path):
    with TestClient(_app(tmp_path)) as c:
        with c.websocket_connect("/phone") as ws:
            with pytest.raises(WebSocketDisconnect) as exc:
                ws.send_json({"type": "hello", "token": BOT})
                ws.receive_text()
            assert exc.value.code == 1008


def test_phone_ws_bad_header_rejected(tmp_path):
    with TestClient(_app(tmp_path)) as c:
        with pytest.raises((WebSocketDisconnect, Exception)):
            with c.websocket_connect("/phone", headers={"Authorization": "Bearer " + ("z" * 32)}) as ws:
                ws.receive_text()


def test_phone_ws_token_in_query_rejected(tmp_path):
    with TestClient(_app(tmp_path)) as c:
        with pytest.raises((WebSocketDisconnect, Exception)):
            with c.websocket_connect(f"/phone?token={PHONE}") as ws:
                ws.receive_text()


def test_phone_ws_does_not_audit_token(tmp_path):
    with TestClient(_app(tmp_path)) as c:
        with c.websocket_connect("/phone") as ws:
            ws.send_json({"type": "hello", "token": PHONE})
        # tentativo fallito
        with c.websocket_connect("/phone") as ws:
            with pytest.raises(WebSocketDisconnect):
                ws.send_json({"type": "hello", "token": "z" * 32})
                ws.receive_text()
    raw = (tmp_path / "audit.jsonl").read_text(encoding="utf-8") if (tmp_path / "audit.jsonl").exists() else ""
    # Anche se l'audit HTTP è vuoto, i log non devono contenere i token.
    assert PHONE not in raw
    assert BOT not in raw


def test_phone_ws_ping_pong(tmp_path):
    with TestClient(_app(tmp_path)) as c:
        with c.websocket_connect("/phone", headers={"Authorization": f"Bearer {PHONE}"}) as ws:
            ws.send_json({"type": "ping"})
            msg = ws.receive_json()
            assert msg == {"type": "pong"}
