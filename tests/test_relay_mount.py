from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from universe.app import create_app
from universe.auth import TokenStore
from universe.relay_routing import identifier_hash, sha256_hex
from universe.settings import Settings

BOT = "test-client-token-00000000000000000001"
PHONE = "phone-device-token-0000000000000000002"
RELAY = "relay-shared-token-0000000000000000003"


def _app(tmp_path: Path, **kw):
    settings = Settings(
        dry_run=True,
        allow_live=False,
        configs_dir=str(Path(__file__).resolve().parents[1] / "configs"),
        audit_path=str(tmp_path / "audit.jsonl"),
        enable_docs=False,
        require_tls=False,
        relay_token=RELAY,
        relay_command_timeout=2.0,
        phone_hello_timeout_seconds=1.0,
        **kw,
    )
    store = TokenStore.from_mapping({"test-client": BOT}, phone_token=PHONE)
    return create_app(settings=settings, token_store=store, require_tokens=True)


def test_relay_only_startup_succeeds(tmp_path):
    settings = Settings(
        configs_dir=str(Path(__file__).resolve().parents[1] / "configs"),
        audit_path=str(tmp_path / "audit.jsonl"),
        relay_token=RELAY,
    )
    app = create_app(settings=settings, token_store=TokenStore(), require_tokens=True)
    with TestClient(app) as c:
        r = c.get("/health")
        assert r.status_code == 200
        assert r.json()["ok"] is True


def test_relay_phone_offline_returns_503(tmp_path):
    with TestClient(_app(tmp_path)) as c:
        r = c.post(
            "/command",
            json={"id": "c1", "action": "dump_screen"},
            headers={"Authorization": f"Bearer {RELAY}"},
        )
        assert r.status_code == 503
        assert r.json()["ok"] is False
        assert "telefono" in r.json()["error"].lower()


def test_relay_command_roundtrip_over_phone_ws(tmp_path):
    app = _app(tmp_path)
    with TestClient(app) as c:
        with c.websocket_connect("/phone") as ws:
            ws.send_json({"type": "hello", "token": RELAY})
            ws.send_json({"type": "ping"})
            assert ws.receive_json() == {"type": "pong"}

            # Verifica che i messaggi di servizio non rompano l'hub
            ws.send_json({"type": "alive", "ts": 1234, "alert_others": False})

            seen = {}

            def _phone_loop():
                cmd = json.loads(ws.receive_text())
                seen["cmd"] = cmd
                ws.send_text(json.dumps({"id": cmd["id"], "ok": True, "result": {"count": 1}}))

            t = threading.Thread(target=_phone_loop, daemon=True)
            t.start()

            r = c.post(
                "/command",
                json={"id": "cmd-1", "action": "dump_screen"},
                headers={"Authorization": f"Bearer {RELAY}"},
            )
            t.join(timeout=3)
            assert r.status_code == 200
            assert r.json() == {"id": "cmd-1", "ok": True, "result": {"count": 1}}
            assert seen["cmd"]["action"] == "dump_screen"

    raw_audit = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    assert RELAY not in raw_audit
    assert PHONE not in raw_audit
    assert BOT not in raw_audit


def test_relay_phone_ws_rejects_wrong_token(tmp_path):
    with TestClient(_app(tmp_path)) as c:
        with c.websocket_connect("/phone") as ws:
            with pytest.raises(WebSocketDisconnect) as exc:
                ws.send_json({"type": "hello", "token": "wrong-" + ("x" * 32)})
                ws.receive_text()
            assert exc.value.code == 1008


def test_relay_control_ws_auth_and_forward(tmp_path):
    app = _app(tmp_path)
    with TestClient(app) as c:
        with c.websocket_connect("/control") as bad_ws:
            with pytest.raises(WebSocketDisconnect) as exc:
                bad_ws.send_json({"token": "wrong"})
                bad_ws.receive_text()
            assert exc.value.code == 1008

        with c.websocket_connect("/phone") as pws:
            pws.send_json({"type": "hello", "token": RELAY})
            pws.send_json({"type": "ping"})
            assert pws.receive_json() == {"type": "pong"}

            def _phone_worker():
                cmd = json.loads(pws.receive_text())
                pws.send_text(json.dumps({"id": cmd["id"], "ok": True, "result": "ok"}))

            t = threading.Thread(target=_phone_worker, daemon=True)
            t.start()

            with c.websocket_connect("/control") as cws:
                cws.send_json({"token": RELAY})
                hello_ack = cws.receive_json()
                assert hello_ack == {"ok": True, "phone_online": True}
                cws.send_json({"id": "w1", "action": "home"})
                reply = cws.receive_json()
                assert reply == {"id": "w1", "ok": True, "result": "ok"}
            t.join(timeout=3)


def test_ring_requires_auth_and_404_single_mode(tmp_path):
    with TestClient(_app(tmp_path)) as c:
        assert c.post("/ring", json={"target": "tab"}).status_code == 401
        r = c.post(
            "/ring",
            json={"target": "tab"},
            headers={"Authorization": f"Bearer {RELAY}"},
        )
        assert r.status_code == 404


def test_multi_account_command_and_ring(tmp_path):
    acc_tok = "acct-maras-token-0000000000000000001"
    cfg = {
        "accounts": [
            {
                "id": "maras",
                "identifier_sha256": [identifier_hash("maras@example.com")],
                "token_sha256": sha256_hex(acc_tok),
                "devices": [
                    {"device_id": "redmi", "label": "Redmi"},
                    {"device_id": "tab", "label": "Tablet"},
                ],
            }
        ]
    }
    acc_file = tmp_path / "accounts.json"
    acc_file.write_text(json.dumps(cfg), encoding="utf-8")
    app = _app(tmp_path, relay_accounts_file=str(acc_file))
    with TestClient(app) as c:
        with c.websocket_connect("/phone") as p1, c.websocket_connect("/phone") as p2:
            p1.send_json({"type": "hello", "token": acc_tok, "account": "maras", "device_id": "redmi"})
            p1.send_json({"type": "ping"})
            assert p1.receive_json() == {"type": "pong"}
            p2.send_json({"type": "hello", "token": acc_tok, "account": "maras", "device_id": "tab"})
            p2.send_json({"type": "ping"})
            assert p2.receive_json() == {"type": "pong"}

            def _tab_worker():
                cmd = json.loads(p2.receive_text())
                p2.send_text(json.dumps({"id": cmd["id"], "ok": True, "result": "ringing"}))

            t = threading.Thread(target=_tab_worker, daemon=True)
            t.start()

            r = c.post(
                "/ring",
                json={"target": "tab"},
                headers={"Authorization": f"Bearer {acc_tok}"},
            )
            t.join(timeout=3)
            assert r.status_code == 200
            assert r.json() == {"ok": True, "rang": ["tab"]}

            def _redmi_worker():
                cmd = json.loads(p1.receive_text())
                assert cmd["account"] == "maras"
                assert "device_id" not in cmd
                p1.send_text(json.dumps({"id": cmd["id"], "ok": True, "result": "home_ok"}))

            t2 = threading.Thread(target=_redmi_worker, daemon=True)
            t2.start()
            rc = c.post(
                "/command",
                json={"id": "m1", "action": "home", "device_id": "redmi"},
                headers={"Authorization": f"Bearer {acc_tok}"},
            )
            t2.join(timeout=3)
            assert rc.status_code == 200
            assert rc.json()["result"] == "home_ok"


def test_relay_does_not_break_universe_bot_dry_run_or_401(tmp_path):
    with TestClient(_app(tmp_path)) as c:
        assert c.post("/command", json={"action": "dump_screen"}).status_code == 401
        assert c.post(
            "/command",
            json={"action": "dump_screen"},
            headers={"Authorization": f"Bearer {PHONE}"},
        ).status_code == 401
        r = c.post(
            "/command",
            json={"source": "test-client", "target": "android.phone", "action": "dump_screen", "dry_run": False},
            headers={"Authorization": f"Bearer {BOT}"},
        )
        assert r.status_code == 200
        assert r.json()["dry_run"] is True
        assert r.json()["auth_client"] == "test-client"
