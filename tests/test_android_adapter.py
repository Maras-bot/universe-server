import httpx
import pytest

from universe.adapters.android import AndroidAdapter
from universe.adapters.base import ExecContext
from universe.errors import ErrorCode, UniverseError
from universe.models import Command, RiskLevel, TargetConfig
from universe.settings import Settings


def _cfg() -> TargetConfig:
    return TargetConfig(
        id="android.phone",
        kind="android",
        endpoint={"base_url": "${RELAY_URL}", "command_path": "/command", "health_path": "/health"},
        auth={"type": "bearer", "token_env": "RELAY_TOKEN"},
    )


def _ctx(dry_run: bool, settings: Settings | None = None) -> ExecContext:
    return ExecContext(settings=settings or Settings(), dry_run=dry_run, risk=RiskLevel.LOW)


@pytest.mark.asyncio
async def test_dry_run_does_not_use_network():
    # Un client che fallisce se viene usato.
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("dry-run non deve chiamare il relay")

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        adapter = AndroidAdapter(_cfg(), client=client)
        cmd = Command(source="ara", target="android.phone", action="dump_screen")
        result = await adapter.execute(cmd, _ctx(True))
    assert result.ok and result.dry_run
    assert result.planned["url"].startswith("${RELAY_URL}")


@pytest.mark.asyncio
async def test_live_posts_to_command(monkeypatch):
    monkeypatch.setenv("RELAY_TOKEN", "tok-test")
    monkeypatch.setenv("RELAY_URL", "http://relay.test")
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["auth"] = request.headers.get("authorization")
        seen["body"] = request.read()
        return httpx.Response(200, json={"id": "1", "ok": True, "result": {"found": True}})

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        adapter = AndroidAdapter(_cfg(), client=client)
        cmd = Command(source="ara", target="android.phone", action="dump_screen", dry_run=False)
        result = await adapter.execute(cmd, _ctx(False))
    assert result.ok and not result.dry_run
    assert result.result == {"found": True}
    assert seen["url"] == "http://relay.test/command"
    assert seen["auth"] == "Bearer tok-test"
    assert b"dump_screen" in seen["body"]


@pytest.mark.asyncio
async def test_phone_offline_503(monkeypatch):
    monkeypatch.setenv("RELAY_TOKEN", "tok-test")
    monkeypatch.setenv("RELAY_URL", "http://relay.test")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, json={"ok": False, "error": "telefono non connesso"})

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        adapter = AndroidAdapter(_cfg(), client=client)
        cmd = Command(source="ara", target="android.phone", action="dump_screen", dry_run=False)
        with pytest.raises(UniverseError) as ei:
            await adapter.execute(cmd, _ctx(False))
    assert ei.value.code == ErrorCode.TARGET_OFFLINE
    assert ei.value.retryable is True


@pytest.mark.asyncio
async def test_planned_never_contains_token(monkeypatch):
    monkeypatch.setenv("RELAY_TOKEN", "super-segreto-non-deve-uscire")
    adapter = AndroidAdapter(_cfg())
    cmd = Command(source="ara", target="android.phone", action="type", params={"text": "ciao"})
    planned = adapter.planned_payload(cmd)
    assert "super-segreto-non-deve-uscire" not in str(planned)
    assert planned["headers"]["Authorization"] == "Bearer [REDATTO]"
