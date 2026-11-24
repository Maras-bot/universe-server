import httpx
import pytest

from universe.adapters.base import ExecContext
from universe.adapters.rest_api import RestApiAdapter
from universe.errors import ErrorCode, UniverseError
from universe.models import Command, RiskLevel, TargetConfig
from universe.settings import Settings


def _cfg() -> TargetConfig:
    return TargetConfig(
        id="rest.generic",
        kind="rest_api",
        endpoint={"base_url": "${REST_BASE_URL}"},
        auth={"type": "bearer", "token_env": "REST_API_TOKEN"},
        actions={
            "get_status": {"method": "GET", "path": "/status", "risk": "low"},
            "delete_item": {"method": "DELETE", "path": "/items/{id}", "risk": "high", "path_params": ["id"]},
            "create_item": {"method": "POST", "path": "/items", "risk": "medium", "body_from_params": True},
        },
    )


def _ctx(dry_run: bool) -> ExecContext:
    return ExecContext(settings=Settings(), dry_run=dry_run, risk=RiskLevel.MEDIUM)


@pytest.mark.asyncio
async def test_dry_run_no_http():
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("dry-run non deve chiamare HTTP")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        adapter = RestApiAdapter(_cfg(), client=client)
        cmd = Command(source="ara", target="rest.generic", action="get_status")
        result = await adapter.execute(cmd, _ctx(True))
    assert result.ok and result.dry_run
    assert result.planned["method"] == "GET"
    assert result.planned["url"].endswith("/status")


@pytest.mark.asyncio
async def test_live_create_and_delete(monkeypatch):
    monkeypatch.setenv("REST_API_TOKEN", "rest-tok")
    monkeypatch.setenv("REST_BASE_URL", "https://api.example.test")
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, str(request.url), request.headers.get("authorization"), request.read()))
        if request.method == "POST":
            return httpx.Response(200, json={"id": "9"})
        return httpx.Response(200, json={"deleted": True})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        adapter = RestApiAdapter(_cfg(), client=client)
        created = await adapter.execute(
            Command(source="ara", target="rest.generic", action="create_item", params={"name": "x"}, dry_run=False),
            _ctx(False),
        )
        deleted = await adapter.execute(
            Command(source="ara", target="rest.generic", action="delete_item", params={"id": "9"}, dry_run=False),
            _ctx(False),
        )
    assert created.result == {"id": "9"}
    assert deleted.result == {"deleted": True}
    assert calls[0][0] == "POST"
    assert calls[0][2] == "Bearer rest-tok"
    assert calls[1][0] == "DELETE"
    assert calls[1][1] == "https://api.example.test/items/9"
    assert b"rest-tok" not in calls[0][3]


@pytest.mark.asyncio
async def test_unknown_action():
    adapter = RestApiAdapter(_cfg())
    with pytest.raises(UniverseError) as ei:
        await adapter.execute(
            Command(source="ara", target="rest.generic", action="explode"),
            _ctx(True),
        )
    assert ei.value.code == ErrorCode.UNKNOWN_ACTION
