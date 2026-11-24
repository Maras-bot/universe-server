import pytest

from universe.errors import ErrorCode
from universe.models import Command, CommandStatus, RiskLevel


@pytest.mark.asyncio
async def test_unknown_target(router):
    result = await router.dispatch(Command(source="ara", target="no.such", action="ping"))
    assert result.ok is False
    assert result.error_code == ErrorCode.UNKNOWN_TARGET


@pytest.mark.asyncio
async def test_unknown_android_action(router):
    result = await router.dispatch(Command(source="ara", target="android.phone", action="explode"))
    assert result.ok is False
    assert result.error_code == ErrorCode.UNKNOWN_ACTION


@pytest.mark.asyncio
async def test_dry_run_dump_screen_ok(router):
    cmd = Command(source="ara", target="android.phone", action="dump_screen", dry_run=True)
    result = await router.dispatch(cmd)
    assert result.ok is True
    assert result.dry_run is True
    assert result.status == CommandStatus.DRY_RUN
    assert result.planned["action"] == "dump_screen"
    assert "Bearer [REDATTO]" in result.planned["headers"]["Authorization"]


@pytest.mark.asyncio
async def test_live_forced_to_dry_run_when_allow_live_false(router):
    cmd = Command(source="ara", target="android.phone", action="dump_screen", dry_run=False)
    result = await router.dispatch(cmd)
    assert result.ok is True
    assert result.dry_run is True


@pytest.mark.asyncio
async def test_high_risk_requires_confirmation_and_blocks(router):
    cmd = Command(
        source="ara",
        target="rest.generic",
        action="delete_item",
        params={"id": "abc"},
        dry_run=True,
        idempotency_key="del-1",
    )
    result = await router.dispatch(cmd)
    assert result.ok is False
    assert result.status == CommandStatus.CONFIRMATION_REQUIRED
    assert result.confirmation_id
    # Seconda chiamata, stessa chiave: ancora in attesa, non esegue.
    again = await router.dispatch(cmd)
    assert again.status == CommandStatus.CONFIRMATION_REQUIRED
    assert again.confirmation_id == result.confirmation_id


@pytest.mark.asyncio
async def test_approve_then_dry_run_executes(router):
    cmd = Command(
        source="ara",
        target="rest.generic",
        action="delete_item",
        params={"id": "abc"},
        dry_run=True,
        idempotency_key="del-2",
    )
    pending = await router.dispatch(cmd)
    router.confirmations.decide(pending.confirmation_id, True, approver="maras")
    result = await router.dispatch(cmd)
    assert result.ok is True
    assert result.dry_run is True
    assert result.planned["method"] == "DELETE"
    assert result.planned["url"].endswith("/items/abc")


@pytest.mark.asyncio
async def test_deny_blocks(router):
    cmd = Command(
        source="ara",
        target="rest.generic",
        action="delete_item",
        params={"id": "abc"},
        idempotency_key="del-3",
    )
    pending = await router.dispatch(cmd)
    router.confirmations.decide(pending.confirmation_id, False, approver="maras")
    result = await router.dispatch(cmd)
    assert result.ok is False
    assert result.status == CommandStatus.DENIED
    assert result.error_code == ErrorCode.CONFIRMATION_DENIED


@pytest.mark.asyncio
async def test_pay_is_critical_even_in_dry_run(router):
    cmd = Command(source="bot", target="rest.generic", action="pay", params={"amount": 5, "iban": "IT00"})
    result = await router.dispatch(cmd)
    assert result.status == CommandStatus.CONFIRMATION_REQUIRED
    assert result.risk == RiskLevel.CRITICAL


@pytest.mark.asyncio
async def test_open_protected_app_needs_confirm(router):
    cmd = Command(
        source="ara",
        target="android.phone",
        action="open_app",
        params={"package": "com.paypal.android.p2pmobile"},
    )
    result = await router.dispatch(cmd)
    assert result.status == CommandStatus.CONFIRMATION_REQUIRED
    assert result.risk == RiskLevel.HIGH


@pytest.mark.asyncio
async def test_idempotency_returns_cached_success(router):
    cmd = Command(
        source="ara",
        target="android.phone",
        action="youtube_status",
        idempotency_key="same-key",
    )
    first = await router.dispatch(cmd)
    second = await router.dispatch(cmd)
    assert first.ok and second.ok
    assert first.id == cmd.id
    assert second.status == first.status


@pytest.mark.asyncio
async def test_rate_limit(router):
    target = router.registry.get("android.phone")
    target.rate_limit.requests_per_minute = 2
    results = []
    for i in range(3):
        results.append(
            await router.dispatch(
                Command(
                    source="ara",
                    target="android.phone",
                    action="dump_screen",
                    idempotency_key=f"rl-{i}",
                )
            )
        )
    assert results[0].ok and results[1].ok
    assert results[2].ok is False
    assert results[2].error_code == ErrorCode.RATE_LIMITED
    assert results[2].retryable is True


@pytest.mark.asyncio
async def test_browser_and_zapier_dry_run_without_adapter(router):
    browser = await router.dispatch(
        Command(source="ara", target="browser.local", action="goto", params={"url": "https://example.com"})
    )
    assert browser.ok and browser.dry_run
    zap = await router.dispatch(Command(source="ara", target="zapier.main", action="notify", params={"text": "ciao"}))
    assert zap.ok and zap.dry_run


@pytest.mark.asyncio
async def test_zapier_send_requires_confirmation(router):
    result = await router.dispatch(
        Command(source="ara", target="zapier.main", action="send", params={"to": "x", "message": "ciao"})
    )
    assert result.status == CommandStatus.CONFIRMATION_REQUIRED
