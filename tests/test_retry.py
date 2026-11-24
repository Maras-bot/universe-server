import pytest

from universe.errors import ErrorCode, UniverseError
from universe.models import RetryConfig
from universe.retry import with_retry


@pytest.mark.asyncio
async def test_retries_then_succeeds():
    n = {"i": 0}

    async def flaky():
        n["i"] += 1
        if n["i"] < 3:
            raise UniverseError(ErrorCode.TIMEOUT, "tempo scaduto", retryable=True)
        return "ok"

    sleeps = []

    async def fake_sleep(s):
        sleeps.append(s)

    out = await with_retry(flaky, RetryConfig(max_attempts=3, backoff_seconds=0.01, retry_on=["timeout"]), sleeper=fake_sleep)
    assert out == "ok"
    assert n["i"] == 3
    assert sleeps == [0.01, 0.02]


@pytest.mark.asyncio
async def test_does_not_retry_auth():
    async def boom():
        raise UniverseError(ErrorCode.AUTH, "no")

    with pytest.raises(UniverseError) as ei:
        await with_retry(boom, RetryConfig(max_attempts=5, retry_on=["timeout", "503"]))
    assert ei.value.code == ErrorCode.AUTH
