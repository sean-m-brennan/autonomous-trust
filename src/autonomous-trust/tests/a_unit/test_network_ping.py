import pytest

from autonomous_trust.core.network.ping import PingServer, ping
from autonomous_trust.core.network.async_ping import AsyncPingServer, async_ping


@pytest.mark.asyncio
async def test_async_ping():
    server = await AsyncPingServer('127.0.0.1')
    stats = await async_ping('127.0.0.1')
    server.close()
    assert stats.count == 1
    assert stats.min == stats.avg == stats.max
    assert stats.loss == 0.0


def test_ping_n():
    server = PingServer('127.0.0.1')
    server.start()
    count = 10
    stats = ping('127.0.0.1', count=count)
    server.stop()
    assert stats.count == count
    assert stats.min <= stats.avg <= stats.max
    assert stats.loss == 0.0
