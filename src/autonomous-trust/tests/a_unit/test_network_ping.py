# ******************
#  Copyright 2023 TekFive, Inc., Sean M. Brennan, and contributors
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
# ******************

import asyncio
import pytest

from autonomous_trust.core.network.ping import PingServer, ping
from autonomous_trust.core.network.async_ping import AsyncPingServer, async_ping


def test_async_ping():
    async def _run():
        server = await AsyncPingServer('127.0.0.1')
        stats = await async_ping('127.0.0.1')
        server.close()
        return stats

    stats = asyncio.run(_run())
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


from datetime import timedelta
from unittest.mock import MagicMock
from autonomous_trust.core.network.ping import PingStats
from autonomous_trust.core.network.async_ping import _PingServerProtocol, _PingClientProtocol


def test_ping_stats_str():
    stats = PingStats('127.0.0.1', {1: 0.01, 2: 0.02}, timedelta(seconds=0.03))
    s = str(stats)
    assert '127.0.0.1' in s
    assert 'transmitted' in s


def test_ping_stats_with_loss():
    stats = PingStats('127.0.0.1', {1: 0.01, 2: None}, timedelta(seconds=0.03))
    assert stats.loss == 50.0
    assert stats.succeeded == 1
    s = str(stats)
    assert '50' in s


def test_ping_stats_all_none():
    stats = PingStats('127.0.0.1', {1: None}, timedelta(seconds=1.0))
    assert stats.loss == 100.0
    assert stats.min == timedelta(seconds=0)
    assert stats.max == timedelta(seconds=0)
    assert stats.avg == timedelta(seconds=0)


def test_ping_server_protocol_connection_lost():
    proto = _PingServerProtocol()
    proto.connection_lost(None)  # should not raise


def test_ping_server_protocol_error():
    proto = _PingServerProtocol()
    proto.error_received(RuntimeError('test'))
    assert proto._error is not None
    with pytest.raises(RuntimeError):
        proto.raise_error()
    # After raising, error should be cleared
    proto.raise_error()  # should not raise


def test_ping_server_protocol_no_error():
    proto = _PingServerProtocol()
    proto.raise_error()  # should not raise when no error


def test_ping_server_overflow():
    proto = _PingServerProtocol()
    transport = MagicMock()
    proto.connection_made(transport)
    # Send data that causes OverflowError
    huge_data = (2**31).to_bytes(8, 'big')  # very large number
    proto.datagram_received(huge_data, ('127.0.0.1', 1234))
    transport.sendto.assert_called()
