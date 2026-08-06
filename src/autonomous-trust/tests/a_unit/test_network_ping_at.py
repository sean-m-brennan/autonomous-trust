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

from autonomous_trust.core.network.ping_at import PingATServer, ping_at
from autonomous_trust.core.network.async_ping_at import AsyncPingATServer, async_ping_at


def test_async_ping():
    async def _run():
        server = await AsyncPingATServer('127.0.0.1')
        stats = await async_ping_at('127.0.0.1')
        server.close()
        return stats

    stats = asyncio.run(_run())
    assert stats.count == 1
    assert stats.min == stats.avg == stats.max
    assert stats.loss == 0.0


def test_ping_n():
    server = PingATServer('127.0.0.1')
    server.start()
    count = 10
    stats = ping_at('127.0.0.1', count=count)
    server.stop()
    assert stats.count == count
    assert stats.min <= stats.avg <= stats.max
    assert stats.loss == 0.0


from datetime import timedelta
from unittest.mock import MagicMock, patch
from autonomous_trust.core.network.ping_at import PingATStats
from autonomous_trust.core.network.async_ping_at import _PingATServerProtocol, _PingATClientProtocol


def test_ping_stats_str():
    stats = PingATStats('127.0.0.1', {1: 0.01, 2: 0.02}, timedelta(seconds=0.03))
    s = str(stats)
    assert '127.0.0.1' in s
    assert 'transmitted' in s


def test_ping_stats_with_loss():
    stats = PingATStats('127.0.0.1', {1: 0.01, 2: None}, timedelta(seconds=0.03))
    assert stats.loss == 50.0
    assert stats.succeeded == 1
    s = str(stats)
    assert '50' in s


def test_ping_stats_all_none():
    stats = PingATStats('127.0.0.1', {1: None}, timedelta(seconds=1.0))
    assert stats.loss == 100.0
    assert stats.min == timedelta(seconds=0)
    assert stats.max == timedelta(seconds=0)
    assert stats.avg == timedelta(seconds=0)


def test_ping_server_protocol_connection_lost():
    proto = _PingATServerProtocol()
    proto.connection_lost(None)  # should not raise


def test_ping_server_protocol_error():
    proto = _PingATServerProtocol()
    proto.error_received(RuntimeError('test'))
    assert proto._error is not None
    with pytest.raises(RuntimeError):
        proto.raise_error()
    # After raising, error should be cleared
    proto.raise_error()  # should not raise


def test_ping_server_protocol_no_error():
    proto = _PingATServerProtocol()
    proto.raise_error()  # should not raise when no error


def test_ping_server_overflow():
    proto = _PingATServerProtocol()
    transport = MagicMock()
    proto.connection_made(transport)
    # Send data that causes OverflowError
    huge_data = (2**31).to_bytes(8, 'big')  # very large number
    proto.datagram_received(huge_data, ('127.0.0.1', 1234))
    transport.sendto.assert_called()


# --- the reply has to name the peer it measured ----------------------------
# PingATStats knows only the ADDRESS it dialed, while every consumer keys peers
# by Identity UUID, so a reply carrying no identity leaves a correct rtt with
# nothing to attach it to (measured 2026-08-05: the inspector's latency panel
# and the bridge's ping_at event both had to guess, and got "?").

def test_ping_at_reply_carries_the_pinged_peer():
    from autonomous_trust.core.network import Network
    from autonomous_trust.core.network.netprocess import NetworkProcess

    proc = MagicMock(spec=NetworkProcess)
    proc.name = 'network'
    proc.q_cadence = 0.01
    proc._do_ping_at_async = NetworkProcess._do_ping_at_async.__get__(proc)

    stats = PingATStats('10.0.0.7', {0: 0.01}, timedelta(seconds=0.01))
    peer = MagicMock()
    peer.uuid = 'uuid-noaa-1'
    sent = []

    with patch('autonomous_trust.core._python.network.netprocess.ping_at',
               return_value=stats):
        proc._do_ping_at_async('10.0.0.7', 1,
                               MagicMock(put=lambda m, **kw: sent.append(m)),
                               peer)

    assert len(sent) == 1
    msg = sent[0]
    assert msg.function == Network.ping_at
    assert msg.obj is stats
    # Message wraps a lone Identity in a list for to_whom; from_whom is passed
    # through as given.
    assert msg.from_whom is peer


def test_ping_at_reply_without_a_peer_is_still_sent():
    """A caller that supplies no peer must not lose the sample entirely."""
    from autonomous_trust.core.network.netprocess import NetworkProcess

    proc = MagicMock(spec=NetworkProcess)
    proc.name = 'network'
    proc.q_cadence = 0.01
    proc._do_ping_at_async = NetworkProcess._do_ping_at_async.__get__(proc)

    stats = PingATStats('10.0.0.7', {0: 0.01}, timedelta(seconds=0.01))
    sent = []
    with patch('autonomous_trust.core._python.network.netprocess.ping_at',
               return_value=stats):
        proc._do_ping_at_async('10.0.0.7', 1,
                               MagicMock(put=lambda m, **kw: sent.append(m)))
    assert len(sent) == 1
    assert sent[0].from_whom is None
