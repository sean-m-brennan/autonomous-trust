# ******************
#  Copyright 2025 Sean M. Brennan and contributors
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
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest

try:
    from autonomous_trust.services.network_statistics import (
        NetworkStats, NetStatsProtocol, NetworkSource, NetStatsSource,
    )
except ImportError as _e:
    pytestmark = pytest.mark.skip(reason=f"missing dependency: {_e}")


# --- NetworkStats ---

class TestNetworkStats:
    def test_creation(self):
        ns = NetworkStats(1.5, 2.5, 100, 200, 3, 4)
        assert ns.up == 1.5
        assert ns.down == 2.5
        assert ns.sent == 100
        assert ns.recv == 200
        assert ns.err_out == 3
        assert ns.err_in == 4

    def test_is_configuration(self):
        from autonomous_trust.core.config import Configuration
        ns = NetworkStats(0, 0, 0, 0, 0, 0)
        assert isinstance(ns, Configuration)


# --- NetStatsProtocol ---

class TestNetStatsProtocol:
    def test_attributes(self):
        assert NetStatsProtocol.request == 'request'
        assert NetStatsProtocol.stats == 'stats'


# --- NetworkSource ---

class TestNetworkSource:
    def test_creation(self):
        ns = NetworkSource('test-proc', 0.5)
        assert ns.name == 'test-proc'
        assert ns.q_cadence == 0.5
        assert ns.latest == {}
        assert ns.net_queue is None

    def test_recv_stores_data(self):
        ns = NetworkSource('test-proc', 0.5)
        data = {'peer1': (1.0, 2.0, 100, 200, 0, 0)}
        ns.recv(data)
        assert ns.latest == data

    def test_acquire_default_uuid(self):
        ns = NetworkSource('test-proc', 0.5)
        ns.latest = {'0': (1.0, 2.0, 100, 200, 0, 0)}
        ns.net_queue = MagicMock()
        # Force past the time check
        ns.last_acq = datetime.now() - timedelta(seconds=60)
        result = ns.acquire()
        assert result == (1.0, 2.0, 100, 200, 0, 0)

    def test_acquire_with_uuid(self):
        ns = NetworkSource('test-proc', 0.5)
        ns.latest = {'peer-123': (5.0, 6.0, 500, 600, 1, 2)}
        ns.net_queue = MagicMock()
        ns.last_acq = datetime.now() - timedelta(seconds=60)
        result = ns.acquire('peer-123')
        assert result == (5.0, 6.0, 500, 600, 1, 2)

    def test_acquire_missing_uuid_returns_zeros(self):
        ns = NetworkSource('test-proc', 0.5)
        ns.latest = {}
        ns.net_queue = MagicMock()
        ns.last_acq = datetime.now() - timedelta(seconds=60)
        result = ns.acquire('missing')
        assert result == (0., 0., 0, 0, 0, 0)

    def test_acquire_sends_message_when_stale(self):
        ns = NetworkSource('test-proc', 0.5)
        ns.latest = {}
        ns.net_queue = MagicMock()
        ns.last_acq = datetime.now() - timedelta(seconds=60)
        ns.acquire()
        ns.net_queue.put.assert_called_once()

    def test_acquire_skips_message_when_recent(self):
        ns = NetworkSource('test-proc', 0.5)
        ns.latest = {}
        ns.net_queue = MagicMock()
        ns.last_acq = datetime.now()  # just now
        ns.acquire()
        ns.net_queue.put.assert_not_called()


# --- NetStatsSource static methods ---

class TestNetStatsSourceStatic:
    def test_acquire_totals(self):
        with patch('autonomous_trust.services.network_statistics.psutil') as mock_psutil:
            mock_io = MagicMock()
            mock_io.bytes_sent = 1000
            mock_io.bytes_recv = 2000
            mock_io.errout = 5
            mock_io.errin = 3
            mock_psutil.net_io_counters.return_value = mock_io
            result = NetStatsSource.acquire_totals()
            assert len(result) == 5
            assert isinstance(result[0], datetime)
            assert result[1] == 1000
            assert result[2] == 2000
            assert result[3] == 5
            assert result[4] == 3


class TestNetStatsSourceComputeRate:
    def test_compute_rate(self):
        t0 = datetime.now()
        t1 = t0 + timedelta(seconds=1)
        src = MagicMock(spec=NetStatsSource)
        src.latest = (t0, 1000, 2000, 0, 0)
        src.acquire_totals = MagicMock(return_value=(t1, 1100, 2200, 0, 0))
        src.compute_rate = NetStatsSource.compute_rate.__get__(src)
        up, down = src.compute_rate()
        assert up == pytest.approx(100.0)
        assert down == pytest.approx(200.0)
        assert src.latest == (t1, 1100, 2200, 0, 0)


class TestNetStatsSourceHandleRequests:
    def _make_source(self):
        src = MagicMock(spec=NetStatsSource)
        src.clients = {}
        src.handle_requests = NetStatsSource.handle_requests.__get__(src)
        return src

    def test_request_adds_client(self):
        src = self._make_source()
        msg = MagicMock()
        msg.function = NetStatsProtocol.request
        msg.from_whom.uuid = 'peer-1'
        result = src.handle_requests(None, msg)
        assert result is True
        assert 'peer-1' in src.clients

    def test_request_duplicate_client(self):
        src = self._make_source()
        existing = MagicMock()
        src.clients = {'peer-1': existing}
        msg = MagicMock()
        msg.function = NetStatsProtocol.request
        msg.from_whom.uuid = 'peer-1'
        result = src.handle_requests(None, msg)
        assert result is True
        assert src.clients['peer-1'] is existing

    def test_wrong_function(self):
        src = self._make_source()
        msg = MagicMock()
        msg.function = 'wrong'
        result = src.handle_requests(None, msg)
        assert result is False


class TestNetStatsSourceProcess:
    def test_process_loop_broadcasts(self):
        import queue as q
        from autonomous_trust.core.system import CfgIds
        from autonomous_trust.core.network import Network
        t0 = datetime.now()
        src = MagicMock(spec=NetStatsSource)
        src.name = 'net-stats-source'
        src.q_cadence = 0.01
        src.cadence = 0.01
        src.clients = {'peer-1': MagicMock()}
        src.protocol = MagicMock()
        src.logger = MagicMock()
        src.latest = (t0, 1000, 2000, 5, 3)
        src.compute_rate = MagicMock(return_value=(10.0, 20.0))
        src.network_source = MagicMock()
        src.network_source.acquire.return_value = (1.0, 2.0, 100, 200, 0, 0)

        src.keep_running = MagicMock(side_effect=[True, False])
        src.process = NetStatsSource.process.__get__(src)
        my_q = q.Queue()
        net_q = q.Queue()
        queues = {src.name: my_q, CfgIds.network: net_q}
        with patch('autonomous_trust.services.network_statistics.Message'):
            src.process(queues, MagicMock())
        assert not net_q.empty()
        assert src.network_source.net_queue is net_q

    def test_process_handles_stats_resp(self):
        import queue as q
        from autonomous_trust.core.system import CfgIds
        from autonomous_trust.core.network import Message, Network
        t0 = datetime.now()
        src = MagicMock(spec=NetStatsSource)
        src.name = 'net-stats-source'
        src.q_cadence = 0.01
        src.cadence = 0.01
        src.clients = {}
        src.protocol = MagicMock()
        src.protocol.run_message_handlers.return_value = False
        src.logger = MagicMock()
        src.latest = (t0, 1000, 2000, 5, 3)
        src.compute_rate = MagicMock(return_value=(0.0, 0.0))
        src.network_source = MagicMock()

        src.keep_running = MagicMock(side_effect=[True, False])
        src.process = NetStatsSource.process.__get__(src)
        my_q = q.Queue()
        stats_msg = Message('net', Network.stats_resp, {'data': 'stats'})
        my_q.put(stats_msg)
        net_q = q.Queue()
        queues = {src.name: my_q, CfgIds.network: net_q}
        src.process(queues, MagicMock())
        src.network_source.recv.assert_called_once_with({'data': 'stats'})

    def test_process_unhandled_message(self):
        import queue as q
        from autonomous_trust.core.system import CfgIds
        from autonomous_trust.core.network import Message
        t0 = datetime.now()
        src = MagicMock(spec=NetStatsSource)
        src.name = 'net-stats-source'
        src.q_cadence = 0.01
        src.cadence = 0.01
        src.clients = {}
        src.protocol = MagicMock()
        src.protocol.run_message_handlers.return_value = False
        src.logger = MagicMock()
        src.latest = (t0, 1000, 2000, 5, 3)
        src.compute_rate = MagicMock(return_value=(0.0, 0.0))
        src.network_source = MagicMock()

        src.keep_running = MagicMock(side_effect=[True, False])
        src.process = NetStatsSource.process.__get__(src)
        my_q = q.Queue()
        my_q.put(Message('test', 'unknown_func', 'data'))
        queues = {src.name: my_q, CfgIds.network: q.Queue()}
        src.process(queues, MagicMock())
        src.logger.error.assert_called()

    def test_process_non_message_object(self):
        import queue as q
        from autonomous_trust.core.system import CfgIds
        t0 = datetime.now()
        src = MagicMock(spec=NetStatsSource)
        src.name = 'net-stats-source'
        src.q_cadence = 0.01
        src.cadence = 0.01
        src.clients = {}
        src.protocol = MagicMock()
        src.protocol.run_message_handlers.return_value = False
        src.logger = MagicMock()
        src.latest = (t0, 1000, 2000, 5, 3)
        src.compute_rate = MagicMock(return_value=(0.0, 0.0))
        src.network_source = MagicMock()

        src.keep_running = MagicMock(side_effect=[True, False])
        src.process = NetStatsSource.process.__get__(src)
        my_q = q.Queue()
        my_q.put("not a message")
        queues = {src.name: my_q, CfgIds.network: q.Queue()}
        src.process(queues, MagicMock())
        src.logger.error.assert_called()
        assert 'str' in src.logger.error.call_args[0][0]
