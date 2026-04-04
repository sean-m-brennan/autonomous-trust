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
import sys
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

try:
    from autonomous_trust.services.peer.metadata import (
        PeerData, MetadataProtocol, TimeSource, PositionSource, Metadata,
    )
    from autonomous_trust.services.peer.position import GeoPosition
except ImportError as _e:
    pytestmark = pytest.mark.skip(reason=f"missing dependency: {_e}")


# --- PeerData ---

class TestPeerData:
    def test_creation(self):
        pos = GeoPosition(34.0, -86.0, 100.0)
        now = datetime.now()
        pd = PeerData(now, pos, 5.0, 'drone', 'video', 3)
        assert pd.time == now
        assert pd.position is pos
        assert pd.speed == 5.0
        assert pd.kind == 'drone'
        assert pd.data_type == 'video'
        assert pd.data_channels == 3

    def test_is_configuration(self):
        from autonomous_trust.core.config import Configuration
        pd = PeerData(datetime.now(), GeoPosition(0, 0), 0, 'a', 'b', 1)
        assert isinstance(pd, Configuration)


# --- MetadataProtocol ---

class TestMetadataProtocol:
    def test_attributes(self):
        assert MetadataProtocol.request == 'request'
        assert MetadataProtocol.metadata == 'metadata'


# --- TimeSource ---

class TestTimeSource:
    def test_acquire_returns_datetime(self):
        ts = TimeSource()
        result = ts.acquire()
        assert isinstance(result, datetime)


# --- PositionSource ---

class TestPositionSource:
    def test_acquire_raises(self):
        ps = PositionSource()
        with pytest.raises(NotImplementedError):
            ps.acquire()


# --- Metadata ---

class TestMetadata:
    def test_class_to_name_from_class(self):
        name = Metadata.class_to_name(TimeSource)
        assert name == 'autonomous_trust.services.peer.metadata.TimeSource'

    def test_class_to_name_from_string(self):
        name = Metadata.class_to_name('already.a.string')
        assert name == 'already.a.string'

    def test_name_to_class(self):
        qual_name = 'autonomous_trust.services.peer.metadata.TimeSource'
        klass = Metadata.name_to_class(qual_name)
        assert klass is TimeSource

    def test_name_to_class_roundtrip(self):
        name = Metadata.class_to_name(PositionSource)
        klass = Metadata.name_to_class(name)
        assert klass is PositionSource

    def test_creation(self):
        m = Metadata('uuid-123', 'drone', {'video': 3}, PositionSource, TimeSource)
        assert m.uuid == 'uuid-123'
        assert m.peer_kind == 'drone'
        assert m.data_meta == {'video': 3}

    def test_creation_default_time_source(self):
        m = Metadata('uuid-123', 'drone', {'video': 3}, PositionSource)
        assert 'TimeSource' in m.time_src_class

    def test_position_source_property(self):
        m = Metadata('uuid-123', 'drone', {}, PositionSource)
        ps = m.position_source
        assert isinstance(ps, PositionSource)

    def test_time_source_property(self):
        m = Metadata('uuid-123', 'drone', {}, PositionSource, TimeSource)
        ts = m.time_source
        assert isinstance(ts, TimeSource)


class TestMetadataSourceHandlers:
    def _make_source(self):
        from autonomous_trust.services.peer.metadata import MetadataSource, MetadataProtocol
        src = MagicMock(spec=MetadataSource)
        src.clients = {}
        src.handle_requests = MetadataSource.handle_requests.__get__(src)
        return src

    def test_request_adds_client(self):
        src = self._make_source()
        msg = MagicMock()
        msg.function = MetadataProtocol.request
        msg.from_whom.uuid = 'peer-1'
        result = src.handle_requests(None, msg)
        assert result is True
        assert 'peer-1' in src.clients

    def test_request_duplicate_ignored(self):
        src = self._make_source()
        existing = MagicMock()
        src.clients = {'peer-1': existing}
        msg = MagicMock()
        msg.function = MetadataProtocol.request
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


class TestMetadataSourceProcess:
    def test_process_loop(self):
        import queue as q
        from autonomous_trust.services.peer.metadata import MetadataSource, MetadataProtocol
        from autonomous_trust.core.system import CfgIds
        from autonomous_trust.core.identity import Identity
        src = MagicMock(spec=MetadataSource)
        src.name = 'metadata-source'
        src.q_cadence = 0.01
        src.cadence = 0.01
        src.clients = {'peer-1': MagicMock(spec=Identity)}
        src.protocol = MagicMock()
        src.logger = MagicMock()

        mock_cfg = MagicMock()
        mock_cfg.time_source.acquire.return_value = datetime.now()
        mock_cfg.position_source.acquire.return_value = (GeoPosition(34.0, -86.0, 100.0), 5.0)
        mock_cfg.peer_kind = 'drone'
        mock_cfg.data_type = 'video'
        mock_cfg.data_channels = 3
        src.cfg = mock_cfg

        src.keep_running = MagicMock(side_effect=[True, False])
        src.process = MetadataSource.process.__get__(src)
        my_q = q.Queue()
        net_q = q.Queue()
        queues = {src.name: my_q, CfgIds.network: net_q}
        with patch('autonomous_trust.services.peer.metadata.Message'):
            src.process(queues, MagicMock())
        assert not net_q.empty()

    def test_process_handles_messages(self):
        import queue as q
        from autonomous_trust.services.peer.metadata import MetadataSource
        from autonomous_trust.core.network import Message
        from autonomous_trust.core.system import CfgIds
        src = MagicMock(spec=MetadataSource)
        src.name = 'metadata-source'
        src.q_cadence = 0.01
        src.cadence = 0.01
        src.clients = {}
        src.protocol = MagicMock()
        src.protocol.run_message_handlers.return_value = False
        src.logger = MagicMock()

        mock_cfg = MagicMock()
        mock_cfg.time_source.acquire.return_value = datetime.now()
        mock_cfg.position_source.acquire.return_value = (GeoPosition(0, 0, 0), 0.0)
        mock_cfg.peer_kind = 'test'
        mock_cfg.data_type = 'none'
        mock_cfg.data_channels = 0
        src.cfg = mock_cfg

        src.keep_running = MagicMock(side_effect=[True, False])
        src.process = MetadataSource.process.__get__(src)
        my_q = q.Queue()
        my_q.put(Message('test', 'unknown', 'data'))
        queues = {src.name: my_q, CfgIds.network: q.Queue()}
        src.process(queues, MagicMock())
        src.logger.error.assert_called_once()

    def test_process_non_message_object(self):
        import queue as q
        from autonomous_trust.services.peer.metadata import MetadataSource
        from autonomous_trust.core.system import CfgIds
        src = MagicMock(spec=MetadataSource)
        src.name = 'metadata-source'
        src.q_cadence = 0.01
        src.cadence = 0.01
        src.clients = {}
        src.protocol = MagicMock()
        src.protocol.run_message_handlers.return_value = False
        src.logger = MagicMock()

        mock_cfg = MagicMock()
        mock_cfg.time_source.acquire.return_value = datetime.now()
        mock_cfg.position_source.acquire.return_value = (GeoPosition(0, 0, 0), 0.0)
        mock_cfg.peer_kind = 'test'
        mock_cfg.data_type = 'none'
        mock_cfg.data_channels = 0
        src.cfg = mock_cfg

        src.keep_running = MagicMock(side_effect=[True, False])
        src.process = MetadataSource.process.__get__(src)
        my_q = q.Queue()
        my_q.put("not a message")
        queues = {src.name: my_q, CfgIds.network: q.Queue()}
        src.process(queues, MagicMock())
        src.logger.error.assert_called_once()
        assert 'str' in src.logger.error.call_args[0][0]
