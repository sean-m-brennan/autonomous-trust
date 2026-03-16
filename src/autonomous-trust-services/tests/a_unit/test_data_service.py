import queue
import struct
import warnings
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from autonomous_trust.core.network import Message
from autonomous_trust.core.system import CfgIds
from autonomous_trust.services.data.server import DataProtocol, DataConfig, DataProcess
from autonomous_trust.services.data.client import DataRcvr


# --- DataProtocol ---

class TestDataProtocol:
    def test_attributes(self):
        assert DataProtocol.request == 'request'
        assert DataProtocol.data == 'data'


# --- DataConfig ---

class TestDataConfig:
    def test_creation(self):
        cfg = DataConfig('/dev/video0')
        assert cfg.device_path == '/dev/video0'
        assert cfg.frame_size == 320
        assert cfg.speed == 1
        assert cfg.channels == 1

    def test_creation_custom(self):
        cfg = DataConfig('/dev/video1', frame_size=640, speed=2, channels=3)
        assert cfg.device_path == '/dev/video1'
        assert cfg.frame_size == 640
        assert cfg.speed == 2
        assert cfg.channels == 3

    def test_initialize(self):
        cfg = DataConfig.initialize('/dev/video0', 480, 2, 3)
        assert isinstance(cfg, DataConfig)
        assert cfg.device_path == '/dev/video0'
        assert cfg.frame_size == 480


# --- DataProcess ---

class TestDataProcess:
    def test_header_fmt(self):
        assert DataProcess.header_fmt == "!Q?Q"
        size = struct.calcsize(DataProcess.header_fmt)
        assert size > 0

    def test_capability_name(self):
        assert DataProcess.capability_name == 'data'

    def test_acquire_warns(self):
        # acquire() on base class warns about NotImplementedError
        proc = MagicMock(spec=DataProcess)
        proc.acquire = DataProcess.acquire
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            result = proc.acquire(proc)
            assert len(w) == 1
            assert 'NotImplementedError' in str(w[0].message)
        assert result == [None, None, None]

    def test_handle_requests_adds_client(self):
        proc = MagicMock(spec=DataProcess)
        proc.active = True
        proc.clients = {}
        proc.handle_requests = DataProcess.handle_requests.__get__(proc)
        message = MagicMock()
        message.function = DataProtocol.request
        message.obj = 'my-proc'
        message.from_whom.uuid = 'peer-1'
        result = proc.handle_requests(None, message)
        assert result is True
        assert 'peer-1' in proc.clients

    def test_handle_requests_wrong_function(self):
        proc = MagicMock(spec=DataProcess)
        proc.active = True
        proc.clients = {}
        proc.handle_requests = DataProcess.handle_requests.__get__(proc)
        message = MagicMock()
        message.function = 'wrong'
        result = proc.handle_requests(None, message)
        assert result is False

    def test_handle_requests_inactive(self):
        proc = MagicMock(spec=DataProcess)
        proc.active = False
        proc.clients = {}
        proc.handle_requests = DataProcess.handle_requests.__get__(proc)
        message = MagicMock()
        message.function = DataProtocol.request
        result = proc.handle_requests(None, message)
        assert result is False

    def test_handle_requests_duplicate_client(self):
        proc = MagicMock(spec=DataProcess)
        proc.active = True
        proc.clients = {'peer-1': ('proc', MagicMock())}
        proc.handle_requests = DataProcess.handle_requests.__get__(proc)
        message = MagicMock()
        message.function = DataProtocol.request
        message.obj = 'my-proc'
        message.from_whom.uuid = 'peer-1'
        result = proc.handle_requests(None, message)
        assert result is True
        # Client dict should not be overwritten
        assert proc.clients['peer-1'][0] == 'proc'


class TestDataProcessMessages:
    def _make_proc(self):
        proc = MagicMock(spec=DataProcess)
        proc.name = 'data-source'
        proc.q_cadence = 0.01
        proc.protocol = MagicMock()
        proc.logger = MagicMock()
        proc.process_messages = DataProcess.process_messages.__get__(proc)
        return proc

    def test_empty_queue(self):
        proc = self._make_proc()
        q = queue.Queue()
        queues = {proc.name: q}
        proc.process_messages(queues)
        proc.protocol.run_message_handlers.assert_not_called()

    def test_handled_message(self):
        proc = self._make_proc()
        msg = Message('test', 'func', 'data')
        q = queue.Queue()
        q.put(msg)
        queues = {proc.name: q}
        proc.protocol.run_message_handlers.return_value = True
        proc.process_messages(queues)
        proc.protocol.run_message_handlers.assert_called_once()

    def test_unhandled_message(self):
        proc = self._make_proc()
        msg = Message('test', 'unknown', 'data')
        q = queue.Queue()
        q.put(msg)
        queues = {proc.name: q}
        proc.protocol.run_message_handlers.return_value = False
        proc.process_messages(queues)
        proc.logger.error.assert_called_once()

    def test_unhandled_non_message(self):
        proc = self._make_proc()
        q = queue.Queue()
        q.put("not a message")
        queues = {proc.name: q}
        proc.protocol.run_message_handlers.return_value = False
        proc.process_messages(queues)
        proc.logger.error.assert_called_once()
        assert 'str' in proc.logger.error.call_args[0][0]


class TestDataProcessLoop:
    def test_process_inactive(self):
        proc = MagicMock(spec=DataProcess)
        proc.active = False
        proc.name = 'data-source'
        proc.keep_running = MagicMock(side_effect=[True, False])
        proc.process = DataProcess.process.__get__(proc)
        queues = {proc.name: queue.Queue()}
        proc.process(queues, MagicMock())
        proc.process_messages.assert_called_once()
        proc.acquire.assert_not_called()

    def test_process_active_with_data(self):
        proc = MagicMock(spec=DataProcess)
        proc.active = True
        proc.name = 'data-source'
        proc.q_cadence = 0.01
        peer = MagicMock()
        proc.clients = {'peer-1': ('sink', peer)}
        proc.keep_running = MagicMock(side_effect=[True, False])
        proc.acquire.return_value = [1, 2, 3]
        proc.process = DataProcess.process.__get__(proc)
        net_q = queue.Queue()
        queues = {proc.name: queue.Queue(), CfgIds.network: net_q}
        proc.process(queues, MagicMock())
        assert not net_q.empty()

    def test_process_active_acquire_none(self):
        proc = MagicMock(spec=DataProcess)
        proc.active = True
        proc.name = 'data-source'
        proc.clients = {}
        proc.keep_running = MagicMock(side_effect=[True, False])
        proc.acquire.return_value = None
        proc.process = DataProcess.process.__get__(proc)
        net_q = queue.Queue()
        queues = {proc.name: queue.Queue(), CfgIds.network: net_q}
        proc.process(queues, MagicMock())
        assert net_q.empty()


# --- DataRcvr ---

class TestDataRcvr:
    def test_header_fmt_matches_process(self):
        assert DataRcvr.header_fmt == DataProcess.header_fmt

    def test_handle_data_known_peer(self):
        rcvr = MagicMock(spec=DataRcvr)
        rcvr.q_cadence = 0.01
        rcvr.handle_data = DataRcvr.handle_data.__get__(rcvr)
        peer_mock = MagicMock()
        peer_mock.data_stream = queue.Queue()
        rcvr.cohort = MagicMock()
        rcvr.cohort.peers = {'peer-1': peer_mock}
        msg = MagicMock()
        msg.function = DataProtocol.data
        msg.from_whom.uuid = 'peer-1'
        msg.obj = '{"test": 1}'
        with patch('autonomous_trust.services.data.client.from_yaml_string', return_value={'test': 1}):
            rcvr.handle_data(None, msg)
        assert not peer_mock.data_stream.empty()

    def test_handle_data_unknown_peer(self):
        rcvr = MagicMock(spec=DataRcvr)
        rcvr.q_cadence = 0.01
        rcvr.handle_data = DataRcvr.handle_data.__get__(rcvr)
        rcvr.cohort = MagicMock()
        rcvr.cohort.peers = {}
        msg = MagicMock()
        msg.function = DataProtocol.data
        msg.from_whom.uuid = 'unknown'
        msg.obj = '{"test": 1}'
        with patch('autonomous_trust.services.data.client.from_yaml_string', return_value={'test': 1}):
            rcvr.handle_data(None, msg)  # should not raise

    def test_process_discovers_peers(self):
        from autonomous_trust.core.identity import Identity
        rcvr = MagicMock(spec=DataRcvr)
        rcvr.name = 'data-sink'
        rcvr.q_cadence = 0.01
        rcvr.servicers = []
        rcvr.protocol = MagicMock()
        peer_ident = MagicMock(spec=Identity)
        rcvr.protocol.peer_capabilities = {DataProcess.capability_name: [peer_ident]}
        rcvr.protocol.run_message_handlers.return_value = True
        rcvr.logger = MagicMock()
        rcvr.keep_running = MagicMock(side_effect=[True, False])
        rcvr.process = DataRcvr.process.__get__(rcvr)
        my_q = queue.Queue()
        net_q = queue.Queue()
        queues = {rcvr.name: my_q, CfgIds.network: net_q}
        with patch('autonomous_trust.services.data.client.Message'):
            rcvr.process(queues, MagicMock())
        assert peer_ident in rcvr.servicers
        assert not net_q.empty()

    def test_process_unhandled_message(self):
        rcvr = MagicMock(spec=DataRcvr)
        rcvr.name = 'data-sink'
        rcvr.q_cadence = 0.01
        rcvr.servicers = []
        rcvr.protocol = MagicMock()
        rcvr.protocol.peer_capabilities = {}
        rcvr.protocol.run_message_handlers.return_value = False
        rcvr.logger = MagicMock()
        rcvr.keep_running = MagicMock(side_effect=[True, False])
        rcvr.process = DataRcvr.process.__get__(rcvr)
        my_q = queue.Queue()
        my_q.put(Message('test', 'unknown', 'data'))
        queues = {rcvr.name: my_q, CfgIds.network: queue.Queue()}
        rcvr.process(queues, MagicMock())
        rcvr.logger.error.assert_called()

    def test_process_non_message(self):
        rcvr = MagicMock(spec=DataRcvr)
        rcvr.name = 'data-sink'
        rcvr.q_cadence = 0.01
        rcvr.servicers = []
        rcvr.protocol = MagicMock()
        rcvr.protocol.peer_capabilities = {}
        rcvr.protocol.run_message_handlers.return_value = False
        rcvr.logger = MagicMock()
        rcvr.keep_running = MagicMock(side_effect=[True, False])
        rcvr.process = DataRcvr.process.__get__(rcvr)
        my_q = queue.Queue()
        my_q.put("not a message")
        queues = {rcvr.name: my_q, CfgIds.network: queue.Queue()}
        rcvr.process(queues, MagicMock())
        rcvr.logger.error.assert_called()
        assert 'str' in rcvr.logger.error.call_args[0][0]
