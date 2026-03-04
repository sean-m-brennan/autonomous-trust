import pytest
import logging
from unittest.mock import MagicMock, patch

from autonomous_trust.core.protocol import Protocol
from autonomous_trust.core.system import CfgIds
from autonomous_trust.core.network.message import Message
from autonomous_trust.core.identity import Group, Peers
from autonomous_trust.core.capabilities import Capabilities, PeerCapabilities


class TestProtocol:
    def test_init_no_configs(self):
        logger = logging.getLogger('test')
        p = Protocol('test_proc', logger, None)
        assert p.proc_name == 'test_proc'
        assert isinstance(p.peers, Peers)
        assert isinstance(p.peer_capabilities, PeerCapabilities)
        assert p.group is None
        assert p.handlers == {}

    def test_init_with_configs(self):
        logger = logging.getLogger('test')
        peers = Peers()
        pc = PeerCapabilities()
        group = MagicMock(spec=Group)
        configs = {
            CfgIds.peers: peers,
            CfgIds.capabilities: pc,
            CfgIds.group: group,
        }
        p = Protocol('test_proc', logger, configs)
        assert p.peers is peers
        assert p.peer_capabilities is pc
        assert p.group is group

    def test_register_handler(self):
        logger = logging.getLogger('test')
        p = Protocol('test_proc', logger, None)
        handler = MagicMock()
        p.register_handler('do_something', handler)
        assert 'do_something' in p.handlers

    def test_handle_group(self):
        logger = logging.getLogger('test')
        p = Protocol('test_proc', logger, None)
        group = MagicMock(spec=Group)
        result = p.run_message_handlers({'q': MagicMock()}, group)
        assert result is True
        assert p.group is group

    def test_handle_peers(self):
        logger = logging.getLogger('test')
        p = Protocol('test_proc', logger, None)
        peers = Peers()
        result = p.run_message_handlers({'q': MagicMock()}, peers)
        assert result is True
        assert p.peers is peers

    def test_handle_capabilities(self):
        logger = logging.getLogger('test')
        p = Protocol('test_proc', logger, None)
        caps = Capabilities()
        result = p.run_message_handlers({'q': MagicMock()}, caps)
        assert result is True
        assert p.capabilities is caps

    def test_handle_peer_capabilities(self):
        logger = logging.getLogger('test')
        p = Protocol('test_proc', logger, None)
        pc = PeerCapabilities()
        result = p.run_message_handlers({'q': MagicMock()}, pc)
        assert result is True
        assert p.peer_capabilities is pc

    def test_handle_message_dispatches(self):
        logger = logging.getLogger('test')
        p = Protocol('test_proc', logger, None)
        handler = MagicMock(return_value=True)
        p.register_handler('do_it', handler)

        msg = Message('test_proc', 'do_it', 'payload')
        result = p.run_message_handlers({'q': MagicMock()}, msg)
        assert result is True
        handler.assert_called_once()

    def test_handle_message_wrong_process(self):
        logger = logging.getLogger('test')
        p = Protocol('test_proc', logger, None)
        handler = MagicMock(return_value=True)
        p.register_handler('do_it', handler)

        msg = Message('other_proc', 'do_it', 'payload')
        result = p.run_message_handlers({'q': MagicMock()}, msg)
        assert result is False

    def test_handle_message_wrong_function(self):
        logger = logging.getLogger('test')
        p = Protocol('test_proc', logger, None)
        handler = MagicMock(return_value=True)
        p.register_handler('do_it', handler)

        msg = Message('test_proc', 'other_func', 'payload')
        result = p.run_message_handlers({'q': MagicMock()}, msg)
        assert result is False

    def test_empty_queues_fails_contract(self):
        logger = logging.getLogger('test')
        p = Protocol('test_proc', logger, None)
        msg = Message('test_proc', 'func', 'data')
        with pytest.raises(Exception):
            p.run_message_handlers({}, msg)

    def test_none_message_fails_contract(self):
        logger = logging.getLogger('test')
        p = Protocol('test_proc', logger, None)
        with pytest.raises(Exception):
            p.run_message_handlers({'q': MagicMock()}, None)
