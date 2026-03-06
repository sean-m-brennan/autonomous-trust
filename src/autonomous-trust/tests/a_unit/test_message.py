import pytest
from unittest.mock import MagicMock, patch

from autonomous_trust.core.network.message import Message
from autonomous_trust.core.network.network import Network
from autonomous_trust.core.identity import Identity, Group


class TestMessage:
    def test_basic_creation(self):
        msg = Message('proc', 'func', 'data')
        assert msg.process == 'proc'
        assert msg.function == 'func'
        assert msg.obj == 'data'
        assert msg.to_whom == []

    def test_process_from_enum(self):
        class FakeEnum:
            value = 'negotiation'
        msg = Message(FakeEnum(), 'func', 'data')
        assert msg.process == 'negotiation'

    def test_to_whom_none(self):
        msg = Message('proc', 'func', 'data', to_whom=None)
        assert msg.to_whom == []

    def test_to_whom_broadcast(self):
        msg = Message('proc', 'func', 'data', to_whom=Network.broadcast)
        assert msg.to_whom == Network.broadcast

    def test_to_whom_identity(self):
        ident = MagicMock(spec=Identity)
        msg = Message('proc', 'func', 'data', to_whom=ident)
        assert msg.to_whom == [ident]

    def test_to_whom_group(self):
        group = MagicMock(spec=Group)
        msg = Message('proc', 'func', 'data', to_whom=group)
        assert msg.to_whom is group

    def test_to_whom_list_identity(self):
        ident1 = MagicMock(spec=Identity)
        ident2 = MagicMock(spec=Identity)
        msg = Message('proc', 'func', 'data', to_whom=[ident1, ident2])
        assert len(msg.to_whom) == 2

    def test_to_whom_invalid_raises(self):
        with pytest.raises(RuntimeError, match='Invalid to_whom'):
            Message('proc', 'func', 'data', to_whom=42)

    def test_to_whom_list_invalid_raises(self):
        with pytest.raises(RuntimeError, match='Invalid to_whom'):
            Message('proc', 'func', 'data', to_whom=['not_identity'])

    def test_str(self):
        msg = Message('proc', 'func', 'hello')
        s = str(msg)
        assert s == 'proc|func|hello'

    def test_bytes(self):
        msg = Message('proc', 'func', 'hello')
        b = bytes(msg)
        assert b == b'proc|func|hello'

    def test_parse_string(self):
        raw = 'proc|func|some data here'
        msg = Message.parse(raw, None, validate=False)
        assert msg.process == 'proc'
        assert msg.function == 'func'
        assert msg.obj == 'some data here'

    def test_parse_bytes(self):
        raw = b'proc|func|data'
        msg = Message.parse(raw, None, validate=False)
        assert msg.process == 'proc'
        assert msg.function == 'func'

    def test_parse_validates_sender(self):
        with pytest.raises(RuntimeError, match='Sender must be an Identity'):
            Message.parse('proc|func|data', 'not_identity', validate=True)

    def test_parse_with_identity_sender(self):
        sender = MagicMock(spec=Identity)
        msg = Message.parse('proc|func|data', sender, validate=True)
        assert msg.from_whom is sender

    def test_roundtrip(self):
        msg = Message('proc', 'func', 'payload')
        raw = str(msg)
        parsed = Message.parse(raw, None, validate=False)
        assert parsed.process == 'proc'
        assert parsed.function == 'func'
        assert parsed.obj == 'payload'

    def test_bytes_roundtrip(self):
        msg = Message('proc', 'func', 'payload')
        raw = bytes(msg)
        parsed = Message.parse(raw, None, validate=False)
        assert parsed.process == 'proc'

    def test_from_whom(self):
        sender = MagicMock(spec=Identity)
        msg = Message('proc', 'func', 'data', from_whom=sender)
        assert msg.from_whom is sender

    def test_return_to(self):
        msg = Message('proc', 'func', 'data', return_to='queue_name')
        assert msg.return_to == 'queue_name'

    def test_encrypt_flag(self):
        msg = Message('proc', 'func', 'data', encrypt=False)
        assert msg.encrypt is False


def test_message_json_string_obj():
    msg = Message('proc', 'func', '{"key": "value"}')
    # Should leave as string since no __type__ tag
    assert msg.obj is not None


def test_message_bytes_conversion():
    msg = Message('proc', 'func', 'data')
    b = bytes(msg)
    assert isinstance(b, bytes)


def test_message_parse_sender_not_identity():
    with pytest.raises(RuntimeError, match='Sender must be an Identity'):
        Message.parse('proc|func|data', 'not_identity')
