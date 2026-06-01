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
        import json
        msg = Message('proc', 'func', 'hello')
        b = bytes(msg)
        wire = json.loads(b)
        assert wire['process'] == 'proc'
        assert wire['function'] == 'func'

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


def _real_identity(pid):
    """Build a real Identity (signing capable) for sig-verify tests."""
    import hashlib
    from uuid import UUID, uuid5
    from autonomous_trust.core.algorithms.impl import AgreementImpl
    from autonomous_trust.core.identity.encrypt import Encryptor
    from autonomous_trust.core.identity.sign import Signature
    ns = UUID('00000000-0000-0000-0000-000000000aaa')
    return Identity(
        uuid5(ns, f'test:{pid}'),
        '10.0.0.1', f'{pid}.test', pid,
        Signature(hashlib.sha256(b'test:sig:' + pid.encode()).hexdigest().encode('ascii'),
                  public_only=False),
        Encryptor(hashlib.sha256(b'test:enc:' + pid.encode()).hexdigest().encode('ascii'),
                  public_only=False),
        'me', False, 0, AgreementImpl.POA.value,
    )


class TestMessageSignatureRoundtrip:
    """Regression coverage for BUGS.md P3 (Message.parse / __bytes__ double-hex).

    Before the 2026-05-11 fix, signing a Message with a real Identity and
    then re-parsing the wire form with that identity as the sender returned
    a Message with verified=False because __bytes__ double-hex-encoded the
    signature field and parse() couldn't reconcile the format. The same
    path affected __str__ + parse. The C side and ReputationProtocol's
    Paxos handlers both rely on `verified=True` for legitimately signed
    messages, so the silent failure mis-classified valid traffic.
    """

    def test_bytes_roundtrip_preserves_verified(self):
        sender = _real_identity('alice')
        msg = Message('identity', 'request_access', '{}', from_whom=sender,
                      encrypt=False)
        parsed = Message.parse(bytes(msg), sender)
        assert parsed.verified is True

    def test_str_roundtrip_preserves_verified(self):
        sender = _real_identity('alice')
        msg = Message('identity', 'request_access', '{}', from_whom=sender,
                      encrypt=False)
        parsed = Message.parse(str(msg), sender)
        assert parsed.verified is True

    def test_tampered_payload_yields_unverified(self):
        """Sanity-check the opposite direction: a flipped data byte must
        leave verified=False after parse. Catches a regression where the
        fix accidentally short-circuits to verified=True regardless of
        signature validity."""
        import json
        from base64 import b64decode, b64encode
        sender = _real_identity('alice')
        msg = Message('identity', 'request_access', '{}', from_whom=sender,
                      encrypt=False)
        wire = json.loads(bytes(msg).decode('utf-8'))
        # Replace the encoded payload while leaving the signature intact.
        wire['data'] = b64encode(b'{"tampered":1}').decode('ascii')
        tampered = json.dumps(wire, separators=(',', ':')).encode('utf-8')
        parsed = Message.parse(tampered, sender)
        assert parsed.verified is False


def test_wrapper_dict_with_nested_configuration_stays_a_string():
    """Regression for the partition-probe JSON-decode-error: a payload
    that's a wrapper dict containing a nested Configuration (e.g.
    ``{'from_identity': <Identity>, 'my_group_uuid': '...'}``) used to
    be auto-deserialized in ``Message.__init__`` because the substring
    check ``'"__type__"' in obj`` matched the nested Identity. The
    resulting ``self.obj`` was a Python dict; ``Message.__bytes__``
    then called ``str(self.obj)``, emitting a Python repr (single
    quotes, unquoted keys) instead of JSON. The receiver's
    ``from_json_string(message.obj)`` blew up with "Expecting property
    name enclosed in double quotes". The fix: only adopt the
    deserialized form when the top-level result is a Configuration.

    See network/message.py:97-117 and idprocess.py:handle_partition_probe.
    """
    import json as _json
    from autonomous_trust.core.config import to_json_string, from_json_string
    sender = _real_identity('alice')
    nested_ident = sender.publish()  # nested Configuration in a wrapper dict
    payload = to_json_string({
        'from_identity': nested_ident,
        'my_group_uuid': 'gid-1234',
        'my_group_size': 5,
    })
    msg = Message('identity', 'partition_probe', payload,
                  from_whom=sender, encrypt=False)
    # 1) Payload stays a JSON string — no Python-repr surprises on the wire.
    assert isinstance(msg.obj, str), \
        f"expected str (preserved JSON), got {type(msg.obj).__name__}"
    # 2) The receiver's normal parse path works.
    parsed = from_json_string(msg.obj)
    assert isinstance(parsed, dict)
    assert parsed['my_group_uuid'] == 'gid-1234'
    assert parsed['my_group_size'] == 5
    # 3) End-to-end wire roundtrip survives.
    wire = bytes(msg)
    rehydrated = Message.parse(wire, sender)
    re_parsed = from_json_string(rehydrated.obj)
    assert re_parsed['my_group_uuid'] == 'gid-1234'


def test_top_level_configuration_still_autodeserializes():
    """Companion to the regression test above: when the payload IS a
    single top-level Configuration (the common case — Identity,
    PeerCapabilities, etc.), Message.__init__ must still adopt the
    deserialized form so handlers receive a typed object directly."""
    sender = _real_identity('bob')
    payload = sender.publish().to_json_string()  # single Configuration
    msg = Message('identity', 'announce', payload, from_whom=sender,
                  encrypt=False)
    # Should be the Identity instance, not the raw JSON string.
    assert isinstance(msg.obj, Identity), \
        f"expected Identity (auto-deserialized), got {type(msg.obj).__name__}"
