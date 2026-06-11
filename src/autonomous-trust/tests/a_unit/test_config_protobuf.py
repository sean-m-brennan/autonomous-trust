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

import os
import tempfile
import uuid as uuid_mod

import pytest

from autonomous_trust.core.config import Configuration
from autonomous_trust.core.config.configuration import SerializeMode, to_yaml_string, from_yaml_string
from autonomous_trust.core.identity.sign import Signature
from autonomous_trust.core.identity.encrypt import Encryptor
from autonomous_trust.core.identity.identity import Identity
from autonomous_trust.core.identity.group import Group
from autonomous_trust.core.algorithms.agreement import AgreementProof
from autonomous_trust.core.capabilities import Capability, PeerCapabilities
from autonomous_trust.core.structures.dag import LinkedStep
from autonomous_trust.core.identity.history.history import IdentityObj
from autonomous_trust.core.protobuf.identity import identity_pb2
from autonomous_trust.core.protobuf.algorithms import agreement_pb2
from autonomous_trust.core.protobuf.processes import capabilities_pb2
from autonomous_trust.core.protobuf.structures import dag_pb2
from autonomous_trust.core.protobuf.identity import history_pb2


# ---- Fixtures ----

@pytest.fixture
def sig():
    return Signature.generate()


@pytest.fixture
def enc():
    return Encryptor.generate()


@pytest.fixture
def identity(sig, enc):
    return Identity(
        uuid_mod.uuid4(), '192.168.1.1', 'Test User',
        Signature(sig.publish(), True), Encryptor(enc.publish(), True),
        petname='tester', _public_only=True
    )


# ---- Proto message classes are assigned ----

def test_signature_has_message(sig):
    pub_sig = Signature(sig.publish(), True)
    assert hasattr(pub_sig, 'message')
    assert isinstance(pub_sig.message, identity_pb2.Signature)


def test_encryptor_has_message(enc):
    pub_enc = Encryptor(enc.publish(), True)
    assert hasattr(pub_enc, 'message')
    assert isinstance(pub_enc.message, identity_pb2.Encryptor)


def test_identity_has_message(identity):
    assert hasattr(identity, 'message')
    assert isinstance(identity.message, identity_pb2.Identity)


def test_group_has_message(enc):
    grp = Group(uuid_mod.uuid4(), {'peer1': '10.0.0.1'}, 'test-group',
                Encryptor(enc.publish(), True))
    assert hasattr(grp, 'message')
    assert isinstance(grp.message, identity_pb2.Group)


def test_agreement_proof_no_proto_init():
    """AgreementProof does not call super().__init__(msg_class) yet."""
    proof = AgreementProof(uuid_mod.uuid4(), b'digest123', True, b'nonce456')
    assert proof.approval is True
    assert proof.digest == b'digest123'


def test_capability_has_message():
    cap = Capability('video_stream')
    assert hasattr(cap, 'message')
    assert isinstance(cap.message, capabilities_pb2.Capability)


def test_peer_capabilities_has_message():
    pc = PeerCapabilities()
    assert hasattr(pc, 'message')
    assert isinstance(pc.message, capabilities_pb2.PeerCapabilities)


def test_linked_step_no_proto_init():
    """LinkedStep does not call super().__init__(msg_class) yet."""
    step = LinkedStep(payload=b'test_payload')
    assert step.payload == b'test_payload'


# ---- sync_to/from_message roundtrips ----

def test_signature_sync_roundtrip(sig):
    pub_sig = Signature(sig.publish(), True)
    pub_sig.sync_to_message()
    raw = pub_sig.message.SerializeToString()

    restored = object.__new__(Signature)
    restored.message = identity_pb2.Signature()
    restored.message.ParseFromString(raw)
    restored.sync_from_message()

    assert restored.publish() == pub_sig.publish()
    assert restored.public_only is True


def test_encryptor_sync_roundtrip(enc):
    pub_enc = Encryptor(enc.publish(), True)
    pub_enc.sync_to_message()
    raw = pub_enc.message.SerializeToString()

    restored = object.__new__(Encryptor)
    restored.message = identity_pb2.Encryptor()
    restored.message.ParseFromString(raw)
    restored.sync_from_message()

    assert restored.publish() == pub_enc.publish()
    assert restored.public_only is True


def test_identity_sync_roundtrip(identity):
    identity.sync_to_message()
    raw = identity.message.SerializeToString()

    restored = object.__new__(Identity)
    restored.message = identity_pb2.Identity()
    restored.message.ParseFromString(raw)
    restored.sync_from_message()

    assert restored.uuid == identity.uuid
    assert restored.nickname == identity.nickname
    assert restored.address == identity.address
    assert restored.signature.publish() == identity.signature.publish()
    assert restored.encryptor.publish() == identity.encryptor.publish()


def test_group_sync_roundtrip(enc):
    grp = Group(uuid_mod.uuid4(), {'peer1': '10.0.0.1'}, 'test-group',
                Encryptor(enc.publish(), True))
    grp.sync_to_message()
    raw = grp.message.SerializeToString()

    restored = object.__new__(Group)
    restored.message = identity_pb2.Group()
    restored.message.ParseFromString(raw)
    restored.sync_from_message()

    assert restored.uuid == grp.uuid
    assert restored.encryptor.publish() == grp.encryptor.publish()


def test_agreement_proof_sync_roundtrip():
    uid = uuid_mod.uuid4()
    proof = AgreementProof(uid, b'digest123', True, b'nonce456')
    proof.sync_to_message()
    raw = proof.message.SerializeToString()

    restored = object.__new__(AgreementProof)
    restored.message = agreement_pb2.AgreementProof()
    restored.message.ParseFromString(raw)
    restored.sync_from_message()

    assert restored.uuid == proof.uuid
    assert restored.digest == proof.digest
    assert restored.approval == proof.approval
    assert restored.nonce == proof.nonce


def test_capability_sync_roundtrip():
    cap = Capability('video_stream')
    cap.sync_to_message()
    raw = cap.message.SerializeToString()

    restored = object.__new__(Capability)
    restored.message = capabilities_pb2.Capability()
    restored.message.ParseFromString(raw)
    restored.sync_from_message()

    assert restored.name == cap.name


def test_peer_capabilities_sync_roundtrip():
    pc = PeerCapabilities()
    pc.register('peer-1', ['video', 'audio'])
    pc.register('peer-2', ['video'])
    pc.sync_to_message()
    raw = pc.message.SerializeToString()

    restored = object.__new__(PeerCapabilities)
    restored.message = capabilities_pb2.PeerCapabilities()
    restored.message.ParseFromString(raw)
    restored.sync_from_message()

    assert set(restored._listing.keys()) == set(pc._listing.keys())
    for key in pc._listing:
        assert sorted(restored._listing[key]) == sorted(pc._listing[key])


def test_linked_step_sync_roundtrip():
    step = LinkedStep(payload=b'test_payload')
    step.sync_to_message()
    raw = step.message.SerializeToString()

    restored = object.__new__(LinkedStep)
    restored.message = dag_pb2.LinkedStep()
    restored.message.ParseFromString(raw)
    restored.sync_from_message()

    assert restored.uuid == step.uuid


def test_identity_obj_sync_roundtrip(identity):
    originator = uuid_mod.uuid4()
    idobj = IdentityObj(identity, originator)
    idobj.sync_to_message()
    raw = idobj.message.SerializeToString()

    restored = object.__new__(IdentityObj)
    restored.message = history_pb2.IdBlob()
    restored.message.ParseFromString(raw)
    restored.sync_from_message()

    assert restored.originator == idobj.originator
    assert restored.identity.uuid == idobj.identity.uuid
    assert restored.identity.nickname == idobj.identity.nickname


# ---- wire bytes roundtrips ----

def test_signature_wire_bytes(sig):
    pub_sig = Signature(sig.publish(), True)
    raw = pub_sig.to_wire_bytes()
    assert isinstance(raw, bytes)
    restored = Signature.from_wire_bytes(raw)
    assert restored.publish() == pub_sig.publish()


def test_encryptor_wire_bytes(enc):
    pub_enc = Encryptor(enc.publish(), True)
    raw = pub_enc.to_wire_bytes()
    assert isinstance(raw, bytes)
    restored = Encryptor.from_wire_bytes(raw)
    assert restored.publish() == pub_enc.publish()


def test_identity_wire_bytes(identity):
    raw = identity.to_wire_bytes()
    assert isinstance(raw, bytes)
    restored = Identity.from_wire_bytes(raw)
    assert restored.uuid == identity.uuid
    assert restored.nickname == identity.nickname
    assert restored.signature.publish() == identity.signature.publish()
    assert restored.encryptor.publish() == identity.encryptor.publish()


def test_group_wire_bytes(enc):
    grp = Group(uuid_mod.uuid4(), {'peer1': '10.0.0.1'}, 'test-group',
                Encryptor(enc.publish(), True))
    raw = grp.to_wire_bytes()
    assert isinstance(raw, bytes)
    restored = Group.from_wire_bytes(raw)
    assert restored.uuid == grp.uuid
    assert restored.encryptor.publish() == grp.encryptor.publish()


def test_agreement_proof_wire_bytes():
    proof = AgreementProof(uuid_mod.uuid4(), b'digest123', True, b'nonce456')
    raw = proof.to_wire_bytes()
    assert isinstance(raw, bytes)
    restored = AgreementProof.from_wire_bytes(raw)
    assert restored.uuid == proof.uuid
    assert restored.digest == proof.digest
    assert restored.approval == proof.approval


def test_capability_wire_bytes():
    cap = Capability('video_stream')
    raw = cap.to_wire_bytes()
    assert isinstance(raw, bytes)
    restored = Capability.from_wire_bytes(raw)
    assert restored.name == cap.name


def test_peer_capabilities_wire_bytes():
    pc = PeerCapabilities()
    pc.register('peer-1', ['video', 'audio'])
    pc.register('peer-2', ['video'])
    raw = pc.to_wire_bytes()
    assert isinstance(raw, bytes)
    restored = PeerCapabilities.from_wire_bytes(raw)
    assert set(restored._listing.keys()) == set(pc._listing.keys())
    for key in pc._listing:
        assert sorted(restored._listing[key]) == sorted(pc._listing[key])


def test_linked_step_wire_bytes():
    step = LinkedStep(payload=b'test_payload')
    raw = step.to_wire_bytes()
    assert isinstance(raw, bytes)
    restored = LinkedStep.from_wire_bytes(raw)
    assert restored.uuid == step.uuid


# ---- YAML disk I/O unchanged ----

class SimpleTestCfg(Configuration):
    def __init__(self, name='default', value=42):
        self.name = name
        self.value = value


def test_json_file_io():
    """to_file/from_file use JSON."""
    cfg = SimpleTestCfg('proto_test', 99)
    with tempfile.NamedTemporaryFile(mode='w', suffix='.cfg.json', delete=False) as f:
        filepath = f.name
    try:
        cfg.to_file(filepath)
        with open(filepath, 'r') as f:
            content = f.read()
        assert 'proto_test' in content

        restored = Configuration.from_file(filepath)
        assert restored.name == 'proto_test'
        assert restored.value == 99
    finally:
        os.unlink(filepath)


def test_to_json_string_plain_types():
    """Non-Configuration objects serialize as JSON."""
    s = to_yaml_string({'key': 'value'})
    restored = from_yaml_string(s)
    assert restored == {'key': 'value'}


def test_json_mode_to_from_string():
    """Verify JSON mode works for to_string/from_string."""
    cfg = SimpleTestCfg('json_test', 7)
    s = cfg.to_string()
    assert 'json_test' in s
    restored = Configuration.from_string(s)
    assert restored.name == 'json_test'
