# ******************
#  Copyright 2024 TekFive, Inc. and contributors
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
from uuid import uuid4, UUID

from autonomous_trust.core.config.configuration import Configuration, SerializeMode, WireFormat
from autonomous_trust.core.identity.sign import Signature
from autonomous_trust.core.identity.encrypt import Encryptor
from autonomous_trust.core.identity.identity import Identity
from autonomous_trust.core.identity.group import Group
from autonomous_trust.core.algorithms.agreement import AgreementProof
from autonomous_trust.core.capabilities import Capability, PeerCapabilities
from autonomous_trust.core.structures.dag import LinkedStep
from autonomous_trust.core.identity.history.history import IdentityObj


@pytest.fixture(params=[WireFormat.JSON, WireFormat.BINARY])
def wire_format(request):
    old_mode = Configuration.mode
    old_fmt = Configuration.wire_format
    Configuration.mode = SerializeMode.PROTO
    Configuration.wire_format = request.param
    yield request.param
    Configuration.mode = old_mode
    Configuration.wire_format = old_fmt


class TestSignatureWire:
    def test_round_trip(self, wire_format):
        sig = Signature.generate()
        pub_key = sig.publish()
        data = sig.to_string()
        restored = Signature.from_string(data)
        assert restored.publish() == pub_key
        assert restored.public_only is True


class TestEncryptorWire:
    def test_round_trip(self, wire_format):
        enc = Encryptor.generate()
        pub_key = enc.publish()
        data = enc.to_string()
        restored = Encryptor.from_string(data)
        assert restored.publish() == pub_key
        assert restored.public_only is True


class TestIdentityWire:
    def _make_identity(self):
        sig = Signature.generate()
        enc = Encryptor.generate()
        uid = uuid4()
        return Identity(uid, '127.0.0.1', 'Test User', 'tester', sig, enc,
                        'pet', False, 0)

    def test_round_trip(self, wire_format):
        ident = self._make_identity()
        data = ident.to_string()
        restored = Identity.from_string(data)
        assert str(restored.uuid) == str(ident.uuid)
        assert restored.address == ident.address
        assert restored.fullname == ident.fullname
        assert restored.signature.publish() == ident.signature.publish()
        assert restored.encryptor.publish() == ident.encryptor.publish()
        # Fields lost on wire
        assert restored._nickname == ''
        assert restored.petname == ''
        assert restored._public_only is True


class TestGroupWire:
    def test_round_trip(self, wire_format):
        enc = Encryptor.generate()
        uid = uuid4()
        addr_map = {str(uid): '10.0.0.1'}
        grp = Group(uid, addr_map, 'testgroup', enc, False)
        data = grp.to_string()
        restored = Group.from_string(data)
        assert str(restored.uuid) == str(grp.uuid)
        assert restored.encryptor.publish() == enc.publish()
        # Proto format stores only a single address, not the full map;
        # address_map is lossy on the wire
        assert restored._address_map == {}


class TestAgreementProofWire:
    def test_round_trip(self, wire_format):
        uid = uuid4()
        proof = AgreementProof(uid, b'digest123456', True, b'nonce_value')
        data = proof.to_string()
        restored = AgreementProof.from_string(data)
        assert restored.uuid == uid
        assert restored.digest == b'digest123456'
        assert restored.approval is True
        assert restored.nonce == b'nonce_value'

    def test_round_trip_no_nonce(self, wire_format):
        uid = uuid4()
        proof = AgreementProof(uid, b'digest123456', False, None)
        data = proof.to_string()
        restored = AgreementProof.from_string(data)
        assert restored.uuid == uid
        assert restored.approval is False
        assert restored.nonce is None


class TestCapabilityWire:
    def test_round_trip(self, wire_format):
        cap = Capability('data_fetch', lambda: None, ['arg1'], {'k': 'v'})
        data = cap.to_string()
        restored = Capability.from_string(data)
        assert restored.name == 'data_fetch'
        # Lossy fields
        assert restored.function is None
        assert restored.arg_names is None
        assert restored.keywords is None


class TestPeerCapabilitiesWire:
    def test_round_trip(self, wire_format):
        pc = PeerCapabilities()
        pc.register('peer-1', ['cap_a', 'cap_b'])
        pc.register('peer-2', ['cap_a', 'cap_c'])
        data = pc.to_string()
        restored = PeerCapabilities.from_string(data)
        assert sorted(restored['cap_a']) == sorted(['peer-1', 'peer-2'])
        assert restored['cap_b'] == ['peer-1']
        assert restored['cap_c'] == ['peer-2']


class TestLinkedStepWire:
    def test_round_trip(self, wire_format):
        parent = LinkedStep(payload='parent_data', uuid=uuid4())
        child = LinkedStep(payload='child_data', uuid=uuid4(), parent=parent)
        data = child.to_string()
        restored = LinkedStep.from_string(data)
        assert restored.uuid == child.uuid
        assert restored.parent is not None
        assert restored.parent.uuid == parent.uuid
        # Lossy fields
        assert restored.payload is None
        assert restored.timestamp is None

    def test_genesis_parent(self, wire_format):
        step = LinkedStep(payload='data', uuid=uuid4())
        data = step.to_string()
        restored = LinkedStep.from_string(data)
        from autonomous_trust.core.structures.dag import Genesis
        assert restored.parent is Genesis


class TestIdentityObjWire:
    def test_round_trip(self, wire_format):
        sig = Signature.generate()
        enc = Encryptor.generate()
        uid = uuid4()
        ident = Identity(uid, '127.0.0.1', 'Test User', 'tester', sig, enc, 'pet', False, 0)
        originator = uuid4()
        obj = IdentityObj(ident, originator)
        data = obj.to_string()
        restored = IdentityObj.from_string(data)
        assert restored.originator == originator
        assert str(restored.identity.uuid) == str(uid)
        assert restored.identity.fullname == 'Test User'
        assert restored.identity.signature.publish() == sig.publish()
