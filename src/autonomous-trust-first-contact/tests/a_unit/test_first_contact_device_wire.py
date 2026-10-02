# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
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
"""Phase 4 slice 1b: the device cert pushed to contacts, and a new device
announcing itself (first_contact/device_contact.py). Handler logic against a
process stub, as test_first_contact_handshake does."""
import json
import logging
import os
import queue
import types

import pytest
from nacl.signing import SigningKey

from autonomous_trust.core.identity import Identity, Peers
from autonomous_trust.core.identity.protocol import CORE_UNENCRYPTED_VERBS
from autonomous_trust.first_contact.fc_protocol import FirstContactProtocol
from autonomous_trust.core.system import CfgIds
from autonomous_trust.core.config import Configuration
from autonomous_trust.first_contact import (Contact, Contacts, adopt_operator,
                                           create_device_cert)
from autonomous_trust.first_contact import first_contact as fc
from autonomous_trust.first_contact._python import device_contact as dc


@pytest.fixture(autouse=True)
def _root(monkeypatch, tmp_path):
    monkeypatch.setenv(Configuration.ROOT_VARIABLE_NAME, str(tmp_path))
    os.makedirs(Configuration.get_cfg_dir(), exist_ok=True)


class StubProc:
    def __init__(self, identity):
        self.name = CfgIds.identity
        self.identity = identity
        self.peers = Peers()
        self.logger = logging.getLogger('test-device-wire')
        self.q_cadence = 1.0
        self.record_peers_calls = 0
        self._first_contact_nonces = fc.SpentNonces()
        self._device_cert_cache = (None, None)

    def _record_peers(self, queues):
        self.record_peers_calls += 1


def _identity(name, addr='10.0.0.9'):
    return Identity.initialize(name, name, addr)


def _inbound(sender, obj):
    return types.SimpleNamespace(from_whom=sender.publish(), obj=obj)


def _install_cert(operator, identity):
    cert = create_device_cert(operator, identity)
    with open(dc.device_cert_path(), 'w') as fh:
        json.dump(cert.to_wire(), fh)
    return cert


def _queues():
    return {CfgIds.network: queue.Queue(), CfgIds.main: queue.Queue()}


def _drain(q):
    out = []
    while not q.empty():
        out.append(q.get_nowait())
    return out


@pytest.fixture
def operator():
    return SigningKey.generate()


@pytest.fixture
def phone():
    return _identity('alice-phone', '10.0.0.1')


@pytest.fixture
def laptop():
    return _identity('alice-laptop', '10.0.0.3')


@pytest.fixture
def bob():
    return _identity('bob', '10.0.0.2')


def _bob_knows_alice(bob_proc, phone, operator, verified=True):
    store = fc._contacts_store(bob_proc)
    contact = Contact(phone.publish())
    if verified:
        contact.mark_verified()
    assert adopt_operator(contact, create_device_cert(operator, phone), store) == ''
    store.add(contact)
    store.save()
    return contact


def test_announce_is_plaintext_and_cert_is_not():
    from autonomous_trust.first_contact import first_contact
    declared = first_contact.EXTENSION.plaintext_verbs
    assert FirstContactProtocol.device_announce in declared
    assert FirstContactProtocol.device_announce not in CORE_UNENCRYPTED_VERBS
    assert FirstContactProtocol.device_cert not in declared
    assert FirstContactProtocol.device_cert not in CORE_UNENCRYPTED_VERBS


# -- our own cert -------------------------------------------------------------
def test_own_cert_must_name_this_node(operator, phone, laptop):
    proc = StubProc(phone)
    assert dc.own_cert(proc) is None
    _install_cert(operator, laptop)
    assert dc.own_cert(proc) is None
    _install_cert(operator, phone)
    os.utime(dc.device_cert_path(), ns=(1, 1))   # a change the mtime cache sees
    assert dc.own_cert(proc).names(phone)


def test_cert_is_pushed_sealed_to_contact_peers(operator, phone, bob):
    proc = StubProc(phone)
    _install_cert(operator, phone)
    store = fc._contacts_store(proc)
    store.add(Contact(bob.publish()))
    proc.peers.add(bob.publish(), proc.peers.mid_level)
    q = _queues()
    assert dc.push_own_cert(proc, q) == 1
    msg = q[CfgIds.network].get_nowait()
    assert msg.function == FirstContactProtocol.device_cert
    assert msg.encrypt is not False
    assert msg.to_whom[0].uuid == bob.uuid


def test_no_cert_nothing_pushed_or_announced(phone, bob):
    proc = StubProc(phone)
    fc._contacts_store(proc).add(Contact(bob.publish()))
    proc.peers.add(bob.publish(), proc.peers.mid_level)
    q = _queues()
    assert dc.push_own_cert(proc, q) == 0 and dc.announce(proc, q) == 0
    assert q[CfgIds.network].empty()


# -- learning a contact's operator key ----------------------------------------
def test_contact_cert_teaches_the_operator_key(operator, phone, bob):
    proc = StubProc(bob)
    store = fc._contacts_store(proc)
    store.add(Contact(phone.publish()))
    cert = create_device_cert(operator, phone)
    dc.handle_device_cert(proc, _queues(), _inbound(phone, json.dumps(cert.to_wire())))
    assert store.get(phone.uuid).operator_key == cert.operator
    assert Contacts.load().get(phone.uuid).operator_key == cert.operator


def test_cert_from_a_stranger_is_ignored(operator, phone, bob):
    proc = StubProc(bob)
    cert = create_device_cert(operator, phone)
    dc.handle_device_cert(proc, _queues(), _inbound(phone, json.dumps(cert.to_wire())))
    assert phone.uuid not in fc._contacts_store(proc)


def test_cert_naming_another_node_teaches_nothing(operator, phone, laptop, bob):
    proc = StubProc(bob)
    store = fc._contacts_store(proc)
    store.add(Contact(phone.publish()))
    cert = create_device_cert(operator, laptop)
    dc.handle_device_cert(proc, _queues(), _inbound(phone, json.dumps(cert.to_wire())))
    assert store.get(phone.uuid).operator_key == ''


# -- a new device announcing itself -------------------------------------------
def test_announce_goes_to_every_contact_node_in_plaintext(operator, laptop, bob, phone):
    proc = StubProc(laptop)
    _install_cert(operator, laptop)
    store = fc._contacts_store(proc)
    store.add(Contact(bob.publish()))
    store.add(Contact(phone.publish()))
    q = _queues()
    assert dc.announce(proc, q) == 2
    msgs = _drain(q[CfgIds.network])
    assert {m.to_whom[0].uuid for m in msgs} == {bob.uuid, phone.uuid}
    assert all(m.function == FirstContactProtocol.device_announce and m.encrypt is False
               for m in msgs)
    body = json.loads(msgs[0].obj)
    assert body['cert']['sig'] and isinstance(body['relays'], list)


def _announce_from(operator, device):
    cert = create_device_cert(operator, device)
    return _inbound(device, json.dumps({'cert': cert.to_wire(), 'relays': []}))


def test_announce_links_admits_and_tells_the_app(operator, phone, laptop, bob):
    proc = StubProc(bob)
    alice = _bob_knows_alice(proc, phone, operator)
    q = _queues()
    dc.handle_device_announce(proc, q, _announce_from(operator, laptop))
    assert alice.device_uuids() == [str(laptop.uuid)]
    assert Contacts.load().get(laptop.uuid).uuid == alice.uuid
    assert proc.peers.find_by_uuid(laptop.uuid) is not None
    events = _drain(q[CfgIds.main])
    assert [(e.kind, e.peer_uuid, e.device_uuid) for e in events] == [
        (dc.EVENT_DEVICE_LINKED, str(phone.uuid), str(laptop.uuid))]
    # Nothing is sent back to the device by way of an answer.
    assert not [m for m in _drain(q[CfgIds.network])
                if m.function in (FirstContactProtocol.device_announce, FirstContactProtocol.hello_ack)]


def test_a_second_announce_is_quiet(operator, phone, laptop, bob):
    proc = StubProc(bob)
    _bob_knows_alice(proc, phone, operator)
    dc.handle_device_announce(proc, _queues(), _announce_from(operator, laptop))
    q = _queues()
    dc.handle_device_announce(proc, q, _announce_from(operator, laptop))
    assert q[CfgIds.main].empty()


@pytest.mark.parametrize('case', ['unverified', 'stranger_operator', 'lifted'])
def test_refused_announce_is_silent(case, operator, phone, laptop, bob):
    proc = StubProc(bob)
    alice = _bob_knows_alice(proc, phone, operator, verified=(case != 'unverified'))
    q = _queues()
    if case == 'stranger_operator':
        message = _announce_from(SigningKey.generate(), laptop)
    elif case == 'lifted':
        mallory = _identity('mallory')
        cert = create_device_cert(operator, laptop)
        message = _inbound(mallory, json.dumps({'cert': cert.to_wire(), 'relays': []}))
    else:
        message = _announce_from(operator, laptop)
    dc.handle_device_announce(proc, q, message)
    assert alice.devices == []
    assert len(proc.peers.all) == 0
    assert q[CfgIds.main].empty() and q[CfgIds.network].empty()
