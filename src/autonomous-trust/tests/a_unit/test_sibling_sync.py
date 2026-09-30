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
"""Phase 4, live pairing, the wire half (identity/sibling_sync.py): a pairing
invitation, two devices becoming siblings, and their address books kept the
same. Handler logic on process stubs, each node with its own config root, and
a tiny router carrying what each puts on its network queue to the other."""
import json
import logging
import os
import queue
import time
import types

import pytest
from nacl.signing import SigningKey

from autonomous_trust.core.identity import Identity, Peers
from autonomous_trust.core.identity.protocol import IdentityProtocol, UNENCRYPTED_VERBS
from autonomous_trust.core.system import CfgIds
from autonomous_trust.core.config import Configuration
from autonomous_trust.core.network.message import Message
from autonomous_trust.core.contacts import (Contact, Contacts, Invitation, Siblings,
                                           adopt_operator, create_device_cert)
from autonomous_trust.core.contacts.invitation import PURPOSE_PAIR
from autonomous_trust.core.identity import first_contact as fc
from autonomous_trust.core._python.identity import device_contact as dc
from autonomous_trust.core._python.identity import sibling_sync as ss
from autonomous_trust.core._python.contacts import reach as _reach


class Node:
    """One device: its identity, its own config root, its queues."""

    def __init__(self, tmp_path, name, addr):
        self.root = str(tmp_path / name)
        self.identity = Identity.initialize(name, name, addr)
        self.name = CfgIds.identity
        self.peers = Peers()
        self.logger = logging.getLogger('test-sibling-' + name)
        self.q_cadence = 1.0
        self._first_contact_nonces = None
        self._device_cert_cache = (None, None)
        self.queues = {CfgIds.network: queue.Queue(), CfgIds.main: queue.Queue()}
        self.events = []
        with self:
            os.makedirs(Configuration.get_cfg_dir(), exist_ok=True)
            self._first_contact_nonces = fc.SpentNonces()

    def _record_peers(self, queues):
        pass

    def __enter__(self):
        os.environ[Configuration.ROOT_VARIABLE_NAME] = self.root
        return self

    def __exit__(self, *exc):
        return False

    def call(self, fn, *args):
        with self:
            return fn(self, self.queues, *args)

    def app(self, verb, payload):
        handler = {fc.APP_INVITE: fc.handle_app_invite,
                   fc.APP_INITIATE: fc.handle_app_initiate,
                   fc.APP_RENAME: fc.handle_app_rename,
                   fc.APP_REMOVE: fc.handle_app_remove,
                   ss.APP_SIBLING_LIST: ss.handle_app_sibling_list,
                   ss.APP_SIBLING_REMOVE: ss.handle_app_sibling_remove}[verb]
        msg = Message(CfgIds.identity, verb, json.dumps(payload),
                      to_whom=None, from_whom=None, encrypt=False)
        return self.call(handler, msg)

    def drain_events(self):
        while not self.queues[CfgIds.main].empty():
            self.events.append(self.queues[CfgIds.main].get_nowait())
        return self.events

    def kinds(self):
        return [e.kind for e in self.drain_events()]

    def store(self):
        with self:
            return fc._contacts_store(self)

    def siblings(self):
        with self:
            return ss.siblings(self)


HANDLERS = {
    IdentityProtocol.hello: fc.handle_hello,
    IdentityProtocol.hello_ack: fc.handle_hello_ack,
    IdentityProtocol.device_cert: dc.handle_device_cert,
    IdentityProtocol.device_announce: dc.handle_device_announce,
    IdentityProtocol.reach_record: fc.handle_reach_record,
    IdentityProtocol.contacts_sync: ss.handle_contacts_sync,
}


def route(*nodes, drop=()):
    """Deliver everything the nodes queued to one another until quiet.
    Returns what went, as (from, to, verb). ``drop`` verbs are lost."""
    by_uuid = {str(n.identity.uuid): n for n in nodes}
    sent = []
    for _ in range(50):
        moved = False
        for node in nodes:
            q = node.queues[CfgIds.network]
            while not q.empty():
                msg = q.get_nowait()
                to = msg.to_whom[0] if isinstance(msg.to_whom, list) else msg.to_whom
                if to is None or getattr(msg, 'function', None) not in HANDLERS:
                    continue
                dest = by_uuid.get(str(to.uuid))
                sent.append((node.identity.nickname, getattr(to, 'nickname', ''),
                             msg.function))
                if dest is None or msg.function in drop:
                    continue
                inbound = types.SimpleNamespace(from_whom=node.identity.publish(),
                                                obj=msg.obj, function=msg.function,
                                                encrypt=msg.encrypt)
                dest.call(HANDLERS[msg.function], inbound)
                moved = True
        if not moved:
            break
    return sent


def install_cert(node, operator):
    with node:
        cert = create_device_cert(operator, node.identity)
        with open(dc.device_cert_path(), 'w') as fh:
            json.dump(cert.to_wire(), fh)
    return cert


@pytest.fixture(autouse=True)
def _restore_root():
    before = os.environ.get(Configuration.ROOT_VARIABLE_NAME)
    yield
    if before is None:
        os.environ.pop(Configuration.ROOT_VARIABLE_NAME, None)
    else:
        os.environ[Configuration.ROOT_VARIABLE_NAME] = before


@pytest.fixture
def operator():
    return SigningKey.generate()


@pytest.fixture
def phone(tmp_path):
    return Node(tmp_path, 'alice-phone', '10.0.0.1')


@pytest.fixture
def laptop(tmp_path):
    return Node(tmp_path, 'alice-laptop', '10.0.0.3')


@pytest.fixture
def bob(tmp_path):
    return Node(tmp_path, 'bob', '10.0.0.2')


def pair_link(node):
    node.app(fc.APP_INVITE, {'ref': 'p', 'pair': True})
    ev = [e for e in node.drain_events() if e.kind == fc.EVENT_INVITATION][-1]
    return ev.blob


def pair(old, new, *others):
    new.app(fc.APP_INITIATE, {'ref': 'n', 'invitation': pair_link(old)})
    return route(old, new, *others)


def befriend(me, other, verified=True, operator=None):
    """``me`` holds ``other`` as a contact (verified, operator learned)."""
    with me:
        store = fc._contacts_store(me)
        c = Contact(other.identity.publish())
        if verified:
            c.mark_verified()
        if operator is not None:
            assert adopt_operator(c, create_device_cert(operator, other.identity),
                                  store) == ''
        store.add(c)
        store.save()
    return c


# -- the invitation -------------------------------------------------------------

def test_contacts_sync_is_sealed():
    assert IdentityProtocol.contacts_sync not in UNENCRYPTED_VERBS


def test_a_pair_link_carries_a_signed_purpose(operator, phone):
    install_cert(phone, operator)
    inv = Invitation.decode(pair_link(phone))
    assert inv.purpose == PURPOSE_PAIR
    assert '"purpose":"pair"' in inv.body_str
    inv.verify_signature()
    phone.app(fc.APP_INVITE, {'ref': 'o'})
    plain = [e for e in phone.drain_events() if e.kind == fc.EVENT_INVITATION][-1]
    assert Invitation.decode(plain.blob).purpose == ''
    assert 'purpose' not in Invitation.decode(plain.blob).body


#: C: at_create_invitation_purpose(identity "c-old", {"10.0.0.5"}, expiry 0,
#: nonce "FFEEDDCCBBAA99887766554433221100", AT_INVITATION_PURPOSE_PAIR).
C_PAIR_LINK = ('at+contact:eyJib2R5Ijoie1wiZXhwaXJ5XCI6MCxcImlkZW50aXR5XCI6e1wiYWRkcmVzc1wiOlwiMTAuMC4wLjVcIixcImVuY3J5cHRvclwiOntcImhleF9zZWVkXCI6XCJlMDNmYzVhOTMyYmQ5MDVmZjEzNzRkMGI5Y2I1MjJmMzU5ODhiZjhkNjgxNDgzODhlMTNkMWM3YmU2ZTgzMzUyXCJ9LFwibmlja25hbWVcIjpcImMtb2xkXCIsXCJzaWduYXR1cmVcIjp7XCJoZXhfc2VlZFwiOlwiYjY2ZWE1N2FlNDg0MDhjODk0MDRlYThlMDc3YzQ1NjgxNDhhZjVkMjgwMjJhYzUxMDRmM2YwZDhiYjVmMTA1MFwifSxcInR5cGVuYW1lXCI6XCJpZGVudGl0eVwiLFwidXVpZFwiOlwiNzI2ZDI3YmUtZDE0MS00OTBiLTkwYjctOGE0MmYxODk2ZTliXCJ9LFwibm9uY2VcIjpcIkZGRUVERENDQkJBQTk5ODg3NzY2NTU0NDMzMjIxMTAwXCIsXCJwdXJwb3NlXCI6XCJwYWlyXCIsXCJyZW5kZXp2b3VzXCI6W1wiMTAuMC4wLjVcIl0sXCJ0eXBlbmFtZVwiOlwiYXQtaW52aXRhdGlvblwiLFwidlwiOjF9Iiwic2lnIjoiMzI2ZTViYjljMzVjNDRmMWEzZDQxMmZiNDdjNGZiYjkzMmU1NmQ4NzQ4MTNhNjg4M2IyZTUyNjE4MTViY2NlOTkyOThhYjMyNWI0MjFiNmFiY2ZmN2U0NzJjYTdhMDBmNTNkNDgzNmJmOTUyZjZlM2RkNmNiMTk0Y2JjNWZkMDAifQ')


def test_a_c_pair_link_verifies_here():
    inv = Invitation.decode(C_PAIR_LINK)
    assert inv.verify_signature().nickname == 'c-old'
    assert inv.purpose == PURPOSE_PAIR


def test_no_cert_no_pair_link(phone):
    phone.app(fc.APP_INVITE, {'ref': 'p', 'pair': True})
    ev = phone.drain_events()[-1]
    assert ev.kind == fc.EVENT_REFUSED and ev.reason == ss.REASON_NOT_SIBLING


def test_pair_must_be_a_boolean(operator, phone):
    install_cert(phone, operator)
    phone.app(fc.APP_INVITE, {'ref': 'p', 'pair': 'yes'})
    ev = phone.drain_events()[-1]
    assert ev.kind == fc.EVENT_REFUSED and ev.reason == 'bad_request'


# -- pairing --------------------------------------------------------------------

def test_two_devices_under_one_operator_pair(operator, phone, laptop):
    install_cert(phone, operator)
    install_cert(laptop, operator)
    sent = pair(phone, laptop)
    assert ('alice-phone', 'alice-laptop', IdentityProtocol.device_cert) in sent
    assert ('alice-laptop', 'alice-phone', IdentityProtocol.device_cert) in sent
    assert phone.siblings().uuids() == [str(laptop.identity.uuid)]
    assert laptop.siblings().uuids() == [str(phone.identity.uuid)]
    # Siblings, not contacts, and on disk.
    assert len(phone.store()) == 0 and len(laptop.store()) == 0
    with phone:
        assert Siblings.load().uuids() == [str(laptop.identity.uuid)]
    assert ss.EVENT_SIBLING_PAIRED in phone.kinds()
    ev = [e for e in laptop.drain_events() if e.kind == ss.EVENT_SIBLING_PAIRED][0]
    assert ev.role == 'initiator' and ev.ref == 'n'
    assert fc.EVENT_ESTABLISHED not in phone.kinds() + laptop.kinds()


def test_the_new_device_gets_the_address_book_and_bob_links_it(operator, phone,
                                                               laptop, bob):
    """The exit criterion, end to end: Alice's new laptop pairs with her phone,
    gets Bob verified, announces itself, and Bob files it under Alice."""
    install_cert(phone, operator)
    install_cert(laptop, operator)
    befriend(phone, bob, verified=True)
    befriend(bob, phone, verified=True, operator=operator)
    sent = pair(phone, laptop, bob)
    got = laptop.store().get(str(bob.identity.uuid))
    assert got is not None and got.verified
    assert got.provenance.value == 'sibling'
    added = [e for e in laptop.drain_events() if e.kind == fc.EVENT_CONTACT]
    assert added and added[0].origin == ss.ORIGIN_SIBLING
    # The laptop announced itself to Bob, who filed it under Alice.
    assert ('alice-laptop', 'bob', IdentityProtocol.device_announce) in sent
    alice = bob.store().get(str(phone.identity.uuid))
    assert str(laptop.identity.uuid) in alice.device_uuids()
    assert dc.EVENT_DEVICE_LINKED in bob.kinds()


def test_another_operators_device_is_refused(operator, phone, laptop):
    install_cert(phone, operator)
    install_cert(laptop, SigningKey.generate())
    pair(phone, laptop)
    assert len(phone.siblings()) == 0 and len(laptop.siblings()) == 0
    assert len(phone.store()) == 0 and len(laptop.store()) == 0
    for node in (phone, laptop):
        refused = [e for e in node.drain_events() if e.kind == fc.EVENT_REFUSED]
        assert refused and refused[-1].reason == ss.REASON_NOT_SIBLING
    assert phone.peers.find_by_uuid(laptop.identity.uuid) is None
    assert laptop.peers.find_by_uuid(phone.identity.uuid) is None


def test_a_new_device_without_a_cert_sends_no_hello(operator, phone, laptop):
    install_cert(phone, operator)
    link = pair_link(phone)
    laptop.app(fc.APP_INITIATE, {'ref': 'n', 'invitation': link})
    assert laptop.drain_events()[-1].reason == ss.REASON_NOT_SIBLING
    assert route(phone, laptop) == []


def test_an_old_device_that_lost_its_cert_does_not_ack(operator, phone, laptop):
    install_cert(phone, operator)
    install_cert(laptop, operator)
    link = pair_link(phone)
    with phone:
        os.remove(dc.device_cert_path())
    laptop.app(fc.APP_INITIATE, {'ref': 'n', 'invitation': link})
    sent = route(phone, laptop)
    assert (('alice-phone', 'alice-laptop', IdentityProtocol.hello_ack) not in sent)
    assert phone.drain_events()[-1].reason == ss.REASON_NOT_SIBLING
    assert phone.peers.find_by_uuid(laptop.identity.uuid) is None


def test_a_cert_that_never_comes_times_out(operator, phone, laptop):
    install_cert(phone, operator)
    install_cert(laptop, operator)
    laptop.app(fc.APP_INITIATE, {'ref': 'n', 'invitation': pair_link(phone)})
    route(phone, laptop, drop=(IdentityProtocol.device_cert,))
    assert str(laptop.identity.uuid) in phone._pairing
    assert phone.call(ss.expire, time.time() + ss.PAIR_WAIT_SECONDS + 1) == 1
    assert phone.drain_events()[-1].reason == ss.REASON_NOT_SIBLING
    assert phone.peers.find_by_uuid(laptop.identity.uuid) is None
    assert len(phone.siblings()) == 0


def test_an_ordinary_link_still_makes_a_contact(operator, phone, laptop):
    install_cert(phone, operator)
    install_cert(laptop, operator)
    phone.app(fc.APP_INVITE, {'ref': 'o'})
    link = [e for e in phone.drain_events() if e.kind == fc.EVENT_INVITATION][-1].blob
    laptop.app(fc.APP_INITIATE, {'ref': 'n', 'invitation': link})
    route(phone, laptop)
    assert len(phone.siblings()) == 0
    assert str(laptop.identity.uuid) in phone.store()


# -- sync -----------------------------------------------------------------------

@pytest.fixture
def paired(operator, phone, laptop, bob):
    install_cert(phone, operator)
    install_cert(laptop, operator)
    befriend(phone, bob)
    pair(phone, laptop)
    phone.drain_events()
    laptop.drain_events()
    phone.events.clear()
    laptop.events.clear()
    return phone, laptop


def test_a_rename_reaches_the_sibling(paired, bob):
    phone, laptop = paired
    phone.app(fc.APP_RENAME, {'ref': 'r', 'peer': str(bob.identity.uuid),
                              'petname': 'Bobby'})
    route(phone, laptop)
    assert laptop.store().get(str(bob.identity.uuid)).petname == 'Bobby'
    ev = [e for e in laptop.drain_events() if e.kind == fc.EVENT_CONTACT][-1]
    assert ev.origin == ss.ORIGIN_SIBLING and ev.petname == 'Bobby'


def test_a_removal_reaches_the_sibling_and_drops_the_peer(paired, bob):
    phone, laptop = paired
    assert laptop.peers.find_by_uuid(bob.identity.uuid) is not None
    phone.app(fc.APP_REMOVE, {'ref': 'r', 'peer': str(bob.identity.uuid)})
    route(phone, laptop)
    assert str(bob.identity.uuid) not in laptop.store()
    assert str(bob.identity.uuid) in laptop.store().tombstones
    assert laptop.peers.find_by_uuid(bob.identity.uuid) is None
    ev = [e for e in laptop.drain_events() if e.kind == fc.EVENT_REMOVED][-1]
    assert ev.origin == ss.ORIGIN_SIBLING and ev.peer_dropped


def test_nothing_changed_nothing_sent(paired):
    phone, laptop = paired
    assert phone.call(ss.push_changes) == 0


def test_only_a_sibling_is_heard(paired, bob, tmp_path):
    phone, laptop = paired
    stranger = Node(tmp_path, 'mallory', '10.0.0.66')
    with stranger:
        store = fc._contacts_store(stranger)
        store.add(Contact(Node(tmp_path, 'eve', '10.0.0.7').identity.publish()))
    payload = json.dumps({'v': 1, 'typename': 'at-contacts-sync',
                          'contacts': {u: c.to_canonical()
                                       for u, c in store.contacts.items()},
                          'tombstones': {}})
    before = len(laptop.store())
    laptop.call(ss.handle_contacts_sync, types.SimpleNamespace(
        from_whom=stranger.identity.publish(), obj=payload))
    assert len(laptop.store()) == before


def test_startup_swaps_books_once_each_way(paired, bob):
    phone, laptop = paired
    sent_before = phone.queues[CfgIds.network].qsize()
    assert laptop.call(ss.restore) == 1
    sent = route(phone, laptop)
    syncs = [s for s in sent if s[2] == IdentityProtocol.contacts_sync]
    assert syncs == [('alice-laptop', 'alice-phone', IdentityProtocol.contacts_sync),
                     ('alice-phone', 'alice-laptop', IdentityProtocol.contacts_sync)]
    assert sent_before == 0


def test_a_siblings_reach_record_moves_its_hints(paired):
    phone, laptop = paired
    with laptop:
        record = _reach.create_record(laptop.identity, 7, ['relay://203.0.113.9:27790'],
                                      ['10.0.0.33'], expiry=int(time.time()) + 3600)
    phone.call(fc.handle_reach_record, types.SimpleNamespace(
        from_whom=laptop.identity.publish(), obj=record.to_json()))
    sib = phone.siblings()
    uuid = str(laptop.identity.uuid)
    assert sib.reach_seq[uuid] == 7
    assert sib.hints[uuid][0] == 'relay://203.0.113.9:27790'
    with phone:
        assert Siblings.load().reach_seq[uuid] == 7
    # An older record is a replay: nothing moves.
    with laptop:
        old = _reach.create_record(laptop.identity, 6, ['relay://198.51.100.1:27790'],
                                   [], expiry=int(time.time()) + 3600)
    phone.call(fc.handle_reach_record, types.SimpleNamespace(
        from_whom=laptop.identity.publish(), obj=old.to_json()))
    assert phone.siblings().reach_seq[uuid] == 7
    assert 'relay://198.51.100.1:27790' not in phone.siblings().hints[uuid]


def test_a_sibling_is_never_tier_capped(paired, monkeypatch):
    monkeypatch.setenv('AT_FIRST_CONTACT', '1')
    phone, laptop = paired
    with phone:
        assert fc.capped_tier(phone, str(laptop.identity.uuid), 3) == 3
        stranger = Identity.initialize('x', 'x', '10.0.0.8')
        assert fc.capped_tier(phone, str(stranger.uuid), 3) == fc.UNVERIFIED_TIER_CAP


def test_list_and_unpair(paired):
    phone, laptop = paired
    phone.app(ss.APP_SIBLING_LIST, {'ref': 'l'})
    evs = phone.drain_events()
    assert [e.kind for e in evs[-2:]] == [ss.EVENT_SIBLING, ss.EVENT_SIBLINGS_DONE]
    assert evs[-2].peer_uuid == str(laptop.identity.uuid) and evs[-1].count == 1
    phone.app(ss.APP_SIBLING_REMOVE, {'ref': 'u', 'peer': str(laptop.identity.uuid)})
    ev = phone.drain_events()[-1]
    assert ev.kind == ss.EVENT_SIBLING_REMOVED and ev.peer_dropped
    assert len(phone.siblings()) == 0
    assert phone.peers.find_by_uuid(laptop.identity.uuid) is None
    # Unpairing is not synced: the laptop still lists the phone.
    assert laptop.siblings().uuids() == [str(phone.identity.uuid)]
    phone.app(ss.APP_SIBLING_REMOVE, {'ref': 'u', 'peer': str(laptop.identity.uuid)})
    assert phone.drain_events()[-1].reason == 'unknown_contact'


def test_sibling_verbs_are_local_only(paired):
    phone, laptop = paired
    wire = types.SimpleNamespace(from_whom=laptop.identity.publish(),
                                 function=ss.APP_SIBLING_REMOVE,
                                 obj=json.dumps({'ref': 'u',
                                                 'peer': str(laptop.identity.uuid)}))
    phone.call(ss.handle_app_sibling_remove, wire)
    assert len(phone.siblings()) == 1
