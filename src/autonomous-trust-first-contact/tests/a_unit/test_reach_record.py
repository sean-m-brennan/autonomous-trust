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
"""Signed reachability records (contacts/reach.py): the record, the relay that
files it, and identity applying a contact's record."""
import json
import logging
import queue
import time
import types

import pytest

from autonomous_trust.core.config import Configuration
from autonomous_trust.first_contact import Contact, Contacts
from autonomous_trust.rendezvous._python import reach
from autonomous_trust.rendezvous._python import rdv_net
from autonomous_trust.core.identity import Identity, Peers
from autonomous_trust.first_contact import first_contact as fc
from autonomous_trust.first_contact.fc_protocol import FirstContactProtocol
from autonomous_trust.core.network.network import Network
from autonomous_trust.rendezvous._python import relay
from autonomous_trust.core.system import CfgIds


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv(Configuration.ROOT_VARIABLE_NAME, str(tmp_path))
    monkeypatch.delenv('AT_USE_RELAY', raising=False)
    monkeypatch.setenv('AT_FIRST_CONTACT', '1')
    import os
    os.makedirs(Configuration.get_data_dir(), exist_ok=True)


def _ident(name, addr='10.0.0.1'):
    return Identity.initialize(name, name, addr)


PIN_HINT = 'relay://203.0.113.7:27790'


# -- the record ---------------------------------------------------------------
def test_a_record_verifies_round_trips_and_names_its_key():
    alice = _ident('alice@ex')
    rec = reach.create_record(alice, 3, [PIN_HINT], ['10.0.0.1'])
    back = reach.ReachRecord.from_wire(rec.to_json()).verify()
    assert (back.uuid, back.seq, back.relays, back.endpoints) == (
        str(alice.uuid).lower(), 3, [PIN_HINT], ['10.0.0.1'])
    assert back.record_id == relay.key_fingerprint(relay._signing_hex(alice))


def test_a_tampered_or_expired_record_is_refused():
    alice = _ident('alice@ex')
    rec = reach.create_record(alice, 1, [PIN_HINT])
    body = json.loads(rec.body_str)
    body['seq'] = 99
    forged = reach.ReachRecord(body, json.dumps(body, sort_keys=True,
                                                separators=(',', ':')), rec.sig_hex)
    with pytest.raises(reach.InvalidRecord):
        forged.verify()
    old = reach.create_record(alice, 1, [PIN_HINT], expiry=int(time.time()) - 1)
    with pytest.raises(reach.InvalidRecord):
        old.verify()
    # The signature is domain-separated: the bare body signature is not one.
    bare = alice.sign(rec.body_str.encode('utf-8')).signature.decode('ascii')
    with pytest.raises(reach.InvalidRecord):
        reach.ReachRecord(rec.body, rec.body_str, bare).verify()


# -- the relay files and serves records ---------------------------------------
@pytest.fixture
def server():
    srv = relay.RelayServer('127.0.0.1', 0)
    yield srv
    srv.stop()


class Answers:
    def __init__(self):
        self.items = []

    def __call__(self, rid, wire):
        self.items.append((rid, wire))

    def wait(self, n=1, timeout=5.0):
        deadline = time.monotonic() + timeout
        while len(self.items) < n and time.monotonic() < deadline:
            time.sleep(0.01)
        return len(self.items) >= n


def _client(server, ident, answers=None):
    return relay.RelayClient(server.address, ident, lambda *a: None,
                             on_record=answers)


def test_a_relay_files_a_nodes_own_record_and_serves_it(server):
    alice, bob = _ident('alice@ex'), _ident('bob@ex')
    a = _client(server, alice)
    a.connect()
    rec = reach.create_record(alice, 2, [PIN_HINT])
    a.publish(rec)
    answers = Answers()
    b = _client(server, bob, answers)
    b.connect()
    deadline = time.monotonic() + 5
    while rec.record_id not in server._records and time.monotonic() < deadline:
        time.sleep(0.01)
    b.lookup(rec.record_id)
    assert answers.wait()
    rid, wire = answers.items[0]
    assert rid == rec.record_id
    assert reach.ReachRecord.from_wire(wire).verify().seq == 2
    # An unknown id answers null, not an error.
    b.lookup('0' * 32)
    assert answers.wait(2) and answers.items[1][1] is None
    a.close(), b.close()


def test_a_relay_refuses_someone_elses_record_and_a_stale_one(server):
    alice, mallory = _ident('alice@ex'), _ident('mallory@ex')
    rec = reach.create_record(alice, 5, [PIN_HINT])
    assert server._publish(str(mallory.uuid).lower(),
                           relay._signing_hex(mallory).lower(),
                           rec.to_wire())['op'] == 'refused'
    au, ak = str(alice.uuid).lower(), relay._signing_hex(alice).lower()
    assert server._publish(au, ak, rec.to_wire())['op'] == 'published'
    older = reach.create_record(alice, 4, ['relay://198.51.100.1:1'])
    assert server._publish(au, ak, older.to_wire())['op'] == 'refused'
    # Refiling the SAME record (every registration does) is not a refusal...
    assert server._publish(au, ak, rec.to_wire())['op'] == 'published'
    # ...but a different record under the same seq is.
    same_seq = reach.create_record(alice, 5, ['relay://198.51.100.9:9'])
    assert server._publish(au, ak, same_seq.to_wire())['op'] == 'refused'
    assert server._records[rec.record_id].seq == 5


# -- identity applies a contact's record ----------------------------------------
class StubProc:
    def __init__(self, identity):
        self.name = CfgIds.identity
        self.identity = identity
        self.peers = Peers()
        self.logger = logging.getLogger('test-reach')
        self.q_cadence = 1.0


def _with_contact(me, who):
    proc = StubProc(me)
    store = fc._contacts_store(proc)
    store.add(Contact(who.publish(), rendezvous=['relay://198.51.100.1:1']))
    return proc


def _msg(record, sender=None):
    return types.SimpleNamespace(obj=record.to_json(), from_whom=sender)


def test_a_newer_record_updates_the_contact_and_its_route():
    me, alice = _ident('me@ex'), _ident('alice@ex')
    proc = _with_contact(me, alice)
    q = {CfgIds.network: queue.Queue()}
    rec = reach.create_record(alice, 7, [PIN_HINT], ['10.0.0.9'])
    fc.handle_reach_record(proc, q, _msg(rec, alice.publish()))
    contact = fc._contacts_store(proc).get(str(alice.uuid))
    assert contact.reach_seq == 7
    assert contact.rendezvous[0] == PIN_HINT
    assert '10.0.0.9' in contact.rendezvous
    route = json.loads(q[CfgIds.network].get_nowait().obj)
    assert route['relays'][0] == '203.0.113.7:27790'
    # It survives a reload of the store.
    assert Contacts.load().get(str(alice.uuid)).reach_seq == 7


@pytest.mark.parametrize('case', ['stale', 'wrong_key', 'wrong_sender', 'stranger'])
def test_a_record_that_is_not_authoritative_is_ignored(case):
    me, alice, mallory = _ident('me@ex'), _ident('alice@ex'), _ident('mallory@ex')
    proc = _with_contact(me, alice)
    q = {CfgIds.network: queue.Queue()}
    fc.handle_reach_record(proc, q, _msg(reach.create_record(alice, 5, [PIN_HINT])))
    while not q[CfgIds.network].empty():
        q[CfgIds.network].get_nowait()
    if case == 'stale':
        rec, sender = reach.create_record(alice, 5, ['relay://1.1.1.1:1']), None
    elif case == 'wrong_key':
        # Alice's uuid, Mallory's key: a uuid is only a label.
        rec = reach.create_record(mallory, 9, ['relay://1.1.1.1:1'])
        body = json.loads(rec.body_str)
        body['uuid'] = str(alice.uuid).lower()
        body_str = json.dumps(body, sort_keys=True, separators=(',', ':'))
        sig = mallory.sign((reach.REACH_DOMAIN + body_str).encode()).signature.decode()
        rec, sender = reach.ReachRecord(body, body_str, sig), None
    elif case == 'wrong_sender':
        rec, sender = reach.create_record(alice, 9, ['relay://1.1.1.1:1']), mallory.publish()
    else:
        rec, sender = reach.create_record(mallory, 9, ['relay://1.1.1.1:1']), None
    fc.handle_reach_record(proc, q, _msg(rec, sender))
    contact = fc._contacts_store(proc).get(str(alice.uuid))
    assert contact.reach_seq == 5
    assert 'relay://1.1.1.1:1' not in contact.rendezvous
    assert q[CfgIds.network].empty()


def test_reach_seq_is_stored_only_once_set():
    alice = _ident('alice@ex')
    c = Contact(alice.publish())
    assert 'reach_seq' not in c.to_canonical()
    c.reach_seq = 4
    assert Contact.from_canonical(c.to_canonical()).reach_seq == 4


# -- our own record ---------------------------------------------------------------
def test_our_record_is_issued_on_change_pushed_and_published(monkeypatch):
    monkeypatch.setenv('AT_USE_RELAY', '203.0.113.7:27790')
    me, alice = _ident('me@ex', '10.0.0.5'), _ident('alice@ex')
    proc = _with_contact(me, alice)
    proc.peers.add(alice.publish(), proc.peers.mid_level)
    q = {CfgIds.network: queue.Queue()}

    def sent():
        out = []
        while not q[CfgIds.network].empty():
            out.append(q[CfgIds.network].get_nowait())
        return out

    rec = fc.refresh_own_record(proc, q)
    assert (rec.seq, rec.relays, rec.endpoints) == (1, [PIN_HINT], ['10.0.0.5'])
    out = sent()
    pushed = [m for m in out if m.function == FirstContactProtocol.reach_record]
    assert [str(m.to_whom[0].uuid) for m in pushed] == [str(alice.uuid)]
    assert any(m.function == Network.reach_publish for m in out)
    # Nothing changed: same record, handed to the network again, pushed to nobody.
    assert fc.refresh_own_record(proc, q).seq == 1
    out = sent()
    assert not [m for m in out if m.function == FirstContactProtocol.reach_record]
    # A relay proves itself: the pinned hint is new content, so a new seq.
    fc.handle_relay_identity(proc, q, types.SimpleNamespace(
        from_whom=None, obj=json.dumps({'relay': '203.0.113.7:27790',
                                        'uuid': str(alice.uuid).lower(),
                                        'fp': '0' * 32})))
    assert fc._current_own_record(proc).seq == 2
    # The seq is durable: it survives a "restart" of the process.
    assert fc.refresh_own_record(StubProc(me), q).seq == 2


@pytest.mark.parametrize('case', ['contact', 'stranger', 'wire'])
def test_a_contact_reaching_us_through_a_relay_is_sent_our_record(monkeypatch, case):
    """A contact that registered at our relay after our startup push missed it;
    its traffic arriving through the relay re-sends it. Strangers get nothing,
    and the trigger is local IPC only."""
    monkeypatch.setenv('AT_USE_RELAY', '203.0.113.7:27790')
    me, alice, mallory = _ident('me@ex', '10.0.0.5'), _ident('alice@ex'), _ident('mallory@ex')
    proc = _with_contact(me, alice)
    proc.peers.add(alice.publish(), proc.peers.mid_level)
    proc.peers.add(mallory.publish(), proc.peers.mid_level)
    q = {CfgIds.network: queue.Queue()}
    fc.refresh_own_record(proc, q)
    while not q[CfgIds.network].empty():
        q[CfgIds.network].get_nowait()
    who = mallory if case == 'stranger' else alice
    fc.handle_relay_peer(proc, q, types.SimpleNamespace(
        from_whom=alice.publish() if case == 'wire' else None,
        obj=json.dumps({'uuid': str(who.uuid)})))
    pushed = []
    while not q[CfgIds.network].empty():
        m = q[CfgIds.network].get_nowait()
        if m.function == FirstContactProtocol.reach_record:
            pushed.append(str(m.to_whom[0].uuid))
    assert pushed == ([str(alice.uuid)] if case == 'contact' else [])


# -- the network process looks a lost peer up ---------------------------------------
def test_a_lost_peer_is_looked_up_at_every_relay_rate_limited():
    from autonomous_trust.core._python.network.netprocess import NetworkProcess
    alice = _ident('alice@ex')
    looked = []
    clients = {('r', i): types.SimpleNamespace(
        connected=True, lookup=lambda rid, i=i: looked.append((i, rid)))
        for i in (1, 2)}
    peers = Peers()
    peers.add(alice.publish(), peers.mid_level)
    stub = types.SimpleNamespace(
        logger=logging.getLogger('t'), peers=peers, _relay_clients=clients,
        _reach_asked={}, REACH_LOOKUP_INTERVAL=60.0)
    stub._peer_key = lambda u: NetworkProcess._peer_key(stub, u)
    rdv_net._lookup_reach(stub, str(alice.uuid).lower())
    rid = relay.key_fingerprint(relay._signing_hex(alice))
    assert sorted(looked) == [(1, rid), (2, rid)]
    rdv_net._lookup_reach(stub, str(alice.uuid).lower())
    assert len(looked) == 2                     # rate limited


def test_lookup_answers_go_to_identity_as_local_records():
    from collections import deque
    alice = _ident('alice@ex')
    rec = reach.create_record(alice, 1, [PIN_HINT])
    stub = types.SimpleNamespace(logger=logging.getLogger('t'), q_cadence=1.0,
                                 relay_records=deque([(rec.record_id, rec.to_wire()),
                                                      (rec.record_id, None)]))
    q = {CfgIds.identity: queue.Queue()}
    rdv_net._drain_relay_records(stub, q)
    msg = q[CfgIds.identity].get_nowait()
    assert msg.function == FirstContactProtocol.reach_record and msg.from_whom is None
    assert reach.ReachRecord.from_wire(msg.obj).seq == 1
    assert q[CfgIds.identity].empty()          # a null answer is not forwarded
