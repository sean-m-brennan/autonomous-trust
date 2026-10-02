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
"""Finding someone by handle and asking to be their contact
(first_contact/directory_contact.py), FIRST_CONTACT_PLAN Phase 3.

Two stub identity processes, each under its own root, with the network in
between played by hand: what one node queues for its network process is
handed to the other node's handler, and registry answers come from a real
network.registry.Registry."""
import json
import logging
import os
import queue
import time
import types

import pytest
from nacl.encoding import HexEncoder
from nacl.signing import SigningKey

from autonomous_trust.core.config import Configuration
from autonomous_trust.first_contact import Contacts, Provenance
from autonomous_trust.core.identity import Identity, Peers
from autonomous_trust.first_contact import first_contact as fc
from autonomous_trust.first_contact._python import directory_contact as dc
from autonomous_trust.first_contact._python import directory as d
from autonomous_trust.rendezvous._python import relay
from autonomous_trust.first_contact._python import registry as reg
from autonomous_trust.first_contact.fc_protocol import FirstContactProtocol
from autonomous_trust.core.network.message import Message
from autonomous_trust.core.network.network import Network
from autonomous_trust.core.system import CfgIds

ISSUER = SigningKey(b'\x44' * 32)
ISSUER_KEY = ISSUER.verify_key.encode(HexEncoder).decode()
REGISTRY_EP = '127.0.0.1:27790'


class Node:
    """A stub IdentityProcess with its own root, queues and registered handlers."""

    def __init__(self, name, root, monkeypatch):
        self.root = str(root / name)
        self.monkeypatch = monkeypatch
        self.identity = Identity.initialize(name, name, '10.0.0.%d' % (len(name) + 1))
        self.name = CfgIds.identity
        self.peers = Peers()
        self.logger = logging.getLogger('test-directory-' + name)
        self.q_cadence = 1.0
        self.queues = {CfgIds.network: queue.Queue(), CfgIds.main: queue.Queue()}
        self.handlers = {}
        self.protocol = types.SimpleNamespace(
            register_handler=lambda verb, fn: self.handlers.__setitem__(verb, fn))
        with self:
            fc.register(self)

    def __enter__(self):
        self.monkeypatch.setenv(Configuration.ROOT_VARIABLE_NAME, self.root)
        return self

    def __exit__(self, *exc):
        return False

    def _record_peers(self, queues):
        pass

    def app(self, verb, payload):
        with self:
            self.handlers[verb](self.queues, Message(
                CfgIds.identity, verb, json.dumps(payload), to_whom=None,
                from_whom=None, encrypt=False))

    def local(self, verb, body):
        with self:
            self.handlers[verb](self.queues, types.SimpleNamespace(
                from_whom=None, function=verb, obj=json.dumps(body)))

    def wire(self, sender, verb, obj):
        with self:
            self.handlers[verb](self.queues, types.SimpleNamespace(
                from_whom=sender.identity.publish(), function=verb, obj=obj))

    def sent(self):
        out = []
        while not self.queues[CfgIds.network].empty():
            out.append(self.queues[CfgIds.network].get_nowait())
        return out

    def events(self):
        out = []
        while not self.queues[CfgIds.main].empty():
            out.append(self.queues[CfgIds.main].get_nowait())
        return out

    def contact(self, other):
        with self:
            return Contacts.load().get(str(other.identity.uuid))

    @property
    def key(self):
        return relay._signing_hex(self.identity).lower()

    @property
    def uuid(self):
        return str(self.identity.uuid).lower()


def _only(msgs, verb):
    found = [m for m in msgs if m.function == verb]
    assert found, 'no %s among %s' % (verb, [m.function for m in msgs])
    return found[-1]


@pytest.fixture
def world(monkeypatch, tmp_path):
    monkeypatch.setenv('AT_FIRST_CONTACT', '1')
    monkeypatch.delenv('AT_USE_RELAY', raising=False)
    alice = Node('alice', tmp_path, monkeypatch)
    bob = Node('bob', tmp_path, monkeypatch)
    registry = reg.Registry({ISSUER_KEY})
    return alice, bob, registry


def _publish(alice, registry, handle='alice@example.org', visibility='anyone'):
    att = d.attest(ISSUER, handle, alice.key, int(time.time()) + 3600)
    alice.app(dc.APP_DIR_PUBLISH, {'ref': 'pub1', 'attestation': att.to_wire(),
                                   'visibility': visibility})
    msg = _only(alice.sent(), Network.dir_publish)
    entry = json.loads(msg.obj)['entry']
    reply = registry.publish(alice.uuid, alice.key, entry)
    alice.local(FirstContactProtocol.dir_status, dict(reply, relay=REGISTRY_EP))
    return entry


def _lookup(bob, registry, handle):
    bob.app(dc.APP_DIR_LOOKUP, {'ref': 'look1', 'handle': handle})
    asked = json.loads(_only(bob.sent(), Network.dir_lookup).obj)['handle']
    ans = registry.lookup(bob.uuid, asked)
    bob.local(FirstContactProtocol.dir_result, {'handle': ans['handle'], 'entry': ans['entry'],
                                            'relay': REGISTRY_EP, 'limited': False})
    return bob.events()


def _request(alice, bob):
    bob.app(dc.APP_REQUEST, {'ref': 'req1', 'handle': 'alice@example.org'})
    sent = bob.sent()
    route = json.loads(_only(sent, Network.relay_route).obj)
    assert route == {'uuid': alice.uuid, 'relays': [REGISTRY_EP]}
    return _only(sent, FirstContactProtocol.contact_request)


def test_find_ask_accept_and_both_hold_an_unverified_directory_contact(world):
    alice, bob, registry = world
    _publish(alice, registry)
    [pub] = alice.events()
    assert (pub.kind, pub.ref, pub.handle, pub.seq) == ('published', 'pub1',
                                                       'alice@example.org', 1)
    [found] = _lookup(bob, registry, 'Alice@Example.org')
    assert (found.kind, found.ref, found.peer_uuid, found.nickname) == (
        'found', 'look1', alice.uuid, 'alice')
    request = _request(alice, bob)
    assert bob.events()[0].kind == 'request_sent'

    alice.wire(bob, FirstContactProtocol.contact_request, request.obj)
    [asked] = alice.events()
    assert (asked.kind, asked.peer_uuid, asked.handle) == ('contact_request', bob.uuid,
                                                         'alice@example.org')
    assert not alice.sent(), 'a request must wait for the app'

    alice.app(dc.APP_ACCEPT, {'ref': asked.ref})
    accept = _only(alice.sent(), FirstContactProtocol.contact_accept)
    assert alice.events()[0].kind == 'accepted'

    bob.wire(alice, FirstContactProtocol.contact_accept, accept.obj)
    hello = _only(bob.sent(), FirstContactProtocol.hello)
    assert bob.events()[0].kind == fc.EVENT_HELLO_SENT
    alice.wire(bob, FirstContactProtocol.hello, hello.obj)
    ack = _only(alice.sent(), FirstContactProtocol.hello_ack)
    [est_a] = [e for e in alice.events() if e.kind == fc.EVENT_ESTABLISHED]
    assert est_a.ref == asked.ref          # reported under the request's ref
    bob.wire(alice, FirstContactProtocol.hello_ack, ack.obj)
    [est_b] = [e for e in bob.events() if e.kind == fc.EVENT_ESTABLISHED]
    assert est_b.ref == 'req1'

    for me, them in ((alice, bob), (bob, alice)):
        c = me.contact(them)
        assert c is not None and not c.verified
        assert c.provenance == Provenance.directory
        assert fc.capped_tier(me, them.uuid, 3) == fc.UNVERIFIED_TIER_CAP


def test_a_decline_sends_nothing_and_the_request_is_gone(world):
    alice, bob, registry = world
    _publish(alice, registry)
    alice.events()
    _lookup(bob, registry, 'alice@example.org')
    alice.wire(bob, FirstContactProtocol.contact_request, _request(alice, bob).obj)
    [asked] = alice.events()
    alice.app(dc.APP_DECLINE, {'ref': asked.ref})
    assert not alice.sent()
    assert alice.events()[0].kind == 'declined'
    alice.app(dc.APP_ACCEPT, {'ref': asked.ref})
    assert alice.events()[0].reason == 'unknown_request'
    assert not alice.sent()


def test_a_request_for_a_handle_we_do_not_publish_is_ignored(world):
    alice, bob, registry = world
    entry = _publish(alice, registry)
    alice.events()
    found = d.DirectoryEntry.from_wire(entry)
    other = d.DirectoryEntry.from_wire(entry)
    other.body = dict(found.body, handle='someone@else.org')
    req = d.create_request(bob.identity, other)
    alice.wire(bob, FirstContactProtocol.contact_request, req.to_json())
    assert not alice.events()


def test_a_request_not_signed_by_its_sender_is_ignored(world, monkeypatch, tmp_path):
    alice, bob, registry = world
    mallory = Node('mallory', tmp_path, monkeypatch)
    entry = d.DirectoryEntry.from_wire(_publish(alice, registry))
    alice.events()
    forged = d.create_request(mallory.identity, entry)      # signed by Mallory...
    alice.wire(bob, FirstContactProtocol.contact_request, forged.to_json())   # ...sent as Bob
    assert not alice.events()


def test_a_request_addressed_to_someone_else_is_ignored(world, monkeypatch, tmp_path):
    alice, bob, registry = world
    carol = Node('carol', tmp_path, monkeypatch)
    entry = d.DirectoryEntry.from_wire(_publish(alice, registry))
    alice.events()
    # Carol holds the same handle (an issuer attested it twice), so only the
    # request's `to` tells her it was meant for Alice.
    _publish(carol, reg.Registry({ISSUER_KEY}))
    carol.events()
    req = d.create_request(bob.identity, entry)
    carol.wire(bob, FirstContactProtocol.contact_request, req.to_json())
    assert not carol.events()


def test_an_accept_nobody_asked_for_is_ignored(world, monkeypatch, tmp_path):
    alice, bob, registry = world
    _publish(alice, registry)
    alice.events()
    _lookup(bob, registry, 'alice@example.org')
    alice.wire(bob, FirstContactProtocol.contact_request, _request(alice, bob).obj)
    [asked] = alice.events()
    bob.events()
    alice.app(dc.APP_ACCEPT, {'ref': asked.ref})
    accept = _only(alice.sent(), FirstContactProtocol.contact_accept)
    # From someone we never asked...
    mallory = Node('mallory', tmp_path, monkeypatch)
    bob.wire(mallory, FirstContactProtocol.contact_accept, accept.obj)
    assert not bob.sent()
    # ...answering another nonce...
    payload = json.loads(accept.obj)
    bob.wire(alice, FirstContactProtocol.contact_accept,
             json.dumps(dict(payload, nonce='0' * 32)))
    assert not bob.sent()
    # ...or carrying someone else's invitation.
    with mallory:
        theirs = fc.create_invitation(mallory.identity, ttl_seconds=60).encode()
    bob.wire(alice, FirstContactProtocol.contact_accept,
             json.dumps(dict(payload, invitation=theirs)))
    assert not bob.sent()
    # The real one still works.
    bob.wire(alice, FirstContactProtocol.contact_accept, accept.obj)
    assert _only(bob.sent(), FirstContactProtocol.hello)


def test_a_lookup_checks_the_entry_itself(world):
    alice, bob, registry = world
    entry = _publish(alice, registry)
    alice.events()
    bob.app(dc.APP_DIR_LOOKUP, {'ref': 'x', 'handle': 'bob@example.org'})
    bob.sent()
    # A registry answering another handle than the one asked...
    bob.local(FirstContactProtocol.dir_result, {'handle': 'bob@example.org', 'entry': entry,
                                            'relay': REGISTRY_EP, 'limited': False})
    [ev] = bob.events()
    assert (ev.kind, ev.reason) == ('not_found', 'invalid')
    # ...and one whose signature does not hold.
    bob.app(dc.APP_DIR_LOOKUP, {'ref': 'y', 'handle': 'alice@example.org'})
    bob.sent()
    bad = dict(entry, body=entry['body'].replace('"seq":1', '"seq":9'))
    bob.local(FirstContactProtocol.dir_result, {'handle': 'alice@example.org', 'entry': bad,
                                            'relay': REGISTRY_EP, 'limited': False})
    assert bob.events()[0].reason == 'invalid'


def test_a_limited_or_empty_lookup_says_so(world):
    alice, bob, registry = world
    bob.app(dc.APP_DIR_LOOKUP, {'ref': 'x', 'handle': 'nobody@example.org'})
    bob.sent()
    bob.local(FirstContactProtocol.dir_result, {'handle': 'nobody@example.org', 'entry': None,
                                            'relay': '', 'limited': True})
    assert [(e.kind, e.reason) for e in bob.events()] == [('not_found', 'limited')]


def test_asking_without_a_lookup_is_refused(world):
    alice, bob, registry = world
    bob.app(dc.APP_REQUEST, {'ref': 'r', 'handle': 'alice@example.org'})
    assert bob.events()[0].reason == 'unknown_handle'
    assert not bob.sent()


def test_republishing_raises_the_seq_and_survives_a_restart(world, monkeypatch, tmp_path):
    alice, bob, registry = world
    _publish(alice, registry)
    second = d.DirectoryEntry.from_wire(_publish(alice, registry, visibility='published'))
    assert second.seq == 2
    alice.events()
    # A fresh process under the same root refiles its entry at startup.
    with alice:
        assert dc.restore_entries(alice, alice.queues) == 1
    refiled = json.loads(_only(alice.sent(), Network.dir_publish).obj)['entry']
    assert d.DirectoryEntry.from_wire(refiled).seq == 2


def test_the_app_verbs_are_local_only(world):
    alice, bob, registry = world
    for verb in dc.APP_VERBS:
        alice.wire(bob, verb, json.dumps({'ref': 'x', 'handle': 'a@x'}))
    assert not alice.sent()


def test_the_app_verbs_are_declared_to_the_identity_process(monkeypatch):
    from autonomous_trust.core._python import app_verbs
    monkeypatch.setenv('AT_FIRST_CONTACT', '1')
    for verb in dc.APP_VERBS:
        assert app_verbs.app_verb_target(verb) == CfgIds.identity
