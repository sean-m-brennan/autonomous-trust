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
"""Finding people nearby at an area hub and asking one to be a contact
(identity/area_contact.py and its path through directory_contact.py).

The same two stub identity processes as test_directory_contact.py, with the
network played by hand and hub answers from a real network.hub.Hub."""
import json
import time

import pytest

from autonomous_trust.core.contacts import Provenance
from autonomous_trust.core.identity import first_contact as fc
from autonomous_trust.core._python.identity import area_contact as ar
from autonomous_trust.core._python.identity import directory_contact as dc
from autonomous_trust.core._python.contacts import area_card as ac
from autonomous_trust.core._python.contacts import directory as d
from autonomous_trust.core._python.network import hub as hb
from autonomous_trust.core.identity.protocol import IdentityProtocol
from autonomous_trust.core.network.network import Network
from autonomous_trust.core.system import CfgIds

from .test_directory_contact import Node, _only

HUB_EP = '127.0.0.1:27790'


@pytest.fixture
def world(monkeypatch, tmp_path):
    monkeypatch.setenv('AT_FIRST_CONTACT', '1')
    monkeypatch.delenv('AT_USE_RELAY', raising=False)
    alice = Node('alice', tmp_path, monkeypatch)
    bob = Node('bob', tmp_path, monkeypatch)
    return alice, bob, hb.Hub(['u4pr'])


def _list(node, hub, area='u4pr', bucket='u4pru', name=''):
    node.app(ar.APP_AREA_PUBLISH, {'ref': 'pub-' + node.uuid[:4], 'area': area,
                                   'bucket': bucket, 'name': name})
    card = json.loads(_only(node.sent(), Network.hub_publish).obj)['card']
    reply = hub.publish(node.uuid, node.key, card)
    node.local(IdentityProtocol.hub_status, dict(reply, relay=HUB_EP))
    return card


def _lookup(node, hub, area='u4pr'):
    node.app(ar.APP_AREA_LOOKUP, {'ref': 'look', 'area': area})
    asked = json.loads(_only(node.sent(), Network.hub_lookup).obj)['area']
    ans = hub.lookup(node.uuid, asked)
    node.local(IdentityProtocol.hub_result, {
        'area': ans['area'], 'limited': ans['op'] == 'hub_limited',
        'cards': [{'card': c, 'relay': HUB_EP} for c in ans.get('cards', [])]})
    return node.events()


def test_listed_find_ask_accept_and_both_hold_an_unverified_area_contact(world):
    alice, bob, hub = world
    _list(alice, hub, name='Alice B.')
    [pub] = alice.events()
    assert (pub.kind, pub.area, pub.seq, pub.relay) == (ar.EVENT_PUBLISHED, 'u4pr', 1, HUB_EP)
    _list(bob, hub, bucket='u4prv')
    bob.events()
    card, done = _lookup(bob, hub)
    assert (card.kind, card.peer_uuid, card.name, card.bucket, card.relay) == (
        ar.EVENT_CARD, alice.uuid, 'Alice B.', 'u4pru', HUB_EP)
    assert (done.kind, done.count, done.reason) == (ar.EVENT_DONE, 1, '')

    bob.app(dc.APP_REQUEST, {'ref': 'req1', 'area': 'u4pr', 'peer_uuid': alice.uuid})
    sent = bob.sent()
    assert json.loads(_only(sent, Network.relay_route).obj) == {
        'uuid': alice.uuid, 'relays': [HUB_EP]}
    request = _only(sent, IdentityProtocol.contact_request)
    body = json.loads(json.loads(request.obj)['body'])
    assert body['area'] == 'u4pr' and 'handle' not in body
    [sent_ev] = bob.events()
    assert (sent_ev.kind, sent_ev.handle) == ('request_sent', 'area:u4pr')

    alice.wire(bob, IdentityProtocol.contact_request, request.obj)
    [asked] = alice.events()
    assert (asked.kind, asked.peer_uuid, asked.handle) == ('contact_request', bob.uuid,
                                                         'area:u4pr')
    assert not alice.sent(), 'a request must wait for the app'
    alice.app(dc.APP_ACCEPT, {'ref': asked.ref})
    accept = _only(alice.sent(), IdentityProtocol.contact_accept)
    alice.events()
    bob.wire(alice, IdentityProtocol.contact_accept, accept.obj)
    hello = _only(bob.sent(), IdentityProtocol.hello)
    alice.wire(bob, IdentityProtocol.hello, hello.obj)
    ack = _only(alice.sent(), IdentityProtocol.hello_ack)
    bob.wire(alice, IdentityProtocol.hello_ack, ack.obj)
    assert [e for e in bob.events() if e.kind == fc.EVENT_ESTABLISHED]
    for me, them in ((alice, bob), (bob, alice)):
        c = me.contact(them)
        assert c is not None and not c.verified
        assert c.provenance == Provenance.area
        assert fc.capped_tier(me, them.uuid, 3) == fc.UNVERIFIED_TIER_CAP


def test_a_hub_lookup_from_someone_not_listed_finds_nobody(world):
    alice, bob, hub = world
    _list(alice, hub)
    [done] = _lookup(bob, hub)
    assert (done.kind, done.count) == (ar.EVENT_DONE, 0)


def test_the_finder_checks_every_card_itself(world, monkeypatch, tmp_path):
    alice, bob, hub = world
    good = _list(alice, hub)
    bob.app(ar.APP_AREA_LOOKUP, {'ref': 'x', 'area': 'u4pr'})
    bob.sent()
    carol = Node('carol', tmp_path, monkeypatch)
    theirs = ac.create_card(carol.identity, 'u4pr', 'u4pru', '', 1).to_wire()
    bad = dict(theirs, body=theirs['body'].replace('"u4pru"', '"u4prz"'))
    mine = ac.create_card(bob.identity, 'u4pr', 'u4prv', '', 1).to_wire()
    bob.local(IdentityProtocol.hub_result, {'area': 'u4pr', 'limited': False, 'cards': [
        {'card': bad, 'relay': HUB_EP},      # forged: signature does not hold
        {'card': mine, 'relay': HUB_EP},     # our own
        {'card': good, 'relay': HUB_EP},
        {'card': good, 'relay': '10.0.0.9:27790'}]})   # the same person at two hubs
    evs = bob.events()
    assert [(e.kind, e.peer_uuid) for e in evs] == [(ar.EVENT_CARD, alice.uuid),
                                                    (ar.EVENT_DONE, '')]
    assert evs[-1].count == 1


def test_a_card_for_another_area_than_asked_is_dropped(world):
    alice, bob, hub = world
    other = ac.create_card(alice.identity, 'gcpv', 'gcpvj', '', 1).to_wire()
    bob.app(ar.APP_AREA_LOOKUP, {'ref': 'x', 'area': 'u4pr'})
    bob.sent()
    bob.local(IdentityProtocol.hub_result, {'area': 'u4pr', 'limited': True,
                                            'cards': [{'card': other, 'relay': HUB_EP}]})
    [done] = bob.events()
    assert (done.count, done.reason) == (0, 'limited')


def test_asking_someone_not_found_in_that_area_is_refused(world):
    alice, bob, hub = world
    bob.app(dc.APP_REQUEST, {'ref': 'r', 'area': 'u4pr', 'peer_uuid': alice.uuid})
    assert bob.events()[0].reason == 'unknown_handle'
    assert not bob.sent()


def test_a_request_via_an_area_we_are_not_listed_in_is_ignored(world):
    alice, bob, hub = world
    card = ac.AreaCard.from_wire(_list(alice, hub))
    alice.events()
    req = d.create_request(bob.identity, card)
    # Withdrawn: the same request is no longer shown.
    alice.app(ar.APP_AREA_WITHDRAW, {'ref': 'w', 'area': 'u4pr'})
    assert json.loads(_only(alice.sent(), Network.hub_withdraw).obj) == {'area': 'u4pr'}
    alice.wire(bob, IdentityProtocol.contact_request, req.to_json())
    assert not alice.events()


def test_a_request_names_a_handle_or_an_area_never_both():
    from autonomous_trust.core.identity import Identity
    bob, alice = Identity.initialize('bob', 'bob', ''), Identity.initialize('alice', 'alice', '')
    card = ac.create_card(alice, 'u4pr', 'u4pru', '', 1)
    req = d.create_request(bob, card)
    body = json.loads(req.body_str)
    for bad in (dict(body, handle='a@x'), {k: v for k, v in body.items() if k != 'area'},
                dict(body, area='u4pa'), dict(body, area=None),
                dict({k: v for k, v in body.items() if k != 'area'}, handle=None)):
        forged = d.ContactRequest.from_wire(d._sign(d._signing_key(bob), d.REQUEST_DOMAIN, bad))
        with pytest.raises(d.InvalidEntry):
            forged.verify()
    assert req.verify().area == 'u4pr'


def test_a_listing_refreshes_past_half_its_life_and_survives_a_restart(world):
    alice, bob, hub = world
    _list(alice, hub)
    alice.events()
    with alice:
        assert ar.refresh(alice, alice.queues) == 1
    same = json.loads(_only(alice.sent(), Network.hub_publish).obj)['card']
    assert ac.AreaCard.from_wire(same).seq == 1           # still fresh: refiled as is
    alice._dir_clock_advance = ac.DEFAULT_TTL_SECONDS * 0.6
    with alice:
        assert ar.refresh(alice, alice.queues) == 1
    fresh = ac.AreaCard.from_wire(json.loads(_only(alice.sent(), Network.hub_publish).obj)['card'])
    assert fresh.seq == 2 and fresh.expiry > time.time() + ac.DEFAULT_TTL_SECONDS
    assert hub.publish(alice.uuid, alice.key, fresh.to_wire())['seq'] == 2
    # Withdrawn: nothing to refresh, and a later listing still rises.
    alice.app(ar.APP_AREA_WITHDRAW, {'ref': 'w', 'area': 'u4pr'})
    alice.sent()
    with alice:
        assert ar.refresh(alice, alice.queues) == 0
    alice._dir_clock_advance = 0.0
    assert ac.AreaCard.from_wire(_list(alice, hub)).seq == 3


def test_a_bad_listing_is_refused_and_the_list_is_bounded(world):
    alice, bob, hub = world
    for payload in ({'area': 'u4pr', 'bucket': 'u4ps'}, {'area': 'u4pr', 'bucket': 'u4pru',
                                                       'name': 'x' * 100}, {'bucket': 'u4pru'}):
        alice.app(ar.APP_AREA_PUBLISH, dict(payload, ref='r'))
        assert alice.events()[0].reason == 'bad_request'
    for i, area in enumerate(('u4pr', 'u4pq', 'u4pn', 'u4pp')):
        alice.app(ar.APP_AREA_PUBLISH, {'ref': 'r', 'area': area, 'bucket': area + 'b'})
    alice.app(ar.APP_AREA_PUBLISH, {'ref': 'r', 'area': 'gcpv', 'bucket': 'gcpvj'})
    assert [e.reason for e in alice.events()] == ['full']


def test_the_app_verbs_are_local_only_and_declared(world, monkeypatch):
    from autonomous_trust.core._python import app_verbs
    alice, bob, hub = world
    for verb in ar.APP_VERBS:
        alice.wire(bob, verb, json.dumps({'ref': 'x', 'area': 'u4pr', 'bucket': 'u4pru'}))
        assert app_verbs.app_verb_target(verb) == CfgIds.identity
    assert not alice.sent()
    alice.wire(bob, IdentityProtocol.hub_result, json.dumps({'area': 'u4pr', 'cards': []}))
    alice.wire(bob, IdentityProtocol.hub_status, json.dumps({'op': 'hub_published'}))
    assert not alice.events()


def test_the_app_installs_and_removes_a_communitys_roster(world):
    from nacl.encoding import HexEncoder
    from nacl.signing import SigningKey
    from autonomous_trust.core._python.network import relay_rosters as rosters
    alice, bob, hub = world
    sk = SigningKey(b'\x52' * 32)
    seed, key = HexEncoder.encode(bytes(sk)).decode(), sk.verify_key.encode(HexEncoder).decode()
    hint = 'relay://00000000-0000-4000-8000-000000000001:%s@198.51.100.1:27790' % ('ab' * 16)
    text = rosters.sign_roster(seed, 2, [hint], areas={hint: ['u4pr']})
    alice.app(ar.APP_ROSTER_INSTALL, {'ref': 'i', 'roster': text})
    [ev] = alice.events()
    assert (ev.kind, ev.issuer, ev.seq) == (ar.EVENT_ROSTER_INSTALLED, key, 2)
    with alice:
        assert rosters.pinned_issuers() == [key]
    forged = json.loads(text)
    forged['body'] = forged['body'].replace('"seq":2', '"seq":3')
    alice.app(ar.APP_ROSTER_INSTALL, {'ref': 'j', 'roster': json.dumps(forged)})
    assert alice.events()[0].reason == 'invalid'
    alice.app(ar.APP_ROSTER_REMOVE, {'ref': 'k', 'issuer': key.upper()})
    [ev] = alice.events()
    assert (ev.kind, ev.count) == (ar.EVENT_ROSTER_REMOVED, 1)
    with alice:
        assert rosters.pinned_issuers() == []
