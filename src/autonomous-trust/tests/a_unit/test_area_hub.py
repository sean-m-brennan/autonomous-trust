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
"""Area cards (contacts/area_card.py) and the area hub on a relay (network/hub.py)."""
import json
import threading
import time

import pytest

from autonomous_trust.core.identity import Identity
from autonomous_trust.core._python.contacts import area_card as ac
from autonomous_trust.core._python.contacts.directory import InvalidEntry
from autonomous_trust.core._python.network import relay, hub as hb


def _ident(name):
    return Identity.initialize(name, name, '127.0.0.1')


def _id(ident):
    return str(ident.uuid).lower(), relay._signing_hex(ident).lower()


def _card(ident, area='u4pr', bucket='u4pru', name='', seq=1, ttl=3600, now=None):
    now = now if now is not None else time.time()
    return ac.create_card(ident, area, bucket, name, seq, expiry=int(now) + ttl, now=now)


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def hub(clock):
    return hb.Hub(['u4pr', 'gcpv'], rate=3, clock=clock)


# -- the card -------------------------------------------------------------------
def test_a_card_verifies_and_names_its_holder():
    alice = _ident('alice')
    card = _card(alice, name='Alice B.')
    back = ac.AreaCard.from_wire(json.loads(card.to_json())).verify()
    assert (back.uuid, back.area, back.bucket, back.name) == (_id(alice)[0], 'u4pr', 'u4pru',
                                                              'Alice B.')
    assert back.identity_json['uuid'].lower() == _id(alice)[0]
    assert back.identity_json['address'] == ''


def test_a_tampered_card_does_not_verify():
    card = _card(_ident('alice'))
    wire = card.to_wire()
    wire['body'] = wire['body'].replace('"u4pru"', '"u4prv"')
    with pytest.raises(InvalidEntry) as err:
        ac.AreaCard.from_wire(wire).verify()
    assert err.value.reason == 'bad_signature'


def test_an_expired_card_does_not_verify():
    with pytest.raises(InvalidEntry) as err:
        _card(_ident('alice'), ttl=-1).verify()
    assert err.value.reason == 'expired'


@pytest.mark.parametrize('area,bucket,name', [
    ('u', 'u4pru', ''),             # area too short
    ('u4pru1', 'u4pru1', ''),       # area too long
    ('u4pa', 'u4pau', ''),          # 'a' is not geohash
    ('u4pr', 'u4ps', ''),           # bucket outside the area
    ('u4pr', 'u4pruu', ''),         # bucket finer than 5 km
    ('u4pr', 'u4pru', 'x' * 65),    # name too long
    ('u4pr', 'u4pru', 'a\nb'),      # control character
])
def test_a_card_no_hub_would_take_is_not_made(area, bucket, name):
    with pytest.raises(InvalidEntry):
        ac.create_card(_ident('alice'), area, bucket, name, 1)


@pytest.mark.parametrize('field', ['area', 'bucket', 'name'])
def test_a_card_missing_a_field_is_malformed_not_a_crash(field):
    from autonomous_trust.core._python.contacts.directory import _sign, _signing_key
    alice = _ident('alice')
    body = json.loads(_card(alice).body_str)
    for bad in ({k: v for k, v in body.items() if k != field}, dict(body, **{field: None})):
        with pytest.raises(InvalidEntry) as err:
            ac.AreaCard.from_wire(_sign(_signing_key(alice), ac.CARD_DOMAIN, bad)).verify()
        assert err.value.reason == 'malformed'


def test_a_card_whose_identity_is_someone_else_is_refused():
    alice, eve = _ident('alice'), _ident('eve')
    card = _card(alice)
    body = json.loads(card.body_str)
    other = _card(eve)
    body['identity'] = other.identity_json
    from autonomous_trust.core._python.contacts.directory import _sign, _signing_key
    forged = ac.AreaCard.from_wire(_sign(_signing_key(alice), ac.CARD_DOMAIN, body))
    with pytest.raises(InvalidEntry) as err:
        forged.verify()
    assert err.value.reason == 'mismatch'


# -- the hub ---------------------------------------------------------------------
def test_listed_people_see_each_other_but_never_themselves(hub):
    alice, bob = _ident('alice'), _ident('bob')
    assert hub.publish(*_id(alice), _card(alice).to_wire()) == {
        'op': 'hub_published', 'area': 'u4pr', 'seq': 1}
    hub.publish(*_id(bob), _card(bob, bucket='u4prv').to_wire())
    ans = hub.lookup(_id(bob)[0], 'U4PR')
    assert ans['op'] == 'hub_cards' and ans['area'] == 'u4pr'
    assert [ac.AreaCard.from_wire(c).uuid for c in ans['cards']] == [_id(alice)[0]]


def test_a_lookup_from_outside_the_area_sees_an_empty_area(hub):
    alice, eve = _ident('alice'), _ident('eve')
    hub.publish(*_id(alice), _card(alice).to_wire())
    assert hub.lookup(_id(eve)[0], 'u4pr') == {'op': 'hub_cards', 'area': 'u4pr', 'cards': []}
    # Listed in ANOTHER area of the same hub is still outside this one.
    hub.publish(*_id(eve), _card(eve, area='gcpv', bucket='gcpvj').to_wire())
    assert hub.lookup(_id(eve)[0], 'u4pr')['cards'] == []


def test_an_area_the_hub_does_not_serve_is_refused(hub):
    alice = _ident('alice')
    ans = hub.publish(*_id(alice), _card(alice, area='9q8y', bucket='9q8yy').to_wire())
    assert ans == {'op': 'hub_refused', 'area': '9q8y', 'reason': 'area'}


def test_only_the_holder_files_its_card(hub):
    alice, mallory = _ident('alice'), _ident('mallory')
    assert hub.publish(*_id(mallory), _card(alice).to_wire())['reason'] == 'not_holder'


def test_a_card_longer_than_a_day_is_refused(hub):
    alice = _ident('alice')
    ans = hub.publish(*_id(alice), _card(alice, ttl=ac.MAX_TTL_SECONDS + 60).to_wire())
    assert ans['reason'] == 'expiry'


def test_a_newer_seq_replaces_and_an_older_is_refused(hub):
    alice, bob = _ident('alice'), _ident('bob')
    hub.publish(*_id(bob), _card(bob).to_wire())
    assert hub.publish(*_id(alice), _card(alice, seq=2).to_wire())['seq'] == 2
    assert hub.publish(*_id(alice), _card(alice, seq=1).to_wire())['reason'] == 'stale'
    held = hub._cards['u4pr'][_id(alice)[0]]
    assert hub.publish(*_id(alice), held.to_wire())['op'] == 'hub_published'
    hub.publish(*_id(alice), _card(alice, bucket='u4prw', seq=3).to_wire())
    [c] = hub.lookup(_id(bob)[0], 'u4pr')['cards']
    assert ac.AreaCard.from_wire(c).bucket == 'u4prw'   # one card per holder


def test_withdraw_is_holder_only_and_takes_effect_at_once(hub):
    alice, bob, eve = _ident('alice'), _ident('bob'), _ident('eve')
    hub.publish(*_id(alice), _card(alice).to_wire())
    hub.publish(*_id(bob), _card(bob).to_wire())
    hub.withdraw(*_id(eve), 'u4pr')
    assert len(hub.lookup(_id(bob)[0], 'u4pr')['cards']) == 1
    assert hub.withdraw(*_id(alice), 'U4PR') == {'op': 'hub_withdrawn', 'area': 'u4pr'}
    assert hub.lookup(_id(bob)[0], 'u4pr')['cards'] == []


def test_an_expired_listing_neither_shows_nor_sees(hub):
    alice, bob = _ident('alice'), _ident('bob')
    now = time.time()
    hub.publish(*_id(alice), _card(alice, ttl=3600).to_wire())
    hub.publish(*_id(bob), _card(bob, ttl=3600).to_wire())
    hub.wallclock = lambda: now + 7200
    assert hub.lookup(_id(bob)[0], 'u4pr')['cards'] == []


def test_lookups_are_rate_limited_per_client(hub, clock):
    alice, bob = _ident('alice'), _ident('bob')
    hub.publish(*_id(alice), _card(alice).to_wire())
    hub.publish(*_id(bob), _card(bob).to_wire())
    bu = _id(bob)[0]
    assert [hub.lookup(bu, 'u4pr')['op'] for _ in range(4)] == [
        'hub_cards', 'hub_cards', 'hub_cards', 'hub_limited']
    clock.t += 20.0            # one token back at 3/min
    assert hub.lookup(bu, 'u4pr')['op'] == 'hub_cards'


def test_an_answer_is_bounded_and_freshest_first(clock):
    h = hb.Hub(['u4pr'], rate=100, clock=clock)
    me = _ident('me')
    h.publish(*_id(me), _card(me).to_wire())
    now = time.time()
    people = [_ident('p%d' % i) for i in range(hb.LOOKUP_MAX + 3)]
    for i, p in enumerate(people):
        h.publish(*_id(p), _card(p, ttl=600 + i, now=now).to_wire())
    cards = [ac.AreaCard.from_wire(c) for c in h.lookup(_id(me)[0], 'u4pr')['cards']]
    assert len(cards) == hb.LOOKUP_MAX
    assert [c.expiry for c in cards] == sorted((c.expiry for c in cards), reverse=True)
    assert cards[0].uuid == _id(people[-1])[0]


def test_an_area_has_a_cap(clock, monkeypatch):
    monkeypatch.setattr(hb, 'MAX_PER_AREA', 2)
    h = hb.Hub(['u4pr'], clock=clock)
    a, b, c = _ident('a'), _ident('b'), _ident('c')
    h.publish(*_id(a), _card(a).to_wire())
    h.publish(*_id(b), _card(b).to_wire())
    assert h.publish(*_id(c), _card(c).to_wire())['reason'] == 'full'
    # Refiling one already held is not a new card.
    assert h.publish(*_id(a), _card(a, seq=2).to_wire())['op'] == 'hub_published'


def test_a_distrusted_holder_is_not_shown(clock):
    alice, bob = _ident('alice'), _ident('bob')
    bad = set()
    h = hb.Hub(['u4pr'], rate=10, clock=clock, distrusted=lambda uuid, key: uuid in bad)
    h.publish(*_id(alice), _card(alice).to_wire())
    h.publish(*_id(bob), _card(bob).to_wire())
    bad.add(_id(alice)[0])
    assert h.lookup(_id(bob)[0], 'u4pr')['cards'] == []


def test_the_served_areas_come_from_the_environment(monkeypatch):
    monkeypatch.setenv('AT_HUB_AREAS', ' U4PR, gcpv,nonsense-area,u4pr,x')
    assert hb.hub_areas() == ['u4pr', 'gcpv']
    monkeypatch.setenv('AT_HUB', 'yes')
    assert hb.hub_enabled()


# -- over the relay's own link ------------------------------------------------
class Answers:
    def __init__(self):
        self.items, self._ev = [], threading.Event()

    def __call__(self, msg):
        self.items.append(msg)
        self._ev.set()

    def wait(self, n=1, timeout=5):
        deadline = time.monotonic() + timeout
        while len(self.items) < n and time.monotonic() < deadline:
            self._ev.wait(0.05)
            self._ev.clear()
        return len(self.items) >= n


def test_the_ops_run_over_the_relay_link():
    srv = relay.RelayServer('127.0.0.1', 0, hub=hb.Hub(['u4pr']))
    alice, bob = _ident('alice'), _ident('bob')
    got_a, got_b = Answers(), Answers()
    a = relay.RelayClient(srv.address, alice, lambda *x: None, on_hub=got_a)
    b = relay.RelayClient(srv.address, bob, lambda *x: None, on_hub=got_b)
    try:
        a.hub_publish(_card(alice))
        b.hub_publish(_card(bob))
        assert got_a.wait() and got_a.items[0]['op'] == 'hub_published'
        assert got_b.wait()
        b.hub_lookup('u4pr')
        assert got_b.wait(2)
        [c] = got_b.items[1]['cards']
        assert ac.AreaCard.from_wire(c).uuid == _id(alice)[0]
    finally:
        a.close(), b.close(), srv.stop()


def test_a_plain_relay_refuses_hub_ops():
    srv = relay.RelayServer('127.0.0.1', 0)
    got = Answers()
    a = relay.RelayClient(srv.address, _ident('alice'), lambda *x: None, on_hub=got)
    try:
        a.hub_lookup('u4pr')
        assert got.wait() and got.items[0] == {'op': 'hub_refused', 'area': 'u4pr',
                                               'reason': 'not_hub'}
    finally:
        a.close(), srv.stop()


# -- the network process between identity and the hubs -------------------------
def _net(monkeypatch, own=('198.51.100.1:27790', '198.51.100.2:27790')):
    import collections
    import queue
    import types
    from autonomous_trust.core._python.network.netprocess import NetworkProcess
    from autonomous_trust.core.system import CfgIds
    monkeypatch.setenv('AT_USE_RELAY', ','.join(own))
    eps = [relay.parse_endpoint(e) for e in own]
    asked = []
    clients = {ep: types.SimpleNamespace(
        connected=True,
        hub_lookup=lambda a, ep=ep: asked.append((ep, 'lookup', a)),
        hub_publish=lambda w, ep=ep: asked.append((ep, 'publish', w)),
        hub_withdraw=lambda a, ep=ep: asked.append((ep, 'withdraw', a))) for ep in eps}
    stub = types.SimpleNamespace(
        logger=__import__('logging').getLogger('test-hub-net'),
        _relay_clients=clients, _own_cards={}, relay_hub=collections.deque(),
        _hub_lookups={}, q_cadence=0.1, HUB_LOOKUP_TIMEOUT=NetworkProcess.HUB_LOOKUP_TIMEOUT)
    for name in ('_local_only', '_payload', '_own_registry_clients', '_hub_answer',
                 '_drain_relay_hub', 'handle_hub_lookup', 'handle_hub_publish',
                 'handle_hub_withdraw'):
        raw = NetworkProcess.__dict__[name]
        setattr(stub, name, raw.__func__ if isinstance(raw, staticmethod)
                else raw.__get__(stub))
    queues = {CfgIds.identity: queue.Queue()}
    return stub, queues, eps, asked


def _local(obj):
    import types
    return types.SimpleNamespace(from_whom=None, obj=json.dumps(obj))


def _answers(queues):
    from autonomous_trust.core.system import CfgIds
    out = []
    while not queues[CfgIds.identity].empty():
        m = queues[CfgIds.identity].get_nowait()
        out.append((m.function, json.loads(m.obj)))
    return out


def test_a_lookup_gathers_every_hubs_cards_and_answers_once(monkeypatch):
    stub, queues, (r1, r2), asked = _net(monkeypatch)
    stub.handle_hub_lookup(queues, _local({'area': 'U4PR'}))
    assert sorted(a[0] for a in asked) == sorted([r1, r2])
    alice, bob = _ident('alice'), _ident('bob')
    wa, wb = _card(alice).to_wire(), _card(bob).to_wire()
    stub.relay_hub.append((r1, {'op': 'hub_cards', 'area': 'u4pr', 'cards': [wa]}))
    stub._drain_relay_hub(queues)
    assert _answers(queues) == []          # r2 has not answered yet
    stub.relay_hub.append((r2, {'op': 'hub_cards', 'area': 'u4pr', 'cards': [wb]}))
    stub._drain_relay_hub(queues)
    [(verb, body)] = _answers(queues)
    assert verb == 'hub_result' and body['limited'] is False
    assert body['cards'] == [{'card': wa, 'relay': '%s:%d' % r1},
                             {'card': wb, 'relay': '%s:%d' % r2}]


def test_a_relay_that_is_no_hub_counts_as_empty_and_limited_is_passed_on(monkeypatch):
    stub, queues, (r1, r2), asked = _net(monkeypatch)
    stub.handle_hub_lookup(queues, _local({'area': 'u4pr'}))
    stub.relay_hub.append((r1, {'op': 'hub_limited', 'area': 'u4pr'}))
    stub.relay_hub.append((r2, {'op': 'hub_refused', 'area': 'u4pr', 'reason': 'not_hub'}))
    stub._drain_relay_hub(queues)
    [(verb, body)] = _answers(queues)
    assert body == {'area': 'u4pr', 'cards': [], 'limited': True}


def test_a_lookup_times_out_with_what_came(monkeypatch):
    stub, queues, (r1, r2), asked = _net(monkeypatch)
    stub.handle_hub_lookup(queues, _local({'area': 'u4pr'}))
    wa = _card(_ident('alice')).to_wire()
    stub.relay_hub.append((r1, {'op': 'hub_cards', 'area': 'u4pr', 'cards': [wa]}))
    stub._drain_relay_hub(queues)
    stub._hub_lookups['u4pr']['since'] -= stub.HUB_LOOKUP_TIMEOUT + 1
    stub._drain_relay_hub(queues)
    [(verb, body)] = _answers(queues)
    assert [c['card'] for c in body['cards']] == [wa]


def test_our_card_is_filed_at_our_relays_and_a_no_hub_refusal_is_not_reported(monkeypatch):
    stub, queues, (r1, r2), asked = _net(monkeypatch)
    wire = _card(_ident('alice')).to_wire()
    stub.handle_hub_publish(queues, _local({'card': wire}))
    assert sorted((a[0], a[1]) for a in asked) == sorted([(r1, 'publish'), (r2, 'publish')])
    assert stub._own_cards == {'u4pr': wire}
    stub.relay_hub.append((r1, {'op': 'hub_refused', 'area': 'u4pr', 'reason': 'not_hub'}))
    stub.relay_hub.append((r2, {'op': 'hub_published', 'area': 'u4pr', 'seq': 1}))
    stub._drain_relay_hub(queues)
    [(verb, body)] = _answers(queues)
    assert verb == 'hub_status' and body['op'] == 'hub_published' and body['seq'] == 1
    stub.handle_hub_withdraw(queues, _local({'area': 'u4pr'}))
    assert stub._own_cards == {}


def test_the_hub_ipc_is_refused_from_the_wire(monkeypatch):
    import types
    stub, queues, eps, asked = _net(monkeypatch)
    wire = types.SimpleNamespace(from_whom=_ident('m').publish(), obj=json.dumps({'area': 'u4pr'}))
    stub.handle_hub_lookup(queues, wire)
    stub.handle_hub_withdraw(queues, wire)
    assert asked == []
