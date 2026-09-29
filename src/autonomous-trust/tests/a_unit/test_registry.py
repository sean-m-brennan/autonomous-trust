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
"""The directory registry on a relay (network/registry.py), FIRST_CONTACT_PLAN Phase 3."""
import json
import os
import threading
import time

import pytest
from nacl.encoding import HexEncoder
from nacl.signing import SigningKey

from autonomous_trust.core.config import Configuration
from autonomous_trust.core.identity import Identity
from autonomous_trust.core._python.contacts import directory as d
from autonomous_trust.core._python.network import relay, registry as reg

ISSUER = SigningKey(b'\x44' * 32)
ISSUER_KEY = ISSUER.verify_key.encode(HexEncoder).decode()


def _ident(name):
    return Identity.initialize(name, name, '127.0.0.1')


def _id(ident):
    return str(ident.uuid).lower(), relay._signing_hex(ident).lower()


def _entry(ident, handle, seq=1, visibility='anyone', issuer=ISSUER, ttl=3600):
    att = d.attest(issuer, handle, relay._signing_hex(ident).lower(), int(time.time()) + ttl)
    return d.create_entry(ident, att, seq, visibility)


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def registry(clock):
    return reg.Registry({ISSUER_KEY}, rate=3, clock=clock)


def test_publish_then_lookup(registry):
    alice, bob = _ident('alice'), _ident('bob')
    e = _entry(alice, 'Alice@Example.org')
    assert registry.publish(*_id(alice), e.to_wire()) == {
        'op': 'dir_published', 'handle': 'alice@example.org', 'seq': 1}
    ans = registry.lookup(_id(bob)[0], 'ALICE@example.org')
    assert ans['op'] == 'dir_entry' and ans['handle'] == 'alice@example.org'
    assert d.DirectoryEntry.from_wire(ans['entry']).verify().uuid == _id(alice)[0]
    assert registry.lookup(_id(bob)[0], 'nobody@example.org')['entry'] is None


@pytest.mark.parametrize('why,make', [
    ('untrusted', lambda a: _entry(a, 'a@x', issuer=SigningKey(b'\x66' * 32))),
    ('expired', lambda a: _entry(a, 'a@x', ttl=-1)),
])
def test_an_entry_that_fails_its_check_is_refused_with_the_reason(registry, why, make):
    alice = _ident('alice')
    ans = registry.publish(*_id(alice), make(alice).to_wire())
    assert ans == {'op': 'dir_refused', 'handle': 'a@x', 'reason': why}


def test_only_the_holder_files_its_entry(registry):
    alice, mallory = _ident('alice'), _ident('mallory')
    ans = registry.publish(*_id(mallory), _entry(alice, 'a@x').to_wire())
    assert ans['reason'] == 'not_holder'


def test_a_newer_seq_replaces_and_an_older_is_refused(registry):
    alice = _ident('alice')
    assert registry.publish(*_id(alice), _entry(alice, 'a@x', 2).to_wire())['op'] == 'dir_published'
    assert registry.publish(*_id(alice), _entry(alice, 'a@x', 1).to_wire())['reason'] == 'stale'
    same = _entry(alice, 'a@x', 2, visibility='published')
    # A different body under the same seq is stale too; the same one refiles.
    assert registry.publish(*_id(alice), same.to_wire())['reason'] == 'stale'
    held = registry._entries['a@x']
    assert registry.publish(*_id(alice), held.to_wire())['op'] == 'dir_published'
    assert registry.publish(*_id(alice), _entry(alice, 'a@x', 3).to_wire())['seq'] == 3


def test_a_handle_held_by_another_key_is_taken(registry):
    alice, eve = _ident('alice'), _ident('eve')
    registry.publish(*_id(alice), _entry(alice, 'a@x').to_wire())
    assert registry.publish(*_id(eve), _entry(eve, 'a@x').to_wire())['reason'] == 'taken'


def test_withdraw_is_holder_only(registry):
    alice, eve = _ident('alice'), _ident('eve')
    registry.publish(*_id(alice), _entry(alice, 'a@x').to_wire())
    registry.withdraw(*_id(eve), 'a@x')
    assert registry.lookup(_id(eve)[0], 'a@x')['entry'] is not None
    assert registry.withdraw(*_id(alice), 'A@X') == {'op': 'dir_withdrawn', 'handle': 'a@x'}
    assert registry.lookup(_id(eve)[0], 'a@x')['entry'] is None


def test_published_visibility_needs_the_asker_to_be_published(registry):
    alice, bob = _ident('alice'), _ident('bob')
    registry.publish(*_id(alice), _entry(alice, 'a@x', visibility='published').to_wire())
    assert registry.lookup(_id(bob)[0], 'a@x')['entry'] is None
    registry.publish(*_id(bob), _entry(bob, 'b@x').to_wire())
    assert registry.lookup(_id(bob)[0], 'a@x')['entry'] is not None


def test_lookups_are_rate_limited_per_client(registry, clock):
    alice, bob, carol = _ident('alice'), _ident('bob'), _ident('carol')
    registry.publish(*_id(alice), _entry(alice, 'a@x').to_wire())
    bu = _id(bob)[0]
    assert [registry.lookup(bu, 'a@x')['op'] for _ in range(4)] == [
        'dir_entry', 'dir_entry', 'dir_entry', 'dir_limited']
    assert registry.lookup(_id(carol)[0], 'a@x')['op'] == 'dir_entry'
    clock.t += 20.0            # a third of a minute: one token back at 3/min
    assert registry.lookup(bu, 'a@x')['op'] == 'dir_entry'
    assert registry.lookup(bu, 'a@x')['op'] == 'dir_limited'


def test_a_distrusted_holder_is_not_served(clock):
    alice, bob = _ident('alice'), _ident('bob')
    bad = set()
    r = reg.Registry({ISSUER_KEY}, rate=10, clock=clock,
                     distrusted=lambda uuid, key: uuid in bad)
    r.publish(*_id(alice), _entry(alice, 'a@x').to_wire())
    bad.add(_id(alice)[0])
    assert r.lookup(_id(bob)[0], 'a@x')['entry'] is None


def test_issuers_load_from_the_cfg_dir(monkeypatch, tmp_path):
    monkeypatch.setenv(Configuration.ROOT_VARIABLE_NAME, str(tmp_path))
    os.makedirs(Configuration.get_cfg_dir())
    assert reg.load_issuers() == frozenset()
    with open(os.path.join(Configuration.get_cfg_dir(), reg.ISSUERS_FILE), 'w') as f:
        json.dump({'issuers': [ISSUER_KEY.upper(), 'nonsense']}, f)
    assert reg.load_issuers() == {ISSUER_KEY}


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
    srv = relay.RelayServer('127.0.0.1', 0, registry=reg.Registry({ISSUER_KEY}))
    alice, bob = _ident('alice'), _ident('bob')
    got_a, got_b = Answers(), Answers()
    a = relay.RelayClient(srv.address, alice, lambda *x: None, on_dir=got_a)
    b = relay.RelayClient(srv.address, bob, lambda *x: None, on_dir=got_b)
    try:
        a.dir_publish(_entry(alice, 'alice@example.org'))
        assert got_a.wait() and got_a.items[0]['op'] == 'dir_published'
        b.dir_lookup('Alice@Example.org')
        assert got_b.wait()
        assert d.DirectoryEntry.from_wire(got_b.items[0]['entry']).uuid == _id(alice)[0]
    finally:
        a.close(), b.close(), srv.stop()


def test_a_plain_relay_refuses_directory_ops():
    srv = relay.RelayServer('127.0.0.1', 0)
    alice = _ident('alice')
    got = Answers()
    a = relay.RelayClient(srv.address, alice, lambda *x: None, on_dir=got)
    try:
        a.dir_lookup('a@x')
        assert got.wait() and got.items[0] == {'op': 'dir_refused', 'handle': 'a@x',
                                               'reason': 'not_registry'}
    finally:
        a.close(), srv.stop()


# -- the network process between identity and the registries -------------------
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
        dir_lookup=lambda h, ep=ep: asked.append((ep, 'lookup', h)),
        dir_publish=lambda w, ep=ep: asked.append((ep, 'publish', w)),
        dir_withdraw=lambda h, ep=ep: asked.append((ep, 'withdraw', h))) for ep in eps}
    stub = types.SimpleNamespace(
        logger=__import__('logging').getLogger('test-registry-net'),
        _relay_clients=clients, _own_entries={}, relay_dir=collections.deque(),
        _dir_lookups={}, q_cadence=0.1, DIR_LOOKUP_TIMEOUT=NetworkProcess.DIR_LOOKUP_TIMEOUT)
    for name in ('_local_only', '_payload', '_own_registry_clients', '_dir_answer',
                 '_drain_relay_dir', 'handle_dir_lookup', 'handle_dir_publish',
                 'handle_dir_withdraw'):
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


def test_a_lookup_asks_every_relay_and_answers_once(monkeypatch):
    stub, queues, (r1, r2), asked = _net(monkeypatch)
    stub.handle_dir_lookup(queues, _local({'handle': 'A@X'}))
    assert sorted(a[0] for a in asked) == sorted([r1, r2])
    assert {a[2] for a in asked} == {'a@x'}
    alice = _ident('alice')
    wire = _entry(alice, 'a@x').to_wire()
    stub.relay_dir.append((r1, {'op': 'dir_entry', 'handle': 'a@x', 'entry': None}))
    stub._drain_relay_dir(queues)
    assert _answers(queues) == []          # r2 has not answered yet
    stub.relay_dir.append((r2, {'op': 'dir_entry', 'handle': 'a@x', 'entry': wire}))
    stub._drain_relay_dir(queues)
    [(verb, body)] = _answers(queues)
    assert verb == 'dir_result' and body['entry'] == wire
    assert body['relay'] == '%s:%d' % r2


def test_a_lookup_nobody_can_answer_is_not_found_and_limited_is_passed_on(monkeypatch):
    stub, queues, (r1, r2), asked = _net(monkeypatch)
    stub.handle_dir_lookup(queues, _local({'handle': 'a@x'}))
    stub.relay_dir.append((r1, {'op': 'dir_limited', 'handle': 'a@x'}))
    stub.relay_dir.append((r2, {'op': 'dir_refused', 'handle': 'a@x',
                                'reason': 'not_registry'}))
    stub._drain_relay_dir(queues)
    [(verb, body)] = _answers(queues)
    assert body == {'handle': 'a@x', 'entry': None, 'limited': True, 'relay': ''}


def test_an_answer_from_a_relay_not_asked_is_ignored(monkeypatch):
    stub, queues, (r1, r2), asked = _net(monkeypatch)
    stub.handle_dir_lookup(queues, _local({'handle': 'a@x'}))
    alice = _ident('alice')
    stub.relay_dir.append((('203.0.113.66', 1), {'op': 'dir_entry', 'handle': 'a@x',
                                                 'entry': _entry(alice, 'a@x').to_wire()}))
    stub._drain_relay_dir(queues)
    assert _answers(queues) == []


def test_a_lookup_times_out(monkeypatch):
    stub, queues, eps, asked = _net(monkeypatch)
    stub.handle_dir_lookup(queues, _local({'handle': 'a@x'}))
    stub._dir_lookups['a@x']['since'] -= stub.DIR_LOOKUP_TIMEOUT + 1
    stub._drain_relay_dir(queues)
    [(verb, body)] = _answers(queues)
    assert body['entry'] is None


def test_the_directory_ipc_is_refused_from_the_wire(monkeypatch):
    import types
    stub, queues, eps, asked = _net(monkeypatch)
    wire = types.SimpleNamespace(from_whom=_ident('m').publish(), obj=json.dumps({'handle': 'a@x'}))
    stub.handle_dir_lookup(queues, wire)
    stub.handle_dir_withdraw(queues, wire)
    assert asked == []


def test_our_entry_is_filed_at_our_relays_and_withdrawn(monkeypatch):
    stub, queues, (r1, r2), asked = _net(monkeypatch)
    alice = _ident('alice')
    wire = _entry(alice, 'a@x').to_wire()
    stub.handle_dir_publish(queues, _local({'entry': wire}))
    assert sorted((a[0], a[1]) for a in asked) == sorted([(r1, 'publish'), (r2, 'publish')])
    assert stub._own_entries == {'a@x': wire}
    stub.handle_dir_withdraw(queues, _local({'handle': 'a@x'}))
    assert stub._own_entries == {}
    stub.relay_dir.append((r1, {'op': 'dir_published', 'handle': 'a@x', 'seq': 1}))
    stub._drain_relay_dir(queues)
    [(verb, body)] = _answers(queues)
    assert verb == 'dir_status' and body['op'] == 'dir_published' and body['seq'] == 1
