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
"""The rendezvous relay (relay.py), FIRST_CONTACT_PLAN Phase 0.

The protocol runs over real localhost sockets: a RelayServer and RelayClients
that register with a signed challenge and forward sealed frames. Then the
network process's relay routes, failover and relay gate (rdv_net.py). Where
first contact meets the relay is first contact's test_first_contact_relay.py.
"""
import json
import logging
import socket
import struct
import threading
import time
import types

import pytest

from autonomous_trust.core.config import Configuration
from autonomous_trust.core.identity import Identity, Peers
from autonomous_trust.rendezvous._python import relay


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv(Configuration.ROOT_VARIABLE_NAME, str(tmp_path))
    monkeypatch.delenv('AT_USE_RELAY', raising=False)
    monkeypatch.setenv('AT_RELAY_SEED_FALLBACK', '1')


@pytest.fixture
def server():
    srv = relay.RelayServer('127.0.0.1', 0)
    yield srv
    srv.stop()


def _ident(name, addr):
    return Identity.initialize(name, name, addr)


class Inbox:
    def __init__(self):
        self.items = []
        self.event = threading.Event()

    def __call__(self, frm, frame):
        self.items.append((frm, frame))
        self.event.set()

    def wait(self, n=1, timeout=5.0):
        deadline = time.monotonic() + timeout
        while len(self.items) < n and time.monotonic() < deadline:
            time.sleep(0.01)
        return len(self.items) >= n


def _client(server, ident, inbox=None):
    return relay.RelayClient(server.address, ident, inbox or Inbox())


def _wait_registered(server, uuid, timeout=5.0):
    deadline = time.monotonic() + timeout
    while str(uuid).lower() not in server.registered() and time.monotonic() < deadline:
        time.sleep(0.01)
    return str(uuid).lower() in server.registered()


# -- endpoints and hints -----------------------------------------------------
@pytest.mark.parametrize('text,expect', [
    ('relay://10.0.0.9:27790', ('10.0.0.9', 27790)),
    ('10.0.0.9:27790', ('10.0.0.9', 27790)),
    ('relay://[2001:db8::1]:9000', ('2001:db8::1', 9000)),
    ('relay://host.example:1/', ('host.example', 1)),
    ('relay://10.0.0.9', None),
    ('relay://:27790', None),
    ('10.0.0.9:99999', None),
    ('', None),
])
def test_parse_endpoint(text, expect):
    assert relay.parse_endpoint(text) == expect


def test_hint_round_trips():
    for ep in (('10.0.0.9', 27790), ('2001:db8::1', 9000)):
        assert relay.parse_endpoint(relay.hint_for(ep)) == ep


# -- the protocol ------------------------------------------------------------
def test_two_clients_exchange_frames_and_from_is_the_relays(server):
    alice, bob = _ident('alice@ex', '10.0.0.1'), _ident('bob@ex', '10.0.0.2')
    a_in, b_in = Inbox(), Inbox()
    a, b = _client(server, alice, a_in), _client(server, bob, b_in)
    assert a.connect() and b.connect()
    assert _wait_registered(server, alice.uuid) and _wait_registered(server, bob.uuid)

    a.send(bob.uuid, b'sealed-for-bob')
    assert b_in.wait()
    assert b_in.items[0] == (str(alice.uuid).lower(), b'sealed-for-bob')
    b.send(alice.uuid, b'\x00\xffbinary')
    assert a_in.wait()
    assert a_in.items[0] == (str(bob.uuid).lower(), b'\x00\xffbinary')
    a.close(), b.close()


def test_an_unregistered_target_is_reported_unreachable(server):
    alice = _ident('alice@ex', '10.0.0.1')
    a = _client(server, alice)
    a.connect()
    ghost = _ident('ghost@ex', '10.0.0.66')
    a.send(ghost.uuid, b'x')
    deadline = time.monotonic() + 5
    while str(ghost.uuid).lower() not in a.unreachable and time.monotonic() < deadline:
        time.sleep(0.01)
    assert str(ghost.uuid).lower() in a.unreachable
    a.close()


def _raw_register(server, uuid, pubkey_hex, signer):
    """Speak the protocol by hand, signing with `signer`."""
    sock = socket.create_connection(server.address, timeout=5)
    relay.send_frame(sock, {'op': 'hello', 'uuid': str(uuid), 'pubkey': pubkey_hex})
    challenge = relay.recv_frame(sock)
    sig = signer.sign(relay.registration_text(challenge['nonce'], uuid))
    relay.send_frame(sock, {'op': 'register', 'sig': sig.signature.decode('ascii')})
    answer = relay.recv_frame(sock)
    sock.close()
    return answer


def _pubkey(ident):
    from autonomous_trust.core.identity.identity import public_identity_to_canonical
    return public_identity_to_canonical(ident.publish())['signature']['hex_seed']


def test_registering_someone_elses_uuid_is_refused(server):
    """Claim Alice's uuid and key, sign with Mallory's: the hijack the
    challenge exists to stop -- otherwise Mallory receives Alice's hellos."""
    alice, mallory = _ident('alice@ex', '10.0.0.1'), _ident('mallory@ex', '10.0.0.66')
    answer = _raw_register(server, alice.uuid, _pubkey(alice), mallory)
    assert answer['op'] == 'error'
    assert str(alice.uuid).lower() not in server.registered()
    # The real key, same uuid: accepted.
    assert _raw_register(server, alice.uuid, _pubkey(alice), alice)['op'] == 'registered'


def test_an_oversized_frame_drops_the_connection(server):
    sock = socket.create_connection(server.address, timeout=5)
    sock.sendall(struct.pack('!I', relay.MAX_FRAME + 1))
    sock.settimeout(5)
    assert sock.recv(4) == b''          # closed, nothing allocated for it
    sock.close()


def test_a_reconnect_replaces_the_old_registration(server):
    alice, bob = _ident('alice@ex', '10.0.0.1'), _ident('bob@ex', '10.0.0.2')
    first_in, second_in = Inbox(), Inbox()
    first = _client(server, alice, first_in)
    first.connect()
    second = _client(server, alice, second_in)
    second.connect()
    b = _client(server, bob)
    b.connect()
    time.sleep(0.2)
    b.send(alice.uuid, b'hi')
    assert second_in.wait()
    assert first_in.items == []
    for c in (first, second, b):
        c.close()


def test_own_relays_parses_a_list(monkeypatch):
    monkeypatch.setenv('AT_USE_RELAY', 'a:1,b:2, a:1 ,nonsense,c:3,d:4,e:5')
    assert relay.own_relays() == [('a', 1), ('b', 2), ('c', 3), ('d', 4)]
    monkeypatch.setenv('AT_USE_RELAY', '')
    assert relay.own_relays() == []


def test_merge_endpoints_keeps_order_and_the_cap():
    assert relay.merge_endpoints([('b', 2)], [('a', 1), ('b', 2), ('c', 3)]) == [
        ('b', 2), ('a', 1), ('c', 3)]
    assert len(relay.merge_endpoints([(str(i), i) for i in range(1, 9)], [])) == \
        relay.MAX_RELAYS


_MP = None


@pytest.fixture(autouse=True)
def _monkeypatch_for_stubs(monkeypatch):
    """_net_stub patches rendezvous's functions; this undoes it after each test."""
    global _MP
    _MP = monkeypatch
    yield
    _MP = None


class _Net:
    """The relay's network-process functions (network/rdv_net.py), called as
    ``_Net.name(proc, ...)`` the way the tests called the old methods, and the
    core's NetworkProcess methods by the same route. Looked up at call time,
    so what _net_stub patched applies."""
    _RENAMED = {'_is_distrusted': 'is_distrusted'}

    def __getattr__(self, name):
        from autonomous_trust.rendezvous._python import rdv_net
        from autonomous_trust.core._python.network.netprocess import NetworkProcess
        name = self._RENAMED.get(name, name)
        if hasattr(rdv_net, name):
            return getattr(rdv_net, name)
        return getattr(NetworkProcess, name)


def _net_stub(myself):
    from autonomous_trust.rendezvous._python import rdv_net
    stub = types.SimpleNamespace(
        logger=logging.getLogger('test-relay-net'), myself=myself,
        relay_messages=__import__('collections').deque(), _relay_routes={},
        relay_unreachable=__import__('collections').deque(), _relay_last={},
        _relay_clients={}, _relay_live={}, peers=Peers(), delivered=[], sent=[],
        dead=set(), _relay_retry={}, RELAY_RETRY_SEC=0.0)

    def client(ep):
        def send(to, frame):
            if ep in stub.dead:
                raise ConnectionError('%s is down' % (ep,))
            stub.sent.append((ep, to, frame))
        return types.SimpleNamespace(connect=lambda: True, send=send)
    _MP.setattr(rdv_net, '_relay_client', lambda proc, ep: client(ep))
    _MP.setattr(rdv_net, '_maintain_relays', lambda proc: None)
    _MP.setattr(rdv_net, '_announce_own_relay', lambda proc, ep: None)
    _MP.setattr(rdv_net, '_pin_relay', lambda proc, ep, pin: None)
    stub.looked_up = []
    _MP.setattr(rdv_net, '_lookup_reach', lambda proc, uuid: stub.looked_up.append(uuid))
    stub._wire_format_for_addr = lambda addr: None
    stub._msg_to_queue = lambda msg, who, queues, rcvd_by, **kw: stub.delivered.append((msg, who))
    stub._accept_unencrypted = lambda *a, **kw: False
    return _Net(), stub


def test_a_relay_route_is_refused_from_the_wire():
    NetworkProcess, stub = _net_stub(_ident('bob@ex', '10.0.0.2'))
    peer = _ident('mallory@ex', '10.0.0.66')
    msg = types.SimpleNamespace(from_whom=peer.publish(),
                                obj=json.dumps({'uuid': 'x', 'relay': '1.2.3.4:5'}))
    NetworkProcess.handle_relay_route(stub, {}, msg)
    assert stub._relay_routes == {}
    local = types.SimpleNamespace(from_whom=None,
                                  obj=json.dumps({'uuid': 'X', 'relay': '1.2.3.4:5'}))
    NetworkProcess.handle_relay_route(stub, {}, local)
    assert stub._relay_routes == {'x': [('1.2.3.4', 5)]}
    # A list goes ahead of what the route already names.
    more = types.SimpleNamespace(from_whom=None, obj=json.dumps(
        {'uuid': 'x', 'relays': ['9.9.9.9:1', '1.2.3.4:5']}))
    NetworkProcess.handle_relay_route(stub, {}, more)
    assert stub._relay_routes == {'x': [('9.9.9.9', 1), ('1.2.3.4', 5)]}


A, B, C = ('203.0.113.1', 1), ('203.0.113.2', 2), ('203.0.113.3', 3)


def test_a_send_fails_over_to_the_next_relay_that_is_up():
    NetworkProcess, stub = _net_stub(_ident('bob@ex', '10.0.0.2'))
    stub._relay_routes['p'] = [A, B, C]
    stub.dead.add(A)
    NetworkProcess._relay_send(stub, 'p', b'one')
    assert stub.sent == [(B, 'p', b'one')]
    # B is now the active relay, A moved to the back.
    assert stub._relay_routes['p'] == [B, C, A]
    stub.dead.update({B, C})
    with pytest.raises(ConnectionError):
        NetworkProcess._relay_send(stub, 'p', b'two')


def test_unreachable_resends_the_frame_through_the_next_relay():
    NetworkProcess, stub = _net_stub(_ident('bob@ex', '10.0.0.2'))
    stub._relay_routes['p'] = [A, B, C]
    NetworkProcess._relay_send(stub, 'p', b'hello')
    stub.relay_unreachable.append((A, 'p'))
    NetworkProcess._drain_relay_unreachable(stub)
    assert stub.sent[-1] == (B, 'p', b'hello')
    assert stub._relay_routes['p'][0] == B
    # A late refusal from A is stale now: nothing more is sent.
    stub.relay_unreachable.append((A, 'p'))
    NetworkProcess._drain_relay_unreachable(stub)
    assert len(stub.sent) == 2


def test_unreachable_everywhere_ends_after_each_relay_once():
    NetworkProcess, stub = _net_stub(_ident('bob@ex', '10.0.0.2'))
    stub._relay_routes['p'] = [A, B]
    NetworkProcess._relay_send(stub, 'p', b'hello')
    for ep in (A, B, A, B):
        stub.relay_unreachable.append((ep, 'p'))
        NetworkProcess._drain_relay_unreachable(stub)
    assert [ep for ep, _to, _f in stub.sent] == [A, B]
    # Lost through every relay we know: look it up (reachability records).
    assert stub.looked_up and set(stub.looked_up) == {'p'}


def test_a_frame_every_relay_refused_is_retried_a_few_rounds():
    """The peer may register moments later (it minted its link before its
    own registration finished): the refused frame walks the route again, a
    bounded number of times, and a new frame cancels the retry."""
    NetworkProcess, stub = _net_stub(_ident('bob@ex', '10.0.0.2'))
    stub._relay_routes['p'] = [A, B]
    NetworkProcess._relay_send(stub, 'p', b'hello')
    def refuse_all():
        for _ in range(2):
            stub.relay_unreachable.append((stub._relay_routes['p'][0], 'p'))
            NetworkProcess._drain_relay_unreachable(stub)
    refuse_all()
    assert len(stub.sent) == 2 and 'p' in stub._relay_retry
    for _round in range(NetworkProcess.RELAY_RETRY_ROUNDS):  # rdv_net's, via _Net
        before = len(stub.sent)
        NetworkProcess._retry_refused_relayed(stub)
        assert len(stub.sent) == before + 1 and stub.sent[-1][2] == b'hello'
        refuse_all()
    assert 'p' not in stub._relay_retry            # gave up
    NetworkProcess._retry_refused_relayed(stub)
    # A retry that is delivered, or a newer frame, ends it.
    NetworkProcess._relay_send(stub, 'p', b'hello')
    refuse_all()
    assert 'p' in stub._relay_retry
    NetworkProcess._relay_send(stub, 'p', b'newer')
    assert 'p' not in stub._relay_retry


# -- reputation-gated relays: the relay proves itself, both ends gate ---------
@pytest.fixture
def carol():
    return _ident('carol@ex', '10.0.0.3')


@pytest.fixture
def proving_server(carol):
    """A relay that proves it is Carol."""
    srv = relay.RelayServer('127.0.0.1', 0, identity=carol)
    yield srv
    srv.stop()


def _pin_of(ident):
    return str(ident.uuid).lower(), relay.key_fingerprint(_pubkey(ident))


def test_pinned_hints_parse_and_round_trip(carol):
    pin = _pin_of(carol)
    hint = relay.hint_for(('203.0.113.7', 27790), pin)
    assert hint == 'relay://%s:%s@203.0.113.7:27790' % pin
    assert relay.parse_hint(hint) == (('203.0.113.7', 27790), pin)
    assert relay.parse_endpoint(hint) == ('203.0.113.7', 27790)
    assert relay.parse_hint('relay://[2001:db8::1]:5') == (('2001:db8::1', 5), None)
    # A pin that cannot be checked is refused, never silently dropped.
    assert relay.parse_hint('relay://%s@1.2.3.4:5' % pin[0]) == (None, None)
    assert relay.parse_hint('relay://nope:%s@1.2.3.4:5' % pin[1]) == (None, None)
    assert relay.parse_hint('relay://%s:abc@1.2.3.4:5' % pin[0]) == (None, None)
    assert len(pin[1]) == 2 * relay.FP_BYTES


def test_a_relay_proves_who_it_is(proving_server, carol):
    alice = _ident('alice@ex', '10.0.0.1')
    a = _client(proving_server, alice)
    assert a.connect()
    assert a.proven_pin == _pin_of(carol)
    a.close()


def test_a_pinned_client_accepts_the_named_relay(proving_server, carol):
    alice = _ident('alice@ex', '10.0.0.1')
    a = relay.RelayClient(proving_server.address, alice, Inbox(), pin=_pin_of(carol))
    assert a.connect()
    a.close()


def test_a_pinned_client_refuses_another_relay(proving_server):
    """Whoever answers at the address must be the relay the link names -- by
    KEY: the same uuid claimed with another key is refused too."""
    alice, dave = _ident('alice@ex', '10.0.0.1'), _ident('dave@ex', '10.0.0.4')
    a = relay.RelayClient(proving_server.address, alice, Inbox(), pin=_pin_of(dave))
    with pytest.raises(ConnectionError):
        a.connect()
    assert 'not the relay the link names' in a.refused
    assert not a.connected


def test_a_pinned_client_refuses_a_relay_that_proves_nothing(server, carol):
    alice = _ident('alice@ex', '10.0.0.1')
    a = relay.RelayClient(server.address, alice, Inbox(), pin=_pin_of(carol))
    with pytest.raises(ConnectionError):
        a.connect()
    assert 'no proof' in a.refused
    # Unpinned, the same relay is fine -- only unauthenticated.
    b = _client(server, alice)
    assert b.connect() and b.proven_pin is None
    b.close()


def test_a_forged_proof_is_refused(carol):
    """A relay that signs with one key and names another: the proof does not
    verify."""
    mallory = _ident('mallory@ex', '10.0.0.66')
    srv = relay.RelayServer('127.0.0.1', 0, identity=mallory)
    real_sign = mallory.sign
    try:
        # Claim Carol's uuid and key; sign with Mallory's.
        srv.identity = types.SimpleNamespace(uuid=carol.uuid, sign=real_sign,
                                             publish=carol.publish)
        a = _client(srv, _ident('alice@ex', '10.0.0.1'))
        with pytest.raises(ConnectionError):
            a.connect()
        assert 'does not verify' in a.refused
    finally:
        srv.stop()


def test_a_relay_refuses_a_distrusted_client(carol):
    alice = _ident('alice@ex', '10.0.0.1')
    srv = relay.RelayServer('127.0.0.1', 0, identity=carol,
                            distrusted=lambda u, k: u == str(alice.uuid).lower())
    try:
        with pytest.raises(ConnectionError):
            _client(srv, alice).connect()
        assert str(alice.uuid).lower() not in srv.registered()
        bob = _ident('bob@ex', '10.0.0.2')
        assert _client(srv, bob).connect()
    finally:
        srv.stop()


def test_a_client_refuses_a_distrusted_relay(proving_server, carol):
    alice = _ident('alice@ex', '10.0.0.1')
    a = relay.RelayClient(proving_server.address, alice, Inbox(),
                          distrusted=lambda u, k: u == str(carol.uuid).lower())
    with pytest.raises(ConnectionError):
        a.connect()
    assert 'distrusted' in a.refused


def test_evict_drops_a_registration(proving_server):
    alice = _ident('alice@ex', '10.0.0.1')
    a = _client(proving_server, alice)
    a.connect()
    assert _wait_registered(proving_server, alice.uuid)
    proving_server.evict(alice.uuid)
    assert str(alice.uuid).lower() not in proving_server.registered()
    deadline = time.monotonic() + 5
    while a.connected and time.monotonic() < deadline:
        time.sleep(0.01)
    assert not a.connected


def test_the_network_gate_matches_by_uuid_and_by_key():
    """Distrusted: an excluded uuid; the key of an excluded identity under a
    FRESH uuid; and a known peer's uuid claimed with another key."""
    NetworkProcess, stub = _net_stub(_ident('bob@ex', '10.0.0.2'))
    stub._relay_server = None
    stub._excluded_uuids, stub._excluded_keys = set(), set()
    stub._peer_key = lambda uuid: NetworkProcess._peer_key(stub, uuid)
    _MP.setattr(__import__('autonomous_trust.rendezvous._python.rdv_net',
                           fromlist=['x']), '_drop_distrusted_relays', lambda proc: None)
    stub.is_excluded = lambda u, k=None: NetworkProcess.is_excluded(stub, u, k)
    stub._tell_exclusion = lambda u, excluded: None
    stub._exclusion_spec = NetworkProcess._exclusion_spec
    stub._norm_addr = lambda a: a
    stub._rejected_addresses = set()
    mallory, carol = _ident('mallory@ex', '10.0.0.66'), _ident('carol@ex', '10.0.0.3')
    stub.peers.add(mallory.publish(), stub.peers.mid_level)
    stub.peers.add(carol.publish(), stub.peers.mid_level)
    mu, mk = str(mallory.uuid).lower(), _pubkey(mallory).lower()
    assert not NetworkProcess._is_distrusted(stub, mu, mk)         # neutral passes
    assert not NetworkProcess._is_distrusted(stub, 'f' * 8 + '-0000-4000-8000-' + '0' * 12, mk)
    NetworkProcess.handle_exclude(stub, {}, types.SimpleNamespace(
        from_whom=None, obj=json.dumps({'address': '10.0.0.66', 'uuid': mu})))
    assert '10.0.0.66' in stub._rejected_addresses
    assert NetworkProcess._is_distrusted(stub, mu, mk)
    fresh = '12345678-0000-4000-8000-000000000000'
    assert NetworkProcess._is_distrusted(stub, fresh, mk)            # new uuid, same key
    assert NetworkProcess._is_distrusted(stub, str(carol.uuid), mk)  # impostor
    assert not NetworkProcess._is_distrusted(stub, str(carol.uuid), _pubkey(carol))
    NetworkProcess.handle_readmit(stub, {}, types.SimpleNamespace(
        from_whom=None, obj=json.dumps({'address': '10.0.0.66', 'uuid': mu})))
    assert not NetworkProcess._is_distrusted(stub, mu, mk)
    # The older, bare-address form still works.
    NetworkProcess.handle_exclude(stub, {}, types.SimpleNamespace(
        from_whom=None, obj='10.0.0.77'))
    assert '10.0.0.77' in stub._rejected_addresses
    # ...and nobody on the wire may exclude for us.
    NetworkProcess.handle_exclude(stub, {}, types.SimpleNamespace(
        from_whom=mallory.publish(), obj=json.dumps({'uuid': str(carol.uuid)})))
    assert str(carol.uuid).lower() not in stub._excluded_uuids
