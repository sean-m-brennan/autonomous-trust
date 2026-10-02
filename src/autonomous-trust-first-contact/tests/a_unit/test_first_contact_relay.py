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
"""Where first contact meets the rendezvous relay: initiate choosing a relay
hint, the links a node behind a relay mints, relayed hellos and frames, and
restoring contacts' routes at startup. Split from rendezvous's test_relay.py
(FEATURE_SPLIT_PLAN Phase 7b).
"""
import json
import logging
import queue
import types

import pytest

from autonomous_trust.core.config import Configuration
from autonomous_trust.first_contact import create_invitation
from autonomous_trust.core.identity import Identity, Peers
from autonomous_trust.first_contact import first_contact as fc
from autonomous_trust.first_contact.fc_protocol import FirstContactProtocol
from autonomous_trust.core.network.message import Message
from autonomous_trust.core.network.network import Network
from autonomous_trust.rendezvous._python import relay
from autonomous_trust.core.system import CfgIds


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv(Configuration.ROOT_VARIABLE_NAME, str(tmp_path))
    monkeypatch.delenv('AT_USE_RELAY', raising=False)
    monkeypatch.setenv('AT_RELAY_SEED_FALLBACK', '1')


def _ident(name, addr):
    return Identity.initialize(name, name, addr)


def _pubkey(ident):
    from autonomous_trust.core.identity.identity import public_identity_to_canonical
    return public_identity_to_canonical(ident.publish())['signature']['hex_seed']


# -- first contact through a relay -------------------------------------------
class StubProc:
    def __init__(self, identity):
        self.name = CfgIds.identity
        self.identity = identity
        self.peers = Peers()
        self.logger = logging.getLogger('test-relay')
        self.q_cadence = 1.0
        self._first_contact_nonces = fc.SpentNonces()


def test_initiate_routes_the_hello_through_the_invitations_relay():
    alice, bob = _ident('alice@ex', '192.168.1.5'), _ident('bob@ex', '10.0.0.2')
    blob = create_invitation(alice, rendezvous=['192.168.1.5',
                                                'relay://203.0.113.7:27790'],
                             ttl_seconds=600).encode()
    q = {CfgIds.network: queue.Queue()}
    fc.initiate(StubProc(bob), q, blob)
    route = q[CfgIds.network].get_nowait()
    hello = q[CfgIds.network].get_nowait()
    # The route goes first, so the hello takes it.
    assert route.function == Network.relay_route
    assert route.from_whom is None
    assert json.loads(route.obj) == {'uuid': str(alice.uuid),
                                     'relays': ['203.0.113.7:27790']}
    assert hello.function == FirstContactProtocol.hello


def test_initiate_routes_through_every_relay_the_link_names_in_order():
    alice, bob = _ident('alice@ex', '192.168.1.5'), _ident('bob@ex', '10.0.0.2')
    blob = create_invitation(alice, rendezvous=['relay://203.0.113.7:27790',
                                                '192.168.1.5',
                                                'relay://198.51.100.2:27790'],
                             ttl_seconds=600).encode()
    q = {CfgIds.network: queue.Queue()}
    proc = StubProc(bob)
    fc.initiate(proc, q, blob)
    route = q[CfgIds.network].get_nowait()
    assert json.loads(route.obj)['relays'] == ['203.0.113.7:27790',
                                               '198.51.100.2:27790']
    # ...and the pending hello keeps them, for the contact the ack records.
    assert proc._first_contact_pending[str(alice.uuid)].relays == (
        'relay://203.0.113.7:27790', 'relay://198.51.100.2:27790')


def test_initiate_without_a_relay_hint_is_unchanged():
    alice, bob = _ident('alice@ex', '10.0.0.1'), _ident('bob@ex', '10.0.0.2')
    blob = create_invitation(alice, rendezvous=['10.0.0.1'], ttl_seconds=600).encode()
    q = {CfgIds.network: queue.Queue()}
    fc.initiate(StubProc(bob), q, blob)
    assert q[CfgIds.network].get_nowait().function == FirstContactProtocol.hello
    assert q[CfgIds.network].empty()


def test_an_explicit_endpoint_overrides_the_relay_hint():
    alice, bob = _ident('alice@ex', '10.0.0.1'), _ident('bob@ex', '10.0.0.2')
    blob = create_invitation(alice, rendezvous=['relay://203.0.113.7:27790'],
                             ttl_seconds=600).encode()
    q = {CfgIds.network: queue.Queue()}
    fc.initiate(StubProc(bob), q, blob, endpoint='10.0.0.1')
    assert q[CfgIds.network].get_nowait().function == FirstContactProtocol.hello


def test_a_node_behind_a_relay_puts_it_in_the_links_it_mints(monkeypatch):
    monkeypatch.setenv('AT_USE_RELAY', '203.0.113.7:27790')
    alice = _ident('alice@ex', '10.0.0.1')
    q = {CfgIds.network: queue.Queue(), CfgIds.main: queue.Queue()}
    fc.handle_app_invite(StubProc(alice), q, Message(
        CfgIds.identity, fc.APP_INVITE, json.dumps({'rendezvous': ['10.0.0.1']}),
        to_whom=None, from_whom=None, encrypt=False))
    ev = q[CfgIds.main].get_nowait()
    from autonomous_trust.first_contact import Invitation
    assert Invitation.decode(ev.blob).rendezvous == ['10.0.0.1',
                                                     'relay://203.0.113.7:27790']


def test_a_node_with_several_relays_names_them_all_in_order(monkeypatch):
    monkeypatch.setenv('AT_USE_RELAY', '203.0.113.7:27790, [2001:db8::1]:27791')
    alice = _ident('alice@ex', '10.0.0.1')
    q = {CfgIds.network: queue.Queue(), CfgIds.main: queue.Queue()}
    fc.handle_app_invite(StubProc(alice), q, Message(
        CfgIds.identity, fc.APP_INVITE, json.dumps({}),
        to_whom=None, from_whom=None, encrypt=False))
    from autonomous_trust.first_contact import Invitation
    assert Invitation.decode(q[CfgIds.main].get_nowait().blob).rendezvous == [
        'relay://203.0.113.7:27790', 'relay://[2001:db8::1]:27791']


def test_contact_hints_cap_relays_and_addresses_separately():
    """Refreshing an address must not push out a relay the contact is
    reached through, as one shared cap did."""
    relays = ['relay://r%d:1' % i for i in range(4)]
    hints = fc._merge_hints(['10.0.0.9'], relays + ['10.0.0.1', '10.0.0.2',
                                                   '10.0.0.3', '10.0.0.4'])
    assert hints[:4] == relays
    assert hints[4:] == ['10.0.0.9', '10.0.0.1', '10.0.0.2', '10.0.0.3']


A, B = ('203.0.113.1', 1), ('203.0.113.2', 2)

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


def _hello_frame(sender, inviter):
    blob = create_invitation(inviter, ttl_seconds=600).encode()
    return bytes(Message(CfgIds.identity, FirstContactProtocol.hello, blob,
                         to_whom=inviter.publish(), from_whom=sender, encrypt=False))


def test_a_relayed_hello_from_a_stranger_is_delivered_and_routes_the_reply():
    alice, bob = _ident('alice@ex', '10.0.0.1'), _ident('bob@ex', '10.0.0.2')
    NetworkProcess, stub = _net_stub(alice)
    stub.relay_messages.append((_hello_frame(bob, alice), str(bob.uuid).lower(),
                                ('203.0.113.7', 27790)))
    assert NetworkProcess._drain_relayed(stub, {}, 32) == 1
    assert len(stub.delivered) == 1
    assert stub._relay_routes == {str(bob.uuid).lower(): [('203.0.113.7', 27790)]}


def test_a_relayed_frame_makes_its_relay_the_active_one():
    alice, bob = _ident('alice@ex', '10.0.0.1'), _ident('bob@ex', '10.0.0.2')
    NetworkProcess, stub = _net_stub(alice)
    key = str(bob.uuid).lower()
    stub._relay_routes[key] = [A, B]
    stub.relay_messages.append((_hello_frame(bob, alice), key, B))
    NetworkProcess._drain_relayed(stub, {}, 32)
    assert stub._relay_routes[key] == [B, A]


# -- reconnecting saved contacts at startup ----------------------------------
def test_restore_contacts_readmits_and_routes_each_contact(monkeypatch):
    from autonomous_trust.first_contact import Contact
    monkeypatch.setenv('AT_USE_RELAY', '198.51.100.9:27790')
    me = _ident('me@ex', '10.0.0.1')
    carol, dave = _ident('carol@ex', '10.0.0.3'), _ident('dave@ex', '10.0.0.4')
    proc = StubProc(me)
    recorded = []
    asked = []
    proc._record_peers = lambda q: recorded.append(True)
    proc._send_caps_query = lambda q, who: asked.append(str(who.uuid))
    store = fc._contacts_store(proc)
    store.add(Contact(carol.publish(), rendezvous=['relay://203.0.113.7:27790']))
    store.add(Contact(dave.publish()))
    q = {CfgIds.network: queue.Queue()}
    assert fc.restore_contacts(proc, q) == 2
    assert {str(p.uuid) for p in proc.peers.all} == {str(carol.uuid), str(dave.uuid)}
    assert recorded == [True]                     # one broadcast, not one each
    assert sorted(asked) == sorted([str(carol.uuid), str(dave.uuid)])
    routes = {}
    while not q[CfgIds.network].empty():
        msg = q[CfgIds.network].get_nowait()
        if msg.function != Network.relay_route:
            continue            # our own reachability record, to publish
        spec = json.loads(msg.obj)
        routes[spec['uuid']] = spec['relays']
    # Its own relays first, then ours, where it registered to reach us.
    assert routes == {str(carol.uuid): ['203.0.113.7:27790', '198.51.100.9:27790'],
                      str(dave.uuid): ['198.51.100.9:27790']}


def test_restore_contacts_runs_from_first_contacts_on_start_hook(monkeypatch):
    calls = []
    monkeypatch.setattr(fc, 'restore_contacts', lambda proc, q: calls.append('contacts') or 0)
    from autonomous_trust.first_contact._python import directory_contact
    monkeypatch.setattr(directory_contact, 'restore_entries',
                        lambda proc, q: calls.append('entries') or 0)
    from autonomous_trust.first_contact._python import device_contact
    monkeypatch.setattr(device_contact, 'push_own_cert',
                        lambda proc, q: calls.append('cert') or 0)
    monkeypatch.setattr(device_contact, 'announce',
                        lambda proc, q: calls.append('announce') or 0)
    from autonomous_trust.first_contact._python import sibling_sync
    monkeypatch.setattr(sibling_sync, 'restore',
                        lambda proc, q: calls.append('siblings') or 0)
    fc.EXTENSION.identity.on_start(object(), {})
    assert calls == ['contacts', 'siblings', 'entries', 'cert', 'announce']


def test_a_relayed_frame_must_claim_the_sender_the_relay_stamped():
    """The relay vouches for `from`; a frame naming someone else is dropped,
    or a node registered as Mallory could say hello as Bob."""
    alice, bob = _ident('alice@ex', '10.0.0.1'), _ident('bob@ex', '10.0.0.2')
    mallory = _ident('mallory@ex', '10.0.0.66')
    NetworkProcess, stub = _net_stub(alice)
    stub.relay_messages.append((_hello_frame(bob, alice), str(mallory.uuid).lower(),
                                ('203.0.113.7', 27790)))
    NetworkProcess._drain_relayed(stub, {}, 32)
    assert stub.delivered == []


# -- reputation-gated relays: the relay proves itself, both ends gate ---------
@pytest.fixture
def carol():
    return _ident('carol@ex', '10.0.0.3')


def _pin_of(ident):
    return str(ident.uuid).lower(), relay.key_fingerprint(_pubkey(ident))


def test_links_pin_our_relay_once_it_proves_itself(monkeypatch, carol):
    monkeypatch.setenv('AT_USE_RELAY', '203.0.113.7:27790')
    alice = _ident('alice@ex', '10.0.0.1')
    proc = StubProc(alice)
    q = {CfgIds.network: queue.Queue(), CfgIds.main: queue.Queue()}
    from autonomous_trust.first_contact import Invitation

    def mint():
        fc.handle_app_invite(proc, q, Message(
            CfgIds.identity, fc.APP_INVITE, json.dumps({}),
            to_whom=None, from_whom=None, encrypt=False))
        return Invitation.decode(q[CfgIds.main].get_nowait().blob).rendezvous

    assert mint() == ['relay://203.0.113.7:27790']
    pin = _pin_of(carol)
    fc.handle_relay_identity(proc, q, types.SimpleNamespace(
        from_whom=None, obj=json.dumps({'relay': '203.0.113.7:27790',
                                        'uuid': pin[0], 'fp': pin[1]})))
    assert mint() == ['relay://%s:%s@203.0.113.7:27790' % pin]
    # Nobody on the wire chooses our pin.
    fc.handle_relay_identity(proc, q, types.SimpleNamespace(
        from_whom=_ident('m@ex', '10.0.0.66').publish(),
        obj=json.dumps({'relay': '203.0.113.7:27790', 'uuid': str(alice.uuid),
                        'fp': '0' * 32})))
    assert mint() == ['relay://%s:%s@203.0.113.7:27790' % pin]


def test_a_route_carries_its_pins_to_the_network(carol):
    alice, bob = _ident('alice@ex', '192.168.1.5'), _ident('bob@ex', '10.0.0.2')
    pin = _pin_of(carol)
    blob = create_invitation(alice, rendezvous=['relay://%s:%s@203.0.113.7:27790' % pin],
                             ttl_seconds=600).encode()
    q = {CfgIds.network: queue.Queue()}
    fc.initiate(StubProc(bob), q, blob)
    route = json.loads(q[CfgIds.network].get_nowait().obj)
    assert route['relays'] == ['%s:%s@203.0.113.7:27790' % pin]
