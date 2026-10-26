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
"""The generic extension seams an outside transport (a radio) uses: declared
network wire verbs, also-unicast and fan-out hooks, injection by channel."""
import types
import uuid as uuid_mod

import pytest

from autonomous_trust.core._python import extensions
from autonomous_trust.core._python.extensions import (
    Extension, NetworkHooks, reset_extensions)
from autonomous_trust.core._python.network.netprocess import (
    NetworkProcess, wire_verb_admitted)


@pytest.fixture
def only(monkeypatch):
    def _set(*exts):
        monkeypatch.setattr(extensions, '_builtin', lambda: list(exts))
        monkeypatch.setattr(extensions, '_installed', lambda: [])
        monkeypatch.setattr(extensions, '_source_tree', lambda: [])
        reset_extensions()
    yield _set
    reset_extensions()


def _ext(name, **kw):
    return Extension(name=name, enabled=lambda: True,
                     register_handlers=lambda proc, proc_name: None, **kw)


def test_declared_network_verbs_are_admitted_on_member_paths_only(only):
    assert not wire_verb_admitted('network', 't_announce', 'peer')[0]
    only(_ext('t', network_wire_verbs=('t_announce',)))
    assert extensions.network_wire_verbs() == frozenset({'t_announce'})
    assert wire_verb_admitted('network', 't_announce', 'peer')[0]
    assert wire_verb_admitted('network', 't_announce', 'group')[0]
    for path in ('broadcast', 'stranger-plaintext', 'relayed-stranger'):
        assert not wire_verb_admitted('network', 't_announce', path)[0]
    assert not wire_verb_admitted('network', 't_other', 'peer')[0]
    assert wire_verb_admitted('network', 'stats_req', 'peer')[0]


def test_a_disabled_extension_declares_nothing(only):
    only(Extension(name='off', enabled=lambda: False,
                   register_handlers=lambda p, n: None,
                   network_wire_verbs=('t_announce',)))
    assert extensions.network_wire_verbs() == frozenset()


def _hook_stub(*names):
    stub = types.SimpleNamespace(_extensions=list(names))
    stub.logger = types.SimpleNamespace(error=lambda *a, **k: None,
                                        warning=lambda *a, **k: None)
    return stub


def test_also_unicast_reaches_every_watching_extension(only):
    seen = []
    only(_ext('a', network=NetworkHooks(
        also_unicast=lambda p, u, f, proc, fn: seen.append(('a', u, f, proc, fn)))),
         _ext('b', network=NetworkHooks(
        also_unicast=lambda p, u, f, proc, fn: seen.append(('b', u, f, proc, fn)))))
    NetworkProcess._also_unicast(_hook_stub('a', 'b'), 'peer-1', 'identity',
                                 'group_key_update', b'sealed')
    assert seen == [('a', 'peer-1', b'sealed', 'identity', 'group_key_update'),
                    ('b', 'peer-1', b'sealed', 'identity', 'group_key_update')]


def test_a_failing_hook_never_breaks_the_send(only):
    def boom(*a):
        raise RuntimeError('radio on fire')
    only(_ext('a', network=NetworkHooks(also_unicast=boom, fanout=boom)))
    stub = _hook_stub('a')
    NetworkProcess._also_unicast(stub, 'p', 'identity', 'peer_dm', b'x')
    NetworkProcess._fanout(stub, 'group', 'identity', 'presence', None, b'x')


def test_fanout_reaches_extensions_with_channel_and_group(only):
    seen = []
    only(_ext('a', network=NetworkHooks(
        fanout=lambda p, ch, f, proc, fn, g: seen.append((ch, f, proc, fn, g)))))
    group = object()
    NetworkProcess._fanout(_hook_stub('a'), 'broadcast', 'identity',
                           'group_partition_probe', group, b'plain')
    assert seen == [('broadcast', b'plain', 'identity', 'group_partition_probe', group)]


class _Peers:
    def __init__(self, *peers):
        self._peers = peers

    def find_by_uuid(self, u):
        for p in self._peers:
            if str(p.uuid).lower() == str(u).lower():
                return p
        return None


def _inject_stub(peer, in_group=True):
    calls = []
    stub = types.SimpleNamespace(
        peers=_Peers(peer), _via_ext=False, myself=None,
        reject_message=lambda addr: False,
        is_excluded=lambda uuid, key=None: False,
        _group_for_sender=lambda addr: object() if in_group else None,
        _wire_format_for_addr=lambda addr: 'json')
    stub._msg_to_queue = lambda frame, frm, queues, rcvd_by, **kw: calls.append(
        ('route', rcvd_by, frm, stub._via_ext))
    stub._inbound_group = lambda queues, frame, addr: calls.append(
        ('group', addr, stub._via_ext))
    return stub, calls


def test_inject_broadcast_routes_as_multicast_from_the_peer_address():
    peer = types.SimpleNamespace(uuid=uuid_mod.uuid4(), address='10.0.0.2')
    stub, calls = _inject_stub(peer)
    assert NetworkProcess.inject_inbound(stub, {}, 'broadcast', b'{}', peer.uuid)
    assert calls == [('route', 'multicast', '10.0.0.2', True)]
    assert stub._via_ext is False


def test_inject_group_takes_the_group_path_flagged():
    peer = types.SimpleNamespace(uuid=uuid_mod.uuid4(), address='10.0.0.2')
    stub, calls = _inject_stub(peer)
    assert NetworkProcess.inject_inbound(stub, {}, 'group', b'sealed', str(peer.uuid))
    assert calls == [('group', '10.0.0.2', True)]


def test_inject_group_from_outside_the_group_is_counted_not_signalled(monkeypatch):
    from autonomous_trust.core._python.network import netprocess
    counted = []
    monkeypatch.setattr(netprocess, '_probes', types.SimpleNamespace(
        counter=lambda *a, **k: counted.append(a)))
    peer = types.SimpleNamespace(uuid=uuid_mod.uuid4(), address='10.0.0.2')
    stub, calls = _inject_stub(peer, in_group=False)
    assert not NetworkProcess.inject_inbound(stub, {}, 'group', b'sealed', peer.uuid)
    assert calls == []
    assert ('net.ext', 'group_decrypt_fail') in counted


def test_inject_from_an_unknown_uuid_is_dropped():
    peer = types.SimpleNamespace(uuid=uuid_mod.uuid4(), address='10.0.0.2')
    stub, calls = _inject_stub(peer)
    assert not NetworkProcess.inject_inbound(stub, {}, 'broadcast', b'{}', uuid_mod.uuid4())
    assert calls == []


def test_relayed_and_injected_frames_do_not_stamp_transport_liveness():
    heard = []
    lv = types.SimpleNamespace(heard=lambda u, t: heard.append(u))
    stub = types.SimpleNamespace(_liveness=lv, _via_ext=False)
    NetworkProcess._note_transport_heard(stub, 'a', 'relay')
    assert heard == []
    stub._via_ext = True
    NetworkProcess._note_transport_heard(stub, 'a', 'multicast')
    assert heard == []
    stub._via_ext = False
    NetworkProcess._note_transport_heard(stub, 'a', 'group')
    assert heard == ['a']


def _peer_channel_node(me, peer, excluded=False):
    """A NetworkProcess stand-in that holds ``peer``, with the real injection,
    router and liveness stamp."""
    import logging
    from unittest.mock import MagicMock
    from autonomous_trust.core._python.config import NetWireFormat
    from autonomous_trust.core._python.network.liveness import TransportLiveness
    from autonomous_trust.core._python.network.presence import PresenceTracker
    proc = MagicMock(spec=NetworkProcess)
    proc.name = 'network'
    proc.q_cadence = 0
    proc.logger = logging.getLogger('test.net.ext_seams')
    proc.myself = me
    proc.peers = _Peers(peer)
    proc._presence = PresenceTracker(30.0, 90.0)
    proc._liveness = TransportLiveness(0.0)
    proc._via_ext = False
    proc._foreign_format_counts = {}
    proc._crosses_gateway.return_value = False
    proc._wire_format_for_addr.return_value = NetWireFormat.json
    proc.reject_message.side_effect = lambda addr: excluded == 'address'
    proc.is_excluded.side_effect = lambda uuid, key=None: excluded == 'uuid'
    for name in ('inject_inbound', '_msg_to_queue', '_note_transport_heard'):
        setattr(proc, name, getattr(NetworkProcess, name).__get__(proc))
    return proc


def _sealed_peer_dm(sender, recipient):
    from autonomous_trust.core.network.message import Message
    wire = bytes(Message('identity', 'peer_dm', '{}', from_whom=sender))
    return bytes(sender.encrypt(wire, recipient.publish()))


def test_inject_peer_routes_a_sealed_frame_on_the_peer_path_unstamped():
    import queue
    from autonomous_trust.core.identity import Identity
    me = Identity.initialize('me', 'me', '10.0.0.1')
    peer = Identity.initialize('peer', 'peer', '10.0.0.2')
    proc = _peer_channel_node(me, peer.publish())
    qs = {'identity': queue.Queue()}
    assert proc.inject_inbound(qs, 'peer', _sealed_peer_dm(peer, me), str(peer.uuid))
    # peer_dm is admitted only on the peer and group paths.
    assert qs['identity'].get_nowait().function == 'peer_dm'
    assert str(peer.uuid).lower() not in proc._liveness._last
    assert proc._via_ext is False


@pytest.mark.parametrize('how', ('address', 'uuid'))
def test_inject_peer_from_an_excluded_peer_is_refused(monkeypatch, how):
    import queue
    from autonomous_trust.core._python.network import netprocess
    from autonomous_trust.core.identity import Identity
    counted = []
    monkeypatch.setattr(netprocess._probes, 'counter',
                        lambda *a, **k: counted.append(a))
    me = Identity.initialize('me', 'me', '10.0.0.1')
    peer = Identity.initialize('peer', 'peer', '10.0.0.2')
    proc = _peer_channel_node(me, peer.publish(), excluded=how)
    qs = {'identity': queue.Queue()}
    assert not proc.inject_inbound(qs, 'peer', _sealed_peer_dm(peer, me), str(peer.uuid))
    assert qs['identity'].empty()
    assert ('net.ext', 'drop', 'excluded') in counted
