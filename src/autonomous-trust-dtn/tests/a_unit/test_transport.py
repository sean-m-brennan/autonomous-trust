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
"""The DTN transport over an in-process loopback BP agent: what goes where,
receive demux with its one pending slot per channel, and the core's error
contract (TimeoutError when idle, TransmissionError on failure)."""
import collections
import logging
import threading
import uuid
from types import SimpleNamespace

import pytest

from autonomous_trust.dtn import eid
from autonomous_trust.dtn.backend import Backend, BackendError, Bundle, StubBackend, make_backend
from autonomous_trust.dtn.transport import DTNNetworkProcess, TransmissionError

A = uuid.UUID('aaaaaaaa-0000-4000-8000-000000000001')
B = uuid.UUID('bbbbbbbb-0000-4000-8000-000000000002')
GROUP = uuid.UUID('11223344-5566-7788-99aa-bbccddeeff00')


class Agent(object):
    """A BP agent shared by every node in a test: delivers a bundle to every
    backend registered on its destination EID."""

    def __init__(self):
        self.registered = collections.defaultdict(list)   # eid -> [(backend, service)]
        self.sent = []

    def deliver(self, src, dest, payload):
        self.sent.append((src, dest, payload))
        for backend, service in self.registered.get(dest, ()):
            backend.inbox.append(Bundle(payload, src, service))


class LoopbackBackend(Backend):
    name = 'loopback'

    def __init__(self, agent):
        self.agent = agent
        self.inbox = collections.deque()
        self.primary = None
        self.fail = False

    def init(self, endpoints, logger):
        self.primary = endpoints[0][0]
        for eid_, service in endpoints:
            self.agent.registered[eid_].append((self, service))

    def shutdown(self):
        pass

    def send(self, dest_eid, payload, lifetime_sec):
        if self.fail:
            raise BackendError('agent refused')
        self.agent.deliver(self.primary, dest_eid, payload)

    def recv(self, timeout_s):
        return self.inbox.popleft() if self.inbox else None


def _node(node_uuid, group_uuid=None, peers=None):
    proc = DTNNetworkProcess.__new__(DTNNetworkProcess)
    proc.logger = logging.getLogger('dtn-test')
    proc.myself = SimpleNamespace(uuid=str(node_uuid), address='10.0.0.%d' % node_uuid.bytes[0])
    proc.protocol = SimpleNamespace(
        peers=SimpleNamespace(listing=peers or {}),
        group=SimpleNamespace(uuid=str(group_uuid)) if group_uuid else None)
    proc.socket_timeout = 0.01
    proc.stop = False
    proc._rejected_addresses = set()
    proc.default_lifetime_sec = 86400
    proc.endpoints = []
    proc._backend = None
    proc._last_group_frame = None
    return proc


@pytest.fixture
def agent():
    return Agent()


def _open(proc, agent):
    backend = LoopbackBackend(agent)
    proc.open_transport(backend)
    return backend


def test_open_registers_the_three_endpoints(agent):
    a = _node(A, GROUP)
    _open(a, agent)
    assert a.endpoints == [('dtn://at-aaaaaaaa/peer', '/peer'),
                           ('dtn://at-group-1122334455667788/bcast', '/bcast'),
                           ('dtn://at-group-1122334455667788/group', '/group')]


def test_peer_unicast_by_matching_address(agent):
    a = _node(A, GROUP, peers={'10.0.0.187': SimpleNamespace(uuid=str(B))})
    b = _node(B, GROUP)
    _open(a, agent)
    _open(b, agent)
    a.send_peer(b'hello', '10.0.0.187')
    assert agent.sent[-1] == ('dtn://at-aaaaaaaa/peer', 'dtn://at-bbbbbbbb/peer', b'hello')
    assert b.recv_peer() == (b'hello', 'dtn://at-aaaaaaaa/peer', None)


def test_peer_unicast_to_an_eid_address(agent):
    a = _node(A)
    _open(a, agent)
    a.send_peer('text', 'ipn:7.1')
    assert agent.sent[-1][1:] == ('ipn:7.1', b'text')


def test_broadcast_and_group_go_to_the_group_eid(agent):
    a, b = _node(A, GROUP), _node(B, GROUP)
    _open(a, agent)
    _open(b, agent)
    a.send_any(b'discover')
    assert agent.sent[-1][1] == 'dtn://at-group-1122334455667788/bcast'
    frame = b'sealed-for-the-group'
    for member in ('10.0.0.1', '10.0.0.2', '10.0.0.3'):
        a.send_group(frame, member)
    group_sends = [s for s in agent.sent if s[1].endswith('/group')]
    assert len(group_sends) == 1, 'one frame, one bundle, however many members'
    a.send_group(b'next-frame', '10.0.0.1')
    assert len([s for s in agent.sent if s[1].endswith('/group')]) == 2
    # Both nodes are registered on the group EIDs, the sender included (C does
    # not filter its own either).
    assert b.recv_any()[0] == b'discover'
    assert b.recv_group()[0] == frame


def test_wrong_channel_waits_in_its_slot(agent):
    a, b = _node(A, GROUP), _node(B, GROUP)
    _open(a, agent)
    _open(b, agent)
    a.send_any(b'bcast')
    with pytest.raises(TimeoutError):
        b.recv_peer()   # pulls the broadcast bundle, stashes it
    assert b.recv_any() == (b'bcast', 'dtn://at-aaaaaaaa/peer', None)


def test_one_pending_slot_newest_wins(agent):
    a, b = _node(A, GROUP), _node(B, GROUP)
    _open(a, agent)
    _open(b, agent)
    a.send_any(b'first')
    a.send_any(b'second')
    for _ in range(2):
        with pytest.raises(TimeoutError):
            b.recv_peer()
    assert b.recv_any()[0] == b'second'
    with pytest.raises(TimeoutError):
        b.recv_any()


def test_unknown_service_is_dropped(agent):
    b = _node(B)
    backend = _open(b, agent)
    backend.inbox.append(Bundle(b'x', 'dtn://x/', '/other'))
    with pytest.raises(TimeoutError):
        b.recv_peer()
    assert all(v is None for v in b._slots.values())


def test_rejected_sender_is_reported_without_payload(agent):
    a, b = _node(A), _node(B, peers={'10.0.0.187': SimpleNamespace(uuid=str(B))})
    _open(a, agent)
    _open(b, agent)
    b._rejected_addresses.add('dtn://at-aaaaaaaa/peer')
    a.send_peer(b'x', 'dtn://at-bbbbbbbb/peer')
    assert b.recv_peer() == (None, 'dtn://at-aaaaaaaa/peer', None)


def test_send_failures_are_transmission_errors(agent):
    a = _node(A)
    with pytest.raises(TransmissionError):
        a.send_peer(b'x', '10.0.0.1')   # not open
    backend = _open(a, agent)
    backend.fail = True
    with pytest.raises(TransmissionError):
        a.send_any(b'x')
    with pytest.raises(TransmissionError):
        a.send_peer(b'x', 'h' * 200)    # no EID fits


def test_stub_drops_and_times_out():
    a = _node(A)
    a.open_transport(StubBackend())
    a.send_peer(b'x', '10.0.0.1')
    a.send_any(b'x')
    with pytest.raises(TimeoutError):
        a.recv_peer()


def test_backend_choice(monkeypatch):
    monkeypatch.delenv('AT_DTN_BACKEND', raising=False)
    assert make_backend().name == 'stub'
    monkeypatch.setenv('AT_DTN_BACKEND', 'ION')
    with pytest.raises(BackendError, match='only in the C runtime'):
        make_backend()
    monkeypatch.setenv('AT_DTN_BACKEND', 'carrier-pigeon')
    with pytest.raises(BackendError, match='unknown'):
        make_backend()


def test_closed_transport_stops_quietly(agent):
    a = _node(A)
    _open(a, agent)
    a.close_connections()
    assert a._backend is None
    with pytest.raises(TimeoutError):
        a.recv_peer()
    with pytest.raises(TransmissionError):
        a.send_any(b'x')


def test_extension_supplies_the_transport_by_cs_name():
    from autonomous_trust.core.extensions import transport_class
    assert transport_class('dtn_bp') == 'autonomous_trust.dtn.transport.DTNNetworkProcess'


def test_receivers_run_in_threads(agent):
    """The core runs recv_peer / recv_any on separate threads; the slot lock
    keeps a bundle from being lost or delivered twice."""
    a, b = _node(A, GROUP), _node(B, GROUP)
    _open(a, agent)
    _open(b, agent)
    for i in range(50):
        a.send_any(b'b%d' % i)
        a.send_peer(b'p%d' % i, 'dtn://at-bbbbbbbb/peer')
    got = collections.defaultdict(list)

    def drain(method, key):
        misses = 0
        while misses < 200:
            try:
                got[key].append(method()[0])
            except TimeoutError:
                misses += 1
    threads = [threading.Thread(target=drain, args=(b.recv_peer, 'peer')),
               threading.Thread(target=drain, args=(b.recv_any, 'any'))]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    # Either reader may pull the other's bundle and park it in the one slot
    # per channel, where a later one can overwrite it (C's behaviour); so the
    # contract is no duplicates and no reordering, not completeness.
    for key in ('peer', 'any'):
        assert len(set(got[key])) == len(got[key])
        assert got[key] == sorted(got[key], key=lambda x: int(x[1:]))
        assert got[key], key
