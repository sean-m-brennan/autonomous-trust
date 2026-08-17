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

"""The inspector's live pipeline, end to end, with real objects (ISSUES §4.4 I21).

Every unit in this chain is already unit-tested and the chain still broke,
repeatedly and silently, in ways the unit tests could not see — because the
seam, not the unit, is where it breaks:

* `bridge.py` did ``float(PingATStats)`` and `inspector.py` forwarded the raw
  object into a channel whose handler ignores anything that is not a 2-tuple.
  Both consumers had passing tests; neither was ever fed a real `PingATStats`.
* The reply named nobody — no identity on the message — so even a correct rtt
  would have landed on a node keyed by an IP while every other channel keys by
  identity UUID.
* `viz/server.py` asked the registry for the ``live`` graph by name without
  importing the module that registers it, so the live path 500'd on connect for
  every consumer except the one that happened to import it first.
* networkx 3.x renamed ``links`` to ``edges``; `force.js` reads ``links`` at 20+
  sites, and a frame with the wrong key renders nothing and reports nothing.

What is pinned here is therefore the CONTRACT BETWEEN modules: the exact tuple
shapes `Inspector.autonomous_tasking` puts on its data queue, that the live
graph folds each of them into the attribute a client actually renders, and that
the result survives serialization and the websocket to arrive at a browser.

The real producer method runs — not a restatement of it in the test — because a
test that re-derives the shape it is checking cannot catch a producer that
changes shape. What is deliberately NOT exercised is AT's transport: the queues
here are plain queues, and whether a `rep_req` reaches a peer belongs to the
core suite's own integration tests.
"""

import asyncio
import hashlib
import json
import os
from datetime import timedelta
from queue import Queue
from uuid import UUID

import pytest

from autonomous_trust.core import CfgIds
from autonomous_trust.core.identity import Identity
from autonomous_trust.core.identity.encrypt import Encryptor
from autonomous_trust.core.identity.sign import Signature
from autonomous_trust.core.network import Network
from autonomous_trust.core.network.ping_at import PingATStats
from autonomous_trust.core.reputation.reputation import Reputation
from autonomous_trust.core.system import now

from autonomous_trust.inspector.inspector import Inspector
from autonomous_trust.inspector.latency import summarize
from autonomous_trust.inspector.viz import network_graph as ng
from autonomous_trust.inspector.viz import server
from autonomous_trust.inspector.viz.live_graph import LiveData

RECV_TIMEOUT = 10.0


def _peer(tag: str) -> Identity:
    """A real `Identity`, deterministically derived from ``tag``.

    Real rather than a stand-in because the producer SERIALIZES its peers
    (`to_json_string((peer, self.proc_name))`) — a stub with a uuid and a name
    satisfies every attribute the method reads and then fails at the encoder,
    which is exactly the sort of gap this test exists to close. Mirrors the
    core suite's `_identity` helper.
    """
    seed = hashlib.sha256(tag.encode()).hexdigest().encode('ascii')
    enc = hashlib.sha256(('enc-' + tag).encode()).hexdigest().encode('ascii')
    return Identity(UUID(bytes=hashlib.md5(tag.encode()).digest()),
                    '10.0.0.%d' % (abs(hash(tag)) % 200 + 1), '%s.test' % tag,
                    Signature(seed, public_only=False),
                    Encryptor(enc, public_only=False),
                    _public_only=False)


class _Peers:
    def __init__(self, peers):
        self.all = list(peers)


class _CollectingLogger:
    """Records instead of printing, so a test can assert on what was reported."""

    def __init__(self):
        self.errors = []

    def error(self, *args, **kwargs):
        self.errors.append(args[0] if args else '')

    def warning(self, *args, **kwargs):
        pass

    debug = info = warning


def _inspector_under_test(peers):
    """A real `Inspector` with only the state `autonomous_tasking` reads.

    Built without `__init__` on purpose: the constructor chains into
    `AutonomousTrust`, which wants configuration on disk and a process tree, and
    none of that participates in the contract under test. The METHOD is the real
    one, which is the part that matters — every field it touches is set here, so
    a producer that starts reading something new fails loudly rather than
    silently reading a mock's auto-attribute.
    """
    insp = Inspector.__new__(Inspector)
    # What `Protocol.__init__` would have set: AutonomousTrust identifies itself
    # as CfgIds.main, and the reputation query carries that name so a reply can
    # be routed back to it.
    insp.proc_name = CfgIds.main
    insp.peers = _Peers(peers)
    insp.identity = _peer('inspector')
    insp.logger = _CollectingLogger()
    insp.data_queue = Queue()
    insp.latest_reputation = {}
    insp.latest_reputation_pairs = {}
    insp.unhandled_messages = []
    insp.last_tick = {}
    # Far enough in the past that every tasking_tick period has elapsed, so one
    # call drives all three branches rather than whichever the wall clock allows.
    insp.tasking_start = now() - timedelta(seconds=600)
    return insp


def _queues():
    q = {CfgIds.reputation: Queue(), CfgIds.network: Queue(), 'main': Queue()}
    return q


def _drain(q):
    out = []
    while not q.empty():
        out.append(q.get_nowait())
    return out


def _ping_stats(host, seconds):
    """A genuine `PingATStats`, the object the producer actually receives.

    `times` maps sequence number to seconds; `count` and `loss` are derived from
    it, so a real one is the only way to exercise the conversion the two
    consumers used to get wrong.
    """
    return PingATStats(host, {0: seconds, 1: seconds}, timedelta(seconds=seconds * 2))


class _PingReply:
    """A PingAT reply as it sits in `unhandled_messages`: the stats under
    `.obj`, and `from_whom` naming the peer that was pinged."""

    def __init__(self, peer, stats):
        self.function = Network.ping_at
        self.obj = stats
        self.from_whom = peer
        self.to_whom = None


def _live_graph(data_q):
    """The live graph BY NAME through the registry — the same lookup
    `viz/server.py` performs, so this also covers the registration that used to
    be missing."""
    return ng.Graphs.get_graph('live', 1, False, data_q=data_q)


def _pump(graph, rounds=8):
    """Drive the graph the way the websocket handler does, collecting frames.

    Bounded: a graph that never ingests its queue must fail the assertion rather
    than spin.
    """
    frames = []
    for _ in range(rounds):
        _seconds, data, stop = graph.get_update()
        if data is not None:
            frames.append(json.loads(data))
        if stop:
            break
    return frames


def _nodes_by_id(frames):
    """Latest attributes per node across every frame.

    Merged across frames rather than read off the last one because after the
    opening whole-graph frame the server emits DIFFS: a node whose reputation
    arrived three frames ago is simply absent from the newest one, and asserting
    against a single frame would fail for a pipeline that is working.
    """
    merged = {}
    for frame in frames:
        for node in frame.get('nodes', []):
            merged.setdefault(node.get('id'), {}).update(node)
    return merged


def _links(frames):
    out = []
    for frame in frames:
        out.extend(frame.get('links', []))
    return out


######################
# Tests:

def test_tasking_emits_the_shapes_the_live_graph_consumes():
    """One real tasking pass, and what lands on the data queue."""
    peer_a, peer_b = _peer('alpha'), _peer('bravo')
    insp = _inspector_under_test([peer_a, peer_b])
    insp.latest_reputation = {peer_a.uuid: Reputation(peer_a.uuid, 0.75)}
    insp.latest_reputation_pairs = {(peer_a.uuid, peer_b.uuid): Reputation(peer_b.uuid, 0.25)}
    stats = _ping_stats('10.0.0.5', 0.012)
    insp.unhandled_messages = [_PingReply(peer_b, stats)]

    queues = _queues()
    insp.autonomous_tasking(queues)

    # The AT-facing half: a reputation query and a ping per peer.
    rep_msgs = _drain(queues[CfgIds.reputation])
    net_msgs = _drain(queues[CfgIds.network])
    assert len(rep_msgs) >= 2, len(rep_msgs)
    ping_msgs = [m for m in net_msgs if getattr(m, 'function', None) == Network.ping_at]
    assert len(ping_msgs) == 2, len(ping_msgs)

    # The viz-facing half: one entry per channel, in the shape the handlers
    # match on. Asserted structurally, because every historical break here was a
    # well-formed object of the WRONG shape arriving on the right channel.
    published = _drain(insp.data_queue)
    by_label = {}
    for label, payload in published:
        by_label.setdefault(label, []).append(payload)

    direct = by_label[LiveData.reputation]
    triples = [p for p in direct if isinstance(p, tuple) and len(p) == 3]
    objects = [p for p in direct if not isinstance(p, tuple)]
    assert objects and getattr(objects[0], 'peer_id', None) == peer_a.uuid
    assert triples == [(str(peer_a.uuid), str(peer_b.uuid), 0.25)], triples

    latencies = by_label[LiveData.latencies]
    assert len(latencies) == 1
    uuid, rtt = latencies[0]
    assert uuid == str(peer_b.uuid), 'a latency sample must name the peer it measured'
    # Converted, not forwarded: the raw stats object is what the consumers used
    # to receive and silently drop.
    assert isinstance(rtt, float)
    assert rtt == pytest.approx(summarize(stats).rtt_ms)
    assert rtt == pytest.approx(12.0, abs=0.001)

    # A reply that names nobody cannot be attributed and must be dropped rather
    # than landing on a node of its own.
    insp.unhandled_messages = [_PingReply(None, _ping_stats('10.0.0.9', 0.03))]
    insp.tasking_start = now() - timedelta(seconds=600)
    insp.last_tick = {}
    insp.autonomous_tasking(_queues())
    assert not [p for label, p in _drain(insp.data_queue) if label == LiveData.latencies]


def test_tasking_output_reaches_the_graph_a_client_renders():
    """The full chain: producer -> queue -> live graph -> serialized frame."""
    peer_a, peer_b = _peer('alpha'), _peer('bravo')
    insp = _inspector_under_test([peer_a, peer_b])
    insp.latest_reputation = {peer_a.uuid: Reputation(peer_a.uuid, 0.75)}
    insp.latest_reputation_pairs = {(peer_a.uuid, peer_b.uuid): Reputation(peer_b.uuid, 0.25)}
    insp.unhandled_messages = [_PingReply(peer_b, _ping_stats('10.0.0.5', 0.012))]
    insp.autonomous_tasking(_queues())

    # The producer's own queue drives the graph — no re-encoding in between,
    # which is the point: this is the same object the running inspector hands to
    # VizServer as `data_q`.
    frames = _pump(_live_graph(insp.data_queue))
    assert frames, 'the live graph emitted nothing'
    assert frames[0].get('type') == 'new'
    for frame in frames:
        assert 'edges' not in frame, 'networkx edge key leaked past the rename'

    nodes = _nodes_by_id(frames)
    a_id, b_id = str(peer_a.uuid), str(peer_b.uuid)
    assert a_id in nodes and b_id in nodes, sorted(nodes)
    assert nodes[a_id].get('reputation') == 0.75
    assert nodes[b_id].get('latency') == pytest.approx(12.0, abs=0.001)

    edge = [lk for lk in _links(frames)
            if {lk.get('source'), lk.get('target')} == {a_id, b_id}]
    assert edge, 'transitive trust drew no edge between the pair'
    assert edge[-1].get('trust_level') == 0.25


@pytest.mark.asyncio
async def test_tasking_output_reaches_a_websocket_client():
    """...and across the last hop, the one a browser is on.

    Separate from the graph test because the websocket adds two failure modes of
    its own — the handler resolving the live implementation by name, and the
    frame being serialized as text a client can parse — and both have broken
    independently of anything the graph does.
    """
    peer_a, peer_b = _peer('alpha'), _peer('bravo')
    insp = _inspector_under_test([peer_a, peer_b])
    insp.latest_reputation = {peer_a.uuid: Reputation(peer_a.uuid, 0.9)}
    insp.unhandled_messages = [_PingReply(peer_b, _ping_stats('10.0.0.7', 0.025))]
    insp.autonomous_tasking(_queues())

    viz_dir = os.path.abspath(os.path.dirname(server.__file__))
    app = server.VizServer(viz_dir, 8997, False, data_q=insp.data_queue).app

    a_id, b_id = str(peer_a.uuid), str(peer_b.uuid)
    merged = {}
    async with app.test_client().websocket('/ws') as ws:
        for _ in range(8):
            raw = await asyncio.wait_for(ws.receive(), timeout=RECV_TIMEOUT)
            frame = json.loads(raw)
            for node in frame.get('nodes', []):
                merged.setdefault(node.get('id'), {}).update(node)
            if merged.get(a_id, {}).get('reputation') is not None and \
                    merged.get(b_id, {}).get('latency') is not None:
                break

    assert merged.get(a_id, {}).get('reputation') == 0.9, sorted(merged)
    assert merged.get(b_id, {}).get('latency') == pytest.approx(25.0, abs=0.001)


def test_a_peer_that_joins_after_the_client_connects_still_reaches_it():
    """The case a live dashboard exists for, and the one that was broken.

    A cohort grows while somebody is watching. The opening frame is the whole
    graph; everything after it is a diff, so a peer discovered later reaches the
    client only if the diff reports ADDITIONS. It did not: `LiveData._peer_node`
    adds straight to the networkx graph rather than through `add_node()`, so the
    change type stays META, and META reported only what had disappeared. The
    server held the peer, every frame said `meta` with an empty node list, and
    the display stayed at whatever it held on connect.
    """
    q = Queue()
    graph = _live_graph(q)

    opening = _pump(graph, rounds=1)
    assert opening and opening[0].get('type') == 'new'
    late = str(_peer('late-joiner').uuid)
    assert late not in _nodes_by_id(opening), 'precondition: not present at connect'

    q.put((LiveData.reputation, Reputation(late, 0.6)))
    after = _pump(graph, rounds=6)
    nodes = _nodes_by_id(after)
    assert late in nodes, f'a peer that joined after connect never reached the client: {sorted(nodes)}'
    assert nodes[late].get('reputation') == 0.6


def test_a_later_sample_for_a_known_peer_still_reaches_it():
    """The sibling case: not a new peer, a new MEASUREMENT for an old one.

    A frame's node set is a diff over `node_data` only, so an attribute missing
    from that list can change every tick and never produce a difference to emit.
    `latency` and `command` were both missing, so PingAT samples and command
    annotations stopped at the server for any peer the client already knew --
    the display kept the first value it was given.
    """
    q = Queue()
    known = str(_peer('known').uuid)
    q.put((LiveData.reputation, Reputation(known, 0.5)))
    graph = _live_graph(q)
    _pump(graph, rounds=3)               # the peer is now established

    q.put((LiveData.latencies, (known, 31.5)))
    q.put((LiveData.commands, (known, 'halt')))
    nodes = _nodes_by_id(_pump(graph, rounds=6))
    assert nodes.get(known, {}).get('latency') == 31.5, nodes.get(known)
    assert nodes.get(known, {}).get('command') == 'halt', nodes.get(known)


def test_a_malformed_payload_cannot_stall_the_pipeline():
    """A producer half-wired must not take the render loop down with it.

    The channels are fed by several producers at different stages of completion,
    and the live graph is the one place they converge: an exception here stops
    every peer's display, not just the offending one. So each handler is a safe
    no-op on data it does not recognize — asserted by mixing garbage into a
    stream that also carries good data and requiring the good data through.
    """
    q = Queue()
    good = str(_peer('good').uuid)
    q.put((LiveData.peers, 42))                    # not iterable
    q.put((LiveData.latencies, 'not-a-tuple'))
    q.put((LiveData.reputation, None))
    q.put(('no-such-channel', {'anything': True}))
    q.put((LiveData.latencies, (good, 7.5)))       # the one that must survive

    frames = _pump(_live_graph(q), rounds=10)
    nodes = _nodes_by_id(frames)
    assert nodes.get(good, {}).get('latency') == 7.5, sorted(nodes)


def test_the_sentinel_stops_the_pipeline():
    """`(None, None)` is how a shutting-down inspector closes its clients; the
    graph must report `stop` so the websocket handler leaves its loop rather
    than holding a task per client for the life of the process."""
    q = Queue()
    q.put((None, None))
    graph = _live_graph(q)
    for _ in range(4):
        _seconds, _data, stop = graph.get_update()
        if stop:
            break
    assert stop
