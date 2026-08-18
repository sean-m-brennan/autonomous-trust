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
"""The batched reputation query, requestor to responder, with nothing mocked
in between.

The unit tests either side of this seam both pass with a payload shape the other
would reject: the inspector's tests patch `Message` and `to_json_string`, and the
responder's tests hand the handler a dict they built themselves. The shape is
written out in one package and parsed in another, so this drives a real round —
`query_peer_pairs` builds it, the message is serialized and its signature
validated as a receiver would, and `ReputationProcess` parses and answers it.

See doc/architecture/reputation.md, "Asking others what they think".
"""
import queue
from uuid import uuid4
from unittest.mock import MagicMock

import pytest

from autonomous_trust.core import CfgIds
from autonomous_trust.core.identity import Identity
from autonomous_trust.core.network.message import Message
from autonomous_trust.core.processes import ProcessTracker
from autonomous_trust.core.reputation.repprocess import ReputationProcess
from autonomous_trust.inspector.transitive_trust import TransitiveTrustMixin


class _Host(TransitiveTrustMixin):
    """The requestor side: what an Inspector/InspectorBridge supplies."""

    def __init__(self, peers):
        class _Peers:
            pass
        self.peers = _Peers()
        self.peers.all = peers
        self.identity = Identity.initialize('inspector', 'inspector', '10.0.0.1')
        self.proc_name = 'monitor'


def _responder(identity):
    procs = []
    for name in (CfgIds.network, CfgIds.identity, CfgIds.negotiation,
                 CfgIds.reputation):
        proc = MagicMock()
        proc.name = name
        procs.append(proc)
    group = MagicMock()
    group.uuid = uuid4()
    configs = {'processes': procs, CfgIds.identity: identity,
               CfgIds.peers: MagicMock(), CfgIds.group: group}
    rep = ReputationProcess(configs, ProcessTracker(), queue.Queue(),
                            suppress_log=True)
    rep.protocol.group = group
    return rep


@pytest.fixture
def round_trip():
    peers = [Identity.initialize('p%d' % i, 'p%d' % i, '10.0.0.%d' % (i + 2))
             for i in range(4)]
    host = _Host(peers)
    netq = queue.Queue()
    sent = host.query_peer_pairs({CfgIds.network: netq})
    messages = [netq.get() for _ in range(sent)]
    return host, peers, messages


def test_one_request_per_observer(round_trip):
    _, peers, messages = round_trip
    assert len(messages) == len(peers)
    addressed = sorted(str(m.to_whom[0].uuid) for m in messages)
    assert addressed == sorted(str(p.uuid) for p in peers)


def test_round_carries_a_single_signature(round_trip):
    """The saving is only real if the copies genuinely share the signature."""
    _, _, messages = round_trip
    assert len({m.signature for m in messages}) == 1
    assert messages[0].signature is not None


def test_each_message_validates_as_a_receiver_would(round_trip):
    host, _, messages = round_trip
    sender = host.identity.publish()
    for msg in messages:
        parsed = Message.parse(msg.to_wire(), sender, validate=True)
        assert parsed.verified is True, 'readdressed copy failed verification'


def test_responder_parses_what_the_requestor_wrote(round_trip):
    """The seam itself: no hand-built payload on either side."""
    host, peers, messages = round_trip
    observer = peers[0]
    addressed = [m for m in messages
                 if str(m.to_whom[0].uuid) == str(observer.uuid)][0]
    parsed = Message.parse(addressed.to_wire(), host.identity.publish(),
                           validate=True)
    rep = _responder(observer)
    assert rep.handle_consensus_reputation_batch_request(None, parsed) is True


def test_roster_covers_every_other_peer_and_excludes_the_observer(round_trip):
    host, peers, _ = round_trip
    observer = peers[0]
    rep = _responder(observer)
    rep._compute_consensus_reputation_batch(
        [str(p.uuid) for p in peers], 'monitor', host.identity)
    roster, req_proc, requestor = rep.requested_reps.pop()
    ids = sorted(str(entry.peer_id) for entry in roster)
    assert ids == sorted(str(p.uuid) for p in peers[1:])
    assert str(observer.uuid) not in ids
    assert req_proc == 'monitor'


def test_scores_are_in_range(round_trip):
    # Cold chain: whatever the consensus baseline is, it has to be a score.
    host, peers, _ = round_trip
    rep = _responder(peers[0])
    rep._compute_consensus_reputation_batch(
        [str(p.uuid) for p in peers[1:]], 'monitor', host.identity)
    roster, _, _ = rep.requested_reps.pop()
    for entry in roster:
        assert 0.0 <= float(entry.score) <= 1.0, entry
