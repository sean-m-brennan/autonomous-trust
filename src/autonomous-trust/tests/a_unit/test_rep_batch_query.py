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
"""The batched consensus-reputation request: `consensus_rep_batch_req`.

One request naming many subjects, answered with one deduplicated roster. This
exists because an observer-by-subject sweep — which is exactly what the
inspector's transitive-trust round does — cost N(N-1) messages with the
per-subject verb, each one triggering its own chain walk and its own signed
reply. The batched form makes a round N messages.

What matters here is that batching changed only the message COUNT: the same
subjects are answered, with the same scores, in a reply shape (`rep_resp`
carrying a list) that `automate.py` already captured one entry per peer.

See doc/architecture/reputation.md and doc/architecture/gateway-reputation-tree.md.
"""
import queue
from types import SimpleNamespace
from uuid import uuid4
from unittest.mock import MagicMock

from autonomous_trust.core.reputation.repprocess import (
    ReputationProcess, MAX_REP_BATCH_SUBJECTS,
)
from autonomous_trust.core.reputation.reputation import Reputation
from autonomous_trust.core.reputation.protocol import ReputationProtocol
from autonomous_trust.core.processes import ProcessTracker
from autonomous_trust.core.system import CfgIds
from autonomous_trust.core.config import to_json_string


def _make_rep_process():
    """A ReputationProcess with mocked configs (mirrors test_gateway_rep_tree)."""
    log_q = queue.Queue()
    identity = MagicMock()
    identity.uuid = uuid4()
    procs = []
    for name in (CfgIds.network, CfgIds.identity, CfgIds.negotiation,
                 CfgIds.reputation):
        p = MagicMock()
        p.name = name
        procs.append(p)
    group = MagicMock()
    group.uuid = uuid4()
    configs = {
        'processes': procs,
        CfgIds.identity: identity,
        CfgIds.peers: MagicMock(),
        CfgIds.group: group,
    }
    rp = ReputationProcess(configs, ProcessTracker(), log_q, suppress_log=True)
    rp.protocol.group = group
    return rp


def _msg(obj, function=None, from_whom=None):
    """A stand-in for an inbound Message: only the fields the handler reads."""
    return SimpleNamespace(
        function=function or ReputationProtocol.consensus_rep_batch_req,
        obj=obj,
        from_whom=from_whom or SimpleNamespace(nickname='requestor',
                                              uuid=uuid4()))


def _body(uuids, proc='monitor'):
    return {'peer_uuids': [str(u) for u in uuids], 'requesting_process': proc}


class TestVerbIsWiredUp:
    def test_verb_is_distinct_from_the_single_subject_form(self):
        # A one-character difference would be a menace in logs and greps, and
        # the string IS the wire form shared with the C twin.
        assert (ReputationProtocol.consensus_rep_batch_req
                != ReputationProtocol.consensus_rep_req)
        assert ReputationProtocol.consensus_rep_batch_req == \
            'request consensus reputation batch'

    def test_handler_is_registered(self):
        rp = _make_rep_process()
        handlers = rp.protocol.handlers if hasattr(rp.protocol, 'handlers') else None
        if handlers is None:            # registry shape differs; fall back
            assert hasattr(rp, 'handle_consensus_reputation_batch_request')
        else:
            assert ReputationProtocol.consensus_rep_batch_req in handlers

    def test_wrong_function_is_not_claimed(self):
        # Handlers are polled; claiming a message that is not ours would
        # swallow it from whoever it belongs to.
        rp = _make_rep_process()
        assert rp.handle_consensus_reputation_batch_request(
            None, _msg(_body(['a']), function=ReputationProtocol.rep_req)) is False


class TestPayloadParsing:
    def test_dict_form_spawns_the_computation(self):
        rp = _make_rep_process()
        rp._spawn = MagicMock()
        assert rp.handle_consensus_reputation_batch_request(
            None, _msg(_body(['a', 'b']))) is True
        args = rp._spawn.call_args.kwargs['args']
        assert list(args[0]) == ['a', 'b']
        assert args[1] == 'monitor'

    def test_json_string_form_is_parsed(self):
        rp = _make_rep_process()
        rp._spawn = MagicMock()
        assert rp.handle_consensus_reputation_batch_request(
            None, _msg(to_json_string(_body(['a'])))) is True
        assert list(rp._spawn.call_args.kwargs['args'][0]) == ['a']

    def test_tuple_form_is_accepted(self):
        # Mirrors the per-subject handler, which takes both shapes.
        rp = _make_rep_process()
        rp._spawn = MagicMock()
        assert rp.handle_consensus_reputation_batch_request(
            None, _msg((['a', 'b'], 'monitor'))) is True
        assert list(rp._spawn.call_args.kwargs['args'][0]) == ['a', 'b']

    def test_unusable_shape_is_claimed_but_not_computed(self):
        rp = _make_rep_process()
        rp._spawn = MagicMock()
        # Claimed (True) so it is not re-dispatched, but nothing is computed.
        assert rp.handle_consensus_reputation_batch_request(None, _msg(42)) is True
        assert not rp._spawn.called

    def test_non_list_subjects_are_refused(self):
        rp = _make_rep_process()
        rp._spawn = MagicMock()
        assert rp.handle_consensus_reputation_batch_request(
            None, _msg({'peer_uuids': 'not-a-list',
                        'requesting_process': 'monitor'})) is True
        assert not rp._spawn.called


class TestAmplificationBound:
    def test_oversized_request_is_truncated_not_honored(self):
        """Each named subject costs a chain walk, so one small message must not
        be able to ask for unbounded work."""
        rp = _make_rep_process()
        rp._spawn = MagicMock()
        rp.handle_consensus_reputation_batch_request(
            None, _msg(_body([str(uuid4()) for _ in range(MAX_REP_BATCH_SUBJECTS + 50)])))
        assert len(rp._spawn.call_args.kwargs['args'][0]) == MAX_REP_BATCH_SUBJECTS

    def test_request_at_the_bound_is_untouched(self):
        rp = _make_rep_process()
        rp._spawn = MagicMock()
        uuids = [str(uuid4()) for _ in range(MAX_REP_BATCH_SUBJECTS)]
        rp.handle_consensus_reputation_batch_request(None, _msg(_body(uuids)))
        assert len(rp._spawn.call_args.kwargs['args'][0]) == MAX_REP_BATCH_SUBJECTS


class TestBatchRoster:
    """`_compute_consensus_reputation_batch` — equivalent to running the
    per-subject computation once per subject and concatenating, minus the
    duplication a gateway's subtree roster would otherwise repeat."""

    def test_one_entry_per_subject(self):
        rp = _make_rep_process()
        subjects = [str(uuid4()) for _ in range(4)]
        rp._subtree_roster = lambda u: [Reputation(u, 0.5)]
        rp._compute_consensus_reputation_batch(subjects, 'monitor', 'req')
        roster, req_proc, requestor = rp.requested_reps.pop()
        assert [str(r.peer_id) for r in roster] == subjects
        assert (req_proc, requestor) == ('monitor', 'req')

    def test_duplicate_entries_are_collapsed(self):
        """A gateway's roster carries its child-group members alongside the
        requested subject, and those do not depend on which subject was asked —
        so naming N subjects would repeat them N times."""
        rp = _make_rep_process()
        child = str(uuid4())
        subjects = [str(uuid4()) for _ in range(3)]
        rp._subtree_roster = lambda u: [Reputation(u, 0.5), Reputation(child, 0.9)]
        rp._compute_consensus_reputation_batch(subjects, 'monitor', 'req')
        roster, _, _ = rp.requested_reps.pop()
        ids = [str(r.peer_id) for r in roster]
        assert ids.count(child) == 1, ids
        assert sorted(ids) == sorted(subjects + [child])

    def test_our_own_uuid_is_skipped(self):
        """No self-pair: the sweep has no use for one, and skipping it here is
        what lets one request body serve every observer in a round."""
        rp = _make_rep_process()
        me = str(rp.identity.uuid)
        other = str(uuid4())
        rp._subtree_roster = lambda u: [Reputation(u, 0.5)]
        rp._compute_consensus_reputation_batch([me, other], 'monitor', 'req')
        roster, _, _ = rp.requested_reps.pop()
        assert [str(r.peer_id) for r in roster] == [other]

    def test_self_entries_inside_a_roster_are_also_dropped(self):
        rp = _make_rep_process()
        me = str(rp.identity.uuid)
        other = str(uuid4())
        rp._subtree_roster = lambda u: [Reputation(u, 0.5), Reputation(me, 1.0)]
        rp._compute_consensus_reputation_batch([other], 'monitor', 'req')
        roster, _, _ = rp.requested_reps.pop()
        assert [str(r.peer_id) for r in roster] == [other]

    def test_empty_result_queues_nothing(self):
        # An empty roster would serialise as an empty reply the requestor cannot
        # use; better to stay silent than to spend a signature saying nothing.
        rp = _make_rep_process()
        rp._subtree_roster = lambda u: []
        rp._compute_consensus_reputation_batch([str(uuid4())], 'monitor', 'req')
        assert list(rp.requested_reps) == []

    def test_only_own_uuid_requested_queues_nothing(self):
        rp = _make_rep_process()
        rp._subtree_roster = lambda u: [Reputation(u, 0.5)]
        rp._compute_consensus_reputation_batch(
            [str(rp.identity.uuid)], 'monitor', 'req')
        assert list(rp.requested_reps) == []

    def test_a_failing_subject_does_not_lose_the_round(self):
        rp = _make_rep_process()
        good = str(uuid4())
        rp._subtree_roster = MagicMock(side_effect=RuntimeError('chain gone'))
        # Must not raise out of the worker; the warning path handles it.
        rp._compute_consensus_reputation_batch([good], 'monitor', 'req')
        assert list(rp.requested_reps) == []

    def test_matches_the_per_subject_path_score_for_score(self):
        """The batch verb is a message-count optimisation, not a scoring change:
        for the same subjects it must produce what the per-subject handler
        produces, entry for entry."""
        rp = _make_rep_process()
        subjects = [str(uuid4()) for _ in range(3)]
        rp._subtree_roster = lambda u: [Reputation(u, 0.25)]

        per_subject = []
        for subject in subjects:
            rp._compute_consensus_reputation(subject, 'monitor', 'req')
            roster, _, _ = rp.requested_reps.pop()
            per_subject.extend(roster)

        rp._compute_consensus_reputation_batch(subjects, 'monitor', 'req')
        batched, _, _ = rp.requested_reps.pop()
        assert [(str(r.peer_id), r.score) for r in batched] == \
               [(str(r.peer_id), r.score) for r in per_subject]
