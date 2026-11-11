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
"""A commit certificate names the roster it was collected under.

Hostile-join run, 2026-11-04: while the roster grew from 4 to 10 members, a
proposer one roster behind its receivers sent certificates that met its own
bar and fell short of theirs ("4 of 4 signature(s) verify, 5 needed, roster
of 10"), and every such half was lost. A commit now carries the digest of the
roster its certificate met, unsigned, and a receiver judges against that roster
while it was in force within the last ``CERT_ROSTER_WINDOW`` instances of its
own chain. A digest it does not hold, or one older than that, is judged on its
own roster in force, as before. The C twin is src/c/test/rep_cert_roster_test.c.
"""
import queue
from uuid import uuid4

from autonomous_trust.core.config import from_json_string, to_json_string
from autonomous_trust.core.reputation.placement import (entry_from_dict,
                                                        entry_to_dict)
from autonomous_trust.core.reputation.protocol import ReputationProtocol
from autonomous_trust.core.reputation.reputation import (
    Transaction, TransactionHistory, evidence_from_dict, evidence_to_dict,
    placement_entry, roster_task_id)
from autonomous_trust.core.system import CfgIds

from tests.a_unit.test_commit_certificates import (_half, _ident, _msg, _node,
                                                    _sign)
from tests.a_unit.test_placement_roster import _add_of, _roster_of


def _grown(n_start=4, adds=2):
    """`me` and n_start + adds others: a genesis of `me` and the first
    n_start - 1 others at 0, then one add per further member. Returns the
    process, the people (me first) and the rosters in placement order."""
    people = [_ident('p%d' % i, i + 1) for i in range(n_start + adds)]
    me = people[0]
    rp, _q = _node(me, people[1:])
    rosters = [_roster_of(people[:n_start])]
    assert rp.history.apply_placed(0, [rosters[0]]) == 'applied'
    for i in range(adds):
        add = _add_of(rp.history, people[n_start + i])
        assert rp.history.apply_placed(1 + i, [add]) == 'applied'
        rosters.append(add)
    return rp, people, rosters


def _restate(hist, n_min):
    r = hist.latest_roster()
    d = r.roster_digest
    return Transaction(roster_task_id(r.task_id, 'restate', None, d, n_min),
                       roster_op='restate', roster_digest=d,
                       roster_members=r.roster_members, roster_n_min=n_min)


class TestLookup:
    def test_a_superseded_roster_is_found_inside_the_window(self):
        rp, _people, rosters = _grown()
        h = rp.history
        assert h.roster_named(rosters[0].roster_digest, 32) is not None
        assert h.roster_named(rosters[0].roster_digest, 32).index == 0
        assert h.roster_named(rosters[2].roster_digest, 32).index == 2

    def test_a_roster_superseded_before_the_window_is_not(self):
        rp, _people, rosters = _grown()
        h = rp.history                       # next 3; the window reaches 2
        assert h.roster_named(rosters[0].roster_digest, 1) is None
        assert h.roster_named(rosters[1].roster_digest, 1).index == 1
        assert h.roster_named(rosters[2].roster_digest, 1).index == 2

    def test_a_digest_never_held_is_not_found(self):
        rp, _people, _rosters = _grown()
        assert rp.history.roster_named('ab' * 32, 32) is None
        assert rp.history.roster_named(None, 32) is None

    def test_a_restated_roster_is_its_newest_declaration(self):
        rp, _people, rosters = _grown()
        h = rp.history
        assert h.apply_placed(3, [_restate(h, 7)]) == 'applied'
        got = h.roster_named(rosters[2].roster_digest, 32)
        assert (got.index, got.roster_n_min) == (3, 7)

    def test_the_anchor_is_found_while_in_force(self):
        people = [_ident('p%d' % i, i + 1) for i in range(3)]
        rp, _q = _node(people[0], people[1:])
        rp.history.roster_anchor = _roster_of(people)
        assert rp.history.roster_named(
            rp.history.roster_anchor.roster_digest, 32) is rp.history.roster_anchor


class TestJudged:
    """Six members, the roster grown 4 -> 5 -> 6. A half by p3 certified by p1
    and p2: a majority of the first roster with its scorer, short of the
    roster of six in force (which needs three)."""

    def _half(self, people):
        task = uuid4()
        scorer = people[3]
        sigs = {str(p.uuid): _sign(p, scorer, task, 900) for p in people[1:3]}
        return scorer, task, sigs

    def test_a_certificate_meets_the_roster_it_names(self):
        rp, people, rosters = _grown()
        scorer, task, sigs = self._half(people)
        assert not rp._commit_cert_ok(scorer.uuid, task, 900, None, sigs)
        assert rp._commit_cert_ok(scorer.uuid, task, 900, None, sigs,
                                  named=rosters[0].roster_digest)

    def test_a_named_roster_past_the_window_is_judged_on_ours(self, monkeypatch):
        rp, people, rosters = _grown()
        monkeypatch.setattr(type(rp), 'CERT_ROSTER_WINDOW', 1)
        scorer, task, sigs = self._half(people)
        tally = {}
        assert not rp._commit_cert_ok(scorer.uuid, task, 900, None, sigs,
                                      named=rosters[0].roster_digest,
                                      tally=tally)
        assert (tally['members'], tally['needed'], tally['named']) == (6, 3, False)

    def test_an_unknown_digest_is_judged_on_ours(self):
        rp, people, _rosters = _grown()
        scorer, task, sigs = self._half(people)
        tally = {}
        assert not rp._commit_cert_ok(scorer.uuid, task, 900, None, sigs,
                                      named='ab' * 32, tally=tally)
        assert (tally['members'], tally['named']) == (6, False)

    def test_the_tally_says_the_named_roster_decided(self):
        rp, people, rosters = _grown()
        scorer, task, sigs = self._half(people)
        tally = {}
        assert rp._commit_cert_ok(scorer.uuid, task, 900, None, sigs,
                                  named=rosters[0].roster_digest, tally=tally)
        assert tally == {'offered': 2, 'verified': 2, 'needed': 2,
                         'members': 4, 'named': True}

    def test_a_signer_outside_the_named_roster_is_not_counted(self):
        rp, people, rosters = _grown()
        task = uuid4()
        scorer = people[3]
        sigs = {str(p.uuid): _sign(p, scorer, task, 900)
                for p in (people[1], people[4])}     # p4 joined later
        assert not rp._commit_cert_ok(scorer.uuid, task, 900, None, sigs,
                                      named=rosters[0].roster_digest)


def _committed(scorer, other, task, sigs, roster=...):
    """A `committed` payload for `scorer`'s half naming `other`; `roster` the
    trailing element 9, left off when not given."""
    body = [task, scorer.uuid, 900, None, None, sigs,
            str(other.uuid), _half(scorer, other, task, 900)]
    if roster is not ...:
        body.append(roster)
    return from_json_string(to_json_string(body))


class TestCarried:
    def test_a_receiver_ahead_pools_a_half_its_commit_names_the_roster_of(self):
        rp, people, rosters = _grown()
        scorer, other = people[3], people[2]
        d = rosters[0].roster_digest
        task = uuid4()
        sigs = {str(p.uuid): _sign(p, scorer, task, 900) for p in people[:2]}
        rp.handle_committed(None, _msg(ReputationProtocol.committed,
                                       _committed(scorer, other, task, sigs, d),
                                       scorer))
        held = rp.history.pooled(task)
        assert held is not None and held.cert_roster_of(scorer.uuid) == d

    def test_without_the_name_the_same_half_is_refused(self):
        rp, people, _rosters = _grown()
        scorer, other = people[3], people[2]
        task = uuid4()
        sigs = {str(p.uuid): _sign(p, scorer, task, 900) for p in people[:2]}
        rp.logger = __import__('unittest.mock').mock.MagicMock()
        rp.handle_committed(None, _msg(ReputationProtocol.committed,
                                       _committed(scorer, other, task, sigs),
                                       scorer))
        assert rp.history.pooled(task) is None
        (call,) = rp.logger.warning.call_args_list
        assert '2 of 2 signature(s) verify, 3 needed, roster of 6' \
            in call.args[-1]

    def test_the_refusal_says_when_the_named_roster_decided(self):
        rp, people, rosters = _grown()
        scorer, other = people[3], people[2]
        task = uuid4()
        sigs = {str(people[0].uuid): _sign(people[0], scorer, task, 900)}
        rp.logger = __import__('unittest.mock').mock.MagicMock()
        rp.handle_committed(None, _msg(
            ReputationProtocol.committed,
            _committed(scorer, other, task, sigs, rosters[0].roster_digest),
            scorer))
        (call,) = rp.logger.warning.call_args_list
        assert '1 of 1 signature(s) verify, 2 needed, named roster of 4' \
            in call.args[-1]

    def _entry(self, people, rosters):
        """p2 and p3, each half certified by p0 and p1 under the first
        roster, which each half names."""
        task = uuid4()
        a, b = people[2], people[3]
        d = rosters[0].roster_digest
        tx = Transaction(
            task, p1_id=a.uuid, p1_score_milli=900, p2_id=b.uuid,
            p2_score_milli=700,
            commit_sigs={str(a.uuid): {str(p.uuid): _sign(p, a, task, 900)
                                       for p in people[:2]},
                         str(b.uuid): {str(p.uuid): _sign(p, b, task, 700)
                                       for p in people[:2]}},
            half_sigs={str(a.uuid): _half(a, b, task, 900),
                       str(b.uuid): _half(b, a, task, 700)},
            cert_rosters={str(a.uuid): d, str(b.uuid): d})
        return placement_entry(tx)

    def test_the_placement_value_carries_it_and_is_judged_by_it(self):
        rp, people, rosters = _grown()
        e = self._entry(people, rosters)
        back = entry_from_dict(from_json_string(to_json_string(entry_to_dict(e))))
        assert back.cert_rosters == e.cert_rosters
        assert rp._place_value_ok([back], rp.history, None) is None
        back.cert_rosters = None
        assert 'is not certified' in rp._place_value_ok([back], rp.history, None)

    def test_the_hash_and_the_placement_digest_do_not_change(self):
        _rp, people, rosters = _grown()
        e = self._entry(people, rosters)
        # placement_entry orders the halves by uuid, so the scores go with e.
        bare = Transaction(e.task_id, p1_id=e.p1_id,
                           p1_score_milli=e.p1_score_milli, p2_id=e.p2_id,
                           p2_score_milli=e.p2_score_milli)
        assert e.entry_hash() == bare.entry_hash()
        assert 'cert_rosters' not in bare.to_dict()

    def test_the_pool_keeps_it_across_a_restart(self):
        h = TransactionHistory()
        task, a, d = uuid4(), uuid4(), 'cd' * 32
        h.record_half(task, a, 900, certificate={'v': 'aa'}, cert_roster=d)
        again = TransactionHistory()
        again.pool_from_dict(from_json_string(to_json_string(h.pool_to_dict())))
        assert again.pooled(task).cert_roster_of(a) == d

    def test_evidence_and_catchup_keep_it(self):
        rp, people, rosters = _grown()
        e = self._entry(people, rosters)
        h = TransactionHistory()
        h.apply_placed(0, [e])
        chain, _ = evidence_from_dict(evidence_to_dict(h))
        assert chain[0].cert_rosters == e.cert_rosters
        back = from_json_string(to_json_string(list(h)))
        assert back[0].cert_rosters == e.cert_rosters

    def test_catchup_judges_a_certificate_by_the_roster_it_names(self):
        rp, people, rosters = _grown()
        e = self._entry(people, rosters)
        e.index = 3
        msg = _msg(ReputationProtocol.update, [], people[1])
        assert rp._commit_certs_ok([e], msg)
        e.cert_rosters = None
        assert not rp._commit_certs_ok([e], msg)

    def test_the_handoff_resend_carries_it(self):
        rp, people, _rosters = _grown()
        me, d = rp.identity.uuid, 'cd' * 32
        rp.history.record_half(uuid4(), me, 900, certificate={'v': 'aa'},
                               cert_roster=d)
        q = queue.Queue()
        rp.protocol.peers.all = []
        rp._hand_off_pending_halves({CfgIds.network: q}, 0.0)
        rp.protocol.peers.all = [people[1]]
        rp._hand_off_pending_halves({CfgIds.network: q}, 1.0)
        rp._hand_off_pending_halves({CfgIds.network: q}, 7.0)
        frames = [q.get_nowait() for _ in range(q.qsize())]
        assert frames and from_json_string(frames[0].obj)[8] == d
