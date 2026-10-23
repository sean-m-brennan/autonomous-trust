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
"""A half in a group that places its order has no round of its own
(doc/architecture/reputation.md, "Agreeing on an order").

Where its entry lands is decided by placement, so the proposer skips `ask
permission` and sends its `transaction` at once, naming the group and asking
to be certified. An acceptor in such a group signs it without having granted
it; one in a group that does not place its order still needs the grant, which
is what orders that chain. Mirrors the C cases in rep_place_halves_test.c.
"""
from uuid import uuid4

from autonomous_trust.core.config import from_json_string
from autonomous_trust.core.reputation.protocol import ReputationProtocol
from autonomous_trust.core.reputation.reputation import TransactionScore

from tests.a_unit.test_commit_certificates import (_msg, _node, _roster, _sent,
                                                   four)  # noqa: F401


def _placing(me, everyone):
    rp, q = _node(me, _roster(me, everyone))
    return rp, q


def _proposal(rp, q):
    """What `rp` sends for a fresh half of its own, by function."""
    # Our half names whom it scores (R+D.md §14.2); which peer does not
    # matter here.
    rp._start_paxos(q, TransactionScore(uuid4(), 0.9, subject_uuid=uuid4()))
    out = {}
    for m in _sent(q):
        out.setdefault(m.function, []).append(m)
    return out


class TestProposer:
    def test_a_placing_proposer_sends_its_half_without_asking(self, four):
        rp, q = _placing(four[0], four)
        out = _proposal(rp, q)
        assert not set(ReputationProtocol.retired) & set(out)
        assert len(out[ReputationProtocol.transaction]) == 1
        parts = from_json_string(out[ReputationProtocol.transaction][0].obj)
        assert parts[2] is True
        assert parts[3] == str(rp.protocol.group.uuid)
        assert len(rp.proposals) == 1



class TestAcceptor:
    def _offer(self, acc, q, proposer, tail):
        score = TransactionScore(uuid4(), 0.9)
        acc.handle_transaction(q, _msg(ReputationProtocol.transaction,
                                       ((7, 1, proposer.uuid), score) + tail,
                                       proposer))
        return [from_json_string(m.obj) for m in _sent(q)
                if m.function == ReputationProtocol.accepted]

    def test_a_placing_acceptor_signs_a_half_it_never_granted(self, four):
        acc, q = _placing(four[1], four)
        out = self._offer(acc, q, four[0], (True, ''))
        assert len(out) == 1 and len(out[0]) == 4      # with its signature

    def test_unless_it_asks_to_be_certified(self, four):
        acc, q = _placing(four[1], four)
        assert self._offer(acc, q, four[0], (False, '')) == []



def test_end_to_end_the_half_reaches_every_pool(four):
    p, a1, a2, o = four
    prop, pq = _placing(p, four)
    accs = [_placing(a, four) for a in (a1, a2)]
    obs, _ = _placing(o, four)
    out = _proposal(prop, pq)
    tx = out[ReputationProtocol.transaction][0]
    task = from_json_string(tx.obj)[1].task_id
    for (acc, q), who in zip(accs, (a1, a2)):
        acc.handle_transaction(q, _msg(ReputationProtocol.transaction,
                                       from_json_string(tx.obj), p))
        for m in _sent(q):
            prop.handle_accepted(pq, _msg(ReputationProtocol.accepted,
                                          from_json_string(m.obj), who))
    commits = [m for m in _sent(pq) if m.function == ReputationProtocol.committed]
    assert len(commits) == 1
    assert prop.history.pooled(task) is not None and len(prop.history) == 0
    obs.handle_committed(None, _msg(ReputationProtocol.committed,
                                    from_json_string(commits[0].obj), p))
    assert obs.history.pooled(task) is not None and len(obs.history) == 0
