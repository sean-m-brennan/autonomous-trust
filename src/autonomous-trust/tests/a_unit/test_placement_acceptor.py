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
"""The acceptor and learner of ordered placement (doc/architecture/
reputation.md, "Agreeing on an order"), on real keys.

An acceptor promises the highest ballot it has seen for the chain's next
index, reports the value it last accepted there, and accepts a value only
under a ballot it has not outranked, only on its own prefix, and only when
every half carries its commit certificate. Its promises survive a restart. A
learner writes a placement only on a quorum certificate over the placement's
designation after its own head.
"""
import os
from uuid import uuid4

import pytest

from autonomous_trust.core.reputation.placement import (
    ballot_obj, entry_from_dict, entry_to_dict)
from autonomous_trust.core.reputation.protocol import ReputationProtocol
from autonomous_trust.core.reputation.repprocess import ReputationProcess
from autonomous_trust.core.reputation.reputation import (
    Transaction, commit_designation, half_designation, place_designation,
    place_value_digest, placement_entry)

from tests.a_unit.test_commit_certificates import (_ident, _node, _sent, _msg,
                                                    _roster)


@pytest.fixture
def four(tmp_path, monkeypatch):
    """Four members: a roster of 3 per node, so a half's certificate needs 2
    signatures besides its scorer's and a placement's needs 3 signers."""
    os.makedirs(tmp_path / 'etc' / 'at')
    monkeypatch.setenv('AUTONOMOUS_TRUST_ROOT', str(tmp_path))
    return (_ident('prop', 1), _ident('acc1', 2), _ident('acc2', 3),
            _ident('obs', 4))


def _placing(me, everyone):
    """`me` in a group of `everyone`, its roster in force (an anchor: these
    cases are about placing entries, not founding the group)."""
    rp, q = _node(me, _roster(me, everyone))
    peers = rp.protocol.peers.all
    rp.protocol.peers.find_top_n = lambda n: list(peers)[:n]
    rp.history.roster_anchor = _roster_of(everyone)
    return rp, q


def _roster_of(everyone):
    from nacl.encoding import HexEncoder
    from autonomous_trust.core.reputation.reputation import (roster_digest,
                                                             roster_task_id)
    members = [[str(i.uuid), i.signature.public.encode(encoder=HexEncoder).decode()]
               for i in everyone]
    d = roster_digest(members)
    return Transaction(roster_task_id(None, 'genesis', None, d), roster_op='genesis',
                       roster_digest=d, roster_members=members)


def _cert(scorer, task, score, signers):
    return {str(s.uuid): ReputationProcess._detached_sig(
        s, commit_designation(scorer.uuid, task, score)) for s in signers}


def _entry(everyone, a, b, task=None):
    """A completed task between members a and b, each half certified by the
    two other members."""
    task = task or uuid4()
    others = [m for m in everyone if m is not a and m is not b]
    tx = Transaction(task, p1_id=a.uuid, p1_score_milli=900, p2_id=b.uuid,
                     p2_score_milli=700,
                     commit_sigs={str(a.uuid): _cert(a, task, 900, others),
                                  str(b.uuid): _cert(b, task, 700, others)},
                     half_sigs={str(a.uuid): _half_sig(a, b, task, 900),
                                str(b.uuid): _half_sig(b, a, task, 700)})
    return placement_entry(tx)


def _half_sig(scorer, other, task, score):
    """`scorer`'s own signature over its half, naming `other`."""
    return ReputationProcess._detached_sig(
        scorer, half_designation(task, scorer.uuid, other.uuid, score))


def _value(*entries):
    return [entry_to_dict(e) for e in sorted(entries,
                                             key=lambda e: str(e.task_id))]


def _head(rp):
    return rp.history.head_hash.decode('ascii')


def _ask(rp, q, sender, k=0, n=5, head=None):
    rp.handle_place_request(q, _msg(ReputationProtocol.place_request,
                                    {'group': '', 'k': k,
                                     'ballot': {'n': n, 'by': str(sender.uuid)},
                                     'head': _head(rp) if head is None else head},
                                    sender))
    return _sent(q)


def _place(rp, q, sender, value, k=0, n=5):
    rp.handle_place(q, _msg(ReputationProtocol.place,
                            {'group': '', 'k': k,
                             'ballot': {'n': n, 'by': str(sender.uuid)},
                             'head': _head(rp), 'value': value}, sender))
    return _sent(q)


def _only(sent, function):
    out = [m for m in sent if m.function == function]
    assert len(out) == 1, [m.function for m in sent]
    from autonomous_trust.core.config import from_json_string
    return from_json_string(out[0].obj)


class TestPromise:
    def test_the_next_index_is_granted_and_the_promise_kept(self, four):
        prop, acc = four[0], four[1]
        rp, q = _placing(acc, four)
        grant = _only(_ask(rp, q, prop), ReputationProtocol.place_grant)
        assert grant['ballot'] == {'n': 5, 'by': str(prop.uuid)}
        assert 'accepted' not in grant
        assert os.path.exists(rp._placement_path(''))

    def test_an_equal_or_lower_ballot_is_refused(self, four):
        prop, acc = four[0], four[1]
        rp, q = _placing(acc, four)
        _ask(rp, q, prop, n=5)
        nack = _only(_ask(rp, q, prop, n=5), ReputationProtocol.place_nack)
        assert nack['promised'] == {'n': 5, 'by': str(prop.uuid)}
        _only(_ask(rp, q, prop, n=4), ReputationProtocol.place_nack)

    def test_a_ballot_ties_on_n_by_proposer(self, four):
        a, b, acc = four[0], four[2], four[1]
        lo, hi = sorted((a, b), key=lambda m: str(m.uuid))
        rp, q = _placing(acc, four)
        _only(_ask(rp, q, lo, n=5), ReputationProtocol.place_grant)
        _only(_ask(rp, q, hi, n=5), ReputationProtocol.place_grant)
        _only(_ask(rp, q, lo, n=5), ReputationProtocol.place_nack)

    def test_another_index_or_head_is_refused(self, four):
        prop, acc = four[0], four[1]
        rp, q = _placing(acc, four)
        assert _only(_ask(rp, q, prop, k=1), ReputationProtocol.place_nack)['next'] == 0
        _only(_ask(rp, q, prop, head='ab' * 32), ReputationProtocol.place_nack)

    def test_a_ballot_must_be_its_senders(self, four):
        prop, acc, other = four[0], four[1], four[2]
        rp, q = _placing(acc, four)
        rp.handle_place_request(q, _msg(ReputationProtocol.place_request,
                                        {'group': '', 'k': 0, 'head': '',
                                         'ballot': {'n': 5, 'by': str(other.uuid)}},
                                        prop))
        assert _sent(q) == []

    def test_an_unverified_request_gets_no_answer(self, four):
        prop, acc = four[0], four[1]
        rp, q = _placing(acc, four)
        m = _msg(ReputationProtocol.place_request,
                 {'group': '', 'k': 0, 'head': '',
                  'ballot': {'n': 5, 'by': str(prop.uuid)}}, prop)
        m.verified = False
        rp.handle_place_request(q, m)
        assert _sent(q) == []


class TestAccept:
    def test_a_certified_value_is_accepted_and_signed(self, four):
        prop, acc = four[0], four[1]
        rp, q = _placing(acc, four)
        value = _value(_entry(four, four[2], four[3]))
        _ask(rp, q, prop)
        ok = _only(_place(rp, q, prop, value), ReputationProtocol.place_accepted)
        entries = [entry_from_dict(d) for d in value]
        digest = place_value_digest(entries, 0)
        assert ok['digest'] == digest.decode('ascii')
        assert rp._verify_cosignature(place_designation(0, b'', digest),
                                      str(acc.uuid), ok['sig'])

    def test_the_accepted_value_is_reported_to_a_higher_ballot(self, four):
        prop, acc, rival = four[0], four[1], four[2]
        rp, q = _placing(acc, four)
        value = _value(_entry(four, four[2], four[3]))
        _ask(rp, q, prop, n=5)
        _place(rp, q, prop, value, n=5)
        grant = _only(_ask(rp, q, rival, n=9), ReputationProtocol.place_grant)
        assert grant['accepted'] == {'ballot': {'n': 5, 'by': str(prop.uuid)},
                                     'value': value}

    def test_an_outranked_ballot_is_not_accepted(self, four):
        prop, acc, rival = four[0], four[1], four[2]
        rp, q = _placing(acc, four)
        _ask(rp, q, prop, n=5)
        _ask(rp, q, rival, n=9)
        sent = _place(rp, q, prop, _value(_entry(four, four[2], four[3])), n=5)
        _only(sent, ReputationProtocol.place_nack)

    @pytest.mark.parametrize('spoil', ['uncertified', 'order', 'unsorted',
                                       'held', 'unsigned', 'forged-half'])
    def test_an_invalid_value_is_not_accepted(self, four, spoil):
        prop, acc = four[0], four[1]
        rp, q = _placing(acc, four)
        e1 = _entry(four, four[2], four[3])
        e2 = _entry(four, four[0], four[3])
        value = _value(e1, e2)
        if spoil == 'uncertified':
            value[0].pop('p1_cert')
        elif spoil == 'order':
            d = value[0]
            d['p1'], d['p2'] = d['p2'], d['p1']
            d['p1_score_milli'], d['p2_score_milli'] = d['p2_score_milli'], d['p1_score_milli']
            d['p1_cert'], d['p2_cert'] = d['p2_cert'], d['p1_cert']
            d['p1_sig'], d['p2_sig'] = d['p2_sig'], d['p1_sig']
        elif spoil == 'unsorted':
            value.reverse()
        elif spoil == 'unsigned':
            # Certified by the majority, never signed by its scorer
            # (R+D.md §14.2).
            value[0].pop('p1_sig')
        elif spoil == 'forged-half':
            # The certifiers sign the half in the scorer's name.
            d, scorer = value[0], next(m for m in four
                                       if str(m.uuid) == value[0]['p1'])
            forger = next(m for m in four if str(m.uuid) not in
                          (d['p1'], d['p2']))
            other = next(m for m in four if str(m.uuid) == d['p2'])
            d['p1_sig'] = ReputationProcess._detached_sig(
                forger, half_designation(e1.task_id if str(e1.task_id) == d['task']
                                         else e2.task_id, scorer.uuid,
                                         other.uuid, d['p1_score_milli']))
        elif spoil == 'held':
            _pool(rp, e1)
            rp.history.apply_placed(0, rp.history.ready_items())
            value = _value(e1)
        _ask(rp, q, prop, k=rp.history.next_index)
        sent = _place(rp, q, prop, value, k=rp.history.next_index)
        assert not [m for m in sent if m.function == ReputationProtocol.place_accepted]

    def test_a_promise_survives_a_restart(self, four):
        prop, acc, rival = four[0], four[1], four[2]
        rp, q = _placing(acc, four)
        value = _value(_entry(four, four[2], four[3]))
        _ask(rp, q, prop, n=9)
        _place(rp, q, prop, value, n=9)
        again, q2 = _placing(acc, four)
        _only(_ask(again, q2, rival, n=8), ReputationProtocol.place_nack)
        grant = _only(_ask(again, q2, rival, n=10), ReputationProtocol.place_grant)
        assert grant['accepted']['value'] == value

    def test_an_unreadable_state_promises_nothing(self, four):
        """Treating a corrupt file as empty would forget a promise, which is
        exactly what an attacker would want. It is left alone and refused."""
        prop, acc = four[0], four[1]
        rp, q = _placing(acc, four)
        with open(rp._placement_path(''), 'w') as f:
            f.write('{not json')
        assert _ask(rp, q, prop) == []


def _placed(rp, q, sender, value, sigs, k=0):
    rp.handle_placed(q, _msg(ReputationProtocol.placed,
                             {'group': '', 'k': k, 'value': value,
                              'sigs': sigs}, sender))


def _certify(value, k, head, signers):
    entries = [entry_from_dict(d) for d in value]
    desig = place_designation(k, head, place_value_digest(entries, k))
    return {str(s.uuid): ReputationProcess._detached_sig(s, desig)
            for s in signers}


class TestLearn:
    def test_a_certified_placement_is_written(self, four):
        prop, obs = four[0], four[3]
        rp, q = _placing(obs, four)
        e = _entry(four, obs, four[1])
        rp.history.record_half(e.task_id, obs.uuid, 900)
        rp.awaiting_commit[str(e.task_id)] = [0.9, 0, 0, None, 0, 0]
        value = _value(e)
        _placed(rp, q, prop, value, _certify(value, 0, b'', four[:3]))
        assert [tx.task_id for tx in rp.history] == [e.task_id]
        assert rp.history.pooled(e.task_id) is None
        assert str(e.task_id) not in rp.awaiting_commit
        assert rp.history.placed_end == 1

    def test_a_placed_attestation_is_logged_and_brings_a_checkpoint_forward(
            self, four):
        # Placement completes an attested entry, so it does what a commit
        # does in a chain that does not place: the line cohorts watch for
        # (Stele rt-3700990 waited on it), and a checkpoint soon.
        from unittest.mock import MagicMock
        from autonomous_trust.core.reputation.reputation import (AttestedScore,
                                                                 attest_task_id)
        prop, ver, subj, obs = four
        rp, q = _placing(obs, four)
        rp._next_checkpoint_at = float('inf')
        rp.logger = MagicMock()
        digest = 'ab' * 32
        att = AttestedScore(verifier_uuid=str(ver.uuid), subject_uuid=str(subj.uuid),
                            score=0.3, evidence_digest=digest)
        sigs = {str(m.uuid): ReputationProcess._detached_sig(m, att.designation)
                for m in (ver, prop, obs)}
        tx = Transaction(attest_task_id(ver.uuid, subj.uuid, digest),
                         p1_id=ver.uuid, p1_score_milli=300, p1_channel='probe',
                         attested=True, subject_id=subj.uuid,
                         evidence_digest=digest, attest_sigs=sigs)
        value = _value(placement_entry(tx))
        _placed(rp, q, prop, value, _certify(value, 0, b'', four[:3]))
        assert [t.task_id for t in rp.history] == [tx.task_id]
        lines = [c.args[0] % c.args[1:] for c in rp.logger.info.call_args_list
                 if c.args[0].startswith('Attested score committed')]
        assert lines == ['Attested score committed: verifier=%s subject=%s '
                         'score=0.30 channel=probe signers=3 (index 0)'
                         % (str(ver.uuid)[:8], str(subj.uuid)[:8])]
        assert rp._next_checkpoint_at <= __import__('time').time() + \
            rp.ATTEST_CHECKPOINT_SEC + 1

    @pytest.mark.parametrize('spoil', ['sub-quorum', 'forged', 'other-head',
                                       'unsigned-half'])
    def test_an_uncertified_placement_is_refused(self, four, spoil):
        prop, obs = four[0], four[3]
        rp, q = _placing(obs, four)
        value = _value(_entry(four, four[1], four[2]))
        if spoil == 'unsigned-half':
            # Every member signed the placement and both certificates; the
            # scorer never signed its half. The majority's word is not its
            # (R+D.md §14.2).
            value[0].pop('p2_sig')
            sigs = _certify(value, 0, b'', four)
        elif spoil == 'sub-quorum':
            sigs = _certify(value, 0, b'', four[:2])
        elif spoil == 'forged':
            sigs = _certify(value, 0, b'', four[:3])
            sigs[str(four[2].uuid)] = sigs[str(four[1].uuid)]
        else:
            sigs = _certify(value, 0, b'ab' * 32, four[:3])
        _placed(rp, q, prop, value, sigs)
        assert len(rp.history) == 0

    def test_a_placement_ahead_waits_for_the_one_before_it(self, four):
        prop, obs = four[0], four[3]
        rp, q = _placing(obs, four)
        first = _value(_entry(four, four[1], four[2]))
        second = _value(_entry(four, four[0], four[1]))
        sigs1 = _certify(first, 0, b'', four[:3])
        # The second extends the chain the first makes.
        probe, _ = _placing(obs, four)
        probe.history.apply_placed(0, [entry_from_dict(d) for d in first])
        sigs2 = _certify(second, 1, probe.history.head_hash, four[:3])
        _placed(rp, q, prop, second, sigs2, k=1)
        assert len(rp.history) == 0
        _placed(rp, q, prop, first, sigs1, k=0)
        assert len(rp.history) == 2

    def test_a_placement_behind_the_chain_is_ignored(self, four):
        prop, obs = four[0], four[3]
        rp, q = _placing(obs, four)
        value = _value(_entry(four, four[1], four[2]))
        sigs = _certify(value, 0, b'', four[:3])
        _placed(rp, q, prop, value, sigs)
        _placed(rp, q, prop, value, sigs)
        assert len(rp.history) == 1


class TestWire:
    def test_an_entry_round_trips(self, four):
        e = _entry(four, four[0], four[1])
        back = entry_from_dict(entry_to_dict(e))
        assert back._canonical_bytes() == e._canonical_bytes()
        assert back.commit_sigs == e.commit_sigs

    def test_a_bad_channel_is_malformed(self, four):
        d = entry_to_dict(_entry(four, four[0], four[1]))
        d['p1_channel'] = 'no-such-channel'
        with pytest.raises(ValueError):
            entry_from_dict(d)

    def test_ballots_travel_as_objects(self):
        assert ballot_obj((3, 'ab')) == {'n': 3, 'by': 'ab'}


def _start(rp, q):
    """Open a round on the primary chain now; its request payload."""
    rp._start_place_round(q, '', rp.history)
    return _only(_sent(q), ReputationProtocol.place_request)


def _grant(rp, q, voter, req, accepted=None):
    payload = {'group': '', 'k': req['k'], 'ballot': req['ballot']}
    if accepted is not None:
        payload['accepted'] = accepted
    rp.handle_place_grant(q, _msg(ReputationProtocol.place_grant, payload, voter))
    return _sent(q)


def _pool(rp, e):
    for uid, score in ((e.p1_id, e.p1_score_milli), (e.p2_id, e.p2_score_milli)):
        rp.history.record_half(e.task_id, uid, score,
                               certificate=e.certificate_of(uid),
                               counterparty=e.counterparty_of(uid),
                               half_sig=e.half_sig_of(uid))


class TestPropose:
    def test_a_round_places_our_ready_items(self, four):
        me = four[0]
        rp, q = _placing(me, four)
        e = _entry(four, four[1], four[2])
        _pool(rp, e)
        req = _start(rp, q)
        assert _grant(rp, q, four[1], req) == []        # one grant: no majority
        place = _only(_grant(rp, q, four[2], req), ReputationProtocol.place)
        assert [d['task'] for d in place['value']] == [str(e.task_id)]
        entries = [entry_from_dict(d) for d in place['value']]
        desig = place_designation(0, b'', place_value_digest(entries, 0))
        for voter in four[1:3]:
            rp.handle_place_accepted(q, _msg(
                ReputationProtocol.place_accepted,
                {'group': '', 'k': 0, 'ballot': req['ballot'],
                 'digest': place_value_digest(entries, 0).decode('ascii'),
                 'sig': ReputationProcess._detached_sig(voter, desig)}, voter))
        _only(_sent(q), ReputationProtocol.placed)
        assert [tx.task_id for tx in rp.history] == [e.task_id]

    def test_a_reported_value_is_carried_instead_of_ours(self, four):
        me = four[0]
        rp, q = _placing(me, four)
        ours, theirs = _entry(four, four[1], four[2]), _entry(four, four[2], four[3])
        _pool(rp, ours)
        req = _start(rp, q)
        reported = {'ballot': {'n': 1, 'by': str(four[3].uuid).lower()},
                    'value': _value(theirs)}
        _grant(rp, q, four[1], req, accepted=reported)
        place = _only(_grant(rp, q, four[2], req), ReputationProtocol.place)
        assert place['value'] == _value(theirs)

    def test_a_nack_ends_the_round_and_the_next_outranks_it(self, four):
        me = four[0]
        rp, q = _placing(me, four)
        _pool(rp, _entry(four, four[1], four[2]))
        req = _start(rp, q)
        big = req['ballot']['n'] + 10 ** 6
        rp.handle_place_nack(q, _msg(ReputationProtocol.place_nack,
                                     {'group': '', 'k': 0, 'ballot': req['ballot'],
                                      'next': 0,
                                      'promised': {'n': big, 'by': str(four[3].uuid)}},
                                     four[1]))
        assert _grant(rp, q, four[2], req) == []
        assert _grant(rp, q, four[3], req) == []
        again = _start(rp, q)
        assert again['ballot']['n'] > big
