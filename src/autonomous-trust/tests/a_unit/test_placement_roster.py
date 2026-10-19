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
"""Roster entries: who the group is, recorded in the chain
(doc/architecture/reputation.md, "Who is in the group").

A roster entry has no scorer and no score. Its op (genesis, add, restate), the
member an add adds and the digest of its member list are in its hash; the
member list itself, [[uuid, signing key]], travels beside it and must
reproduce the digest. The bytes are pinned so the C twin
(src/c/test/rep_place_roster_test.c) produces exactly these.
"""
from uuid import UUID

import pytest

from autonomous_trust.core.config import from_json_string, to_json_string
from autonomous_trust.core.reputation.placement import (entry_from_dict,
                                                        entry_to_dict)
from autonomous_trust.core.reputation.reputation import (
    ROSTER_OPS, Transaction, TransactionHistory, evidence_from_dict,
    evidence_to_dict, roster_digest, roster_task_id)

A = 'aaaaaaaa-0000-4000-8000-000000000001'
B = 'bbbbbbbb-0000-4000-8000-000000000002'
C = 'cccccccc-0000-4000-8000-000000000003'
M2 = [[B, '22' * 32], [A, '11' * 32]]
M3 = M2 + [[C, '33' * 32]]

D2 = 'c02c382b7ab59e73d577c48f3bf8b6bd8f4e010f2fd2787498004e95516fd86a'
T0 = UUID('65c0a743-5641-5b6b-b79d-d5c8a4646039')
G_HASH = b'02a57fe42cfda395872b38d4420e7d6857dd8dccb31d39e6c4f112cd7d7ce279'
D3 = '021d352cc8ff94765e2db73afe2d7b5e6e0a6ab9800a728482a031cc266e23bd'
T1 = UUID('f4076c8e-4a9d-50bd-9575-990b0a9ad5f1')
A_HASH = b'fd4ebd9e23c3c0299abb0b46eebaf08b2c7ab8805021d7d166cbcfdde908da90'


def _genesis():
    return Transaction(T0, roster_op='genesis', roster_digest=D2,
                       roster_members=M2, index=0, prev_hash=b'')


def _add():
    return Transaction(T1, roster_op='add', roster_uuid=UUID(C),
                       roster_digest=D3, roster_members=M3, index=1,
                       prev_hash=G_HASH)


class TestPinned:
    def test_the_digest_and_task_are_pinned(self):
        assert roster_digest(M2) == D2
        assert roster_digest(list(reversed(M2))) == D2      # order-free
        assert roster_task_id(None, 'genesis', None, D2) == T0
        assert roster_digest(M3) == D3
        assert roster_task_id(T0, 'add', C, D3) == T1

    def test_the_entry_bytes_are_pinned(self):
        assert _genesis()._canonical_bytes() == (
            str(T0) + '|null|null|null|null|0|roster|genesis|null|' + D2).encode()
        assert _genesis().entry_hash() == G_HASH
        assert _add()._canonical_bytes() == (
            str(T1) + '|null|null|null|null|1|roster|add|' + C + '|' + D3).encode()
        assert _add().entry_hash() == A_HASH

    def test_the_member_list_is_outside_the_hash(self):
        tx = _genesis()
        tx.roster_members = None
        assert tx.entry_hash() == G_HASH


class TestShape:
    def test_a_bad_list_or_op_is_refused(self):
        with pytest.raises(ValueError):
            roster_digest([])
        with pytest.raises(ValueError):
            roster_digest([[A, '11' * 32], [A, '22' * 32]])
        with pytest.raises(ValueError):
            roster_digest([[A, 'zz' * 32]])
        with pytest.raises(ValueError):
            Transaction(T0, roster_op='remove')
        assert ROSTER_OPS == ('genesis', 'add', 'restate')

    def test_it_scores_nobody(self):
        tx = _genesis()
        assert tx.is_roster and len(tx) == 0
        assert tx.about(UUID(A)) is None

    def test_the_placement_wire_round_trips_and_checks_the_digest(self):
        d = entry_to_dict(_add())
        assert d['roster']['op'] == 'add' and d['roster']['uuid'] == C
        back = entry_from_dict(d)
        back.index, back.prev_hash = 1, G_HASH
        assert back.entry_hash() == A_HASH
        d['roster']['members'] = M2
        with pytest.raises(ValueError):
            entry_from_dict(d)

    def test_the_catchup_wire_round_trips(self):
        back = from_json_string(to_json_string([_genesis(), _add()]))
        assert [t.entry_hash() for t in back] == [G_HASH, A_HASH]
        assert back[1].roster_members == [list(m) for m in sorted(map(tuple, M3))]
        plain = Transaction(T0, p1_id=UUID(A), p1_score=0.5)
        assert 'roster_op' not in plain.to_dict()

    def test_evidence_round_trips_and_checks_the_digest(self):
        doc = evidence_to_dict([_genesis(), _add()])
        chain, _ = evidence_from_dict(doc)
        assert [t.entry_hash() for t in chain] == [G_HASH, A_HASH]
        doc['chain'][1]['roster_members'] = M2
        with pytest.raises(ValueError):
            evidence_from_dict(doc)

    def test_a_history_takes_a_chain_holding_one(self):
        hist = TransactionHistory()
        res = hist.reconcile([_genesis(), _add()])
        assert res.status == 'extended'
        assert hist.next_index == 2 and hist.head_hash == A_HASH


class TestRosterAt:
    def _placed(self, cap=None):
        """genesis at 0, an ordinary task at 1, the add at 2."""
        hist = TransactionHistory(max_chain_len=cap)
        g = Transaction(T0, roster_op='genesis', roster_digest=D2, roster_members=M2)
        assert hist.apply_placed(0, [g]) == 'applied'
        tx = Transaction(UUID(int=7), p1_id=UUID(A), p1_score=0.5,
                         p2_id=UUID(B), p2_score=0.6)
        assert hist.apply_placed(1, [tx]) == 'applied'
        a = Transaction(T1, roster_op='add', roster_uuid=UUID(C),
                        roster_digest=D3, roster_members=M3)
        assert hist.apply_placed(2, [a]) == 'applied'
        return hist

    def test_the_roster_in_force_is_the_last_below(self):
        hist = self._placed()
        assert hist.roster_at(0) is None
        assert hist.roster_at(1).task_id == T0
        assert hist.roster_at(2).task_id == T0
        assert hist.roster_at(3).task_id == T1
        assert hist.latest_roster().roster_members == [list(m) for m in
                                                       sorted(map(tuple, M3))]
        assert hist.head_hash == hist._chain[-1].entry_hash()

    def test_it_travels_with_a_reconciled_chain(self):
        other = TransactionHistory()
        other.reconcile(list(self._placed()))
        assert other.latest_roster().task_id == T1
        assert other.roster_at(2).roster_members is not None

    def test_one_evicted_from_the_window_is_gone(self):
        hist = self._placed(cap=1)
        assert hist.roster_at(3).task_id == T1
        tx = Transaction(UUID(int=8), p1_id=UUID(A), p1_score=0.5,
                         p2_id=UUID(B), p2_score=0.6)
        hist.apply_placed(3, [tx])
        assert hist.latest_roster() is None      # restatement's job to prevent


# --- 7.3: placements and certificates judged by the logged roster ----------

from uuid import uuid4  # noqa: E402

from nacl.encoding import HexEncoder  # noqa: E402

from autonomous_trust.core.reputation.reputation import (  # noqa: E402
    commit_designation, place_designation, place_value_digest)
from autonomous_trust.core.reputation.repprocess import ReputationProcess  # noqa: E402
from tests.a_unit.test_commit_certificates import _ident, _node  # noqa: E402


def _key(ident):
    return ident.signature.public.encode(encoder=HexEncoder).decode('ascii')


def _roster_of(idents, op='genesis'):
    members = [[str(i.uuid), _key(i)] for i in idents]
    d = roster_digest(members)
    return Transaction(roster_task_id(None, op, None, d), roster_op=op,
                       roster_digest=d, roster_members=members)


def _half_cert(signers, scorer, task, score):
    return {str(s.uuid): ReputationProcess._detached_sig(
        s, commit_designation(scorer.uuid, task, score)) for s in signers}


class TestJudgedByRoster:
    """ada learns dee's placement at 1 after adding bob: her live view is
    {dee, amy, bob} (a majority of four is three), but instance 1 belongs to
    the roster logged at 0, {ada, dee, amy}, so dee's and ada's signatures are
    a majority (part-3546034, in one step)."""

    def _setup(self, roster_idents=None):
        ada, dee, amy, bob = (_ident('ada', 1), _ident('dee', 2),
                              _ident('amy', 3), _ident('bob', 4))
        rp, q = _node(ada, [dee, amy, bob])
        roster = _roster_of(roster_idents or [ada, dee, amy])
        assert rp.history.apply_placed(0, [roster]) == 'applied'
        t = uuid4()
        entry = Transaction(t, p1_id=dee.uuid, p1_score=0.9, p2_id=amy.uuid,
                            p2_score=0.8,
                            commit_sigs={str(dee.uuid): _half_cert([ada], dee, t, 0.9),
                                         str(amy.uuid): _half_cert([ada], amy, t, 0.8)})
        from autonomous_trust.core.reputation.reputation import placement_entry
        entries = [placement_entry(entry)]
        desig = place_designation(1, rp.history.head_hash,
                                  place_value_digest(entries, 1))
        return rp, (ada, dee, amy, bob), entries, desig

    def _sigs(self, desig, *who):
        return {str(i.uuid): ReputationProcess._detached_sig(i, desig) for i in who}

    def test_a_majority_of_the_logged_roster_carries_it(self):
        rp, (ada, dee, amy, bob), entries, desig = self._setup()
        assert rp._apply_placement(rp.history, '', 1, entries,
                                   self._sigs(desig, dee, ada), None)
        assert rp.history.next_index == 2

    def test_the_live_view_alone_would_have_refused_it(self):
        rp, (ada, dee, amy, bob), entries, desig = self._setup()
        assert not rp._placement_certified(rp.history, 1, entries,
                                           self._sigs(desig, dee, ada), None,
                                           roster=None)

    def test_a_signer_outside_the_roster_is_not_counted(self):
        rp, (ada, dee, amy, bob), entries, desig = self._setup()
        assert not rp._apply_placement(rp.history, '', 1, entries,
                                       self._sigs(desig, dee, bob), None)

    def test_a_departed_members_signature_still_counts(self):
        # ada's roster lists `gone`, whom she no longer sees: its key comes
        # from the log, so its signature still verifies.
        rp, (ada, dee, amy, bob), entries, _desig = self._setup()
        gone = _ident('gone', 9)
        rp3, _q = _node(ada, [dee, amy])
        rp3.history.apply_placed(0, [_roster_of([ada, dee, gone])])
        desig = place_designation(1, rp3.history.head_hash,
                                  place_value_digest(entries, 1))
        assert rp3._placement_certified(rp3.history, 1, entries,
                                        self._sigs(desig, gone, ada), None)

    def test_a_halfs_certificate_is_judged_by_the_roster_in_force(self):
        rp, (ada, dee, amy, bob), entries, desig = self._setup()
        # One co-signature a half: a majority of the roster of three with
        # its scorer, short of the live view's four.
        assert rp._place_value_ok(entries, rp.history, None) is None
        assert not rp._commit_cert_ok(dee.uuid, entries[0].task_id, 0.9, None,
                                      entries[0].certificate_of(dee.uuid),
                                      roster=None)


# --- 7.4: the acceptor's rules for roster entries ---------------------------

class TestRosterValue:
    def _acceptor(self, peers=3, roster=True):
        me = _ident('me', 1)
        others = [_ident('o%d' % i, i + 2) for i in range(peers)]
        rp, _q = _node(me, others)
        if roster:
            rp.history.apply_placed(0, [_roster_of([me] + others[:2])])
        return rp, me, others

    def _add(self, rp, who, key=None):
        r = rp.history.latest_roster()
        members = list(map(list, r.roster_members)) + [[str(who.uuid), key or _key(who)]]
        d = roster_digest(members)
        return Transaction(roster_task_id(r.task_id, 'add', str(who.uuid), d),
                           roster_op='add', roster_uuid=who.uuid,
                           roster_digest=d, roster_members=members)

    def test_a_genesis_within_our_view_is_accepted(self):
        rp, me, others = self._acceptor(roster=False)
        assert rp._place_value_ok([_roster_of([me, others[0]])], rp.history, None) is None

    def test_a_genesis_naming_a_stranger_or_leaving_us_out_is_refused(self):
        rp, me, others = self._acceptor(roster=False)
        stranger = _ident('x', 9)
        assert rp._place_value_ok([_roster_of([me, stranger])], rp.history, None)
        assert rp._place_value_ok([_roster_of(others)], rp.history, None)

    def test_an_add_of_a_member_we_see_is_accepted(self):
        rp, me, others = self._acceptor()
        assert rp._place_value_ok([self._add(rp, others[2])], rp.history, None) is None

    def test_an_add_of_someone_we_do_not_see_is_refused(self):
        rp, me, others = self._acceptor()
        assert rp._place_value_ok([self._add(rp, _ident('x', 9))], rp.history, None)

    def test_an_add_with_another_key_is_refused(self):
        rp, me, others = self._acceptor()
        assert rp._place_value_ok([self._add(rp, others[2], '77' * 32)],
                                  rp.history, None)

    def test_a_roster_entry_is_placed_alone(self):
        rp, me, others = self._acceptor()
        t = uuid4()
        tx = Transaction(t, p1_id=me.uuid, p1_score=0.9, p2_id=others[0].uuid,
                         p2_score=0.8)
        assert rp._place_value_ok([self._add(rp, others[2]), tx], rp.history, None)

    def test_an_early_restatement_and_a_wrong_task_are_refused(self):
        rp, me, others = self._acceptor()
        r = rp.history.latest_roster()
        early = Transaction(roster_task_id(r.task_id, 'restate', None, r.roster_digest),
                            roster_op='restate', roster_digest=r.roster_digest,
                            roster_members=r.roster_members)
        assert rp._place_value_ok([early], rp.history, None) == 'a restatement too early'
        wrong = self._add(rp, others[2])
        wrong.task_id = uuid4()
        assert rp._place_value_ok([wrong], rp.history, None)

    def test_a_genesis_needs_every_member_it_lists(self):
        rp, me, others = self._acceptor(roster=False)
        g = _roster_of([me, others[0], others[1]])
        desig = place_designation(0, b'', place_value_digest([g], 0))
        two = {str(i.uuid): ReputationProcess._detached_sig(i, desig)
               for i in (me, others[0])}
        assert not rp._placement_certified(rp.history, 0, [g], two, None)
        two[str(others[1].uuid)] = ReputationProcess._detached_sig(others[1], desig)
        assert rp._placement_certified(rp.history, 0, [g], two, None)


# --- 7.5: the newcomer's anchor ----------------------------------------------

from types import SimpleNamespace  # noqa: E402


def _place(hist, k, entry, signers):
    """Write `entry` at k with a placement certificate by `signers`."""
    from autonomous_trust.core.reputation.reputation import placement_entry
    e = placement_entry(entry)
    desig = place_designation(k, hist.head_hash, place_value_digest([e], k))
    hist.apply_placed(k, [e], {str(s.uuid): ReputationProcess._detached_sig(s, desig)
                               for s in signers})


def _add_of(hist, who, key=None):
    r = hist.latest_roster()
    members = list(map(list, r.roster_members)) + [[str(who.uuid), key or _key(who)]]
    d = roster_digest(members)
    return Transaction(roster_task_id(r.task_id, 'add', str(who.uuid), d),
                       roster_op='add', roster_uuid=who.uuid,
                       roster_digest=d, roster_members=members)


class TestAnchor:
    """d, new to the group {a, b, c}, catches up: it knows no roster of the
    chain, so it anchors on the segment's latest roster entry -- the add of d
    itself -- judged by the group as identity shows it."""

    def _group(self):
        a, b, c, d = (_ident(n, i) for i, n in enumerate('abcd', start=1))
        src = TransactionHistory()
        _place(src, 0, _roster_of([a, b, c]), [a, b, c])
        t = uuid4()
        _place(src, 1, Transaction(t, p1_id=a.uuid, p1_score=0.9, p2_id=b.uuid,
                                   p2_score=0.8), [a, b])
        _place(src, 2, _add_of(src, d), [a, b])
        rp, _q = _node(d, [a, b, c])
        return rp, src, (a, b, c, d)

    MSG = SimpleNamespace(from_whom=SimpleNamespace(nickname='a'))

    def test_a_newcomer_adopts_the_history_its_group_signed(self):
        rp, src, _who = self._group()
        seg = list(src)
        assert rp._chain_certified(seg, self.MSG)
        rp._reconcile_into(None, '', seg, 'a')
        assert rp.history.next_index == 3
        assert rp.history.latest_roster().roster_op == 'add'

    def test_a_history_only_an_insider_signed_is_refused(self):
        rp, src, (a, b, c, d) = self._group()
        fake = TransactionHistory()
        _place(fake, 0, _roster_of([a, b, c]), [a, b, c])
        _place(fake, 1, _add_of(fake, d), [a])         # a alone: no majority
        assert not rp._chain_certified(list(fake), self.MSG)

    def test_a_roster_two_members_from_our_view_is_refused(self):
        rp, src, (a, b, c, d) = self._group()
        x, y = _ident('x', 8), _ident('y', 9)
        other = TransactionHistory()
        _place(other, 0, _roster_of([a, b, x, y]), [a, b, x, y])
        _place(other, 1, _add_of(other, d), [a, b, x])
        assert not rp._chain_certified(list(other), self.MSG)


# --- 7.6: before a roster, nothing; chains from before rosters reset --------

class TestBeforeTheRoster:
    def _node(self, tmp_path):
        me, a, b = _ident('me', 1), _ident('a', 2), _ident('b', 3)
        rp, _q = _node(me, [a, b])
        rp._placement_path = lambda key: str(tmp_path / ('placement-%s' % (key or 'p')))
        rp._pool_path = lambda key: str(tmp_path / ('pool-%s' % (key or 'p')))
        return rp, (me, a, b)

    def test_nothing_but_a_genesis_is_accepted_before_a_roster(self, tmp_path):
        rp, (me, a, b) = self._node(tmp_path)
        t = uuid4()
        tx = Transaction(t, p1_id=a.uuid, p1_score=0.9, p2_id=b.uuid, p2_score=0.8)
        assert rp._place_value_ok([tx], rp.history, None) == \
            'nothing is placed before the genesis'

    def test_a_chain_from_before_rosters_is_reset_at_boot(self, tmp_path):
        rp, (me, a, b) = self._node(tmp_path)
        t = uuid4()
        rp.history.update(t, a.uuid, 0.9)
        rp.history.update(t, b.uuid, 0.8)
        for path in (rp._placement_path(''), rp._pool_path('')):
            open(path, 'w').write('{}')
        assert rp._reset_pre_roster_chain('')
        assert len(rp.history) == 0
        assert not (tmp_path / 'placement-p').exists()
        assert not (tmp_path / 'pool-p').exists()

    def test_a_chain_with_a_roster_is_kept(self, tmp_path):
        rp, (me, a, b) = self._node(tmp_path)
        rp.history.apply_placed(0, [_roster_of([me, a, b])])
        assert not rp._reset_pre_roster_chain('')
        assert len(rp.history) == 1
