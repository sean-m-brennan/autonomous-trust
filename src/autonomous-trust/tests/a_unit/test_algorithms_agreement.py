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
import pytest
from uuid import uuid4
from unittest.mock import MagicMock

from autonomous_trust.core.algorithms.agreement import (
    AgreementProof, AgreementVoter, VoterTracker, AgreementProtocol,
)
from autonomous_trust.core.structures.merkle import SimplestBlob


class ConcreteVoter(AgreementVoter):
    def __init__(self, _uuid, _rank, _tier=0):
        super().__init__(_uuid, _rank, _tier=_tier)

    def verify(self, *args, **kwargs):
        # Accept both legacy (proof, sig) and SignedMessage-style (smessage)
        # call conventions; AgreementProtocol.finalize was updated to pass
        # the latter to align with Identity.verify.
        return True


class ConcreteBlob(SimplestBlob):
    def __init__(self, originator, data=b'test', uuid=None):
        super().__init__(originator, uuid)
        self.data = data

    @property
    def designation(self):
        return self.data


class ConcreteAgreementProtocol(AgreementProtocol):
    def _pre_verify(self, blob, proof, sig):
        return True

    def _count_vote(self, blob, proof, voter):
        return proof.approval

    def _accumulate_votes(self, votes):
        return sum(votes) > len(votes) / 2


class TestAgreementProof:
    def test_init(self):
        uid = uuid4()
        proof = AgreementProof(uid, b'digest', True, nonce=b'nonce')
        assert proof.uuid == uid
        assert proof.digest == b'digest'
        assert proof.approval is True
        assert proof.nonce == b'nonce'

    def test_bytes(self):
        uid = uuid4()
        proof = AgreementProof(uid, b'digest', True, nonce=b'nonce')
        b = bytes(proof)
        assert isinstance(b, bytes)
        assert len(b) > 0


class TestAgreementVoter:
    def test_properties(self):
        uid = uuid4()
        voter = ConcreteVoter(uid, 5)
        assert voter.uuid == uid
        assert voter.rank == 5


class TestAgreementVoterEffectiveRank:
    """Dynamic topology-rank source (deferred.md §2.2): operational rank =
    signed rank + one-hop-reachability adjustment, floored at 0."""

    def test_effective_rank_defaults_to_signed(self):
        v = ConcreteVoter(uuid4(), 5)
        assert v.effective_rank == 5 and v.rank == 5

    def test_observe_unreachable_demotes_to_zero(self):
        v = ConcreteVoter(uuid4(), 5)
        assert v.observe_reachability(False) is True
        assert v.effective_rank == 0
        assert v.rank == 5  # signed baseline untouched

    def test_observe_reachable_restores(self):
        v = ConcreteVoter(uuid4(), 5)
        v.observe_reachability(False)
        assert v.observe_reachability(True) is True
        assert v.effective_rank == 5

    def test_observe_idempotent_returns_false(self):
        v = ConcreteVoter(uuid4(), 5)
        assert v.observe_reachability(True) is False  # already reachable

    def test_set_and_reset_adjustment_floors_at_zero(self):
        v = ConcreteVoter(uuid4(), 5)
        v.set_rank_adjustment(-2)
        assert v.effective_rank == 3
        v.set_rank_adjustment(-100)
        assert v.effective_rank == 0  # floored, never negative
        v.reset_rank_adjustment()
        assert v.effective_rank == 5


class TestAuthorityEffectiveRank:
    """Authority voting keys off effective_rank, so a peer that loses one-hop
    reachability drops out of the cutoff / leadership (deferred.md §2.2)."""

    def _build(self, ranks):
        from autonomous_trust.core.algorithms.authority import AgreementByAuthority

        class _Probe(AgreementByAuthority):
            def _pre_verify(self, blob, proof, sig):
                return True

        voters = [ConcreteVoter(uuid4(), r) for r in ranks]
        return _Probe(voters[0], voters[1:], threshold_rank=None), voters

    def test_threshold_uses_effective_rank(self):
        proto, voters = self._build([6, 0, 0])
        assert proto.threshold_rank == 6           # derived from [6,0,0]
        voters[0].observe_reachability(False)       # gateway loss on the top
        assert proto.threshold_rank == 0            # now [0,0,0]

    def test_leader_changes_when_demoted(self):
        proto, voters = self._build([6, 3, 0])
        assert max(v.effective_rank for v in proto.voters) == 6
        voters[0].observe_reachability(False)
        assert max(v.effective_rank for v in proto.voters) == 3

    def test_count_vote_returns_effective_rank_key(self):
        proto, voters = self._build([6, 0])
        voters[0].observe_reachability(False)       # demote the leader to 0
        proof = MagicMock()
        proof.approval = True
        rank_key, approval = proto._count_vote(None, proof, voters[0])
        # key is the effective rank (0), so the demoted peer can no longer be
        # the leader in _accumulate_votes.
        assert rank_key == 0


class TestVoterTracker:
    def test_init(self):
        voter = ConcreteVoter(uuid4(), 1)
        # Can't instantiate VoterTracker directly (ABC), but via subclass
        proto = ConcreteAgreementProtocol(voter, [])
        assert proto.myself is voter


class TestAgreementProtocol:
    def _make_protocol(self, n_voters=3):
        myself = ConcreteVoter(uuid4(), 1)
        others = [ConcreteVoter(uuid4(), i) for i in range(n_voters - 1)]
        return ConcreteAgreementProtocol(myself, others)

    def test_init(self):
        proto = self._make_protocol(3)
        assert len(proto.voters) == 3
        assert proto._votes == {}

    def test_prove(self):
        proto = self._make_protocol()
        blob = ConcreteBlob(uuid4())
        proof = proto.prove(blob)
        assert isinstance(proof, AgreementProof)
        assert proof.approval is True
        assert proof.uuid == proto.myself.uuid

    def test_verify(self):
        proto = self._make_protocol()
        blob = ConcreteBlob(uuid4())
        proof = AgreementProof(proto.voters[0].uuid, blob.get_hash(), True, nonce=b'\x00')
        result = proto.verify(blob, proof, b'sig')
        assert result is True
        assert blob.uuid in proto._votes

    def test_finalize_originator(self):
        proto = self._make_protocol()
        blob = ConcreteBlob(proto.myself.uuid)
        assert proto.finalize(blob) is True

    def test_finalize_no_votes(self):
        proto = self._make_protocol()
        blob = ConcreteBlob(uuid4())
        assert proto.finalize(blob) is False

    def test_finalize_with_votes(self):
        proto = self._make_protocol(3)
        blob = ConcreteBlob(uuid4())
        # Add approving votes from all voters
        for voter in proto.voters:
            proof = AgreementProof(voter.uuid, blob.get_hash(), True, nonce=b'\x00')
            proto.verify(blob, proof, b'sig')
        result = proto.finalize(blob)
        assert result is True

    def test_finalize_with_rejections(self):
        proto = self._make_protocol(3)
        blob = ConcreteBlob(uuid4())
        # Add rejecting votes
        for voter in proto.voters:
            proof = AgreementProof(voter.uuid, blob.get_hash(), False, nonce=b'\x00')
            proto.verify(blob, proof, b'sig')
        result = proto.finalize(blob)
        assert result is False


class TestAgreementVoterVerify:
    """Cover the abstract verify() return value on AgreementVoter."""

    def test_verify_returns_false_base(self):
        """Calling the super().verify() of the concrete subclass returns True (concrete impl)."""
        uid = uuid4()
        voter = ConcreteVoter(uid, 1)
        # ConcreteVoter.verify always returns True
        proof = MagicMock()
        assert voter.verify(proof, b'sig') is True


class TestAgreementPreVerifyFalse:
    """Cover the _pre_verify False path in AgreementProtocol.verify()."""

    def test_verify_returns_false_when_pre_verify_fails(self):
        """When _pre_verify returns False, verify() returns False without adding to _votes."""

        class RejectingProtocol(AgreementProtocol):
            def _pre_verify(self, blob, proof, sig):
                return False

            def _count_vote(self, blob, proof, voter):
                return False

            def _accumulate_votes(self, votes):
                return False

        myself = ConcreteVoter(uuid4(), 1)
        proto = RejectingProtocol(myself, [])
        blob = ConcreteBlob(uuid4())
        proof = AgreementProof(myself.uuid, blob.get_hash(), True)
        result = proto.verify(blob, proof, b'sig')
        assert result is False
        assert blob.uuid not in proto._votes


class TestAgreementFinalizeUnknownVoter:
    """finalize() skips votes whose proof.uuid is not in the voters dict."""

    def test_finalize_skips_unknown_voter_uuid(self):
        proto = ConcreteAgreementProtocol(ConcreteVoter(uuid4(), 1), [])
        blob = ConcreteBlob(uuid4())
        # Manually inject a vote with an unknown voter uuid
        stranger_uuid = uuid4()
        proof = AgreementProof(stranger_uuid, blob.get_hash(), True)
        proto._votes[blob.uuid] = [(blob, proof, b'sig')]
        # finalize() will try to look up stranger_uuid in voters dict, not find it, skip
        # Then _accumulate_votes([]) → sum([]) > 0/2 → False
        result = proto.finalize(blob)
        assert result is False


class TestAgreementProofNoneNonce:
    """Cover AgreementProof bytes conversion path with a None nonce.

    Originally the path raised TypeError ("can't concat NoneType to bytes")
    when nonce defaulted to None. __bytes__ now treats None as the empty
    byte string so callers don't have to defend against the default.
    """

    def test_bytes_with_none_nonce_ok(self):
        uid = uuid4()
        proof = AgreementProof(uid, b'digest', True, nonce=None)
        b = bytes(proof)
        assert isinstance(b, bytes)
        # uuid (36) + digest (6) + bytes(True) (1) + nonce (0) == 43
        assert len(b) == 43

    def test_bytes_with_none_digest_ok(self):
        uid = uuid4()
        proof = AgreementProof(uid, None, False, nonce=None)
        b = bytes(proof)
        assert isinstance(b, bytes)
        # uuid (36) + digest (0) + bytes(False) (0) + nonce (0) == 36
        assert len(b) == 36


class TestAgreementImplEnum:
    """Cover algorithms/impl.py AgreementImpl enum."""

    def test_impl_values(self):
        from autonomous_trust.core.algorithms.impl import AgreementImpl
        assert str(AgreementImpl.POW) == 'work'
        assert str(AgreementImpl.POS) == 'stake'
        assert str(AgreementImpl.POA) == 'authority'

    def test_impl_str(self):
        from autonomous_trust.core.algorithms.impl import AgreementImpl
        assert AgreementImpl.POW == 'work'
        assert AgreementImpl.POS == 'stake'
        assert AgreementImpl.POA == 'authority'

    def test_impl_enum_members(self):
        from autonomous_trust.core.algorithms.impl import AgreementImpl
        members = list(AgreementImpl)
        assert len(members) == 3


class TestAuthorityAccumulateLeaderAbstains:
    """Regression coverage for BUGS.md P4 (POA finalize with absent leader).

    Before the 2026-05-11 fix, AgreementByAuthority._accumulate_votes called
    dict(votes)[leader] unconditionally — when the highest-ranked voter
    had not actually cast a vote (network drop, slow peer, etc.), Python
    raised KeyError. The C side handled the same case by falling through
    to return False ("no leader vote → not approved"). The asymmetry was
    surfaced by the agreement/poa-leader-abstains conformance scenario.
    """

    def _build_protocol(self, voter_ranks):
        """Construct a minimal AgreementByAuthority-style protocol via
        ConcreteAgreementProtocol-style subclassing of authority.

        Avoids the full Identity/PyNaCl stack — just enough plumbing to
        invoke _accumulate_votes directly.
        """
        from autonomous_trust.core.algorithms.authority import AgreementByAuthority

        class _Probe(AgreementByAuthority):
            def _pre_verify(self, blob, proof, sig):
                return True

        voters = []
        for idx, rank in enumerate(voter_ranks):
            voters.append(ConcreteVoter(uuid4(), rank))
        if not voters:
            raise ValueError("need at least one voter")
        return _Probe(voters[0], voters[1:], threshold_rank=0)

    def test_leader_abstain_returns_false(self):
        # voters: ranks 5 (leader, absent) and 0 (present).
        proto = self._build_protocol([5, 0])
        # _accumulate_votes receives the list returned by _count_vote
        # across all (proof, voter) pairs. authority's _count_vote
        # returns (rank, approval). Only rank=0 voted here:
        result = proto._accumulate_votes([(0, True)])
        assert result is False, (
            "leader (rank 5) didn't vote → finalize must return False, "
            "not raise KeyError"
        )

    def test_no_votes_returns_false(self):
        # Pathological: no voter cast anything. Same expectation.
        proto = self._build_protocol([5, 0])
        assert proto._accumulate_votes([]) is False

    def test_leader_present_decides(self):
        # Sanity: when the leader DID vote, their verdict still drives
        # the outcome (the fix mustn't have weakened the leader-decides
        # semantics).
        proto = self._build_protocol([5, 0])
        assert proto._accumulate_votes([(5, True), (0, False)]) is True
        assert proto._accumulate_votes([(5, False), (0, True)]) is False

    def test_tied_leaders_split_rejects_in_either_order(self):
        # RD_13.1 D7: tied leaders combine by conjunction. A dict lookup
        # kept the last vote at the leader rank, so the outcome flipped
        # with arrival order (and C, which kept the first, disagreed).
        proto = self._build_protocol([5, 5, 0])
        assert proto._accumulate_votes([(5, True), (5, False)]) is False
        assert proto._accumulate_votes([(5, False), (5, True)]) is False

    def test_tied_leaders_all_approve(self):
        proto = self._build_protocol([5, 5, 0])
        assert proto._accumulate_votes([(5, True), (5, True), (0, False)]) is True

    def test_tied_leader_abstains_other_decides(self):
        # Conjunction is over tied leaders who VOTED; one tied leader's
        # silence does not veto.
        proto = self._build_protocol([5, 5, 0])
        assert proto._accumulate_votes([(5, True)]) is True


class TestAgreementByTrust:
    """PoT is a strict majority of eligible voters (tier >= threshold),
    with abstention counted against and no leader (RD_13.1).
    See doc/architecture/trust-tiers.md §10."""

    def _build_protocol(self, voter_tiers, threshold_tier=None):
        from autonomous_trust.core.algorithms.trust import AgreementByTrust

        class _Probe(AgreementByTrust):
            def _pre_verify(self, blob, proof, sig):
                return True

        voters = []
        for tier in voter_tiers:
            voters.append(ConcreteVoter(uuid4(), 0, _tier=tier))
        if not voters:
            raise ValueError("need at least one voter")
        return _Probe(voters[0], voters[1:], threshold_tier=threshold_tier)

    def test_voter_tier_property(self):
        v = ConcreteVoter(uuid4(), 1, _tier=3)
        assert v.tier == 3
        # default
        v2 = ConcreteVoter(uuid4(), 1)
        assert v2.tier == 0

    def test_explicit_threshold_wins(self):
        proto = self._build_protocol([4, 2, 1], threshold_tier=5)
        assert proto.threshold_tier == 5

    def test_derived_threshold_is_default_floor(self):
        # No top-third derivation any more: the default is a fixed floor,
        # whatever the tier distribution.
        proto = self._build_protocol([4, 4, 3, 2, 1, 0])
        assert proto.threshold_tier == 1
        assert proto.threshold_tier == proto.DEFAULT_THRESHOLD_TIER

    def test_count_vote_reports_cast_vote(self):
        # _count_vote no longer filters; eligibility is applied in
        # _accumulate_votes, which needs the threshold for the eligible set.
        proto = self._build_protocol([2, 1], threshold_tier=3)
        voter = next(v for v in proto.voters if v.tier == 2)
        assert proto._count_vote(MagicMock(), MagicMock(approval=True), voter) == (2, True)
        assert proto._count_vote(MagicMock(), MagicMock(approval=False), voter) == (2, False)

    def test_climbed_top_tier_is_outvoted(self):
        # The case RD_13.1 exists for: the unique top-tier voter rejects,
        # three of the other four eligible voters approve.
        proto = self._build_protocol([4, 2, 2, 1, 1])
        votes = [(4, False), (2, True), (2, True), (1, True)]
        assert proto._accumulate_votes(votes) is True

    def test_top_tier_alone_cannot_approve(self):
        proto = self._build_protocol([4, 2, 2, 1, 1])
        assert proto._accumulate_votes([(4, True)]) is False

    def test_tie_rejects(self):
        proto = self._build_protocol([3, 2, 2, 1])
        assert proto._accumulate_votes([(3, True), (2, True), (2, False), (1, False)]) is False

    def test_abstention_counts_against(self):
        # 2 of 5 eligible approve, the rest silent: not a majority.
        proto = self._build_protocol([1, 1, 1, 1, 1])
        assert proto._accumulate_votes([(1, True), (1, True)]) is False
        assert proto._accumulate_votes([(1, True), (1, True), (1, True)]) is True

    def test_below_threshold_votes_dropped_not_nay(self):
        # Two eligible voters (tier >= 3) both approve; the tier-1 nays
        # neither count against nor enlarge the eligible set.
        proto = self._build_protocol([3, 3, 1, 1, 1], threshold_tier=3)
        votes = [(3, True), (3, True), (1, False), (1, False), (1, False)]
        assert proto._accumulate_votes(votes) is True
        # Below-threshold approvals do not help either.
        assert proto._accumulate_votes([(3, True), (1, True), (1, True)]) is False

    def test_zero_eligible_returns_false(self):
        proto = self._build_protocol([2, 1], threshold_tier=3)
        assert proto._accumulate_votes([(2, True), (1, True)]) is False

    def test_accumulate_no_votes_returns_false(self):
        proto = self._build_protocol([4, 2])
        assert proto._accumulate_votes([]) is False

    def test_finalize_replayed_vote_counts_once(self):
        # Through finalize: a replayed approval must not stand in for a
        # second voter. 3 eligible voters, one approves twice -> 1/3.
        proto = self._build_protocol([1, 1, 1])
        voter = proto.voters[0]
        blob = ConcreteBlob(uuid4())
        proof = MagicMock(uuid=voter.uuid, approval=True)
        proto.verify(blob, proof, b'sig')
        proto.verify(blob, proof, b'sig')
        assert proto.finalize(blob) is False

    def test_finalize_originator_short_circuits(self):
        # AgreementProtocol.finalize returns True without consulting
        # _count_vote when blob.originator == myself.uuid.
        from autonomous_trust.core.algorithms.trust import AgreementByTrust

        class _Probe(AgreementByTrust):
            def _pre_verify(self, blob, proof, sig):
                return True

        me = ConcreteVoter(uuid4(), 0, _tier=1)
        other = ConcreteVoter(uuid4(), 0, _tier=4)
        proto = _Probe(me, [other], threshold_tier=3)
        blob = ConcreteBlob(me.uuid)
        # Even though me's tier (1) is below threshold (3), originator
        # short-circuit wins.
        assert proto.finalize(blob) is True
