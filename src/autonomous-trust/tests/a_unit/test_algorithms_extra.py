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

from autonomous_trust.core.algorithms.agreement import AgreementProof, AgreementVoter, AgreementProtocol
from autonomous_trust.core.algorithms.authority import AgreementByAuthority
from autonomous_trust.core.algorithms.stake import AgreementByStake
from autonomous_trust.core.algorithms.work import AgreementByWork


def _mock_voter(rank=1, uid=None, effective_rank=None):
    v = MagicMock(spec=AgreementVoter)
    v.uuid = uid or uuid4()
    v.rank = rank
    # Authority voting keys off effective_rank (deferred.md §2.2); with no
    # reachability adjustment it equals the signed rank. Set it explicitly so
    # the spec'd mock returns an int, not an unconfigured MagicMock.
    v.effective_rank = rank if effective_rank is None else effective_rank
    return v


class ConcreteBlob:
    """Simple blob for testing.

    `get_hash` returns ASCII-hex bytes to match the
    `MerkleTree.hash_func` contract that the POW algorithm expects
    (work.py:25-31): the production code calls
    ``HexEncoder.decode(blob.get_hash(nonce))`` so any raw-bytes
    digest would trip a `binascii.Error` on the first hex-decode.
    """
    def __init__(self):
        self._data = b'testdata'

    def get_hash(self, nonce=None):
        import hashlib
        d = self._data
        if nonce:
            d = d + nonce
        return hashlib.sha256(d).hexdigest().encode('ascii')


# Concrete subclass for AgreementByAuthority
class ConcreteAuthority(AgreementByAuthority):
    def _pre_verify(self, blob, proof, sig):
        return True


class TestAgreementByAuthority:
    def test_init(self):
        me = _mock_voter(rank=5)
        peers = [_mock_voter(rank=i) for i in range(3)]
        ca = ConcreteAuthority(me, peers, threshold_rank=3)
        assert ca.threshold_rank == 3

    def test_count_vote_below_threshold(self):
        me = _mock_voter(rank=5)
        peers = [_mock_voter(rank=i) for i in range(3)]
        ca = ConcreteAuthority(me, peers, threshold_rank=3)
        blob = ConcreteBlob()
        proof = AgreementProof(peers[0].uuid, b'digest', True)
        result = ca._count_vote(blob, proof, peers[0])
        assert result == (0, False)  # rank 0 < threshold 3, vote not counted

    def test_count_vote_above_threshold(self):
        me = _mock_voter(rank=5)
        peer = _mock_voter(rank=5)
        ca = ConcreteAuthority(me, [peer], threshold_rank=3)
        blob = ConcreteBlob()
        proof = AgreementProof(peer.uuid, b'digest', True)
        result = ca._count_vote(blob, proof, peer)
        assert result == (5, True)  # rank >= threshold, authority vote counts

    def test_accumulate_votes(self):
        me = _mock_voter(rank=5)
        p1 = _mock_voter(rank=1)
        p2 = _mock_voter(rank=3)
        ca = ConcreteAuthority(me, [p1, p2], threshold_rank=2)
        # _accumulate_votes uses max rank from self.voters (which includes me + peers)
        # leader rank is 5 (me), so votes dict must have rank 5
        votes = [(1, True), (3, False), (5, True)]
        result = ca._accumulate_votes(votes)
        assert result is True


# Concrete subclass for AgreementByStake
class ConcreteStake(AgreementByStake):
    def _pre_verify(self, blob, proof, sig):
        return True

    def _get_stake(self, voter):
        return getattr(voter, 'stake', 1)


class TestAgreementByStake:
    def test_prep_vote(self):
        me = _mock_voter()
        cs = ConcreteStake(me, [])
        cs._prep_vote()
        assert cs.yea == 0
        assert cs.nay == 0

    def test_count_vote_approval(self):
        me = _mock_voter()
        cs = ConcreteStake(me, [])
        cs._prep_vote()
        voter = _mock_voter()
        voter.stake = 10
        proof = AgreementProof(voter.uuid, b'digest', True)
        cs._count_vote(ConcreteBlob(), proof, voter)
        assert cs.yea == 10

    def test_count_vote_rejection(self):
        me = _mock_voter()
        cs = ConcreteStake(me, [])
        cs._prep_vote()
        voter = _mock_voter()
        voter.stake = 5
        proof = AgreementProof(voter.uuid, b'digest', False)
        cs._count_vote(ConcreteBlob(), proof, voter)
        assert cs.nay == 5

    def test_accumulate_votes_yea_wins(self):
        me = _mock_voter()
        cs = ConcreteStake(me, [])
        cs.yea = 10
        cs.nay = 5
        assert cs._accumulate_votes([]) is True

    def test_accumulate_votes_nay_wins(self):
        me = _mock_voter()
        cs = ConcreteStake(me, [])
        cs.yea = 3
        cs.nay = 7
        assert cs._accumulate_votes([]) is False


# Concrete subclass for AgreementByWork
class ConcreteWork(AgreementByWork):
    def _pre_verify(self, blob, proof, sig):
        return True

    def _accumulate_votes(self, votes):
        return True

    def _count_vote(self, blob, proof, voter):
        pass


class TestAgreementByWork:
    def test_init(self):
        me = _mock_voter()
        cw = ConcreteWork(me, [])
        assert cw._approved == []

    def test_verify_adds_to_approved(self):
        me = _mock_voter()
        cw = ConcreteWork(me, [])
        blob = ConcreteBlob()
        # Get the real hash
        real_hash = blob.get_hash()
        # Create proof with matching hash
        proof = MagicMock()
        proof.digest = real_hash
        proof.nonce = None
        # This should add to approved if digest starts with '00' and matches
        result = cw.verify(blob, proof, b'sig')
        assert result is True

    def test_finalize_approved(self):
        me = _mock_voter()
        cw = ConcreteWork(me, [])
        blob = ConcreteBlob()
        cw._approved.append(blob)
        assert cw.finalize(blob) is True
        assert blob not in cw._approved

    def test_finalize_not_approved(self):
        me = _mock_voter()
        cw = ConcreteWork(me, [])
        blob = ConcreteBlob()
        assert cw.finalize(blob) is False


# ---------------------------------------------------------------------------
# Additional tests for uncovered paths in agreement.py, authority.py, stake.py
# ---------------------------------------------------------------------------

class TestAgreementByAuthorityAccumulateNoLeader:
    """Cover _accumulate_votes when the leader rank is not in the votes dict."""

    def test_accumulate_votes_leader_not_in_votes(self):
        """Leader absent from votes → not approved.

        Updated to match the current production semantics
        (authority.py:46-57): instead of raising KeyError, the POA
        accumulator returns False so a cross-runtime conformance
        scenario (agreement/poa-leader-abstains) passes. The C twin
        ``_authority_accumulate`` does the same. Voters list
        contains the abstaining leader (rank 10) plus a voter at
        rank 3 whose vote is supplied but doesn't decide.
        """
        me = _mock_voter(rank=10)
        other = _mock_voter(rank=3)
        ca = ConcreteAuthority(me, [other], threshold_rank=5)
        # votes contains no entry for rank 10 (the max / leader rank)
        assert ca._accumulate_votes([(3, True)]) is False

    def test_accumulate_votes_multiple_voters_leader_wins(self):
        """_accumulate_votes returns the vote of the highest-rank voter."""
        me = _mock_voter(rank=7)
        p1 = _mock_voter(rank=2)
        p2 = _mock_voter(rank=7)
        ca = ConcreteAuthority(me, [p1, p2], threshold_rank=1)
        # max rank is 7, votes dict entry for 7 is False
        votes = [(2, True), (7, False)]
        result = ca._accumulate_votes(votes)
        assert result is False

    def test_count_vote_at_exact_threshold(self):
        """A voter at exactly threshold_rank has authority — vote counts."""
        me = _mock_voter(rank=5)
        peer = _mock_voter(rank=3)
        ca = ConcreteAuthority(me, [peer], threshold_rank=3)
        blob = ConcreteBlob()
        proof = AgreementProof(peer.uuid, b'digest', True)
        # rank 3 >= 3, so vote counts
        result = ca._count_vote(blob, proof, peer)
        assert result == (3, True)


class TestAgreementByStakeEdgeCases:
    """Cover edge cases in AgreementByStake."""

    def test_count_vote_zero_stake(self):
        """A voter with zero stake does not change yea/nay."""
        me = _mock_voter()
        cs = ConcreteStake(me, [])
        cs._prep_vote()
        voter = _mock_voter()
        voter.stake = 0
        proof = AgreementProof(voter.uuid, b'digest', True)
        cs._count_vote(ConcreteBlob(), proof, voter)
        assert cs.yea == 0

    def test_accumulate_votes_tie_goes_to_nay(self):
        """When yea == nay, accumulate returns False (strict greater-than)."""
        me = _mock_voter()
        cs = ConcreteStake(me, [])
        cs.yea = 5
        cs.nay = 5
        assert cs._accumulate_votes([]) is False

    def test_count_vote_returns_none(self):
        """_count_vote returns None (side-effects only)."""
        me = _mock_voter()
        cs = ConcreteStake(me, [])
        cs._prep_vote()
        voter = _mock_voter()
        voter.stake = 3
        proof = AgreementProof(voter.uuid, b'digest', False)
        result = cs._count_vote(ConcreteBlob(), proof, voter)
        assert result is None
        assert cs.nay == 3


class EasyWorkExtra(AgreementByWork):
    """Concrete AgreementByWork subclass with DIFFICULTY=0 for instant prove()."""
    DIFFICULTY = 0

    def _pre_verify(self, blob, proof, sig):
        return True

    def _accumulate_votes(self, votes):
        return True

    def _count_vote(self, blob, proof, voter):
        pass


class TestAgreementByWorkProve:
    """Cover AgreementByWork.prove with DIFFICULTY=0 (instant completion)."""

    def test_prove_difficulty_zero(self):
        """With DIFFICULTY=0, any hash matches the empty prefix immediately."""
        me = _mock_voter()
        ew = EasyWorkExtra(me, [])
        blob = ConcreteBlob()
        proof = ew.prove(blob)
        assert isinstance(proof, AgreementProof)
        assert proof.approval is True
        assert proof.uuid == me.uuid
        # DIFFICULTY=0 means startswith(b'') is always True on first iteration (nonce=0)
        # The first hash computed is blob.get_hash() with no nonce argument
        assert proof.digest is not None

    def test_prove_returns_correct_digest(self):
        """prove() digest is the hash that satisfied the difficulty requirement."""
        me = _mock_voter()
        ew = EasyWorkExtra(me, [])
        blob = ConcreteBlob()
        proof = ew.prove(blob)
        # With DIFFICULTY=0 and nonce starting at 0, computed_hash = blob.get_hash()
        # (no nonce on first iteration since nonce=0 → str(0).encode() = b'0'... actually
        # the loop increments BEFORE hashing, so first hash is get_hash() before loop starts)
        assert isinstance(proof.digest, bytes)
        assert len(proof.digest) > 0


class TestAgreementByWorkVerifyNonce:
    """Cover AgreementByWork.verify when digest matches with a nonce."""

    def test_verify_with_matching_nonce_hash_easy(self):
        """With DIFFICULTY=0, any digest that matches blob.get_hash(nonce) is approved.

        proof.digest must be the raw-bytes digest (HexEncoder.decode
        of blob.get_hash output) — that's what prove() stores, and
        what verify() compares against. Using hex-bytes here would
        spuriously fail the equality check.
        """
        from nacl.encoding import HexEncoder
        me = _mock_voter()
        ew = EasyWorkExtra(me, [])
        blob = ConcreteBlob()
        nonce = b'42'
        digest = HexEncoder.decode(blob.get_hash(nonce))
        proof = MagicMock()
        proof.digest = digest
        proof.nonce = nonce
        result = ew.verify(blob, proof, b'sig')
        assert result is True
        assert blob in ew._approved

    def test_verify_with_matching_nonce_hash_no_nonce(self):
        """With DIFFICULTY=0, digest matching blob.get_hash(None) is approved.

        Same raw-bytes-digest invariant as the nonce variant above.
        """
        from nacl.encoding import HexEncoder
        me = _mock_voter()
        ew = EasyWorkExtra(me, [])
        blob = ConcreteBlob()
        digest = HexEncoder.decode(blob.get_hash())  # no nonce
        proof = MagicMock()
        proof.digest = digest
        proof.nonce = None
        result = ew.verify(blob, proof, b'sig')
        assert result is True
        assert blob in ew._approved
