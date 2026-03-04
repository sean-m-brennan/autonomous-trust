import pytest
from uuid import uuid4
from unittest.mock import MagicMock

from autonomous_trust.core.algorithms.agreement import (
    AgreementProof, AgreementVoter, VoterTracker, AgreementProtocol,
)
from autonomous_trust.core.structures.merkle import SimplestBlob


class ConcreteVoter(AgreementVoter):
    def verify(self, proof, sig):
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
    """Cover AgreementProof bytes conversion path with None nonce (raises TypeError)."""

    def test_bytes_with_none_nonce_raises(self):
        uid = uuid4()
        proof = AgreementProof(uid, b'digest', True, nonce=None)
        with pytest.raises(TypeError):
            _ = bytes(proof)


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
