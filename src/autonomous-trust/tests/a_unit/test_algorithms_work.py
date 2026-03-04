"""Tests for AgreementByWork prove/verify/finalize methods."""
from uuid import uuid4
from unittest.mock import MagicMock

from autonomous_trust.core.algorithms.agreement import AgreementProof, AgreementVoter
from autonomous_trust.core.algorithms.work import AgreementByWork


def _mock_voter():
    v = MagicMock(spec=AgreementVoter)
    v.uuid = uuid4()
    return v


class EasyWork(AgreementByWork):
    """Concrete subclass with difficulty=0 for fast tests."""
    DIFFICULTY = 0

    def _pre_verify(self, blob, proof, sig):
        pass

    def _accumulate_votes(self, votes):
        return True

    def _count_vote(self, blob, proof, voter):
        pass


class SimpleBlob:
    def __init__(self):
        self.uuid = uuid4()

    def get_hash(self, nonce=None):
        from nacl.hash import blake2b
        data = str(self.uuid).encode()
        if nonce:
            data += nonce
        return blake2b(data)


def test_prove_returns_proof():
    me = _mock_voter()
    ew = EasyWork(me, [])
    blob = SimpleBlob()
    proof = ew.prove(blob)
    assert isinstance(proof, AgreementProof)
    assert proof.approval is True
    assert proof.uuid == me.uuid


def test_prove_with_difficulty():
    """With DIFFICULTY=0, the first hash always starts with '' (matches immediately)."""
    me = _mock_voter()
    ew = EasyWork(me, [])
    blob = SimpleBlob()
    proof = ew.prove(blob)
    assert proof.digest is not None


def test_verify_matching_hash():
    me = _mock_voter()
    ew = EasyWork(me, [])
    blob = SimpleBlob()
    real_hash = blob.get_hash()
    proof = AgreementProof(me.uuid, real_hash, True, nonce=None)
    result = ew.verify(blob, proof, b'sig')
    assert result is True
    assert blob in ew._approved


def test_verify_non_matching_hash():
    me = _mock_voter()
    ew = EasyWork(me, [])
    blob = SimpleBlob()
    proof = AgreementProof(me.uuid, b'badhash', True, nonce=None)
    result = ew.verify(blob, proof, b'sig')
    assert result is True
    assert blob not in ew._approved


def test_finalize_approved():
    me = _mock_voter()
    ew = EasyWork(me, [])
    blob = SimpleBlob()
    ew._approved.append(blob)
    assert ew.finalize(blob) is True


def test_finalize_not_approved():
    me = _mock_voter()
    ew = EasyWork(me, [])
    blob = SimpleBlob()
    assert ew.finalize(blob) is False


def test_prove_memory_error_returns_proof():
    """When MemoryError is raised during the nonce loop, prove() still returns a proof."""
    from unittest.mock import patch

    me = _mock_voter()

    class HighDifficultyWork(AgreementByWork):
        DIFFICULTY = 64  # essentially impossible without MemoryError injection

        def _pre_verify(self, blob, proof, sig):
            pass

        def _accumulate_votes(self, votes):
            return True

        def _count_vote(self, blob, proof, voter):
            pass

    hw = HighDifficultyWork(me, [])
    blob = SimpleBlob()

    # Patch blob.get_hash to raise MemoryError on the second call
    original_get_hash = blob.get_hash
    call_count = [0]

    def patched_get_hash(nonce=None):
        call_count[0] += 1
        if call_count[0] > 1:
            raise MemoryError('simulated OOM')
        return original_get_hash(nonce)

    blob.get_hash = patched_get_hash
    proof = hw.prove(blob)
    assert isinstance(proof, AgreementProof)
    assert proof.approval is True


def test_verify_digest_does_not_start_with_prefix():
    """When proof.digest doesn't start with DIFFICULTY zeros, blob is not added to _approved."""
    me = _mock_voter()
    ew = EasyWork(me, [])
    blob = SimpleBlob()
    # Use difficulty 2 to check the startswith logic
    ew.DIFFICULTY = 2
    real_hash = blob.get_hash()
    # Force a digest that does NOT start with b'00'
    bad_digest = b'\xff' * 64
    proof = AgreementProof(me.uuid, bad_digest, True, nonce=None)
    result = ew.verify(blob, proof, b'sig')
    assert result is True  # verify always returns True
    assert blob not in ew._approved


def test_verify_digest_starts_with_prefix_but_wrong_hash():
    """Digest starts with required zeros but doesn't match blob hash → not approved."""
    me = _mock_voter()
    ew = EasyWork(me, [])
    ew.DIFFICULTY = 2
    blob = SimpleBlob()
    # Craft a digest starting with b'00' but not matching blob.get_hash(nonce)
    wrong_digest = b'00' + b'\xff' * 62
    proof = AgreementProof(me.uuid, wrong_digest, True, nonce=b'somenonce')
    result = ew.verify(blob, proof, b'sig')
    assert result is True
    assert blob not in ew._approved
