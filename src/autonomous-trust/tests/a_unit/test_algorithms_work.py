# ******************
#  Copyright 2025 Sean M. Brennan and contributors
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


class TestProveStoresNonce:
    """Regression coverage for BUGS.md P5 (AgreementByWork.prove dropped the nonce).

    Before the 2026-05-11 fix, `prove()` returned `AgreementProof(...,
    nonce=None)` even when its inner loop incremented the nonce to find
    a valid hash. `verify()` then re-hashed against the no-nonce form
    and rejected the freshly-mined proof in every loop case — POW
    end-to-end (prove → verify → finalize) silently failed unless the
    no-nonce hash already met DIFFICULTY (~1/256 of blobs at
    DIFFICULTY=2). C's `agreement_prove` had always stored the nonce
    correctly. Asymmetry surfaced by
    `agreement/pow-mined-proof-finalizes-true`.
    """

    def _force_loop_blob(self):
        # Build a blob whose no-nonce hash deliberately does NOT start
        # with b'00', so prove() must enter the increment loop. Uses
        # SimpleBlob and a fixed uuid until we find one that requires
        # mining (deterministic).
        from uuid import UUID
        # The exact UUID doesn't matter as long as the no-nonce hash
        # doesn't start with b'00'. Iterate counter-style UUIDs.
        for i in range(256):
            b = SimpleBlob()
            b.uuid = UUID(int=i + 1)
            if not b.get_hash().startswith(b'00'):
                return b
        raise AssertionError(
            "couldn't find a SimpleBlob whose no-nonce hash needs mining"
        )

    def test_prove_loop_path_produces_verifiable_proof(self):
        me = _mock_voter()
        ew = EasyWork(me, [])
        ew.DIFFICULTY = 2
        blob = self._force_loop_blob()
        proof = ew.prove(blob)
        # The proof carries a non-None nonce because prove looped.
        assert proof.nonce is not None, (
            "prove() must record the nonce when mining iterates "
            "beyond the no-nonce baseline"
        )
        # And verify must accept it — this is the regression.
        ew.verify(blob, proof, b'sig')
        assert blob in ew._approved

    def test_prove_no_loop_path_keeps_nonce_none(self):
        # DIFFICULTY=0 means the no-nonce hash matches trivially.
        # In that case prove() returns nonce=None, and verify recomputes
        # blob.get_hash(None) → match → approved.
        me = _mock_voter()
        ew = EasyWork(me, [])  # DIFFICULTY = 0
        blob = SimpleBlob()
        proof = ew.prove(blob)
        assert proof.nonce is None
        ew.verify(blob, proof, b'sig')
        assert blob in ew._approved
