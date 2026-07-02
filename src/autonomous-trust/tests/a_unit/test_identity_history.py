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
import pytest
import queue
from uuid import uuid4
from unittest.mock import MagicMock, patch

from autonomous_trust.core.identity.history.history import IdentityHistory, IdentityObj
from autonomous_trust.core.identity.history.poa import IdentityByAuthority
from autonomous_trust.core.identity.history.pos import IdentityByStake
from autonomous_trust.core.identity.history.pow import IdentityByWork
from autonomous_trust.core.identity.peers import Peers
from autonomous_trust.core.identity.encrypt import Encryptor
from autonomous_trust.core.identity.identity import Identity
from autonomous_trust.core.identity.sign import Signature
from autonomous_trust.core.structures.merkle import SimplestBlob


def _make_mock_identity(nickname='test', address='10.0.0.1', uid=None):
    ident = MagicMock(spec=Identity)
    ident.uuid = uid or uuid4()
    ident.nickname = nickname
    ident.address = address
    ident.petname = 'Test User'
    sig = Signature.generate()
    ident.signature = MagicMock()
    ident.signature.publish.return_value = sig.publish()
    ident.rank = 1
    ident.sign.return_value = b'fakesig'
    ident.verify.return_value = True
    return ident


class TestIdentityObj:
    def test_init(self):
        ident = _make_mock_identity()
        originator = uuid4()
        obj = IdentityObj(ident, originator)
        assert obj.identity is ident
        assert obj.originator == originator
        assert obj.uuid == ident.uuid

    def test_designation(self):
        ident = _make_mock_identity()
        obj = IdentityObj(ident, uuid4())
        d = obj.designation
        assert isinstance(d, bytes)

    def test_to_dict(self):
        ident = _make_mock_identity()
        originator = uuid4()
        obj = IdentityObj(ident, originator)
        d = obj.to_dict()
        assert 'identity' in d
        assert 'originator' in d
        assert d['originator'] == originator

    def test_validate(self):
        ident = _make_mock_identity()
        obj = IdentityObj(ident, uuid4())
        obj.validate()  # should not raise

    def test_get_hash(self):
        ident = _make_mock_identity()
        obj = IdentityObj(ident, uuid4())
        h = obj.get_hash()
        assert isinstance(h, bytes)


class TestIdentityHistory:
    def _make_history(self):
        myself = _make_mock_identity(nickname='myself')
        peers = Peers()
        log_q = queue.Queue()
        return IdentityHistory(myself, peers, log_q)

    def test_init(self):
        h = self._make_history()
        assert h.blacklist == []
        assert h._timeout == 0

    def test_timeout_property(self):
        h = self._make_history()
        assert h.timeout == 0

    def test_to_dict(self):
        h = self._make_history()
        d = h.to_dict()
        assert 'step_dag' in d
        assert 'blacklist' in d

    def test_insert_peer(self):
        h = self._make_history()
        peer = _make_mock_identity(nickname='peer1', address='10.0.0.2')
        h.insert_peer(peer)
        assert peer in h._peers.all

    def test_insert_peer_duplicate(self):
        h = self._make_history()
        peer = _make_mock_identity(nickname='peer1', address='10.0.0.2')
        h.insert_peer(peer)
        h.insert_peer(peer)  # should not add again to merkle
        assert h._peers.all.count(peer) == 1

    def test_contains(self):
        h = self._make_history()
        ident = _make_mock_identity()
        # _find_identity always returns None currently
        assert ident not in h

    def test_prove_existence_none(self):
        h = self._make_history()
        result = h.prove_existence(_make_mock_identity())
        assert result is None

    def test_verify_existence_none(self):
        h = self._make_history()
        result = h.verify_existence(_make_mock_identity(), MagicMock())
        assert result is None

    def test_validate(self):
        h = self._make_history()
        assert h._validate('main') is True

    def test_verify_object_valid(self):
        h = self._make_history()
        ident = _make_mock_identity()
        blob = IdentityObj(ident, uuid4())
        # The verifier looks up the voter by proof.uuid; point it at
        # ourselves so the look-up resolves to h.myself (whose mocked
        # .verify returns True).
        proof = MagicMock()
        proof.uuid = h.myself.uuid
        result = h.verify_object(blob, proof, b'sig')
        assert result is True

    def test_verify_object_not_identity_obj(self):
        h = self._make_history()
        result = h.verify_object('not_blob', MagicMock(), b'sig')
        assert result is False

    def test_verify_object_not_identity_inside(self):
        h = self._make_history()
        blob = MagicMock(spec=IdentityObj)
        blob.identity = 'not_an_identity'
        result = h.verify_object(blob, MagicMock(), b'sig')
        assert result is False

    def test_share(self):
        h = self._make_history()
        steps_msg, sig = h.share()
        assert isinstance(steps_msg, bytes)
        assert sig is not None

    def test_hear_no_sig(self):
        h = self._make_history()
        from autonomous_trust.core.config import to_yaml_string
        data = [1, 2, 3]
        steps_msg = to_yaml_string(data)
        result = h.hear(steps_msg, sig=None)
        assert result == data

    def test_hear_with_valid_sig(self):
        h = self._make_history()
        from autonomous_trust.core.config import to_yaml_string
        data = [1, 2, 3]
        steps_msg = to_yaml_string(data)
        result = h.hear(steps_msg, sig=b'valid')
        assert result == data

    def test_hear_invalid_sig(self):
        h = self._make_history()
        h.myself.verify.return_value = False
        result = h.hear('data', sig=b'invalid')
        assert result is None

    def test_pre_verify_duplicate(self):
        h = self._make_history()
        peer = _make_mock_identity(nickname='peer1', address='10.0.0.2')
        h._peers.add(peer)
        blob = IdentityObj(peer, peer.uuid)  # originator matches existing peer
        proof = MagicMock()
        proof.uuid = uuid4()
        result = h._pre_verify(blob, proof, b'sig')
        assert result is False

    def test_pre_verify_new(self):
        h = self._make_history()
        blob = IdentityObj(_make_mock_identity(), uuid4())
        proof = MagicMock()
        proof.uuid = uuid4()
        result = h._pre_verify(blob, proof, b'sig')
        assert result is True

    # --- §3.2 divergence detection (proof-digest consistency) ---

    def _make_proof(self, blob, uuid, digest=None, nonce=None):
        from autonomous_trust.core.algorithms.agreement import AgreementProof
        if digest is None:
            digest = blob.get_hash(nonce)
        return AgreementProof(uuid, digest, True, nonce)

    def test_verify_object_matching_digest_accepted(self):
        """A proof whose digest matches the canonical blob hash is accepted."""
        h = self._make_history()
        blob = IdentityObj(_make_mock_identity(), uuid4())
        proof = self._make_proof(blob, h.myself.uuid)  # digest = blob.get_hash()
        assert h.verify_object(blob, proof, b'sig') is True

    def test_verify_object_mismatched_digest_rejected(self):
        """A proof committing to a DIFFERENT view (wrong digest) is rejected —
        the voter holds a divergent history view of this candidate."""
        h = self._make_history()
        blob = IdentityObj(_make_mock_identity(), uuid4())
        proof = self._make_proof(blob, h.myself.uuid,
                                 digest=b'\x00' * len(blob.get_hash()))
        assert h.verify_object(blob, proof, b'sig') is False

    def test_verify_object_nonce_aware_digest(self):
        """PoW-style proofs carry the nonce in the digest; the check must
        recompute with the proof nonce, not reject a legitimate mined digest."""
        h = self._make_history()
        blob = IdentityObj(_make_mock_identity(), uuid4())
        nonce = b'12345'
        proof = self._make_proof(blob, h.myself.uuid, nonce=nonce)
        assert h.verify_object(blob, proof, b'sig') is True
        # ...and the same digest without accounting for the nonce would mismatch
        stale = self._make_proof(blob, h.myself.uuid,
                                 digest=blob.get_hash(), nonce=nonce)
        assert h.verify_object(blob, stale, b'sig') is False

    def test_verify_object_empty_digest_tolerated(self):
        """An absent/empty digest falls through (prior behavior) — the check
        only fires when a voter actually committed a digest."""
        h = self._make_history()
        blob = IdentityObj(_make_mock_identity(), uuid4())
        proof = self._make_proof(blob, h.myself.uuid, digest=b'')
        assert h.verify_object(blob, proof, b'sig') is True

    def test_branch_heads_exposes_all_heads(self):
        h = self._make_history()
        heads = h.branch_heads()
        assert h.main_branch in heads
        # snapshot is a copy — mutating it must not affect the DAG
        heads['bogus'] = None
        assert 'bogus' not in h.branch_heads()

    def test_populate(self):
        h = self._make_history()
        steps = h.recite()
        dictionary = {'step_dag': steps, 'blacklist': ['bad_peer']}
        h.populate(dictionary)
        assert h.blacklist == ['bad_peer']


class TestIdentityByAuthority:
    def _make(self):
        myself = _make_mock_identity(nickname='auth')
        peers = Peers()
        log_q = queue.Queue()
        return IdentityByAuthority(myself, peers, log_q, timeout=0, threshold_rank=3)

    def test_init(self):
        h = self._make()
        assert h.threshold_rank == 3

    def test_prove_blacklisted_uuid(self):
        h = self._make()
        bad = _make_mock_identity(nickname='bad')
        h.blacklist.append(bad)
        blob = IdentityObj(bad, uuid4())
        result = h.prove(blob)
        assert result is None

    def test_prove_blacklisted_address(self):
        h = self._make()
        bad = _make_mock_identity(nickname='bad', address='10.0.0.99')
        h.blacklist.append(bad)
        blob_ident = _make_mock_identity(nickname='other', address='10.0.0.99')
        blob = IdentityObj(blob_ident, uuid4())
        result = h.prove(blob)
        assert result is None

    def test_pre_verify(self):
        h = self._make()
        blob = IdentityObj(_make_mock_identity(), uuid4())
        # verify_object now looks the voter up by proof.uuid; aim it at
        # ourselves so it resolves.
        proof = MagicMock()
        proof.uuid = h.myself.uuid
        result = h._pre_verify(blob, proof, b'sig')
        assert result is True

    def test_finalize(self):
        h = self._make()
        blob = IdentityObj(_make_mock_identity(), uuid4())
        result = h.finalize(blob)
        assert isinstance(result, bool)


class TestIdentityByStake:
    def _make(self):
        myself = _make_mock_identity(nickname='stake')
        peers = Peers()
        log_q = queue.Queue()
        return IdentityByStake(myself, peers, log_q, timeout=0)

    def test_init(self):
        h = self._make()
        assert h is not None

    def test_prove_blacklisted(self):
        h = self._make()
        bad = _make_mock_identity(nickname='bad')
        h.blacklist.append(bad)
        blob = IdentityObj(bad, uuid4())
        result = h.prove(blob)
        assert result is None

    def test_get_stake_default(self):
        h = self._make()
        voter = _make_mock_identity()
        assert h._get_stake(voter) == 1.0  # default when no reputation_fn

    def test_get_stake_with_reputation(self):
        h = self._make()
        h._reputation_fn = lambda uid: 0.75
        voter = _make_mock_identity()
        assert h._get_stake(voter) == 0.75

    def test_finalize(self):
        h = self._make()
        blob = IdentityObj(_make_mock_identity(), uuid4())
        result = h.finalize(blob)
        assert isinstance(result, bool)

    def test_pre_verify(self):
        h = self._make()
        blob = IdentityObj(_make_mock_identity(), uuid4())
        proof = MagicMock()
        proof.uuid = h.myself.uuid
        result = h._pre_verify(blob, proof, b'sig')
        assert result is True


class TestIdentityByWork:
    def test_is_abstract(self):
        # IdentityByWork is abstract (missing _accumulate_votes, _count_vote, _pre_verify)
        myself = _make_mock_identity(nickname='work')
        peers = Peers()
        log_q = queue.Queue()
        with pytest.raises(TypeError, match='abstract'):
            IdentityByWork(myself, peers, log_q, timeout=0)
