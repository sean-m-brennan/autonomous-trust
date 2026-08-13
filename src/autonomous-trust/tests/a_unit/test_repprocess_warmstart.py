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
"""Verifiable warm start: persisted reputation evidence and the graded
restoration it gates (ISSUES.md §10.3).

The claim under test is narrow and worth stating plainly: a persisted
reputation score is restored in full ONLY when the evidence file beside it
carries a quorum-signed checkpoint whose root the entries on disk actually
reproduce. Everything else -- no evidence, a broken hash link, an edited
score, a root nobody signed, signatures short of quorum -- restores the peer
at the unverified-restore tier instead.

Each negative case below therefore checks TWO things: that the score was
clamped, and that the chain was not adopted. The second matters more than it
looks: hash-linkage is computable by anyone, so a forger can always hand us a
self-consistent chain, and adopting one would let the ordinary scoring path
re-derive the elevated score the clamp just withheld.
"""
import hashlib
import json
import queue
from uuid import UUID, uuid4
from unittest.mock import MagicMock

import pytest

from autonomous_trust.core.config import Configuration
from autonomous_trust.core.reputation.repprocess import ReputationProcess
from autonomous_trust.core.reputation.reputation import (
    Checkpoint, EVIDENCE_FILE, Reputations, SignedCheckpoint,
    SlashAttestation, TransactionHistory, evidence_from_dict, evidence_to_dict,
)
from autonomous_trust.core._python.identity.identity import Identity
from autonomous_trust.core._python.identity.sign import Signature
from autonomous_trust.core._python.identity.encrypt import Encryptor
from autonomous_trust.core.processes import ProcessTracker
from autonomous_trust.core.system import CfgIds


def _identity(tag: str, uuid=None) -> Identity:
    """A real identity with a per-tag signing key (see the note in
    test_repprocess_checkpoint: distinct keys are what make the
    negative-signature cases fail for the right reason)."""
    seed = hashlib.sha256(tag.encode()).hexdigest().encode('ascii')
    enc = hashlib.sha256(('enc-' + tag).encode()).hexdigest().encode('ascii')
    return Identity(uuid or UUID(bytes=hashlib.md5(tag.encode()).digest()),
                    '10.0.0.1', '%s.test' % tag,
                    Signature(seed, public_only=False),
                    Encryptor(enc, public_only=False),
                    _public_only=False)


@pytest.fixture
def cfg_root(tmp_path, monkeypatch):
    """Point Configuration at a private tree so the evidence file is written
    and read where the test can see it (the default is /etc/at)."""
    monkeypatch.setenv(Configuration.ROOT_VARIABLE_NAME, str(tmp_path))
    cfg_dir = tmp_path / 'etc' / 'at'
    cfg_dir.mkdir(parents=True)
    return cfg_dir


def _uu(value):
    """A ``Reputations`` key. The store holds UUID objects while
    ``Identity.uuid`` is a str, so peer lookups have to normalize."""
    return value if isinstance(value, UUID) else UUID(str(value))


def _make_rep_process(identity=None, peers=(), reputations=None):
    log_q = queue.Queue()
    if identity is None:
        identity = _identity('self-node')
    procs = []
    for nm in (CfgIds.network, CfgIds.identity, CfgIds.negotiation,
               CfgIds.reputation):
        p = MagicMock()
        p.name = nm
        procs.append(p)
    peer_store = MagicMock()
    peer_store.all = list(peers)
    configs = {
        'processes': procs,
        CfgIds.identity: identity,
        CfgIds.peers: peer_store,
        CfgIds.group: MagicMock(),
    }
    if reputations is not None:
        configs[CfgIds.reputation] = reputations
    rp = ReputationProcess(configs, ProcessTracker(), log_q, suppress_log=True)
    rp.protocol.group.uuid = uuid4()
    return rp


def _evidence_file(cfg_dir):
    return cfg_dir / (EVIDENCE_FILE + Configuration.file_ext)


TX_SCORE = 0.9


def _supported(n, score=TX_SCORE):
    """The ceiling `n` attested transactions at `score` support -- the shrunk
    mean the runtime derives (_evidence_ceilings). Spelled out here rather than
    hard-coded so a test states "what the evidence supports" and not a
    magic number."""
    k = ReputationProcess.RESTORE_SHRINKAGE_K
    neutral = ReputationProcess.PREREP_NEUTRAL
    return (n * score + k * neutral) / (n + k)


def _build_evidence(proposer: Identity, cosigners, peer_uuids, count=3):
    """A complete, honestly-signed evidence document: `count` committed
    bilateral txs between the proposer and each peer in turn, checkpointed
    over the whole window and co-signed by `cosigners`.

    Each peer therefore appears in ``count // len(peer_uuids)`` transactions,
    which is what bounds its restorable score."""
    history = TransactionHistory()
    for i in range(count):
        tid = UUID(int=i + 1)
        peer = peer_uuids[i % len(peer_uuids)]
        history.update(tid, proposer.uuid, TX_SCORE)
        history.update(tid, peer, TX_SCORE)
    window = history._indexed_window()
    ckpt = Checkpoint(proposer_uuid=proposer.uuid, root=history.window_root(),
                      epoch=4, first_index=window[0].index if window else 0,
                      count=len(window))
    sigs = {str(ident.uuid): ident.sign(ckpt.designation).signature.decode('ascii')
            for ident in cosigners}
    return history, evidence_to_dict(history, SignedCheckpoint(ckpt, sigs))


def _write(cfg_dir, doc):
    _evidence_file(cfg_dir).write_text(json.dumps(doc, indent=2))


# --- document format --------------------------------------------------------

class TestEvidenceDocument:
    def test_roundtrip_preserves_chain_and_checkpoint(self):
        me = _identity('me')
        peer = uuid4()
        history, doc = _build_evidence(me, [me], [peer], count=3)
        chain, signed = evidence_from_dict(doc)
        assert [tx.index for tx in chain] == [0, 1, 2]
        # The links survive the round trip, which is the only reason the root
        # can be recomputed on the far side: entry_hash folds prev_hash in.
        assert TransactionHistory.verify_chain_links(chain)
        assert TransactionHistory(_chain=chain).window_root() == \
            history.window_root()
        assert signed.checkpoint.designation == \
            Checkpoint(proposer_uuid=me.uuid, root=history.window_root(),
                       epoch=4, first_index=0, count=3).designation

    def test_incomplete_entries_are_not_written(self):
        """A tx with no counterparty yet is not evidence of anything, so it
        stays out of the document rather than arriving un-indexed."""
        history = TransactionHistory()
        history.update(UUID(int=1), uuid4(), 0.8)  # one-sided, no index
        doc = evidence_to_dict(history, None)
        assert doc['chain'] == []
        assert doc['checkpoint'] is None

    def test_wrong_schema_is_refused(self):
        _, doc = _build_evidence(_identity('me'), [], [uuid4()])
        doc['schema'] = '99'
        with pytest.raises(ValueError):
            evidence_from_dict(doc)

    def test_plain_json_no_type_tags(self):
        """The C runtime reads this file too, so it must not carry Python
        class names (the reason it is not a Configuration dump)."""
        _, doc = _build_evidence(_identity('me'), [], [uuid4()])
        assert '__type__' not in json.dumps(doc)


# --- verified restoration ---------------------------------------------------

class TestVerifiedWarmStart:
    def test_quorum_signed_evidence_restores_supported_score(self, cfg_root):
        me = _identity('me')
        peer_a = _identity('peer-a')
        peer_b = _identity('peer-b')
        # 40 txs alternating between the two peers -> 20 each.
        _, doc = _build_evidence(me, [me, peer_a, peer_b],
                                 [peer_a.uuid, peer_b.uuid], count=40)
        supported = _supported(20)
        assert supported > 0.8  # the scores below are inside what 20 txs bear
        _write(cfg_root, doc)
        reps = Reputations({peer_a.uuid: 0.80, peer_b.uuid: 0.75})
        rp = _make_rep_process(identity=me, peers=[peer_a, peer_b],
                               reputations=reps)
        # Scores stand: a quorum signed a window that bears them out.
        assert rp.reputations.current[_uu(peer_a.uuid)] == pytest.approx(0.80)
        assert rp.reputations.current[_uu(peer_b.uuid)] == pytest.approx(0.75)
        assert rp._trust_tier(rp.reputations.current[_uu(peer_a.uuid)]) == 3
        # ...and the attested history itself is adopted, with the checkpoint
        # that attests it.
        assert len(rp.history) == 40
        assert rp.history.window_root() == doc['checkpoint']['root'].encode()
        assert rp._checkpoint is not None
        assert rp._checkpoint.epoch == 4
        # Per chain now: '' is the primary chain (a gateway also keys
        # child-group chains here). See ISSUES §10.2.
        assert len(rp._checkpoint_sigs_final['']) == 3

    def test_score_beyond_the_evidence_is_pulled_back(self, cfg_root):
        """The attack the presence check missed: raise a score in
        `reputation.cfg.json` and leave the (perfectly valid) evidence alone.
        The peer really does transact, so vouching for the PEER restores the
        typed-in number; bounding the VALUE does not."""
        me = _identity('me')
        peer_a = _identity('peer-a')
        _, doc = _build_evidence(me, [me, peer_a], [peer_a.uuid], count=20)
        _write(cfg_root, doc)
        rp = _make_rep_process(identity=me, peers=[peer_a],
                               reputations=Reputations({peer_a.uuid: 0.99}))
        assert rp.reputations.current[_uu(peer_a.uuid)] == \
            pytest.approx(_supported(20))
        assert rp.reputations.current[_uu(peer_a.uuid)] < 0.99

    def test_short_window_supports_little(self, cfg_root):
        """Shrinkage toward neutral is what makes a two-entry window of
        perfect scores worth almost nothing -- otherwise a forger would only
        need to mint the shortest chain that verifies."""
        me = _identity('me')
        peer_a = _identity('peer-a')
        _, doc = _build_evidence(me, [me, peer_a], [peer_a.uuid], count=2)
        _write(cfg_root, doc)
        rp = _make_rep_process(identity=me, peers=[peer_a],
                               reputations=Reputations({peer_a.uuid: 0.99}))
        restored = rp.reputations.current[_uu(peer_a.uuid)]
        assert restored == pytest.approx(_supported(2))
        assert rp._trust_tier(restored) == 0

    def test_ceiling_ignores_the_persisted_snapshot(self, cfg_root):
        """The bound is a pure function of the attested window. If it were
        derived from anything the persisted file feeds, the file would be
        vouching for itself."""
        me = _identity('me')
        peer_a = _identity('peer-a')
        _, doc = _build_evidence(me, [me, peer_a], [peer_a.uuid], count=12)
        _write(cfg_root, doc)
        low = _make_rep_process(identity=me, peers=[peer_a],
                                reputations=Reputations({peer_a.uuid: 0.99}))
        high = _make_rep_process(identity=me, peers=[peer_a],
                                 reputations=Reputations({peer_a.uuid: 1.0}))
        assert low.reputations.current[_uu(peer_a.uuid)] == \
            high.reputations.current[_uu(peer_a.uuid)]

    def test_own_checkpoint_epoch_resumes_past_persisted(self, cfg_root):
        """A restarted proposer must not reuse an epoch its peers have already
        seen: their (proposer, epoch) dedup rings outlive our restart, so
        beginning again at 1 would have the first proposals silently dropped."""
        me = _identity('me')
        peer = _identity('peer-a')
        _, doc = _build_evidence(me, [me, peer], [peer.uuid])
        _write(cfg_root, doc)
        rp = _make_rep_process(identity=me, peers=[peer])
        assert rp._checkpoint_epochs[''] == 4

    def test_peer_absent_from_evidence_gets_the_unverified_clamp(self, cfg_root):
        """Two different bounds, and the distinction matters: a peer the window
        covers is held to what its own transactions support, while a peer the
        window never mentions falls back to the unverified-tier ceiling. The
        second is not derived from evidence because there is none."""
        me = _identity('me')
        peer_a = _identity('peer-a')
        stranger = uuid4()
        _, doc = _build_evidence(me, [me, peer_a], [peer_a.uuid], count=20)
        _write(cfg_root, doc)
        reps = Reputations({peer_a.uuid: 0.95, stranger: 0.95})
        rp = _make_rep_process(identity=me, peers=[peer_a], reputations=reps)
        assert rp.reputations.current[_uu(peer_a.uuid)] == \
            pytest.approx(_supported(20))
        assert rp.reputations.current[_uu(stranger)] == \
            rp._tier_ceiling(rp.UNVERIFIED_RESTORE_TIER)


# --- graded (clamped) restoration -------------------------------------------

class TestClampedWarmStart:
    def _assert_clamped(self, rp, peer_uuid, original=0.95):
        ceiling = rp._tier_ceiling(rp.UNVERIFIED_RESTORE_TIER)
        assert rp.reputations.current[_uu(peer_uuid)] == ceiling
        assert rp._trust_tier(rp.reputations.current[_uu(peer_uuid)]) == \
            rp.UNVERIFIED_RESTORE_TIER
        assert ceiling < original
        # Nothing adopted: an unverified chain must not be able to feed the
        # scoring path back up to where it was.
        assert len(rp.history) == 0
        assert rp._checkpoint is None

    def test_no_evidence_file_clamps(self, cfg_root):
        peer = uuid4()
        rp = _make_rep_process(reputations=Reputations({peer: 0.95}))
        self._assert_clamped(rp, peer)

    def test_malformed_evidence_clamps(self, cfg_root):
        _evidence_file(cfg_root).write_text('{not json')
        peer = uuid4()
        rp = _make_rep_process(reputations=Reputations({peer: 0.95}))
        self._assert_clamped(rp, peer)

    def test_unsigned_chain_clamps(self, cfg_root):
        """The forgery this whole mechanism exists to refuse: a well-formed,
        internally consistent chain with no checkpoint over it. Anyone can
        compute the digests; only a quorum can sign the root."""
        me = _identity('me')
        peer = _identity('peer-a')
        _, doc = _build_evidence(me, [], [peer.uuid])
        doc['checkpoint'] = None
        _write(cfg_root, doc)
        rp = _make_rep_process(identity=me, peers=[peer],
                               reputations=Reputations({peer.uuid: 0.95}))
        self._assert_clamped(rp, peer.uuid)

    def test_edited_score_breaks_hash_link_and_clamps(self, cfg_root):
        """Raising a committed score in the file changes that entry's hash, so
        its successor's prev_hash no longer matches. Tamper-evident."""
        me = _identity('me')
        peer = _identity('peer-a')
        _, doc = _build_evidence(me, [me, peer], [peer.uuid], count=3)
        doc['chain'][0]['p2_score'] = 1.0
        _write(cfg_root, doc)
        chain, _ = evidence_from_dict(doc)
        assert not TransactionHistory.verify_chain_links(chain)
        rp = _make_rep_process(identity=me, peers=[peer],
                               reputations=Reputations({peer.uuid: 0.95}))
        self._assert_clamped(rp, peer.uuid)

    def test_root_not_matching_entries_clamps(self, cfg_root):
        """A checkpoint signed over some OTHER window: the signatures verify,
        the chain links verify, and the two still do not describe each other.
        Caught by recomputing the root rather than trusting the field."""
        me = _identity('me')
        peer = _identity('peer-a')
        _, doc = _build_evidence(me, [], [peer.uuid], count=3)
        forged = Checkpoint(proposer_uuid=me.uuid, root=b'c' * 64, epoch=4,
                            first_index=0, count=3)
        doc['checkpoint'] = {
            'proposer_uuid': str(me.uuid), 'root': 'c' * 64, 'epoch': 4,
            'first_index': 0, 'count': 3,
            'sigs': {str(i.uuid): i.sign(forged.designation).signature.decode('ascii')
                     for i in (me, peer)},
        }
        _write(cfg_root, doc)
        rp = _make_rep_process(identity=me, peers=[peer],
                               reputations=Reputations({peer.uuid: 0.95}))
        self._assert_clamped(rp, peer.uuid)

    def test_truncated_window_clamps(self, cfg_root):
        """Dropping an entry the checkpoint counted leaves the root
        unreproducible, so the window is refused rather than partially
        credited."""
        me = _identity('me')
        peer = _identity('peer-a')
        _, doc = _build_evidence(me, [me, peer], [peer.uuid], count=4)
        del doc['chain'][2]
        _write(cfg_root, doc)
        rp = _make_rep_process(identity=me, peers=[peer],
                               reputations=Reputations({peer.uuid: 0.95}))
        self._assert_clamped(rp, peer.uuid)

    def test_signature_from_unknown_key_clamps(self, cfg_root):
        """Signatures are counted only when they verify against a key we
        hold. A stranger's genuine signature is not a vote."""
        me = _identity('me')
        peer = _identity('peer-a')
        outsider = _identity('outsider')
        _, doc = _build_evidence(me, [outsider], [peer.uuid])
        _write(cfg_root, doc)
        rp = _make_rep_process(identity=me, peers=[peer],
                               reputations=Reputations({peer.uuid: 0.95}))
        self._assert_clamped(rp, peer.uuid)

    def test_forged_signature_clamps(self, cfg_root):
        me = _identity('me')
        peer = _identity('peer-a')
        _, doc = _build_evidence(me, [], [peer.uuid])
        doc['checkpoint']['sigs'] = {str(me.uuid): 'ab' * 64,
                                     str(peer.uuid): 'cd' * 64}
        _write(cfg_root, doc)
        rp = _make_rep_process(identity=me, peers=[peer],
                               reputations=Reputations({peer.uuid: 0.95}))
        self._assert_clamped(rp, peer.uuid)

    def test_quorum_sized_against_our_own_roster(self, cfg_root):
        """One genuine co-signature does not carry a five-member group. The
        bar comes from OUR roster, so whoever wrote the file cannot also
        choose how many signatures it needs."""
        me = _identity('me')
        peers = [_identity('peer-%d' % i) for i in range(5)]
        _, doc = _build_evidence(me, [me], [peers[0].uuid])
        _write(cfg_root, doc)
        rp = _make_rep_process(identity=me, peers=peers,
                               reputations=Reputations({peers[0].uuid: 0.95}))
        self._assert_clamped(rp, peers[0].uuid)

    def test_clamp_never_raises_a_low_score(self, cfg_root):
        """One-directional: restoration can withhold standing, never confer
        it -- so an excluded peer is not quietly lifted to tier 1."""
        low, mid = uuid4(), uuid4()
        rp = _make_rep_process(reputations=Reputations({low: 0.05, mid: 0.3}))
        assert rp.reputations.current[_uu(low)] == pytest.approx(0.05)
        assert rp.reputations.current[_uu(mid)] == pytest.approx(0.3)

    def test_self_score_is_not_clamped(self, cfg_root):
        me = _identity('me')
        rp = _make_rep_process(identity=me,
                               reputations=Reputations({me.uuid: 0.99}))
        assert rp.reputations.current[_uu(me.uuid)] == pytest.approx(0.99)


# --- the clamp target itself ------------------------------------------------

class TestTierCeiling:
    def test_ceiling_stays_inside_its_tier(self):
        for _floor, tier in ReputationProcess.TIER_FLOORS:
            ceiling = ReputationProcess._tier_ceiling(tier)
            assert ReputationProcess._trust_tier(ceiling) == tier

    def test_ceiling_is_just_below_the_next_floor(self):
        ceiling = ReputationProcess._tier_ceiling(1)
        next_floor = ReputationProcess.TIER_FLOORS[1][0]
        assert ceiling < next_floor
        assert ReputationProcess._trust_tier(next_floor) == 2

    def test_top_tier_has_no_ceiling(self):
        top = ReputationProcess.TIER_FLOORS[-1][1]
        assert ReputationProcess._tier_ceiling(top) == 1.0


# --- gateway child chains (ISSUES §10.2) ------------------------------------

class TestChildChainEvidence:
    """A gateway keeps one chain per child group, and each gets its own
    checkpoints and its own evidence file. Before this, checkpoint rounds only
    ever covered the primary chain, so a gateway's subtree standing could not be
    attested — and therefore could not be restored under §10.3's rule."""

    def _gateway(self, cfg_root, child_uuid, peers=(), reputations=None):
        me = _identity('gw')
        rp = _make_rep_process(identity=me, peers=peers,
                              reputations=reputations)
        child = MagicMock()
        child.uuid = child_uuid
        rp.protocol.child_groups = {str(child_uuid): child}
        return rp

    def test_child_chain_gets_its_own_evidence_file(self, cfg_root):
        me = _identity('gw')
        peer = _identity('member')
        child_uuid = uuid4()
        rp = self._gateway(cfg_root, child_uuid, peers=[peer])
        chain = rp._chain_for_group(str(child_uuid))
        for i in range(4):
            tid = UUID(int=100 + i)
            chain.update(tid, me.uuid, TX_SCORE)
            chain.update(tid, peer.uuid, TX_SCORE)
        rp._originate_checkpoint({CfgIds.network: queue.Queue()},
                                 str(child_uuid))
        # One file per chain, named for the group — mirroring the
        # group_child_<name>.cfg.json convention.
        child_file = cfg_root / ('%s-%s%s' % (EVIDENCE_FILE, child_uuid,
                                              Configuration.file_ext))
        assert child_file.exists()
        doc = json.loads(child_file.read_text())
        assert len(doc['chain']) == 4
        assert doc['checkpoint']['group_uuid'] == str(child_uuid)
        assert doc['checkpoint']['root'] == chain.window_root().decode()
        # ...and the primary file is untouched: its chain is empty, so nothing
        # was attested for it.
        assert not _evidence_file(cfg_root).exists()

    def test_child_designation_differs_from_primary(self):
        """A co-signature harvested from a child-group round must not read as
        agreement about the primary chain. Two chains can perfectly well share
        a root, epoch and bounds, so the chain has to be inside the signed
        bytes."""
        root = b'a' * 64
        primary = Checkpoint(proposer_uuid=uuid4(), root=root, epoch=2,
                             first_index=0, count=3)
        child = Checkpoint(proposer_uuid=primary.proposer_uuid, root=root,
                           epoch=2, first_index=0, count=3,
                           group_uuid=str(uuid4()))
        assert primary.designation != child.designation
        # The primary form is unchanged from before child chains existed, which
        # is what keeps every pinned scenario and the C twin verifying.
        assert primary.designation.endswith(b'|3')
        assert child.designation.endswith(child.group_uuid.encode())
        assert primary.key() != child.key()

    def test_child_and_primary_epochs_are_independent(self, cfg_root):
        me = _identity('gw')
        peer = _identity('member')
        child_uuid = uuid4()
        rp = self._gateway(cfg_root, child_uuid, peers=[peer])
        for i in range(2):
            tid = UUID(int=200 + i)
            rp.history.update(tid, me.uuid, TX_SCORE)
            rp.history.update(tid, peer.uuid, TX_SCORE)
        child = rp._chain_for_group(str(child_uuid))
        for i in range(2):
            tid = UUID(int=300 + i)
            child.update(tid, me.uuid, TX_SCORE)
            child.update(tid, peer.uuid, TX_SCORE)
        q = {CfgIds.network: queue.Queue()}
        rp._originate_checkpoint(q, '')
        rp._originate_checkpoint(q, str(child_uuid))
        rp._originate_checkpoint(q, str(child_uuid))
        assert rp._checkpoint_epochs[''] == 1
        assert rp._checkpoint_epochs[str(child_uuid)] == 2
        # Both chains hold a finalized checkpoint, each over its own root.
        assert rp._checkpoints[''].root == rp.history.window_root()
        assert rp._checkpoints[str(child_uuid)].root == child.window_root()

    def test_periodic_sweep_covers_every_chain(self, cfg_root):
        me = _identity('gw')
        peer = _identity('member')
        child_uuid = uuid4()
        rp = self._gateway(cfg_root, child_uuid, peers=[peer])
        for i in range(2):
            tid = UUID(int=400 + i)
            rp.history.update(tid, me.uuid, TX_SCORE)
            rp.history.update(tid, peer.uuid, TX_SCORE)
        child = rp._chain_for_group(str(child_uuid))
        for i in range(2):
            tid = UUID(int=500 + i)
            child.update(tid, me.uuid, TX_SCORE)
            child.update(tid, peer.uuid, TX_SCORE)
        q = {CfgIds.network: queue.Queue()}
        rp._maybe_checkpoint(q, 1000.0)              # takes the phase
        rp._maybe_checkpoint(q, rp._next_checkpoint_at)
        assert '' in rp._checkpoints
        assert str(child_uuid) in rp._checkpoints
        # An unmoved chain is not re-checkpointed on the next tick...
        epochs = dict(rp._checkpoint_epochs)
        rp._maybe_checkpoint(q, rp._next_checkpoint_at)
        assert rp._checkpoint_epochs == epochs
        # ...while a chain that HAS moved is, on its own.
        child.update(UUID(int=999), me.uuid, TX_SCORE)
        child.update(UUID(int=999), peer.uuid, TX_SCORE)
        rp._maybe_checkpoint(q, rp._next_checkpoint_at)
        assert rp._checkpoint_epochs[str(child_uuid)] == \
            epochs[str(child_uuid)] + 1
        assert rp._checkpoint_epochs[''] == epochs['']

    def test_child_evidence_restores_on_restart(self, cfg_root):
        """The point of §10.2's phase-3 persistence item: a restarted gateway
        comes back with its subtree chain, verified, instead of relearning it."""
        me = _identity('gw')
        peer = _identity('member')
        child_uuid = uuid4()
        rp = self._gateway(cfg_root, child_uuid, peers=[peer])
        chain = rp._chain_for_group(str(child_uuid))
        for i in range(20):
            tid = UUID(int=600 + i)
            chain.update(tid, me.uuid, TX_SCORE)
            chain.update(tid, peer.uuid, TX_SCORE)
        ckpt = Checkpoint(proposer_uuid=me.uuid, root=chain.window_root(),
                          epoch=3, first_index=0, count=20,
                          group_uuid=str(child_uuid))
        sigs = {str(i.uuid): i.sign(ckpt.designation).signature.decode('ascii')
                for i in (me, peer)}
        rp._store_checkpoint(ckpt, sigs)

        restarted = self._gateway(
            cfg_root, child_uuid, peers=[peer],
            reputations=Reputations({peer.uuid: 0.75}))
        # Child groups arrive over IPC after __init__, so the child restore is
        # driven from the process loop rather than the constructor. At boot the
        # peer was clamped as uncovered; the subtree's own evidence then lifts
        # it back to what that evidence bears out.
        ceiling = restarted._tier_ceiling(restarted.UNVERIFIED_RESTORE_TIER)
        assert restarted.reputations.current[_uu(peer.uuid)] == ceiling
        restarted._restore_child_evidence({CfgIds.identity: queue.Queue(),
                                           CfgIds.negotiation: queue.Queue(),
                                           CfgIds.main: queue.Queue(),
                                           CfgIds.network: queue.Queue()})
        assert len(restarted._chain_for_group(str(child_uuid))) == 20
        assert restarted._checkpoints[str(child_uuid)].epoch == 3
        # The subtree's own evidence is what bounds the peer's restored score.
        assert restarted.reputations.current[_uu(peer.uuid)] == \
            pytest.approx(0.75)
        assert len(restarted.history) == 0   # primary chain had nothing to attest

    def test_late_child_evidence_never_lowers_a_live_score(self, cfg_root):
        """Late-arriving evidence is not a reason to discount what a peer has
        earned since boot, and it may not raise a score above what was actually
        persisted either. The lift is bounded on both sides."""
        me = _identity('gw')
        peer = _identity('member')
        child_uuid = uuid4()
        rp = self._gateway(cfg_root, child_uuid, peers=[peer])
        chain = rp._chain_for_group(str(child_uuid))
        for i in range(20):
            tid = UUID(int=900 + i)
            chain.update(tid, me.uuid, TX_SCORE)
            chain.update(tid, peer.uuid, TX_SCORE)
        ckpt = Checkpoint(proposer_uuid=me.uuid, root=chain.window_root(),
                          epoch=1, first_index=0, count=20,
                          group_uuid=str(child_uuid))
        sigs = {str(i.uuid): i.sign(ckpt.designation).signature.decode('ascii')
                for i in (me, peer)}
        rp._store_checkpoint(ckpt, sigs)

        restarted = self._gateway(
            cfg_root, child_uuid, peers=[peer],
            reputations=Reputations({peer.uuid: 0.75}))
        # The peer has climbed past both the clamp and the persisted value
        # during this session.
        restarted.reputations.current[_uu(peer.uuid)] = 0.88
        restarted._restore_child_evidence({CfgIds.identity: queue.Queue(),
                                           CfgIds.negotiation: queue.Queue(),
                                           CfgIds.main: queue.Queue(),
                                           CfgIds.network: queue.Queue()})
        assert restarted.reputations.current[_uu(peer.uuid)] == \
            pytest.approx(0.88)

    def test_child_file_claiming_another_chain_is_refused(self, cfg_root):
        """A document must cover the chain its filename names. Otherwise a child
        file could be adopted as the primary chain's history on the strength of
        signatures made over different bytes."""
        me = _identity('gw')
        peer = _identity('member')
        child_uuid = uuid4()
        rp = self._gateway(cfg_root, child_uuid, peers=[peer])
        chain = rp._chain_for_group(str(child_uuid))
        for i in range(20):
            tid = UUID(int=700 + i)
            chain.update(tid, me.uuid, TX_SCORE)
            chain.update(tid, peer.uuid, TX_SCORE)
        # Honestly signed, but for the PRIMARY chain (group_uuid '')...
        ckpt = Checkpoint(proposer_uuid=me.uuid, root=chain.window_root(),
                          epoch=3, first_index=0, count=20)
        sigs = {str(i.uuid): i.sign(ckpt.designation).signature.decode('ascii')
                for i in (me, peer)}
        doc = evidence_to_dict(chain, SignedCheckpoint(ckpt, sigs))
        (cfg_root / ('%s-%s%s' % (EVIDENCE_FILE, child_uuid,
                                  Configuration.file_ext))
         ).write_text(json.dumps(doc))

        restarted = self._gateway(
            cfg_root, child_uuid, peers=[peer],
            reputations=Reputations({peer.uuid: 0.95}))
        restarted._restore_child_evidence({CfgIds.identity: queue.Queue(),
                                           CfgIds.negotiation: queue.Queue(),
                                           CfgIds.main: queue.Queue(),
                                           CfgIds.network: queue.Queue()})
        assert str(child_uuid) not in restarted.child_histories
        assert restarted.reputations.current[_uu(peer.uuid)] == \
            restarted._tier_ceiling(restarted.UNVERIFIED_RESTORE_TIER)

    def test_slash_evidence_may_anchor_on_a_child_root(self, cfg_root):
        """A tx that offended inside a child group is anchored in that group's
        root. Accepting only the primary root would refuse every legitimate
        subtree slash while adding no security — each root cleared the same
        quorum test."""
        me = _identity('gw')
        peer = _identity('member')
        child_uuid = uuid4()
        rp = self._gateway(cfg_root, child_uuid, peers=[peer])
        chain = rp._chain_for_group(str(child_uuid))
        task_ids = []
        for i in range(4):
            tid = UUID(int=800 + i)
            chain.update(tid, me.uuid, TX_SCORE)
            chain.update(tid, peer.uuid, 0.1)
            task_ids.append(tid)
        rp._checkpoints[str(child_uuid)] = Checkpoint(
            proposer_uuid=me.uuid, root=chain.window_root(), epoch=1,
            first_index=0, count=4, group_uuid=str(child_uuid))
        tx = chain._task_mapping[task_ids[1]]
        evidence = {
            'task_id': str(task_ids[1]),
            'leaf': tx.entry_hash().decode('ascii'),
            'proof': [[s.decode('ascii'), bool(left)]
                      for s, left in chain.inclusion_proof(tx.index)],
            'root': chain.window_root().decode('ascii'),
        }
        att = SlashAttestation(slasher_uuid=me.uuid, target_uuid=peer.uuid,
                               reason='defection', floor_score=0.0, epoch=1,
                               evidence_ref=evidence)
        assert rp._verify_slash_evidence(att) is True
        # A root we never finalized is still refused.
        att.evidence_ref = dict(evidence, root='f' * 64)
        assert rp._verify_slash_evidence(att) is False


# --- periodic origination ---------------------------------------------------

class TestPeriodicCheckpoint:
    """Checkpointing used to be reactive only, and nothing triggered it, so no
    deployment ever held a checkpoint -- which made every warm start
    unverifiable no matter how sound the verification was."""

    def _rp(self, cfg_root):
        me = _identity('me')
        peer = _identity('peer-a')
        rp = _make_rep_process(identity=me, peers=[peer])
        for i in range(3):
            tid = UUID(int=i + 1)
            rp.history.update(tid, me.uuid, 0.9)
            rp.history.update(tid, peer.uuid, 0.9)
        return rp

    def test_proposes_when_due(self, cfg_root):
        rp = self._rp(cfg_root)
        net_q = queue.Queue()
        queues = {CfgIds.network: net_q}
        rp._maybe_checkpoint(queues, 1000.0)  # first call only takes the phase
        assert rp._checkpoint is None
        rp._maybe_checkpoint(queues, rp._next_checkpoint_at)
        assert rp._checkpoint is not None
        assert rp._checkpoint.root == rp.history.window_root()
        assert rp._checkpoint.count == 3

    def test_not_before_due(self, cfg_root):
        rp = self._rp(cfg_root)
        rp._maybe_checkpoint({CfgIds.network: queue.Queue()}, 1000.0)
        due = rp._next_checkpoint_at
        rp._maybe_checkpoint({CfgIds.network: queue.Queue()}, due - 0.01)
        assert rp._checkpoint is None

    def test_unmoved_window_is_not_recheckpointed(self, cfg_root):
        """A second epoch over the same root tells a verifier nothing the
        first did not, and costs a co-signature from every member."""
        rp = self._rp(cfg_root)
        net_q = queue.Queue()
        queues = {CfgIds.network: net_q}
        rp._maybe_checkpoint(queues, 1000.0)
        rp._maybe_checkpoint(queues, rp._next_checkpoint_at)
        first_epoch = rp._checkpoint.epoch
        rp._maybe_checkpoint(queues, rp._next_checkpoint_at)
        assert rp._checkpoint.epoch == first_epoch
        # ...but a new commit makes the window worth attesting again.
        rp.history.update(UUID(int=99), rp.identity.uuid, 0.9)
        rp.history.update(UUID(int=99), uuid4(), 0.9)
        rp._maybe_checkpoint(queues, rp._next_checkpoint_at)
        assert rp._checkpoint.epoch == first_epoch + 1

    def test_empty_window_is_not_checkpointed(self, cfg_root):
        rp = _make_rep_process(identity=_identity('me'))
        queues = {CfgIds.network: queue.Queue()}
        rp._maybe_checkpoint(queues, 1000.0)
        rp._maybe_checkpoint(queues, rp._next_checkpoint_at)
        assert rp._checkpoint is None

    def test_interval_zero_disables(self, cfg_root, monkeypatch):
        rp = self._rp(cfg_root)
        monkeypatch.setattr(rp, 'CHECKPOINT_INTERVAL', 0.0)
        rp._maybe_checkpoint({CfgIds.network: queue.Queue()}, 1000.0)
        assert rp._next_checkpoint_at == 0.0
        assert rp._checkpoint is None

    def test_phase_is_stable_and_within_the_interval(self, cfg_root):
        """Restart-stable by construction (derived from our uuid, not drawn),
        so a restarted node returns to its own slot rather than landing on
        somebody else's."""
        me = _identity('me')
        first = _make_rep_process(identity=me)._checkpoint_phase()
        second = _make_rep_process(identity=me)._checkpoint_phase()
        assert first == second
        assert 0.0 <= first < ReputationProcess.CHECKPOINT_INTERVAL
        other = _make_rep_process(identity=_identity('other'))._checkpoint_phase()
        assert other != first


# --- writer side ------------------------------------------------------------

class TestEvidencePersistence:
    def test_store_checkpoint_writes_verifiable_evidence(self, cfg_root):
        """Round trip through the real writer: what _store_checkpoint puts on
        disk is what a restart accepts."""
        me = _identity('me')
        peer = _identity('peer-a')
        rp = _make_rep_process(identity=me, peers=[peer])
        for i in range(20):
            tid = UUID(int=i + 1)
            rp.history.update(tid, me.uuid, TX_SCORE)
            rp.history.update(tid, peer.uuid, TX_SCORE)
        window = rp.history._indexed_window()
        ckpt = Checkpoint(proposer_uuid=me.uuid, root=rp.history.window_root(),
                          epoch=2, first_index=window[0].index,
                          count=len(window))
        sigs = {str(i.uuid): i.sign(ckpt.designation).signature.decode('ascii')
                for i in (me, peer)}
        rp._store_checkpoint(ckpt, sigs)
        assert _evidence_file(cfg_root).exists()

        restarted = _make_rep_process(
            identity=me, peers=[peer],
            reputations=Reputations({peer.uuid: 0.75}))
        assert restarted.reputations.current[_uu(peer.uuid)] == pytest.approx(0.75)
        assert len(restarted.history) == 20
        assert restarted.history.window_root() == rp.history.window_root()

    def test_fuller_signature_set_upgrades_the_file(self, cfg_root):
        """The proposer self-stores holding only its own signature; the quorum
        map arrives later and must replace it on disk, or the evidence stays
        attested by nobody but us."""
        me = _identity('me')
        peer = _identity('peer-a')
        rp = _make_rep_process(identity=me, peers=[peer])
        for i in range(2):
            tid = UUID(int=i + 1)
            rp.history.update(tid, me.uuid, 0.9)
            rp.history.update(tid, peer.uuid, 0.9)
        window = rp.history._indexed_window()
        ckpt = Checkpoint(proposer_uuid=me.uuid, root=rp.history.window_root(),
                          epoch=1, first_index=window[0].index,
                          count=len(window))
        own = {str(me.uuid): me.sign(ckpt.designation).signature.decode('ascii')}
        rp._store_checkpoint(ckpt, own)
        assert len(json.loads(_evidence_file(cfg_root).read_text())
                   ['checkpoint']['sigs']) == 1
        full = dict(own)
        full[str(peer.uuid)] = \
            peer.sign(ckpt.designation).signature.decode('ascii')
        rp._store_checkpoint(ckpt, full)  # same key: the dedup path
        assert len(json.loads(_evidence_file(cfg_root).read_text())
                   ['checkpoint']['sigs']) == 2

    def test_unwritable_cfg_dir_is_survivable(self, monkeypatch, tmp_path):
        """The evidence is an optimization of trust: losing it costs a warm
        start its elevated tiers and nothing else, so a write failure must
        never reach the caller."""
        monkeypatch.setenv(Configuration.ROOT_VARIABLE_NAME,
                           str(tmp_path / 'nonexistent'))
        me = _identity('me')
        rp = _make_rep_process(identity=me)
        rp.history.update(UUID(int=1), me.uuid, 0.9)
        rp.history.update(UUID(int=1), uuid4(), 0.9)
        ckpt = Checkpoint(proposer_uuid=me.uuid, root=rp.history.window_root(),
                          epoch=1, first_index=0, count=1)
        rp._store_checkpoint(ckpt, {})  # must not raise
        assert rp._checkpoint is ckpt
