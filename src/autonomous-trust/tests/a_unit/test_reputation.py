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
from types import SimpleNamespace
from uuid import uuid4

from autonomous_trust.core.reputation.reputation import (
    TransactionScore, Transaction, TransactionHistory,
    Reputation, Reputations,
)
from autonomous_trust.core.reputation.repprocess import ReputationProcess


class TestTransactionScore:
    def test_init(self):
        ts = TransactionScore(task_id=uuid4(), score=0.9)
        assert ts.score == 0.9


class TestTransaction:
    def test_len_empty(self):
        tx = Transaction(task_id=uuid4())
        assert len(tx) == 0

    def test_len_one(self):
        tx = Transaction(task_id=uuid4(), p1_id=uuid4(), p1_score=0.5)
        assert len(tx) == 1

    def test_len_two(self):
        tx = Transaction(task_id=uuid4(), p1_id=uuid4(), p1_score=0.5,
                         p2_id=uuid4(), p2_score=0.8)
        assert len(tx) == 2

    def test_add_first(self):
        tx = Transaction(task_id=uuid4())
        pid = uuid4()
        tx.add(pid, 0.7)
        assert tx.p1_id == pid
        assert tx.p1_score == 0.7
        assert len(tx) == 1

    def test_add_second(self):
        tx = Transaction(task_id=uuid4())
        p1, p2 = uuid4(), uuid4()
        tx.add(p1, 0.7)
        tx.add(p2, 0.9)
        assert tx.p2_id == p2
        assert tx.p2_score == 0.9
        assert len(tx) == 2


class TestTransactionHistory:
    def test_empty_init(self):
        th = TransactionHistory()
        assert len(th) == 0

    def test_update_creates_transaction(self):
        th = TransactionHistory()
        tid = uuid4()
        p1, p2 = uuid4(), uuid4()
        th.update(tid, p1, 0.8)
        th.update(tid, p2, 0.9)
        assert len(th) == 1
        assert th[tid].p1_id == p1
        assert th[tid].p2_id == p2

    def test_update_ignores_duplicate(self):
        th = TransactionHistory()
        tid = uuid4()
        p1, p2, p3 = uuid4(), uuid4(), uuid4()
        th.update(tid, p1, 0.8)
        th.update(tid, p2, 0.9)
        th.update(tid, p3, 0.5)  # ignored since already 2 participants
        assert th[tid].p2_id == p2  # unchanged

    def test_by_peer(self):
        th = TransactionHistory()
        tid = uuid4()
        p1, p2 = uuid4(), uuid4()
        th.update(tid, p1, 0.8)
        th.update(tid, p2, 0.9)
        assert len(th.by_peer(p1)) >= 1

    def test_era(self):
        th = TransactionHistory()
        for _ in range(3):
            tid = uuid4()
            th.update(tid, uuid4(), 0.5)
            th.update(tid, uuid4(), 0.6)
        chain = th.era(1)
        assert len(chain) == 2

    def test_catchup(self):
        th = TransactionHistory()
        tid = uuid4()
        p1, p2 = uuid4(), uuid4()
        chain = [Transaction(tid, p1, 0.8, p2, 0.9, index=5)]
        th.catchup(chain)
        # catchup checks if index > len(chain), so with empty chain and index=5, it adds
        assert len(th) == 1

    def test_init_with_chain(self):
        tid = uuid4()
        p1, p2 = uuid4(), uuid4()
        tx = Transaction(tid, p1, 0.8, p2, 0.9, index=0)
        th = TransactionHistory(_chain=[tx])
        assert len(th) == 1
        assert th[tid] is tx

    def test_eviction_caps_chain_length(self):
        # Lockstep with the C twin's test_tx_history_eviction in
        # src/c/test/reputation2_test.c — both confirm FIFO eviction
        # at max_chain_len so divergence fails one language's tests
        # immediately. shared is always the p2 (second update) so we
        # avoid the long-standing _map_peers double-append for the
        # p1 side; this test is about eviction, not the bilateral
        # mapping quirk.
        cap = 3
        th = TransactionHistory(max_chain_len=cap)
        shared = uuid4()
        tids = []
        for _ in range(cap + 2):
            tid = uuid4()
            tids.append(tid)
            th.update(tid, uuid4(), 0.7)
            th.update(tid, shared, 0.3)
        assert len(th) == cap
        # Oldest 2 task_ids were evicted from the task map.
        for tid in tids[:2]:
            assert tid not in th
        # Most recent are present.
        for tid in tids[-cap:]:
            assert tid in th
        # by_peer for the shared p2 peer is bounded by the residency
        # window, not by the total number of inserts.
        assert len(th.by_peer(shared)) == cap

    def test_eviction_keeps_tx_index_monotonic(self):
        th = TransactionHistory(max_chain_len=3)
        for i in range(5):
            tid = uuid4()
            th.update(tid, uuid4(), 0.5)
            th.update(tid, uuid4(), 0.6)
        # Indices in the resident chain should be 2, 3, 4 — preserved
        # across evictions so era() and catchup() remain coherent.
        assert [tx.index for tx in th._chain] == [2, 3, 4]
        assert th._first_index == 2
        assert th._next_index == 5
        # era() takes absolute indices and clips below the window.
        assert len(th.era(0)) == 3
        assert len(th.era(3)) == 2

    def test_env_var_overrides_default_cap(self, monkeypatch):
        monkeypatch.setenv('AT_TX_HISTORY_CAP', '7')
        th = TransactionHistory()
        assert th.max_chain_len == 7

    def test_constructor_arg_beats_env(self, monkeypatch):
        monkeypatch.setenv('AT_TX_HISTORY_CAP', '7')
        th = TransactionHistory(max_chain_len=11)
        assert th.max_chain_len == 11

    def test_evicted_task_does_not_reanimate(self):
        # Late `committed` broadcasts arrive at every peer's
        # handle_committed, which calls history.update without
        # knowing whether the task was already rolled out. Once a
        # task_id has been evicted, update() must refuse to re-add
        # it — otherwise a half-completed Transaction lingers in
        # _task_mapping and any counterparty-side late broadcast
        # would complete it and re-insert it at the head of the
        # chain. See TransactionHistory class docstring.
        cap = 3
        th = TransactionHistory(max_chain_len=cap)
        first_tid = uuid4()
        # Fill the chain past cap so first_tid is evicted.
        for i in range(cap + 2):
            tid = first_tid if i == 0 else uuid4()
            th.update(tid, uuid4(), 0.7)
            th.update(tid, uuid4(), 0.3)
        assert first_tid in th._evicted_task_ids
        # Late "committed" for the evicted task — both sides.
        evicted_p1, evicted_p2 = uuid4(), uuid4()
        th.update(first_tid, evicted_p1, 0.7)
        th.update(first_tid, evicted_p2, 0.3)
        # The chain length must not exceed cap, the evicted task
        # must not be re-added, and _task_mapping must not be
        # poisoned with a half-completed orphan.
        assert len(th) == cap
        assert first_tid not in th._task_mapping

    # ----- Phase 1: prev-hash linking (reputation-vs-blockchain-analysis
    # §2.1). Lockstep with the C twin's hash-link tests in
    # src/c/test/reputation2_test.c — keep the canonical serialization and
    # blake2b hashing byte-identical so the two languages agree on links.

    def test_genesis_entry_has_empty_prev_hash(self):
        th = TransactionHistory()
        tid = uuid4()
        th.update(tid, uuid4(), 0.7)
        th.update(tid, uuid4(), 0.5)
        # The first committed entry chains from the empty genesis digest.
        assert th[tid].prev_hash in (b'', None)

    def test_each_entry_links_to_previous(self):
        th = TransactionHistory()
        for _ in range(4):
            tid = uuid4()
            th.update(tid, uuid4(), 0.7)
            th.update(tid, uuid4(), 0.5)
        chain = list(th)
        for i in range(1, len(chain)):
            assert chain[i].prev_hash == chain[i - 1].entry_hash()
        assert th.verify_links() is True

    def test_verify_links_detects_tampering(self):
        th = TransactionHistory()
        for _ in range(4):
            tid = uuid4()
            th.update(tid, uuid4(), 0.7)
            th.update(tid, uuid4(), 0.5)
        assert th.verify_links() is True
        # Mutating a committed score changes that entry's hash, breaking
        # the link its successor recorded.
        list(th)[1].p1_score = 0.99
        assert th.verify_links() is False

    def test_links_survive_eviction(self):
        # Eviction drops the head and never rewrites the tail's prev_hash,
        # so the resident window stays internally linked.
        th = TransactionHistory(max_chain_len=3)
        for _ in range(6):
            tid = uuid4()
            th.update(tid, uuid4(), 0.7)
            th.update(tid, uuid4(), 0.5)
        assert len(th) == 3
        assert th.verify_links() is True

    def test_verify_chain_links_static(self):
        th = TransactionHistory()
        for _ in range(3):
            tid = uuid4()
            th.update(tid, uuid4(), 0.7)
            th.update(tid, uuid4(), 0.5)
        chain = list(th)
        assert TransactionHistory.verify_chain_links(chain) is True
        # A single-entry or empty segment trivially verifies.
        assert TransactionHistory.verify_chain_links(chain[:1]) is True
        assert TransactionHistory.verify_chain_links([]) is True

    def test_catchup_rejects_broken_chain(self):
        # Build a valid committed chain, then corrupt a middle entry. The
        # receiver must verify the segment's linkage and replay nothing.
        src = TransactionHistory()
        for _ in range(3):
            tid = uuid4()
            src.update(tid, uuid4(), 0.7)
            src.update(tid, uuid4(), 0.5)
        good = list(src)
        dst = TransactionHistory()
        dst.catchup(good)
        assert len(dst) == 3  # clean chain accepted

        bad = list(TransactionHistory(_chain=[
            Transaction(t.task_id, t.p1_id, t.p1_score, t.p2_id,
                        t.p2_score, t.index, t.prev_hash) for t in good]))
        bad[1].p2_score = -1.0  # break the link to bad[2]
        dst2 = TransactionHistory()
        dst2.catchup(bad)
        assert len(dst2) == 0  # tampered chain rejected wholesale

    def test_prev_hash_survives_wire_round_trip(self):
        from autonomous_trust.core.config import (
            to_json_string, from_json_string)
        th = TransactionHistory()
        for _ in range(3):
            tid = uuid4()
            th.update(tid, uuid4(), 0.7)
            th.update(tid, uuid4(), 0.5)
        wire = from_json_string(to_json_string(list(th)))
        assert isinstance(wire[1].prev_hash, bytes)
        assert TransactionHistory.verify_chain_links(wire) is True

    # ----- Phase 2: ordered Merkle root over the resident window
    # (reputation-vs-blockchain-analysis.md §2.1). Lockstep with the C twin's
    # transaction_window_root tests in src/c/test/reputation2_test.c.

    @staticmethod
    def _fill(th, n):
        for _ in range(n):
            tid = uuid4()
            th.update(tid, uuid4(), 0.7)
            th.update(tid, uuid4(), 0.5)
        return th

    def test_empty_window_root_is_hash_of_empty(self):
        from autonomous_trust.core.structures.merkle import MerkleTree
        th = TransactionHistory()
        assert th.window_root() == MerkleTree.get_hash(b'')

    def test_window_root_is_deterministic_and_content_bound(self):
        # Same committed content -> same root; mutating any entry changes it.
        a = self._fill(TransactionHistory(), 5)
        b = TransactionHistory(_chain=[
            Transaction(t.task_id, t.p1_id, t.p1_score, t.p2_id,
                        t.p2_score, t.index, t.prev_hash) for t in list(a)])
        assert a.window_root() == b.window_root()
        b._chain[2].p1_score = 0.123456789
        assert a.window_root() != b.window_root()

    def test_single_entry_root_matches_rfc6962_leaf(self):
        from autonomous_trust.core.structures.merkle import MerkleTree
        th = self._fill(TransactionHistory(), 1)
        leaf = th._chain[0].entry_hash()
        assert th.window_root() == MerkleTree.get_hash(b'\x00' + leaf)

    def test_inclusion_proof_verifies_for_every_entry(self):
        th = self._fill(TransactionHistory(), 7)  # not a power of two
        root = th.window_root()
        for tx in th._chain:
            proof = th.inclusion_proof(tx.index)
            assert proof is not None
            assert TransactionHistory.verify_inclusion(
                tx.entry_hash(), proof, root) is True

    def test_inclusion_proof_rejects_wrong_leaf_or_root(self):
        th = self._fill(TransactionHistory(), 4)
        root = th.window_root()
        tx = th._chain[1]
        proof = th.inclusion_proof(tx.index)
        # Wrong leaf digest under a valid proof/root -> fail.
        assert TransactionHistory.verify_inclusion(
            th._chain[2].entry_hash(), proof, root) is False
        # Correct leaf/proof but wrong root -> fail.
        assert TransactionHistory.verify_inclusion(
            tx.entry_hash(), proof, b'not-the-root') is False

    def test_inclusion_proof_none_for_absent_index(self):
        th = self._fill(TransactionHistory(), 3)
        assert th.inclusion_proof(9999) is None
        assert TransactionHistory.verify_inclusion(b'x', None, b'y') is False

    def test_window_root_tracks_eviction(self):
        # Root commits to the RESIDENT window; eviction rolls it forward.
        th = TransactionHistory(max_chain_len=3)
        self._fill(th, 3)
        root_before = th.window_root()
        self._fill(th, 1)  # evicts oldest, appends newest
        assert len(th) == 3
        assert th.window_root() != root_before
        # Every still-resident entry remains provable against the new root.
        for tx in th._chain:
            assert TransactionHistory.verify_inclusion(
                tx.entry_hash(), th.inclusion_proof(tx.index),
                th.window_root()) is True


class TestReputation:
    def test_init(self):
        pid = uuid4()
        r = Reputation(peer_id=pid, score=0.95)
        assert r.peer_id == pid
        assert r.score == 0.95


class TestReputations:
    def test_empty_init(self):
        r = Reputations()
        assert uuid4() not in r

    def test_update_and_get(self):
        r = Reputations()
        pid = uuid4()
        r.update(pid, 0.88)
        assert pid in r
        assert r[pid] == 0.88

    def test_update_overwrite(self):
        r = Reputations()
        pid = uuid4()
        r.update(pid, 0.5)
        r.update(pid, 0.9)
        assert r[pid] == 0.9

    def test_init_with_data(self):
        pid = uuid4()
        r = Reputations(current={pid: 0.7})
        assert r[pid] == 0.7


# Algorithm pins for ReputationProcess._contrite_tit_for_tat and
# ._pure_reputation.  These mirror the C unit tests in
# src/c/test/reputation3_test.c (test_reputation_contrite_tft,
# test_reputation_pure_with_counterparty) using identical input shapes
# and expected outputs, so cross-language divergence in the algorithm
# fails one side's tests immediately.  Documented in
# doc/architecture/reputation.md:71-83.

def _stub_proc(self_uuid, reputations=None):
    """Build the minimal SimpleNamespace that _contrite_tit_for_tat /
    _pure_reputation read off ``self``: history, identity, reputations,
    logger, task_weights.  Constructing a real ReputationProcess pulls
    in queues, keys, and a temp config dir we don't need here."""
    stub = SimpleNamespace()
    stub.history = TransactionHistory()
    stub.identity = SimpleNamespace(uuid=self_uuid)
    stub.reputations = reputations or Reputations()
    stub.logger = SimpleNamespace(debug=lambda *a, **k: None)
    # _pure_reputation weights each TS by the originating capability's
    # transaction_weight, looked up via self.task_weights[task_id]
    # (doc/architecture/trust-tiers.md §5). Default per-task weight 1
    # mirrors the production fallback when the cache is empty.
    stub.task_weights = {}
    # _contrite_tit_for_tat now defers its cold-start (no-bilateral-history)
    # branch to _prereputation_prior; bind the real method so the stub
    # exercises the production algorithm rather than a fake.
    stub._prereputation_prior = lambda pid: \
        ReputationProcess._prereputation_prior(stub, pid)
    stub.PREREP_NEUTRAL = ReputationProcess.PREREP_NEUTRAL
    stub.PREREP_SHRINKAGE_K = ReputationProcess.PREREP_SHRINKAGE_K
    return stub


class TestContriteTitForTat:
    def test_empty_history_returns_neutral(self):
        # No bilateral history AND nothing on the chain → cold-start prior
        # returns PREREP_NEUTRAL (0.2): an unknown peer starts at neutral
        # (a small leeway above the 0.1 comm cut-off) and must earn its
        # way up.
        self_id, peer_id = uuid4(), uuid4()
        stub = _stub_proc(self_id)
        peer = SimpleNamespace(uuid=peer_id)
        assert ReputationProcess._contrite_tit_for_tat(stub, peer) == 0.2

    def test_cooperative_self_p1(self):
        """Self enters as p1, peer as p2, both cooperate. Falls into
        the cooperate branch → max(0.51, peer_standing) = 0.8."""
        self_id, peer_id, task = uuid4(), uuid4(), uuid4()
        stub = _stub_proc(self_id)
        stub.history.update(task, self_id, 0.9)  # self → p1
        stub.history.update(task, peer_id, 0.8)  # peer → p2
        score = ReputationProcess._contrite_tit_for_tat(
            stub, SimpleNamespace(uuid=peer_id))
        assert score == pytest.approx(0.8, abs=0.001)

    def test_cooperative_self_p2(self):
        """Peer enters as p1, self as p2.  Same expected output — the
        algorithm must be order-symmetric in which side filled p1
        first.  This is the exact case the previous swap bug
        regressed."""
        self_id, peer_id, task = uuid4(), uuid4(), uuid4()
        stub = _stub_proc(self_id)
        stub.history.update(task, peer_id, 0.8)  # peer → p1
        stub.history.update(task, self_id, 0.9)  # self → p2
        score = ReputationProcess._contrite_tit_for_tat(
            stub, SimpleNamespace(uuid=peer_id))
        assert score == pytest.approx(0.8, abs=0.001)

    def test_retaliation_branch(self):
        """Peer defected on last tx (0.2) and self's standing is good
        (mean 0.9) → retaliation branch → min(0.49, peer_standing) =
        0.2."""
        self_id, peer_id = uuid4(), uuid4()
        stub = _stub_proc(self_id)
        t1, t2 = uuid4(), uuid4()
        stub.history.update(t1, self_id, 0.9)
        stub.history.update(t1, peer_id, 0.8)  # peer cooperated once
        stub.history.update(t2, self_id, 0.9)
        stub.history.update(t2, peer_id, 0.2)  # peer defects, peer_last
        score = ReputationProcess._contrite_tit_for_tat(
            stub, SimpleNamespace(uuid=peer_id))
        # peer_standing = (0.8 + 0.2) / 2 = 0.5; my_standing = 0.9.
        # peer_last < 0.5, my_standing >= 0.5 → min(0.49, 0.5) = 0.49.
        assert score == pytest.approx(0.49, abs=0.001)

    def test_contrition_branch(self):
        """Peer defected on last tx but my standing is also poor →
        contrition branch → max(0.51, peer_standing)."""
        self_id, peer_id = uuid4(), uuid4()
        stub = _stub_proc(self_id)
        t1, t2 = uuid4(), uuid4()
        stub.history.update(t1, self_id, 0.2)   # self defected too
        stub.history.update(t1, peer_id, 0.3)
        stub.history.update(t2, self_id, 0.2)
        stub.history.update(t2, peer_id, 0.4)   # peer_last < 0.5
        score = ReputationProcess._contrite_tit_for_tat(
            stub, SimpleNamespace(uuid=peer_id))
        # peer_standing = (0.3 + 0.4) / 2 = 0.35; my_standing = 0.2
        # peer_last < 0.5, my_standing < 0.5 → max(0.51, 0.35) = 0.51.
        assert score == pytest.approx(0.51, abs=0.001)

    def test_third_party_transactions_inform_prior(self):
        """Third-party transactions (peer ↔ other, no self involvement) do
        not enter the *bilateral* CTFT computation, but with no bilateral
        history WITH us they now feed the cold-start prior
        (_prereputation_prior) instead of a flat neutral (deferred.md §2.4)."""
        self_id, peer_id, other = uuid4(), uuid4(), uuid4()
        stub = _stub_proc(self_id)
        t = uuid4()
        stub.history.update(t, peer_id, 0.1)   # peer → p1
        stub.history.update(t, other, 0.1)     # other → p2 (scores the peer)
        score = ReputationProcess._contrite_tit_for_tat(
            stub, SimpleNamespace(uuid=peer_id))
        # observed standing = other's score about peer = 0.1 (cp_rep cancels
        # in the weighted mean of a single observation), shrunk toward
        # neutral 0.2: (1*0.1 + 3*0.2) / (1+3) = 0.175.
        assert score == pytest.approx(0.175, abs=0.001)


class TestPrereputationPrior:
    """The CTFT cold-start prior (deferred.md §2.4). Mirror in C:
    reputation_prereputation_prior / src/c/test reputation tests."""

    def test_no_observations_returns_neutral(self):
        self_id, peer_id = uuid4(), uuid4()
        stub = _stub_proc(self_id)
        assert ReputationProcess._prereputation_prior(stub, peer_id) \
            == pytest.approx(0.2, abs=1e-9)

    def test_self_counterparty_excluded(self):
        # A one-sided tx where WE are the counterparty must not seed the
        # prior (that is the bilateral path's job, not the cold-start prior).
        self_id, peer_id = uuid4(), uuid4()
        stub = _stub_proc(self_id)
        t = uuid4()
        stub.history.update(t, peer_id, 0.9)   # peer → p1
        stub.history.update(t, self_id, 0.2)   # self → p2 (we score peer)
        # self is excluded → no third-party observation → neutral.
        assert ReputationProcess._prereputation_prior(stub, peer_id) \
            == pytest.approx(0.2, abs=1e-9)

    def test_shrinks_toward_neutral_with_sample_size(self):
        # More consistent third-party evidence pulls the prior further from
        # neutral toward the observed mean.
        self_id, peer_id = uuid4(), uuid4()
        reps = Reputations()
        stub = _stub_proc(self_id, reputations=reps)
        others = [uuid4() for _ in range(4)]
        for i, o in enumerate(others):
            t = uuid4()
            stub.history.update(t, peer_id, 0.9)  # peer → p1
            stub.history.update(t, o, 0.9)        # other scores peer 0.9
        prior = ReputationProcess._prereputation_prior(stub, peer_id)
        # observed=0.9, n=4, k=3, neutral=0.2 → (4*0.9 + 3*0.2)/7 = 0.6.
        assert prior == pytest.approx((4 * 0.9 + 3 * 0.2) / 7, abs=0.001)
        assert 0.2 < prior < 0.9

    def test_kill_switch_restores_flat_neutral(self, monkeypatch):
        monkeypatch.setenv('AT_PREREP_HEURISTIC', '0')
        self_id, peer_id, other = uuid4(), uuid4(), uuid4()
        stub = _stub_proc(self_id)
        t = uuid4()
        stub.history.update(t, peer_id, 0.9)
        stub.history.update(t, other, 0.9)
        assert ReputationProcess._prereputation_prior(stub, peer_id) == 0.2


class TestPureReputation:
    def test_empty_history_returns_neutral(self):
        """Default PREREP_NEUTRAL (0.2) on no history (mirrors C).
        Returning a lower value would route the peer right back into
        CTFT mode."""
        self_id, peer_id = uuid4(), uuid4()
        stub = _stub_proc(self_id)
        score = ReputationProcess._pure_reputation(
            stub, SimpleNamespace(uuid=peer_id))
        assert score == 0.2

    def test_weighted_average(self):
        """Counterparty score weighted by counterparty reputation."""
        self_id, peer_id = uuid4(), uuid4()
        reps = Reputations()
        reps.update(self_id, 0.8)
        stub = _stub_proc(self_id, reputations=reps)
        t = uuid4()
        stub.history.update(t, peer_id, 0.9)   # peer is p1
        stub.history.update(t, self_id, 0.7)   # self is p2 (counterparty)
        score = ReputationProcess._pure_reputation(
            stub, SimpleNamespace(uuid=peer_id))
        # counterparty_score = 0.7, cp_rep = 0.8 → 0.56.
        assert score == pytest.approx(0.56, abs=0.001)

    def test_unknown_counterparty_uses_default_neutral(self):
        """Counterparty missing from self.reputations falls back to
        PREREP_NEUTRAL (0.2, mirrors C); does not silently skip the
        transaction."""
        self_id, peer_id = uuid4(), uuid4()
        stub = _stub_proc(self_id)  # empty reputations dict
        t = uuid4()
        stub.history.update(t, peer_id, 0.9)
        stub.history.update(t, self_id, 0.6)
        score = ReputationProcess._pure_reputation(
            stub, SimpleNamespace(uuid=peer_id))
        # counterparty_score = 0.6, cp_rep = 0.2 → 0.12.
        assert score == pytest.approx(0.12, abs=0.001)


class TestProposerHistoryBilateral:
    """Bug 4 regression: the proposer's local history must record a
    bilateral transaction after both peers paxos-commit for the same
    task_id.  Before the fix, `forward_transaction` wrote
    (task_id, self, self_score) immediately and `handle_accepted` for
    the proposer's own round wrote the same tuple again, filling p2
    with self.  Subsequent peer submissions were then dropped by
    `TransactionHistory.update` (len(tx)==2 guard).

    These tests simulate the post-commit step (handle_accepted's call
    to `self.history.update`) directly, bypassing the paxos messaging
    that's already exercised by the conformance scenarios.  The
    invariant we pin is purely about *what ends up in history*."""

    def test_proposer_history_records_bilateral(self):
        self_id, peer_id = uuid4(), uuid4()
        history = TransactionHistory()
        task = uuid4()

        # Proposer's own paxos commit (was preceded by the now-removed
        # local forward_transaction write).
        history.update(task, self_id, 0.9)
        # Peer's paxos commit for the same task arrives.
        history.update(task, peer_id, 0.3)

        tx = history[task]
        # Both slots filled and the two peers are distinct.
        assert {tx.p1_id, tx.p2_id} == {self_id, peer_id}
        # Score for self is 0.9, for peer is 0.3.
        if tx.p1_id == self_id:
            assert tx.p1_score == pytest.approx(0.9)
            assert tx.p2_score == pytest.approx(0.3)
        else:
            assert tx.p2_score == pytest.approx(0.9)
            assert tx.p1_score == pytest.approx(0.3)

    def test_committed_broadcast_writes_acceptor_history(self):
        """Phase 3 (Bug 5 fix): a peer receiving a `committed`
        broadcast must write (task_id, proposer_id, score) to its
        own history — *unless* the broadcast is its own bounce-back,
        in which case handle_accepted already wrote it locally."""
        from autonomous_trust.core.reputation.protocol import (
            ReputationProtocol,
        )
        from autonomous_trust.core.config import to_json_string

        self_id, peer_id = uuid4(), uuid4()
        history = TransactionHistory()

        stub = SimpleNamespace()
        stub.history = history
        # Gateway-tree routing: a legacy 3-tuple commit carries no
        # group_uuid, so _chain_for_group(None) resolves to the primary
        # chain — which for this leaf stub is just `history`.
        stub._chain_for_group = lambda g: history
        stub._note_interaction = lambda *a, **k: None
        stub._fold_committed_tx = lambda *a, **k: None
        stub.identity = SimpleNamespace(uuid=self_id)
        stub.logger = SimpleNamespace(
            warning=lambda *a, **k: None, debug=lambda *a, **k: None,
            info=lambda *a, **k: None)

        task = uuid4()
        msg = SimpleNamespace(
            function=ReputationProtocol.committed,
            obj=to_json_string((task, peer_id, 0.7)),
        )
        ReputationProcess.handle_committed(stub, {}, msg)

        # Acceptor wrote the proposer's entry.
        tx = history[task]
        assert tx.p1_id == peer_id
        assert tx.p1_score == pytest.approx(0.7)
        assert tx.p2_id is None  # only the proposer's slot is filled

        # Bouncing-back broadcast from self — should be skipped to
        # avoid double-write (handle_accepted already wrote it).
        msg_self = SimpleNamespace(
            function=ReputationProtocol.committed,
            obj=to_json_string((task, self_id, 0.9)),
        )
        ReputationProcess.handle_committed(stub, {}, msg_self)
        # Re-fetch; p2 must still be empty.
        tx = history[task]
        assert tx.p2_id is None

    def test_bilateral_via_two_commits(self):
        """Putting the two halves together: a proposer's own
        handle_accepted writes their entry; the peer's committed
        broadcast then fills the second slot.  This is the path
        CTFT relies on for non-default scoring."""
        from autonomous_trust.core.reputation.protocol import (
            ReputationProtocol,
        )
        from autonomous_trust.core.config import to_json_string

        self_id, peer_id = uuid4(), uuid4()
        history = TransactionHistory()
        task = uuid4()

        # 1. Self's handle_accepted reaches majority — writes
        #    (task, self, 0.9) directly.  We simulate that with a
        #    plain history.update.
        history.update(task, self_id, 0.9)
        assert {history[task].p1_id, history[task].p2_id} == {self_id, None}

        # 2. Peer's committed broadcast arrives.  Our handle_committed
        #    fills the second slot.
        stub = SimpleNamespace(
            history=history,
            # Legacy 3-tuple commit -> group_uuid None -> primary chain.
            _chain_for_group=lambda g: history,
            _note_interaction=lambda *a, **k: None,
            _fold_committed_tx=lambda *a, **k: None,
            identity=SimpleNamespace(uuid=self_id),
            logger=SimpleNamespace(
                warning=lambda *a, **k: None, debug=lambda *a, **k: None,
                info=lambda *a, **k: None),
        )
        msg = SimpleNamespace(
            function=ReputationProtocol.committed,
            obj=to_json_string((task, peer_id, 0.3)),
        )
        ReputationProcess.handle_committed(stub, {}, msg)

        tx = history[task]
        assert {tx.p1_id, tx.p2_id} == {self_id, peer_id}

    def test_forward_transaction_does_not_write_history(self):
        """Direct guard against Bug 4 regressing: forward_transaction
        must NOT touch history.  We stub _start_paxos so we don't
        have to build a real paxos environment — the assertion is
        purely that forward_transaction leaves history empty."""
        self_id = uuid4()
        history = TransactionHistory()
        start_paxos_calls = []

        stub = SimpleNamespace()
        stub.history = history
        stub.identity = SimpleNamespace(uuid=self_id)
        stub.logger = SimpleNamespace(
            error=lambda *a, **k: None, debug=lambda *a, **k: None)
        stub._start_paxos = lambda q, m: start_paxos_calls.append((q, m))

        task = uuid4()
        ts = TransactionScore(task_id=task, score=0.9)

        ReputationProcess.forward_transaction(stub, queues={}, message=ts)

        # _start_paxos was called…
        assert len(start_paxos_calls) == 1
        assert start_paxos_calls[0][1] is ts
        # …but history is still empty.
        assert len(history) == 0


class TestConsensusByTier:
    """Per-tier consensus aggregation (trust-tiers §12 / deferred.md §2.3).
    Mirror in C: reputation_consensus_by_tier (src/c/test reputation tests)."""

    def _stub(self):
        stub = SimpleNamespace()
        stub.history = TransactionHistory()
        stub.task_weights = {}
        stub.task_tiers = {}
        stub._per_tier_last = {}
        stub.CONSENSUS_EMA_HALF_LIFE = ReputationProcess.CONSENSUS_EMA_HALF_LIFE
        return stub

    def test_empty_history_returns_empty(self):
        stub = self._stub()
        assert ReputationProcess._consensus_reputation_by_tier(
            stub, uuid4()) == {}

    def test_partitions_score_by_capability_tier(self):
        stub = self._stub()
        peer, o1, o3 = uuid4(), uuid4(), uuid4()
        t1, t3 = uuid4(), uuid4()
        # tier-1 interaction: counterparty (o1) scores the peer 0.9.
        stub.history.update(t1, peer, 0.5)   # peer side (p1)
        stub.history.update(t1, o1, 0.9)     # counterparty scores peer (p2)
        stub.task_tiers[str(t1)] = 1
        # tier-3 interaction: counterparty (o3) scores the peer 0.4.
        stub.history.update(t3, peer, 0.5)
        stub.history.update(t3, o3, 0.4)
        stub.task_tiers[str(t3)] = 3
        result = ReputationProcess._consensus_reputation_by_tier(stub, peer)
        # "trusted at tier 1 (0.92-ish), untrusted at tier 3 (0.41-ish)".
        assert set(result) == {1, 3}
        assert result[1] == pytest.approx(0.9, abs=1e-6)
        assert result[3] == pytest.approx(0.4, abs=1e-6)
        # cached for later query
        assert stub._per_tier_last[str(peer)] == result

    def test_same_tier_folds_into_one_ema(self):
        stub = self._stub()
        peer, o1, o2 = uuid4(), uuid4(), uuid4()
        ta, tb = uuid4(), uuid4()
        for task, other, sc in ((ta, o1, 1.0), (tb, o2, 0.0)):
            stub.history.update(task, peer, 0.5)
            stub.history.update(task, other, sc)
            stub.task_tiers[str(task)] = 2
        result = ReputationProcess._consensus_reputation_by_tier(stub, peer)
        assert set(result) == {2}
        # one EMA over [1.0, 0.0]: starts at 1.0, then folds 0.0 → strictly
        # between 0 and 1, below the first sample.
        assert 0.0 < result[2] < 1.0

    def test_unmapped_task_defaults_to_tier_zero(self):
        stub = self._stub()
        peer, other = uuid4(), uuid4()
        t = uuid4()
        stub.history.update(t, peer, 0.5)
        stub.history.update(t, other, 0.8)
        # no task_tiers entry → bucket 0
        result = ReputationProcess._consensus_reputation_by_tier(stub, peer)
        assert set(result) == {0}
        assert result[0] == pytest.approx(0.8, abs=1e-6)


class TestResolveTxTier:
    """_resolve_tx_tier maps capability_name → required_tier (deferred.md §2.3)."""

    def test_resolves_registered_tier(self):
        from autonomous_trust.core.capabilities import Capabilities
        caps = Capabilities()
        caps.register_ability('cap.high', None, required_tier=3,
                              transaction_weight=8)
        stub = SimpleNamespace(protocol=SimpleNamespace(capabilities=caps))
        ts = TransactionScore(task_id=uuid4(), score=0.9,
                              capability_name='cap.high')
        assert ReputationProcess._resolve_tx_tier(stub, ts) == 3

    def test_unknown_capability_defaults_zero(self):
        from autonomous_trust.core.capabilities import Capabilities
        stub = SimpleNamespace(
            protocol=SimpleNamespace(capabilities=Capabilities()))
        ts = TransactionScore(task_id=uuid4(), score=0.9,
                              capability_name='cap.missing')
        assert ReputationProcess._resolve_tx_tier(stub, ts) == 0

    def test_no_capability_name_defaults_zero(self):
        stub = SimpleNamespace(protocol=SimpleNamespace(capabilities=None))
        ts = TransactionScore(task_id=uuid4(), score=0.9)
        assert ReputationProcess._resolve_tx_tier(stub, ts) == 0
