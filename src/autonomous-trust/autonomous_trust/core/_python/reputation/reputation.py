# ******************
#  Copyright 2023 TekFive, Inc., Sean M. Brennan, and contributors
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

import os
from collections import OrderedDict
from collections.abc import Mapping
from uuid import UUID

from ..config import Configuration
from ..structures.merkle import MerkleTree


class TransactionScore(Configuration):
    def __init__(self, task_id, score, capability_name: str = None):
        self.task_id = task_id
        self.score = score
        # Optional: name of the Capability whose execution produced this
        # TS. Used by _pure_reputation to look up transaction_weight at
        # scoring time (Slice 3). None means "unknown / legacy" — weight
        # defaults to 1. See doc/architecture/trust-tiers.md §4.4.
        self.capability_name = capability_name


class Transaction(Configuration):
    def __init__(self, task_id: UUID, p1_id: UUID = None, p1_score: float = None,
                 p2_id: UUID = None, p2_score: float = None, index: int = None,
                 prev_hash: bytes = None):
        self.task_id = task_id
        self.p1_id = p1_id
        self.p1_score = p1_score
        self.p2_id = p2_id
        self.p2_score = p2_score
        self.index = index
        # Phase 1 hash-linking: digest of the entry committed immediately
        # before this one in the resident chain (b'' / None for the genesis
        # entry or the oldest entry whose predecessor has been evicted). Set
        # by TransactionHistory when the tx goes bilateral and is appended.
        # Makes a committed Transaction tamper-evident on its own and the
        # catch-up sync verifiable (see reputation-vs-blockchain-analysis.md
        # §2.1). Mirrors transaction_t.prev_hash in the C twin; the canonical
        # serialization below MUST stay byte-identical across languages.
        self.prev_hash = prev_hash

    def __len__(self):
        if self.p1_id is None and self.p2_id is None:
            return 0
        if self.p1_id is None or self.p2_id is None:
            return 1
        return 2

    def _canonical_bytes(self) -> bytes:
        """Deterministic, language-agnostic serialization of the entry's
        identifying content (everything EXCEPT prev_hash). Floats use
        ``%.17g`` (round-trip-exact for IEEE-754 doubles and identical to
        C's ``snprintf("%.17g", …)``); UUIDs use the canonical lowercase
        hyphenated form (== C's ``uuid_unparse_lower``); None is ``null``.
        Keep this in lockstep with ``transaction_canonical_bytes`` in
        ``src/c/autonomous_trust/reputation/reputation.c``."""
        def _u(x):
            return 'null' if x is None else str(x)

        def _f(x):
            return 'null' if x is None else format(float(x), '.17g')

        def _i(x):
            return 'null' if x is None else str(int(x))

        return '|'.join((_u(self.task_id), _u(self.p1_id), _f(self.p1_score),
                         _u(self.p2_id), _f(self.p2_score),
                         _i(self.index))).encode('utf-8')

    def entry_hash(self) -> bytes:
        """blake2b digest (64-char lowercase-hex bytes, matching
        ``MerkleTree.get_hash``) over the canonical content chained with
        ``prev_hash``. This is the value the next entry stores as its
        ``prev_hash``, forming the tamper-evident link."""
        prev = self.prev_hash if self.prev_hash else b''
        return MerkleTree.get_hash(self._canonical_bytes() + prev)

    def add(self, peer_id: UUID, score: float):
        if self.p1_id is None:
            self.p1_id = peer_id
            self.p1_score = score
        elif self.p2_id is None and peer_id != self.p1_id:
            # A Transaction is intrinsically bilateral; the same peer cannot
            # occupy both slots. Without this guard a duplicate `committed`
            # broadcast for the same paxos round would set p2 = p1, producing
            # a self-transaction that CTFT's `p1==peer && p2==self` check
            # silently rejects.
            self.p2_id = peer_id
            self.p2_score = score


class TransactionHistory(Mapping):
    """Bounded commit log of bilateral Transactions.

    ``max_chain_len`` caps the resident chain (default
    ``DEFAULT_MAX_CHAIN_LEN``). When the cap is reached, the oldest
    committed tx is evicted from ``_chain`` along with its entries in
    ``_task_mapping`` and ``_peer_mapping``. ``tx.index`` stays
    monotonically increasing across evictions so ``era()`` and
    ``catchup()`` retain absolute-index semantics — only the suffix
    still resident in ``_chain`` is materializable.

    Override the default with ``max_chain_len`` (constructor) or the
    ``AT_TX_HISTORY_CAP`` env var; constructor wins. Loaded chains
    longer than the cap are accepted as-is — trimming starts on the
    first new ``update()``. Mirrors the C twin in
    ``src/c/autonomous_trust/reputation/reputation.c``; keep
    eviction semantics in lockstep so the conformance corpus stays
    valid.

    Behavior change vs. the unbounded predecessor: ``catchup()`` no
    longer back-fills indices below ``_next_index`` (i.e. anything
    already evicted is gone — peers that need the old prefix can
    no longer fetch it from us). Acceptable because reputation
    scoring weights recent txs heavily, and consensus drift past
    the window is unrecoverable anyway.

    Tombstone: evicted ``task_id``s are kept in ``_evicted_task_ids``
    (a bounded FIFO ordered set the same size as the chain) so
    ``update()`` can refuse to re-create entries for tasks we
    already committed and rolled out. Without this, a late
    ``committed`` broadcast — common when handle_accepted's dedup
    window is exceeded and re-broadcasts fire — would call
    ``update(evicted_task, …)``, the ``task_id not in _task_mapping``
    branch would create a fresh ``Transaction``, and the
    counterparty's late ``committed`` would complete it and append
    a zombie to the head of the chain (evicting a legitimate recent
    entry). The tombstone breaks that loop.
    """

    DEFAULT_MAX_CHAIN_LEN = 200

    def __init__(self, _chain: list[Transaction] = None,
                 max_chain_len: int = None):
        if max_chain_len is None:
            env = os.environ.get('AT_TX_HISTORY_CAP')
            try:
                max_chain_len = (int(env) if env
                                 else self.DEFAULT_MAX_CHAIN_LEN)
            except ValueError:
                max_chain_len = self.DEFAULT_MAX_CHAIN_LEN
        if max_chain_len < 1:
            raise ValueError("max_chain_len must be >= 1")
        self.max_chain_len = max_chain_len
        self._chain: list[Transaction] = list(_chain) if _chain else []
        self._task_mapping: dict[UUID, Transaction] = {
            link.task_id: link for link in self._chain}
        self._peer_mapping: dict[UUID, list[Transaction]] = {}
        for link in self._chain:
            self._map_peers(link)
        # Monotonic insertion counter — survives evictions so
        # tx.index keeps growing forever. Seed past the highest
        # index already in the loaded chain (if any) so subsequent
        # appends don't collide.
        max_existing = max(
            (link.index for link in self._chain if link.index is not None),
            default=-1)
        self._next_index = max_existing + 1
        # Absolute index of self._chain[0] — needed to translate an
        # absolute era(idx) request into a deque-relative offset after
        # the head has been rolled forward by eviction.
        if self._chain and self._chain[0].index is not None:
            self._first_index = self._chain[0].index
        else:
            self._first_index = 0
        # Tombstone: FIFO ordered set of evicted task_ids. Sized to
        # match max_chain_len so we remember the most-recent
        # max_chain_len evictions; combined with the resident chain,
        # the dedup horizon covers the last 2 * max_chain_len task_ids.
        # See class docstring for the late-committed reanimation
        # hazard this guards against.
        self._evicted_task_ids: 'OrderedDict[UUID, None]' = OrderedDict()
        # Phase 1 hash-linking: digest of the current chain head (the most
        # recently appended entry), i.e. the prev_hash the next finalized tx
        # will carry. b'' before the first commit. Recomputed from the loaded
        # chain's tail so a persisted/synced chain resumes the link cleanly.
        self._head_hash: bytes = (self._chain[-1].entry_hash()
                                  if self._chain else b'')

    def _map_peers(self, tx: Transaction):
        if tx.p1_id is not None:
            if tx.p1_id not in self._peer_mapping:
                self._peer_mapping[tx.p1_id] = []
            self._peer_mapping[tx.p1_id].append(tx)
        if tx.p2_id is not None:
            if tx.p2_id not in self._peer_mapping:
                self._peer_mapping[tx.p2_id] = []
            self._peer_mapping[tx.p2_id].append(tx)

    def _evict_oldest(self):
        """Drop chain[0] and scrub it from the task and peer maps.

        Identity-compares on removal because ``_map_peers`` may have
        appended the same tx twice to the same peer's list (it fires
        on both the p1-only and completed states), so a single
        ``list.remove`` would leave a stale reference behind.
        """
        oldest = self._chain.pop(0)
        self._task_mapping.pop(oldest.task_id, None)
        for peer_id in {oldest.p1_id, oldest.p2_id} - {None}:
            lst = self._peer_mapping.get(peer_id)
            if not lst:
                continue
            lst[:] = [tx for tx in lst if tx is not oldest]
            if not lst:
                del self._peer_mapping[peer_id]
        # Tombstone the evicted task so late `committed` broadcasts
        # for it can't reanimate a zombie entry. Bounded same as
        # the chain — together they cover 2 * max_chain_len task_ids.
        self._evicted_task_ids[oldest.task_id] = None
        while len(self._evicted_task_ids) > self.max_chain_len:
            self._evicted_task_ids.popitem(last=False)
        if self._chain and self._chain[0].index is not None:
            self._first_index = self._chain[0].index
        else:
            self._first_index = self._next_index

    def __getitem__(self, key):
        return self._task_mapping[key]

    def update(self, task_id: UUID, peer_id: UUID, score: float):
        if task_id not in self._task_mapping:
            # Refuse to reanimate a task we already committed and
            # rolled out of the resident chain. handle_committed
            # calls update() unconditionally on inbound broadcasts;
            # without this guard, late `committed` messages would
            # build a half-completed Transaction in _task_mapping
            # that any later counterparty-side late `committed`
            # would complete and re-insert at the head of the
            # chain — silently evicting a legitimate recent entry
            # and corrupting reputation math.
            if task_id in self._evicted_task_ids:
                return
            self._task_mapping[task_id] = Transaction(task_id)
        tx = self._task_mapping[task_id]
        if len(tx) == 2:
            return  # ignore duplicates
        if peer_id == tx.p1_id:
            # Skip before `_map_peers` so we don't re-append the same tx to
            # `_peer_mapping[p1_id]` (which would inflate by_peer() results
            # and skew downstream peer-tx counts).
            return
        tx.add(peer_id, score)
        self._map_peers(tx)
        if len(tx) > 1:
            tx.index = self._next_index
            self._next_index += 1
            # Link this entry to the current head BEFORE eviction (eviction
            # drops chain[0] and never touches the head digest, so the link
            # stays valid across the sliding window).
            tx.prev_hash = self._head_hash
            if len(self._chain) >= self.max_chain_len:
                self._evict_oldest()
            self._chain.append(tx)
            self._head_hash = tx.entry_hash()
            if len(self._chain) == 1:
                self._first_index = tx.index

    def __len__(self):
        return len(self._chain)

    def __iter__(self):
        return self._chain.__iter__()

    def by_peer(self, peer_id: UUID):
        return self._peer_mapping[peer_id]

    def era(self, idx: int):
        """Return the chain suffix from absolute index ``idx`` onward.

        If ``idx`` predates ``_first_index`` (entries already evicted)
        the available suffix is returned; older entries are gone.
        """
        if not self._chain:
            return []
        offset = max(0, idx - self._first_index)
        return self._chain[offset:]

    @staticmethod
    def verify_chain_links(chain: 'list[Transaction]') -> bool:
        """Verify the hash-linkage of a (contiguous) committed chain.

        Returns False if any adjacent pair fails ``chain[i].prev_hash ==
        chain[i-1].entry_hash()`` — i.e. the segment was tampered with or
        corrupted in transit. The first entry's ``prev_hash`` points at a
        predecessor outside the segment and is therefore not checkable, so
        verification spans ``chain[1:]`` onward. An empty or single-entry
        chain trivially verifies. Unindexed (not-yet-bilateral) entries are
        skipped — only committed entries participate in the link.
        """
        prev = None
        for link in chain:
            if link.index is None:
                continue
            if prev is not None and link.prev_hash != prev.entry_hash():
                return False
            prev = link
        return True

    def verify_links(self) -> bool:
        """Verify the resident window's internal hash-linkage. See
        ``verify_chain_links``; the oldest resident entry's predecessor has
        been evicted, so checking starts at the second resident entry."""
        return self.verify_chain_links(self._chain)

    def catchup(self, chain: list[Transaction]):
        # Reject a chain whose internal hash-linkage doesn't hold: a peer
        # (or a corrupted transfer) cannot slip an altered committed entry
        # past us. This is the "verifiable instead of social" sync win
        # (reputation-vs-blockchain-analysis.md §2.1) — the received segment
        # must be self-consistent before any of it is replayed.
        if not self.verify_chain_links(chain):
            return
        for link in chain:
            if link.index is None:
                continue
            if link.index >= self._next_index:
                self.update(link.task_id, link.p1_id, link.p1_score)
                self.update(link.task_id, link.p2_id, link.p2_score)

    # ----- Phase 2: ordered Merkle root over the resident window ----------
    # The prev_hash chain (Phase 1) makes the window tamper-EVIDENT in
    # sequence; a Merkle root makes it tamper-PROVABLE in O(log n): a single
    # quorum-signed root commits to every resident entry, and an inclusion
    # proof lets a verifier (gateway parent, slash adjudicator) confirm one tx
    # belongs to the committed window without holding the whole chain
    # (reputation-vs-blockchain-analysis.md §2.1 / §3). Leaves are the
    # per-entry ``entry_hash`` values in resident order. We use the RFC 6962
    # Merkle Tree Hash — domain-separated leaf (0x00) and node (0x01) prefixes
    # defeat the CVE-2012-2459 duplicate-subtree ambiguity that the red-black
    # ``MerkleTree`` guards against by promotion. This construction is a pure
    # function of the ordered leaf digests, so it is byte-identical to the C
    # twin ``transaction_window_root`` (no tree-shape dependence).

    _MERKLE_LEAF_PREFIX = b'\x00'
    _MERKLE_NODE_PREFIX = b'\x01'

    @classmethod
    def _mth(cls, leaves: 'list[bytes]') -> bytes:
        """RFC 6962 Merkle Tree Hash over an ordered list of leaf digests
        (each already a ``Transaction.entry_hash``). Empty -> H(b''). Keep in
        lockstep with C ``transaction_window_root``."""
        n = len(leaves)
        if n == 0:
            return MerkleTree.get_hash(b'')
        if n == 1:
            return MerkleTree.get_hash(cls._MERKLE_LEAF_PREFIX + leaves[0])
        k = 1
        while k * 2 < n:
            k *= 2
        left = cls._mth(leaves[:k])
        right = cls._mth(leaves[k:])
        return MerkleTree.get_hash(cls._MERKLE_NODE_PREFIX + left + right)

    @classmethod
    def _audit_path(cls, m: int, leaves: 'list[bytes]') -> 'list[tuple]':
        """RFC 6962 audit path for leaf index ``m``: a bottom-up list of
        ``(sibling_root, sibling_is_left)`` tuples."""
        n = len(leaves)
        if n <= 1:
            return []
        k = 1
        while k * 2 < n:
            k *= 2
        if m < k:
            return cls._audit_path(m, leaves[:k]) + [(cls._mth(leaves[k:]), False)]
        return cls._audit_path(m - k, leaves[k:]) + [(cls._mth(leaves[:k]), True)]

    def _indexed_window(self) -> 'list[Transaction]':
        """Resident committed (bilateral, indexed) entries in chain order."""
        return [tx for tx in self._chain if tx.index is not None]

    def window_root(self) -> bytes:
        """Merkle root committing to every committed entry resident in the
        window. The value a Phase 2 checkpoint quorum-signs."""
        return self._mth([tx.entry_hash() for tx in self._indexed_window()])

    def inclusion_proof(self, abs_index: int) -> 'list[tuple]':
        """Audit path proving the entry at absolute ``index`` belongs to the
        current ``window_root``. Returns None if that index is not resident."""
        window = self._indexed_window()
        pos = next((i for i, tx in enumerate(window) if tx.index == abs_index), None)
        if pos is None:
            return None
        return self._audit_path(pos, [tx.entry_hash() for tx in window])

    @classmethod
    def verify_inclusion(cls, leaf_digest: bytes, proof: 'list[tuple]',
                         root: bytes) -> bool:
        """Fold a leaf ``entry_hash`` up its audit ``proof`` and check it
        reproduces ``root``. Static so an adjudicator can verify against a
        signed checkpoint root without the originating chain."""
        if proof is None:
            return False
        digest = MerkleTree.get_hash(cls._MERKLE_LEAF_PREFIX + leaf_digest)
        for sibling, sibling_is_left in proof:
            if sibling_is_left:
                digest = MerkleTree.get_hash(cls._MERKLE_NODE_PREFIX + sibling + digest)
            else:
                digest = MerkleTree.get_hash(cls._MERKLE_NODE_PREFIX + digest + sibling)
        return digest == root


class SlashAttestation(Configuration):
    """A signed accusation that ``target_uuid`` defected, carrying the
    floor its reputation should be pinned to.

    Slashing is the fast-penalty path: where the consensus EMA
    (``CONSENSUS_EMA_HALF_LIFE``) takes ~20 committed bilateral txs to
    move a peer's score, a quorum-co-signed slash floors it *immediately*
    at the top of ``_consensus_reputation`` / ``_compute_reputation``,
    bypassing the chain entirely. This is the principled fix for the
    "short-lived rogue never drops off baseline" problem (a peer active
    only ~30 s can't accumulate enough anomalous txs before exclusion
    freezes it). See doc/architecture/reputation.md and
    reputation-vs-blockchain-analysis.md (slashing == PoS-style penalty /
    PKI-style revocation).

    ``reason`` ∈ {sustained_anomaly, peer_exclude, invalid_tx,
    rehabilitate}. ``evidence_ref`` is an optional
    ``(task_id, inclusion_proof)`` tying the slash to a Merkle-committed
    anomalous transaction — unused/optional in the Phase-0 trust-the-
    detector path; verified against a finalized checkpoint root once the
    Merkle/checkpoint phases land. ``signature`` is the slasher's
    Ed25519 signature over ``designation`` (HexEncoder SignedMessage),
    enabling non-repudiable re-dissemination on the ``slash_final`` path.
    """

    REASON_SUSTAINED_ANOMALY = 'sustained_anomaly'
    REASON_PEER_EXCLUDE = 'peer_exclude'
    REASON_INVALID_TX = 'invalid_tx'
    REASON_REHABILITATE = 'rehabilitate'

    def __init__(self, slasher_uuid: UUID, target_uuid: UUID,
                 reason: str, floor_score: float, epoch: int = 0,
                 evidence_ref=None, nonce: bytes = None, signature=None):
        self.slasher_uuid = slasher_uuid
        self.target_uuid = target_uuid
        self.reason = reason
        self.floor_score = floor_score
        self.epoch = epoch
        self.evidence_ref = evidence_ref
        self.nonce = nonce
        self.signature = signature

    @property
    def designation(self) -> bytes:
        """Canonical, domain-separated bytes the slasher signs and every
        co-signer / verifier re-derives. Float is fixed-precision so the
        bytes match the C twin (the one byte-pinning hazard). Excludes
        ``signature`` (self-reference) and ``evidence_ref`` (large,
        verified separately)."""
        return (b'AT-SLASH\x00'
                + str(self.slasher_uuid).encode()
                + b'|' + str(self.target_uuid).encode()
                + b'|' + str(self.reason).encode()
                + b'|' + ('%.6f' % float(self.floor_score)).encode()
                + b'|' + str(self.epoch).encode())

    def key(self):
        """Dedup / sig-accumulation key: a slash is identified by its
        target and epoch (a re-slash of the same target uses a fresh
        epoch)."""
        return (str(self.target_uuid), int(self.epoch))


class SignedSlash(Configuration):
    """A ``SlashAttestation`` plus the set of co-signer signatures that
    finalized it. Disseminated on ``slash_final`` so a node that missed
    the live quorum round can still verify (Phase 3) and apply the floor.
    ``sigs`` maps voter-uuid-str -> Ed25519 signature over the
    attestation's ``designation``."""

    def __init__(self, attestation: 'SlashAttestation' = None,
                 sigs: dict = None):
        self.attestation = attestation
        self.sigs = sigs if sigs is not None else {}


class Checkpoint(Configuration):
    """A signed commitment to a peer's resident committed window: the RFC 6962
    Merkle ``root`` (``TransactionHistory.window_root``) plus the window bounds
    (``first_index`` .. ``first_index + count``) it covers.

    A checkpoint is the quorum-agreed anchor the gateway-tree rollup and the
    Phase 3 slash-evidence proofs verify against
    (reputation-vs-blockchain-analysis.md §2.1 / §3): instead of replaying a
    peer's whole chain, a verifier checks an inclusion proof against a
    checkpoint root that a quorum co-signed. Co-signing is conditional — a
    member signs only if ITS OWN ``window_root`` matches the proposed root, so
    a finalized checkpoint certifies that a majority observed the same
    committed window (a lightweight finality gadget over the BFT chain).

    ``root`` is the 64-char lowercase-hex digest as bytes. ``signature`` is the
    proposer's Ed25519 signature over ``designation`` (HexEncoder
    SignedMessage). Mirrors the SlashAttestation shape; keep ``designation``
    byte-identical to the C twin (fixed-form integers, raw hex root)."""

    def __init__(self, proposer_uuid: UUID, root: bytes, epoch: int = 0,
                 first_index: int = 0, count: int = 0, nonce: bytes = None,
                 signature=None):
        self.proposer_uuid = proposer_uuid
        self.root = root
        self.epoch = epoch
        self.first_index = first_index
        self.count = count
        self.nonce = nonce
        self.signature = signature

    @property
    def designation(self) -> bytes:
        """Canonical, domain-separated bytes the proposer signs and every
        co-signer / verifier re-derives. Excludes ``signature`` (self-ref) and
        ``nonce`` (anti-replay only, carried alongside)."""
        root = self.root if self.root else b''
        if isinstance(root, str):
            root = root.encode()
        return (b'AT-CKPT\x00'
                + str(self.proposer_uuid).encode()
                + b'|' + root
                + b'|' + str(int(self.epoch)).encode()
                + b'|' + str(int(self.first_index)).encode()
                + b'|' + str(int(self.count)).encode())

    def key(self):
        """Dedup / sig-accumulation key: proposer + epoch. Each proposer
        numbers its own checkpoints monotonically."""
        return (str(self.proposer_uuid), int(self.epoch))


class SignedCheckpoint(Configuration):
    """A ``Checkpoint`` plus the co-signer signatures that finalized it.
    Disseminated on ``checkpoint_final`` so a node that missed the live quorum
    round can still store (and Phase 3: verify against) the agreed root.
    ``sigs`` maps voter-uuid-str -> Ed25519 signature over the checkpoint's
    ``designation``."""

    def __init__(self, checkpoint: 'Checkpoint' = None, sigs: dict = None):
        self.checkpoint = checkpoint
        self.sigs = sigs if sigs is not None else {}


class Reputation(Configuration):
    def __init__(self, peer_id: UUID, score: float):
        self.peer_id = peer_id
        self.score = score


class Reputations(Configuration):
    def __init__(self, current: dict[UUID, float] = None):
        if current is None:
            self.current = {}
        else:
            # Convert string keys back to UUIDs (from JSON deserialization)
            self.current = {UUID(k) if isinstance(k, str) else k: v
                            for k, v in current.items()}

    def __getitem__(self, key):
        return self.current[key]

    def __contains__(self, item):
        return item in self.current

    def to_dict(self):
        return {'current': {str(k): v for k, v in self.current.items()}}

    def update(self, peer_id: UUID, score: float):
        self.current[peer_id] = score

    def filtered_for_persist(self, keep_uuids):
        keep = {UUID(str(u)) if not isinstance(u, UUID) else u for u in keep_uuids}
        return Reputations(current={u: r for u, r in self.current.items() if u in keep})
