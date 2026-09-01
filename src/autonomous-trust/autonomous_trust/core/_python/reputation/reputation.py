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


#: The scale every absolute measure in AT and in the tiers above it assumes.
#: Named here so the bound is one value rather than a convention repeated in
#: prose; mirrors TX_SCORE_MIN / TX_SCORE_MAX in the C twin's reputation.h.
TX_SCORE_MIN = 0.0
TX_SCORE_MAX = 1.0


def validate_tx_score(score, where: str = 'TransactionScore'):
    """Return `score` as a float in [0, 1], or raise ValueError.

    The [0, 1] score bound, enforced (doc/architecture/reputation.md; asked for
    by kith-covenant's erosion-legibility audit). The
    [0, 1] scale was a convention in AT rather than an enforced invariant, so an
    out-of-range score was *graded* rather than rejected — it flowed into the
    weighted average and moved a reputation by an unbounded amount. Rejecting is
    the whole point, so this deliberately does not clamp: a caller submitting 5.0
    has a bug, and silently recording 1.0 would hide it while still rewarding the
    peer more than any honest score could.

    NaN is rejected by the same comparison that rejects 5.0 (every comparison
    against NaN is false), which is worth knowing because NaN is the value that
    would otherwise poison an average irrecoverably.
    """
    try:
        value = float(score)
    except (TypeError, ValueError):
        raise ValueError('%s: score must be a number, got %r' % (where, score))
    if not (TX_SCORE_MIN <= value <= TX_SCORE_MAX):
        raise ValueError('%s: score %r is outside the [%g, %g] scale '
                         '(NaN is rejected here too)'
                         % (where, score, TX_SCORE_MIN, TX_SCORE_MAX))
    return value


#: Evidence channels (R+D.md §12.8, doc/verification_oracle.md "Keep the
#: channels separate").
#:
#: A transaction score says HOW WELL a peer did. The channel says HOW WE KNOW
#: — and those are not the same fact. "Refuted by conservation of energy,"
#: "poorly calibrated over the last hundred predictions," "disagrees with the
#: swarm," "failed a replicated task," and "contradicted its own signed
#: archive" are different findings warranting different responses (immediate
#: demotion, gradual decay, an opened dispute). Collapsing them into one scalar
#: before the score reaches the reputation algebra destroys exactly what an
#: escalation path would need to choose between those responses, and a bare
#: score is what the wire carried before this field existed.
#:
#: The first slice (2026-08-21) carried the channel and branched on nothing.
#: The second (below, :data:`TX_CHANNEL_WEIGHTS` / :data:`TX_CHANNELS_HARD`)
#: gives it consequences: a graded channel weights the consensus EMA, and a
#: hard-falsification channel additionally makes a defection-grade score
#: grounds to PROPOSE a slash. Both apply ONLY to evidence this node produced
#: itself — see :func:`tx_channel_weight` for why a peer's tag stays
#: legibility-only.
#:
#: Mirrors TX_CHANNEL_* in the C twin's reputation/tx_channel.h; the spellings
#: must match verbatim, since a divergence is a score one twin accepts and the
#: other drops.

#: Ordinary grading of a completed task: the negotiation-driven path that
#: produced every score before channels existed. The default, and what an
#: absent/empty channel normalizes to, so a legacy peer's scores stay
#: indistinguishable from a tagged peer's task outcomes.
TX_CHANNEL_TASK_OUTCOME = 'task_outcome'

#: Hard refutation by conservation law or dimensional analysis. Needs no
#: history and no training data (oracle layer 1) — a verdict, not a drift.
TX_CHANNEL_PHYSICAL = 'physical'

#: A certificate-carrying task interface checked out (or failed to). Interface
#: work rather than algorithm work (oracle layer 2); this is where a ZKP
#: verdict on a task result lands (see automate.py).
TX_CHANNEL_CERTIFICATE = 'certificate'

#: Conformal coverage audit / prequential log-loss: the peer is not wrong so
#: much as overconfident, which averaged reputation cannot see (layers 3-4).
TX_CHANNEL_CALIBRATION = 'calibration'

#: The peer contradicted its own signed, hash-chained claim archive (layer 5).
#: The cheapest channel of the set: falsification needing no peers, no physics,
#: and no domain knowledge.
TX_CHANNEL_SELF_CONSISTENCY = 'self_consistency'

#: Outcome of sampled replication of the peer's work (layer 6).
TX_CHANNEL_REPLICATION = 'replication'

#: The peer disagrees with the swarm (layers 7-8). Named separately BECAUSE it
#: is the one that should eventually open a dispute rather than levy a penalty
#: — a majority is not an oracle.
TX_CHANNEL_SWARM_DISAGREEMENT = 'swarm_disagreement'

#: A honeypot probe: a task whose correct answer the requestor already knows,
#: checked against that answer (R+D.md §12.7). The AT bootstrap corpus
#: (at.handshake / at.time-attest / at.echo-challenge) is this pattern.
#:
#: Kept distinct from :data:`TX_CHANNEL_TASK_OUTCOME` because a probe verdict is
#: the one piece of evidence that does not degrade as the adversarial fraction
#: rises — every other channel is ultimately an aggregate over peers, and a
#: majority cannot be beaten without an external reference. A probe IS that
#: reference. Distinct from :data:`TX_CHANNEL_CERTIFICATE` too: a certificate is
#: a proof the PEER supplies about its own work, while a probe is a question the
#: VERIFIER authored and already knows the answer to.
TX_CHANNEL_PROBE = 'probe'

#: The closed set, in the build order of doc/verification_oracle.md. Mirrors
#: TX_CHANNEL_ALL in the C twin. Ordered (not a set literal) so error messages
#: list the vocabulary the same way on both sides of the wire.
TX_CHANNELS = (TX_CHANNEL_TASK_OUTCOME,
               TX_CHANNEL_PHYSICAL,
               TX_CHANNEL_CERTIFICATE,
               TX_CHANNEL_CALIBRATION,
               TX_CHANNEL_SELF_CONSISTENCY,
               TX_CHANNEL_REPLICATION,
               TX_CHANNEL_SWARM_DISAGREEMENT,
               TX_CHANNEL_PROBE)

#: What an absent channel resolves to. Absence means "a peer or an app that
#: predates channels," which is a task outcome by construction — every
#: producer before this field was grading a completed task.
TX_CHANNEL_DEFAULT = TX_CHANNEL_TASK_OUTCOME


def validate_tx_channel(channel, where: str = 'TransactionScore'):
    """Return `channel` as one of :data:`TX_CHANNELS`, or raise ValueError.

    ``None`` and ``''`` resolve to :data:`TX_CHANNEL_DEFAULT` — absence is a
    different question from invalidity, and a legacy producer (or a peer
    running a build from before this field) is *absent*, not wrong. Anything
    else must match a known channel byte-exactly.

    Unknown spellings are REFUSED rather than passed through or coerced to the
    default. A channel that silently becomes "some string a peer sent" is worth
    less than no channel at all, since the entire value of the field is that a
    demotion reason means one agreed thing on both sides of the wire; and
    coercing an unknown to ``task_outcome`` would be worse still, because it
    turns a typo'd physics refutation into an ordinary task grade with no trace
    that anything was lost. Matching is case-sensitive for the same reason
    (``'Physical'`` is refused): a closed set that accepts near-misses is not
    closed.

    Like :func:`validate_tx_score`, this runs in ``TransactionScore``'s
    constructor and therefore on the remote path, where ``from_json_string``
    reconstructs via ``cls(**kwargs)``. Handlers there already catch
    ``ValueError`` and drop the message, so a peer sending an unknown channel
    loses its proposal rather than raising inside the process loop.
    """
    if channel is None or channel == '':
        return TX_CHANNEL_DEFAULT
    if not isinstance(channel, str):
        raise ValueError('%s: channel must be a string, got %r'
                         % (where, channel))
    if channel not in TX_CHANNELS:
        raise ValueError('%s: unknown evidence channel %r (known: %s)'
                         % (where, channel, ', '.join(TX_CHANNELS)))
    return channel


# --- What a channel DOES (R+D.md §12.8, the differentiated responses) ------
#
# Two responses, both settled with the user before implementing:
#
#   weighting        every channel carries an integer multiplier on the
#                    consensus EMA, composed with the per-capability
#                    transaction weight (they multiply: a heavy capability
#                    refuted on physics counts as both).
#   slash-eligible   the hard-falsification channels additionally make a
#                    defection-grade score grounds to PROPOSE a slash, which
#                    the EXISTING quorum co-signature then accepts or refuses.
#
# Deliberately NOT a third mechanism: `swarm_disagreement` should open a
# DISPUTE rather than levy a penalty (doc/verification_oracle.md), and no
# dispute machinery exists in either runtime. Weighting it like a hard channel
# would be the opposite of what that entry asks for -- a majority is not an
# oracle -- so it sits at the baseline weight until the dispute path is built.

#: Multiplier on a locally-produced score's EMA weight, by channel.
#:
#: The weight is applied by folding the score into the EMA that many times
#: (``consensus_score_from_window``), which is why these are small integers
#: rather than floats: the existing per-capability ``transaction_weight`` uses
#: the same repeat mechanism, and the two multiply.
#:
#: The values are a ranking of how much one observation tells you, not a tuning
#: surface: 1 = one peer's reading of one event; 2 = corroborated by
#: construction (a replication has several executors; a probe is checked
#: against an answer the verifier authored); 3 = a verdict that needs no
#: history at all. `calibration` is deliberately 1 — it is the channel the
#: oracle doc names as the one that should decay a peer *gradually*.
#:
#: Mirrors TX_CHANNEL_WEIGHT_* in the C twin's reputation/tx_channel.h.
TX_CHANNEL_WEIGHTS = {
    TX_CHANNEL_TASK_OUTCOME: 1,
    TX_CHANNEL_CALIBRATION: 1,
    TX_CHANNEL_SWARM_DISAGREEMENT: 1,
    TX_CHANNEL_REPLICATION: 2,
    TX_CHANNEL_PROBE: 2,
    TX_CHANNEL_PHYSICAL: 3,
    TX_CHANNEL_CERTIFICATE: 3,
    TX_CHANNEL_SELF_CONSISTENCY: 3,
}

#: The channels whose findings are FALSIFICATIONS rather than grades: the peer
#: did not do poorly, it asserted something that is not true. Each is a verdict
#: reachable without consulting any other peer — physics refutes, a certificate
#: fails to verify, an archive contradicts itself — which is exactly what makes
#: a single observation of one sufficient grounds to accuse.
#:
#: `probe` is deliberately NOT here even though its ground truth is certain.
#: A probe is synthetic traffic the verifier generates continuously (§12.7), so
#: making one failed probe slash-eligible would put every node's exclusion in
#: the hands of its own probe cadence. It gets the corroborated weight instead.
#:
#: Mirrors TX_CHANNEL_IS_HARD in the C twin.
TX_CHANNELS_HARD = frozenset({TX_CHANNEL_PHYSICAL,
                              TX_CHANNEL_CERTIFICATE,
                              TX_CHANNEL_SELF_CONSISTENCY})


def tx_channel_weight(channel) -> int:
    """The EMA multiplier for *channel*, defaulting to 1 for anything unknown.

    Unknown is impossible through ``TransactionScore`` (the constructor refuses
    it), so the default is for a caller reading a raw string off an older
    record — and 1 is the right answer there: an unrecognized channel must
    never weigh MORE than a recognized one, or adding a channel on one side of
    the wire would silently amplify it on the other.

    **Only ever applied to locally-produced evidence.** The channel is chosen
    by whoever wrote the score, so honoring a remote peer's tag here would hand
    every peer a lever on every other peer's reputation: tag a fabricated 0.0
    `physical` and it lands with triple weight. A remote score keeps its
    channel for legibility and is weighted by capability alone. The cost is
    that two nodes can compute slightly different EMAs for the same peer — but
    that is already true of the per-capability weights (see
    ``consensus_score_from_window``'s ``weights`` argument, which a verifier
    across a trust boundary cannot reproduce either), so this adds a term to an
    existing local-view divergence rather than introducing one.
    """
    return int(TX_CHANNEL_WEIGHTS.get(channel, 1))


def tx_channel_is_hard(channel) -> bool:
    """Whether *channel* is a falsification (see :data:`TX_CHANNELS_HARD`)."""
    return channel in TX_CHANNELS_HARD


def slash_reason_for_channel(channel) -> str:
    """The ``SlashAttestation.reason`` a hard channel slashes under.

    ``'refuted_' + channel``, so the accusation names the evidence that
    produced it rather than collapsing to a generic "bad peer" — which is the
    whole point of §12.8, and what an operator reading a demotion needs. The
    reason is part of ``designation``, so it is SIGNED and co-signed: unlike
    ``evidence_ref``, a channel claim carried here cannot be altered in flight.

    Raises ValueError for a channel that is not slash-eligible, rather than
    inventing a reason for it: a caller asking this about `task_outcome` has a
    bug, and a silently-minted reason would produce a slash no reader could
    place.
    """
    if not tx_channel_is_hard(channel):
        raise ValueError('channel %r is not slash-eligible (hard channels: %s)'
                         % (channel, ', '.join(sorted(TX_CHANNELS_HARD))))
    return SlashAttestation.REASON_REFUTED_PREFIX + channel


class TransactionScore(Configuration):
    """One peer's score for one task, plus how that score was arrived at.

    ``channel`` names the evidence channel the score came from (see
    :data:`TX_CHANNELS` and R+D.md §12.8). On a score THIS node produced it
    also carries consequences — an EMA multiplier
    (:data:`TX_CHANNEL_WEIGHTS`) and, for a hard channel, slash eligibility
    (:data:`TX_CHANNELS_HARD`). On a score that arrived from a peer it stays
    legibility only, because the sender picks its own tag.

    ``subject_uuid`` is the peer this score is ABOUT. It is local-only and
    never serialized (see :meth:`to_dict`): the wire form pairs the two sides
    of a transaction by ``task_id``, and nothing downstream of the chain needs
    it. It exists so a locally-produced hard-channel score can name the peer it
    accuses without waiting for the bilateral pairing to close, and dropping it
    from the wire is also what makes the "locally-produced evidence only" rule
    structural rather than a check that could be forgotten: a score off the
    wire has no subject to accuse, so it cannot originate a slash whatever it
    claims in its channel.

    Deliberately NOT part of ``Transaction._canonical_bytes`` — the channel
    rides on the TS and stops at the chain boundary. Adding a field to the
    canonical bytes would change every entry hash in every resident chain and
    invalidate the byte-pinned C parity, which is a migration this slice has no
    reason to spend: a committed chain entry answers "who transacted, and how
    well," and the channel is provenance for the score rather than part of the
    fact being committed. If a future escalation path needs the channel to be
    tamper-evident, that is its own slice with its own chain migration.
    """

    def __init__(self, task_id, score, capability_name: str = None,
                 channel: str = None, subject_uuid=None):
        self.task_id = task_id
        # Enforced, not assumed (doc/architecture/reputation.md). This constructor is also the wire-side
        # entry point -- `from_json_string` reconstructs via `cls(**kwargs)` --
        # so a peer sending an out-of-range score raises here. Handlers on the
        # remote path therefore CATCH this and drop the message: an exception a
        # remote can trigger inside the process loop is its own problem.
        self.score = validate_tx_score(score)
        # Optional: name of the Capability whose execution produced this
        # TS. Used by _pure_reputation to look up transaction_weight at
        # scoring time (Slice 3). None means "unknown / legacy" — weight
        # defaults to 1. See doc/architecture/trust-tiers.md §4.4.
        self.capability_name = capability_name
        # Which evidence channel produced this score (R+D.md §12.8). Refused
        # here if unknown, on the same remote path and for the same reason as
        # `score` above. Normalized rather than left None so every TS on the
        # wire carries an explicit channel and a reader never has to know
        # whether None meant "task outcome" or "producer forgot".
        self.channel = validate_tx_channel(channel)
        # Local-only; see the class docstring. Accepted as a keyword because
        # `from_json_string` rebuilds via `cls(**kwargs)` and a record written
        # by some future producer could carry it -- but `to_dict` drops it, so
        # nothing this node SENDS ever has one, and a peer that sets it anyway
        # gets it back out of the reputation process's hands at the one place
        # that matters (`forward_transaction` is IPC-only; see there).
        self.subject_uuid = None if subject_uuid is None else str(subject_uuid)

    def to_dict(self):
        # `subject_uuid` is process-local provenance, not part of the score:
        # the committed wire form pairs p1/p2 by task_id and has never carried
        # a subject. Dropping it here is the same discipline as Group.to_dict
        # dropping `_previous_keys` and Identity dropping `_rank_adjustment`,
        # and it keeps every byte-pinned TransactionScore vector valid.
        d = super().to_dict()
        d.pop('subject_uuid', None)
        return d


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
        # doc/architecture/process-architecture.md). Mirrors transaction_t.prev_hash in the C twin; the canonical
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
    rehabilitate} plus the per-channel `refuted_*` set
    (:data:`REASON_REFUTED_PREFIX`, R+D.md §12.8). ``evidence_ref`` is an optional
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

    #: Prefix for the evidence-channel reasons (R+D.md §12.8). The suffix is
    #: the channel verbatim, so the closed channel set defines the closed
    #: reason set and neither can drift from the other:
    #: `refuted_physical`, `refuted_certificate`, `refuted_self_consistency`.
    #: Minted only by :func:`slash_reason_for_channel`. Mirrors
    #: REP_SLASH_REASON_REFUTED_PREFIX in the C twin.
    REASON_REFUTED_PREFIX = 'refuted_'

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
                 signature=None, group_uuid: str = ''):
        self.proposer_uuid = proposer_uuid
        self.root = root
        self.epoch = epoch
        self.first_index = first_index
        self.count = count
        self.nonce = nonce
        self.signature = signature
        # Which chain this checkpoint commits to: '' (the default) is the node's PRIMARY
        # chain, and a group-uuid string is one of a gateway's child-group chains. A
        # gateway keeps one TransactionHistory per child group, and without this a
        # receiver could not tell which of its chains to compare the proposed root
        # against. Follows the same optional-trailing-group_uuid shape the `committed`
        # broadcast already uses. See doc/architecture/gateway-reputation-tree.md and
        # doc/architecture/gateway-reputation-tree.md.
        self.group_uuid = str(group_uuid) if group_uuid else ''

    @property
    def designation(self) -> bytes:
        """Canonical, domain-separated bytes the proposer signs and every
        co-signer / verifier re-derives. Excludes ``signature`` (self-ref) and
        ``nonce`` (anti-replay only, carried alongside).

        ``group_uuid`` is appended ONLY when non-empty, which does two things
        at once. A primary-chain designation stays byte-identical to what it
        was before child chains existed, so every co-signature, pinned
        scenario and C twin keeps verifying. And a child-chain designation can
        never collide with a primary one, so a co-signature harvested from a
        child-group round cannot be replayed as agreement about the primary
        chain — which it otherwise could, since two chains can perfectly well
        produce the same root, epoch and bounds."""
        root = self.root if self.root else b''
        if isinstance(root, str):
            root = root.encode()
        desig = (b'AT-CKPT\x00'
                 + str(self.proposer_uuid).encode()
                 + b'|' + root
                 + b'|' + str(int(self.epoch)).encode()
                 + b'|' + str(int(self.first_index)).encode()
                 + b'|' + str(int(self.count)).encode())
        if self.group_uuid:
            desig += b'|' + self.group_uuid.encode()
        return desig

    def key(self):
        """Dedup / sig-accumulation key: proposer + epoch + chain. Each
        proposer numbers its checkpoints monotonically PER CHAIN, so the chain
        has to be part of the key or a gateway's primary and child rounds
        would collide at the same epoch number."""
        return (str(self.proposer_uuid), int(self.epoch), self.group_uuid)


class SignedCheckpoint(Configuration):
    """A ``Checkpoint`` plus the co-signer signatures that finalized it.
    Disseminated on ``checkpoint_final`` so a node that missed the live quorum
    round can still store (and Phase 3: verify against) the agreed root.
    ``sigs`` maps voter-uuid-str -> Ed25519 signature over the checkpoint's
    ``designation``."""

    def __init__(self, checkpoint: 'Checkpoint' = None, sigs: dict = None):
        self.checkpoint = checkpoint
        self.sigs = sigs if sigs is not None else {}


# --- Persisted evidence (reputation-history.cfg.json) ----------------------
#
# `reputation.cfg.json` holds the CONCLUSION -- {peer: score} -- and nothing
# that shows how it was reached, so warm start had no way to tell an earned 0.9
# from one typed into the file. This is the evidence beside it: the resident
# hash-linked window plus the quorum-signed checkpoint over it. See
# doc/architecture/reputation.md (Verifiable warm start) and doc/architecture/reputation.md.
#
# Deliberately PLAIN JSON rather than a `Configuration` dump: one file is read
# by both runtimes, and Configuration's encoder emits `__type__` keys naming
# Python classes that mean nothing to the C reader. Same reasoning as the trust
# ladder. Field names follow the checkpoint wire payload so a reader of
# either is reading the same vocabulary.
#
# Schema is pinned so a future shape change is a refusal to rebuild (which
# degrades to capped restoration) rather than a misparse.
EVIDENCE_SCHEMA = '1'
EVIDENCE_FILE = 'reputation-history'
# Per-(target, slasher) slash high-water marks. Separate from the chain
# evidence deliberately: the evidence is an optimization of trust that a node
# can lose harmlessly, while these marks are the memory a replayed slash has
# to clear, so the two should not share a failure.
SLASH_MARKS_FILE = 'reputation-slash-marks'


def _hex_str(value) -> str:
    """Digests are carried as 64-char lowercase hex. Python holds them as
    hex-ASCII *bytes* (MerkleTree.get_hash), so accept either."""
    if value is None:
        return ''
    if isinstance(value, bytes):
        return value.decode('ascii')
    return str(value)


def evidence_to_dict(chain, signed_checkpoint=None) -> dict:
    """The persisted-evidence document for ``chain`` (an iterable of committed
    ``Transaction``) and the finalized ``SignedCheckpoint`` covering it.

    Only entries with an assigned ``index`` are written: an index is what a
    committed, bilateral entry has, and an un-indexed one is not evidence of
    anything yet.
    """
    entries = []
    for tx in chain:
        if tx.index is None:
            continue
        entries.append({
            'task_id': str(tx.task_id),
            'p1_id': None if tx.p1_id is None else str(tx.p1_id),
            'p1_score': None if tx.p1_score is None else float(tx.p1_score),
            'p2_id': None if tx.p2_id is None else str(tx.p2_id),
            'p2_score': None if tx.p2_score is None else float(tx.p2_score),
            'index': int(tx.index),
            'prev_hash': _hex_str(tx.prev_hash),
        })
    doc = {
        'schema': EVIDENCE_SCHEMA,
        'chain': entries,
        'checkpoint': None,
    }
    ckpt = getattr(signed_checkpoint, 'checkpoint', None)
    if ckpt is not None:
        doc['checkpoint'] = {
            'proposer_uuid': str(ckpt.proposer_uuid),
            'root': _hex_str(ckpt.root),
            'epoch': int(ckpt.epoch),
            'first_index': int(ckpt.first_index),
            'count': int(ckpt.count),
            # Which chain the checkpoint covers ('' == primary). Part of the
            # signed designation when non-empty, so it has to travel with the
            # signatures or a restart could not re-derive the bytes they were
            # made over. Additive to schema 1: a reader that predates child
            # chains ignores it, and this reader defaults it to ''.
            'group_uuid': str(getattr(ckpt, 'group_uuid', '') or ''),
            'sigs': {str(k): _hex_str(v)
                     for k, v in (signed_checkpoint.sigs or {}).items()},
        }
    return doc


def evidence_from_dict(doc):
    """Parse a persisted-evidence document into
    ``(chain, signed_checkpoint)``.

    Raises ValueError on anything malformed -- a wrong schema, a non-list
    chain, an entry missing its index. The caller treats that as "no usable
    evidence", which is a *safe* outcome (restoration falls back to capped),
    so being strict here costs nothing and misreading would cost a lot.
    """
    if not isinstance(doc, dict):
        raise ValueError('evidence document is not an object')
    schema = doc.get('schema')
    if schema != EVIDENCE_SCHEMA:
        raise ValueError('unsupported evidence schema %r (expected %r)'
                         % (schema, EVIDENCE_SCHEMA))
    raw_chain = doc.get('chain')
    if not isinstance(raw_chain, list):
        raise ValueError('evidence chain is not a list')
    chain = []
    for entry in raw_chain:
        if not isinstance(entry, dict):
            raise ValueError('evidence chain entry is not an object')
        if entry.get('index') is None:
            raise ValueError('evidence chain entry has no index')

        def _uuid(key):
            raw = entry.get(key)
            return None if raw is None else UUID(str(raw))

        def _score(key):
            raw = entry.get(key)
            return None if raw is None else float(raw)

        prev = entry.get('prev_hash') or ''
        chain.append(Transaction(
            task_id=UUID(str(entry['task_id'])),
            p1_id=_uuid('p1_id'), p1_score=_score('p1_score'),
            p2_id=_uuid('p2_id'), p2_score=_score('p2_score'),
            index=int(entry['index']),
            prev_hash=prev.encode('ascii') if prev else b''))
    signed = None
    raw_ck = doc.get('checkpoint')
    if isinstance(raw_ck, dict):
        root = raw_ck.get('root') or ''
        ckpt = Checkpoint(
            proposer_uuid=UUID(str(raw_ck['proposer_uuid'])),
            root=root.encode('ascii') if root else b'',
            epoch=int(raw_ck.get('epoch', 0)),
            first_index=int(raw_ck.get('first_index', 0)),
            count=int(raw_ck.get('count', 0)),
            group_uuid=str(raw_ck.get('group_uuid', '') or ''))
        sigs = raw_ck.get('sigs') or {}
        if not isinstance(sigs, dict):
            raise ValueError('evidence checkpoint sigs is not an object')
        signed = SignedCheckpoint(checkpoint=ckpt,
                                  sigs={str(k): str(v) for k, v in sigs.items()})
    return chain, signed


# --- Deep resolution: one peer, on demand, at any depth
# (doc/architecture/gateway-reputation-tree.md) ---
#
# A node scores a peer against the chain that peer's transactions landed in,
# and holds chains only for groups it belongs to. Two levels down that chain
# belongs to somebody else, so the query is relayed to whoever holds it and the
# ANSWER CARRIES ITS OWN PROOF -- it crosses nodes the requestor has no reason
# to trust, so a bare number would be an unfalsifiable claim.
#
# The proof is the whole quorum-signed window, not the queried peer's entries
# with inclusion proofs. An audit path proves an entry IS in the window; it
# proves nothing about what was left out, so a holder could answer with a
# peer's three good transactions, omit the two bad ones, and pass verification.
# Shipping the window closes that: the verifier recomputes the root from the
# entries themselves, and an omitted entry changes the root, which then fails
# against the signature a quorum made over it. (User's call, 2026-08-13: the
# cost is that the requestor sees every transaction in that window, not only
# the queried peer's.)

#: Hops a resolve may travel before it is dropped. The tree is the real bound;
#: this is the backstop that keeps a routing loop or a lying `children` claim
#: from circulating a query forever. 4 covers any hierarchy contemplated so far
#: (doc/architecture/gateway-reputation-tree.md) with room to spare.
RESOLVE_TTL_DEFAULT = 4
#: Refuse a query that arrives claiming more hops than we would ever originate:
#: TTL is attacker-controlled, and an inflated one is an amplification lever.
RESOLVE_TTL_MAX = 8


def resolve_query_to_dict(query_id: str, peer_uuid, ttl: int = RESOLVE_TTL_DEFAULT,
                          requesting_process: str = '') -> dict:
    """A deep-resolution query. Deliberately says nothing about who is asking:
    the relay answers to the neighbour it heard from, so the originator's
    identity never travels and a deep holder cannot learn who wanted to know."""
    return {
        'query_id': str(query_id),
        'peer_uuid': str(peer_uuid),
        'ttl': int(ttl),
        'requesting_process': str(requesting_process or ''),
    }


def resolve_query_from_dict(doc) -> dict:
    """Parse and BOUND a query. Raises ValueError on anything malformed or on
    a TTL above ``RESOLVE_TTL_MAX`` -- clamping silently would let a hostile
    requestor set the fan-out budget for everyone below it."""
    if not isinstance(doc, dict):
        raise ValueError('resolve query is not an object')
    qid = str(doc.get('query_id') or '')
    peer = str(doc.get('peer_uuid') or '')
    if not qid or not peer:
        raise ValueError('resolve query missing query_id or peer_uuid')
    ttl = int(doc.get('ttl', 0))
    if ttl < 0 or ttl > RESOLVE_TTL_MAX:
        raise ValueError('resolve query ttl %d out of range' % ttl)
    return {'query_id': qid, 'peer_uuid': peer, 'ttl': ttl,
            'requesting_process': str(doc.get('requesting_process') or '')}


def resolved_to_dict(query_id: str, peer_uuid, chain, signed_checkpoint,
                     signers=None, score=None) -> dict:
    """An answer: the queried peer, the holder's own score for it, and the
    quorum-signed window that backs it.

    ``signers`` is a list of co-signer identities in the DRY canonical public
    form (``public_identity_to_canonical``, which C emits byte-identically).
    They are here because the requestor is two boundaries away and holds NO
    identity from the answering group, so without them it could not check a
    single signature. That form -- rather than bare keys -- because it also
    carries each signer's ZTA credential, which is what lets the verifier tie
    a signer to an anchor it accepts. The identities are not trusted for being
    present: an answer that ships its own freshly-minted quorum is exactly
    what the anchor check in ``verify_resolved`` refuses.

    ``score`` is the holder's own value, carried as a cross-check and NOT as
    the answer: the EMA is weighted by per-capability transaction weights that
    live in a node-local cache and are not part of any hashed entry, so a
    remote verifier cannot re-derive them. The attested window is the real
    payload; the requestor computes its own score from it."""
    doc = evidence_to_dict(chain, signed_checkpoint)
    doc['query_id'] = str(query_id)
    doc['peer_uuid'] = str(peer_uuid)
    doc['score'] = None if score is None else float(score)
    doc['signers'] = [dict(s) for s in (signers or []) if isinstance(s, dict)]
    return doc


def resolved_from_dict(doc):
    """Parse an answer into ``(query_id, peer_uuid, score, chain,
    signed_checkpoint, signers)``. Raises ValueError on anything malformed;
    the caller treats that as no answer rather than a bad one."""
    if not isinstance(doc, dict):
        raise ValueError('resolved answer is not an object')
    chain, signed = evidence_from_dict(doc)
    qid = str(doc.get('query_id') or '')
    peer = str(doc.get('peer_uuid') or '')
    if not qid or not peer:
        raise ValueError('resolved answer missing query_id or peer_uuid')
    raw_score = doc.get('score')
    signers = doc.get('signers') or []
    if not isinstance(signers, list):
        raise ValueError('resolved answer signers is not a list')
    return (qid, peer, None if raw_score is None else float(raw_score),
            chain, signed, [s for s in signers if isinstance(s, dict)])


def window_root_of(chain) -> bytes:
    """The RFC 6962 root over an ordered list of committed ``Transaction`` --
    the same value ``TransactionHistory.window_root`` produces for a resident
    window, computed from a bare list so a verifier that never held the chain
    can reproduce it."""
    entries = [tx for tx in chain if tx.index is not None]
    return TransactionHistory._mth([tx.entry_hash() for tx in entries])


def consensus_score_from_window(peer_uuid, chain, half_life: int,
                                weights=None):
    """The deterministic consensus EMA for ``peer_uuid`` over an ordered
    window. Returns None when the window holds no bilateral entry for the peer
    (the caller decides what a no-evidence answer means -- there is no local
    baseline to fall back to when the chain is somebody else's).

    Extracted so ONE implementation serves both the holder computing its own
    score and a verifier recomputing it from attested evidence; the C twin
    mirrors this function rather than the method around it. Keep the fold
    identical to ``ReputationProcess._consensus_reputation``.

    ``weights`` (task-id-str -> int) reproduces the per-capability transaction
    weight. A verifier across a trust boundary has no way to know them and
    passes None, i.e. weight 1 for everything: its number is then the
    unweighted consensus over the same attested entries, which is why the
    holder's own score travels alongside as a cross-check rather than as
    something to be asserted equal."""
    alpha = 1.0 - 0.5 ** (1.0 / float(half_life))
    ema = None
    ordered = sorted(chain, key=lambda t: (t.index if t.index is not None else 0))
    for tx in ordered:
        if tx.p1_id is None or tx.p2_id is None:
            continue
        if str(tx.p1_id) == str(peer_uuid):
            cp_score = tx.p2_score
        elif str(tx.p2_id) == str(peer_uuid):
            cp_score = tx.p1_score
        else:
            continue
        if cp_score is None:
            continue
        w = (weights or {}).get(str(tx.task_id), 1)
        for _ in range(max(1, int(w))):
            if ema is None:
                ema = float(cp_score)
            else:
                ema = alpha * float(cp_score) + (1.0 - alpha) * ema
    return ema


def verify_resolved(chain, signed_checkpoint, signers, verify_signature,
                    trust_signer=None, min_signers: int = 1):
    """Check an answer's evidence. Returns ``(ok, reason)`` -- a reason string
    even on success, because an operator reading "unverified" needs to know
    WHICH check failed and a caller may accept a weaker answer knowingly (see
    feedback_operator_diagnostics).

    Three gates, in order of what they buy:

    1. **The window reproduces the signed root.** This is the load-bearing
       one: it makes both fabrication and OMISSION detectable, since any edit
       to the entry list moves the root away from the bytes a quorum signed.
    2. **The co-signatures verify** over the checkpoint's designation, via the
       caller's ``verify_signature(designation, uuid, sig, signer)`` where
       ``signer`` is that voter's canonical identity dict (or None if the
       answer did not carry one).
    3. **Each signer is trusted**, via the caller's ``trust_signer(uuid,
       signer)`` -- in practice "this signer's credential chains to an anchor
       we accept". Without it, gate 2 proves only that somebody holding some
       key signed, and an answer can carry its own invented quorum.

    NOT checked here, and it cannot be from this side: whether the verified
    signers are a MAJORITY of the group whose chain this is. Quorum sizing
    needs that group's membership, and an opaque subtree is precisely what
    does not disclose it. The count is returned in the reason so the caller
    can apply its own bar."""
    ckpt = getattr(signed_checkpoint, 'checkpoint', None)
    if ckpt is None:
        return False, 'no checkpoint: the window is unattested'
    root = ckpt.root
    if isinstance(root, str):
        root = root.encode('ascii')
    if not root:
        return False, 'checkpoint carries no root'
    recomputed = window_root_of(chain)
    if recomputed != root:
        return False, ('window does not reproduce the signed root '
                       '(entries added, altered or withheld)')
    sigs = getattr(signed_checkpoint, 'sigs', None) or {}
    designation = ckpt.designation
    by_uuid = {str(s.get('uuid')): s for s in (signers or [])
               if isinstance(s, dict) and s.get('uuid')}
    verified = set()
    for voter, sig in sigs.items():
        voter = str(voter)
        signer = by_uuid.get(voter)
        if not verify_signature(designation, voter, sig, signer):
            continue
        if trust_signer is not None and not trust_signer(voter, signer):
            continue
        verified.add(voter)
    if len(verified) < max(1, int(min_signers)):
        return False, ('%d signer(s) verified and trusted, needed %d'
                       % (len(verified), max(1, int(min_signers))))
    return True, ('root reproduced; %d signer(s) verified and trusted '
                  '(quorum size not checkable across a boundary)'
                  % len(verified))


class Reputation(Configuration):
    def __init__(self, peer_id: UUID, score: float):
        self.peer_id = peer_id
        self.score = score


class PeerReputation(Configuration):
    """AT → app: one peer's earned reputation, with whether AT holds one.

    Mirror of the C twin's `peer_reputation_msg_t` (`utilities/msg_types.h`) and
    the flat `at_app_reputation_t` an app decodes (`app_events.h`);
    doc/architecture/app-peer-carrier.md,
    asked for by kith-covenant and ethne (D18).

    `rated` is the load-bearing field. AT's scale is anchored by fixed constants
    (PREREP_NEUTRAL, the comm cut-off, the tier floors) rather than normalized
    across the peer population, so `score` crosses as-is — but a peer AT has
    never scored reads as exactly PREREP_NEUTRAL, which is *also* a score a peer
    can genuinely earn. Collapsing those two lets a consumer treat "no
    information" as a real, mid-range rating.

    Local IPC only, exactly like the C twin: this does NOT change `Reputation`
    or the peer-to-peer `rep_resp` wire form.
    """

    def __init__(self, peer_uuid, score, rated: bool = True):
        self.peer_uuid = peer_uuid
        self.rated = bool(rated)
        # Zeroed when unrated, as C's _publish_reputation does, so a consumer
        # that ignores the flag cannot silently read a plausible-looking number.
        self.score = float(score) if self.rated else 0.0


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
