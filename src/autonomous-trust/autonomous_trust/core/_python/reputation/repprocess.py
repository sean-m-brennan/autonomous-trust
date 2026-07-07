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
import threading
import time
import traceback
from collections import OrderedDict
from queue import Empty, Full
from uuid import UUID
from dataclasses import dataclass

from ..network import Message
from ..processes import Process, ProcMeta
from ..config import Configuration, from_json_string, to_json_string
from ..identity.protocol import IdentityProtocol
from .protocol import ReputationProtocol
from .reputation import (TransactionHistory, Reputation, Reputations,
                         TransactionScore, SlashAttestation, SignedSlash,
                         Checkpoint, SignedCheckpoint)
from ..system import CfgIds, now, encoding
from .. import _probes


# Reputation save gate: only peers strictly above this threshold survive
# a process restart. Self is always persisted regardless. See
# doc/architecture/persistent-cohort.md for the rationale.
REPUTATION_PERSIST_THRESHOLD = 0.5


@dataclass
class TxCount(object):
    score: TransactionScore
    count: int


class ReputationProcess(Process, metaclass=ProcMeta,
                        proc_name=CfgIds.reputation, description='Reputation tracking', cfg_name=CfgIds.reputation):
    protocol_timeout = 30
    backoff_mult = 1.5
    backoff_max = 90
    expiration = 300
    # Reputation-derived trust-tier elevation. Each entry is
    # (score_floor, tier); scores below the lowest floor map to tier 0.
    # Sorted ascending so _trust_tier can iterate and pick the highest
    # matching tier. Tunable, but keep monotonically increasing.
    #
    # NOTE: trust tier is distinct from network rank (peer._rank) —
    # rank is topology / one-hop reachability, populated from
    # identity.json. See doc/architecture/trust-tiers.md §1 for the
    # disambiguation.
    TIER_FLOORS = (
        (0.50, 1),
        (0.65, 2),
        (0.80, 3),
        (0.90, 4),
    )

    # Hysteresis band for the CTFT ↔ pure-reputation dispatch in
    # _compute_reputation. A single 0.5 threshold made peers hovering
    # near 0.5 flip scoring functions every tick (CTFT's 0.51 →
    # pure_reputation's 0.4 → CTFT's 0.51 → …), surfacing as a
    # 0.9 ↔ 0.4 oscillation on the dashboard. Widening the switch
    # band so a peer must clear COOP_ENTER to graduate and fall below
    # COOP_EXIT to fall back removes the chatter without altering
    # either scoring function.
    COOP_ENTER = 0.55
    COOP_EXIT = 0.45

    # Pre-reputation cold-start (CTFT no-bilateral-history-with-us branch).
    # PREREP_NEUTRAL is the "no information" starting reputation: a peer we
    # know nothing about starts at the BOTTOM of the tit-for-tat band (0.0)
    # and must EARN its way up, rather than being handed a near-threshold
    # ~0.5 for free (which let unknown/newcomer peers read as almost-trusted
    # and made the trust graph a flat all-to-all mesh). The transaction-memory
    # prior (_prereputation_prior) shrinks a peer's observed third-party
    # standing toward this value by a pseudo-count of PREREP_SHRINKAGE_K, so a
    # truly-unknown peer (zero observations) reads exactly PREREP_NEUTRAL while
    # a peer others have already scored gets an informed, conservatively-shrunk
    # prior. This is the STARTING point only -- the CTFT bilateral pivots
    # (min(0.49, .)/max(0.51, .) around the 0.5 cooperate threshold) are the
    # earned near-threshold outputs and are deliberately unchanged. Mirror:
    # reputation.c PREREP_NEUTRAL. Disable via AT_PREREP_HEURISTIC=0.
    PREREP_NEUTRAL = 0.0
    PREREP_SHRINKAGE_K = 3.0

    # EMA half-life (in committed bilateral txs) for the dashboard
    # consensus-reputation channel.  Smaller → faster crash on a peer
    # that starts producing bad scores, slower rebuild for the rest.
    # 20 txs gives α ≈ 0.034 — a hacked peer falls visibly within
    # a few seconds of demo time while honest peers recover gradually.
    CONSENSUS_EMA_HALF_LIFE = 20

    # --- Idle reputation decay (warm-start staleness) -----------------
    # A peer's earned operational reputation is a *memory* of past
    # AT-bounded interaction. Memory should fade: the longer since we
    # last transacted with a peer, the closer its operational reputation
    # relaxes toward "almost-but-not-quite neutral" — never all the way
    # to 0.50, so a long-known asset stays faintly preferred over a true
    # stranger, but its elevated trust tier lapses and must be re-earned
    # on contact. The gap a peer spends out of contact between our
    # shutdown and the next start-up counts as idle time (seeded from the
    # persisted snapshot's mtime in _seed_idle_from_snapshot), which is
    # exactly what makes a warm-started cohort safe: re-loaded trust is
    # stale trust, and stale trust decays.
    #
    # ASYMMETRIC by design: decay only erodes reputation *above* the
    # asymptote, pulling it down. Scores at or below the asymptote are
    # left untouched — mere absence never rehabilitates a distrusted or
    # corrupt node (this preserves the sticky-low-reputation intent
    # documented at self._consensus_last). Slashed peers and self are
    # never decayed.
    #
    # Tunable. ONSET is a grace period before any decay starts (brief
    # out-of-range gaps cost nothing); HALF_LIFE sets how fast the gap
    # above the asymptote then halves; SWEEP_INTERVAL throttles the live
    # sweep. Defaults assume wall-clock seconds.
    REPUTATION_DECAY_ASYMPTOTE = 0.51       # just above neutral (0.50)
    REPUTATION_DECAY_ONSET = 3600.0         # s idle before decay begins
    REPUTATION_DECAY_HALF_LIFE = 86400.0    # s for the above-asymptote gap to halve
    REPUTATION_DECAY_SWEEP_INTERVAL = 60.0  # min s between live sweeps

    # Cap on the dedup set for committed paxos rounds (see
    # `self.committed_paxos_rounds` below). FIFO eviction, paired
    # with TransactionHistory's bounded chain so neither structure
    # grows without limit. Sized for ~2 min of in-flight protection
    # at the demo's sustained ~16 paxos commits/sec — small caps
    # let late ACCEPTEDs bypass the dedup, triggering redundant
    # commit re-broadcasts that fan out to every peer. The
    # tombstone in TransactionHistory makes those re-broadcasts
    # cheap no-ops on receivers, but the network/dispatch cost is
    # still real; 2000 eliminates the spurious traffic entirely
    # without measurably growing memory.
    COMMITTED_ROUNDS_CAP = 2000

    # When True, _spawn replaces threading.Thread().start() with a direct,
    # synchronous call. The conformance harness sets this so scenario steps
    # are deterministic; production paths leave it False.
    synchronous_dispatch = False

    def _spawn(self, target, args=(), kwargs=None, daemon=True):
        kwargs = kwargs or {}
        if self.synchronous_dispatch:
            target(*args, **kwargs)
            return None
        thread = threading.Thread(target=target, args=args, kwargs=kwargs, daemon=daemon)
        thread.start()
        return thread

    def __init__(self, configurations, subsystems, log_q, **kwargs):
        super().__init__(configurations, subsystems, log_q,
                         dependencies=[CfgIds.network, CfgIds.identity, CfgIds.negotiation], **kwargs)
        self.identity = self.configs[CfgIds.identity]
        self.protocol = ReputationProtocol(self.name, self.logger, configurations)
        self.protocol.register_handler(ReputationProtocol.request, self.handle_request)
        self.protocol.register_handler(ReputationProtocol.grant, self.handle_grant)
        self.protocol.register_handler(ReputationProtocol.nack, self.handle_nack)
        self.protocol.register_handler(ReputationProtocol.backdate, self.handle_backdate)
        self.protocol.register_handler(ReputationProtocol.transaction, self.handle_transaction)
        self.protocol.register_handler(ReputationProtocol.accepted, self.handle_accepted)
        self.protocol.register_handler(ReputationProtocol.committed, self.handle_committed)
        self.protocol.register_handler(ReputationProtocol.outdated, self.handle_outdated)
        self.protocol.register_handler(ReputationProtocol.update, self.handle_update)
        self.protocol.register_handler(ReputationProtocol.rep_req, self.handle_reputation_request)
        self.protocol.register_handler(
            ReputationProtocol.consensus_rep_req,
            self.handle_consensus_reputation_request)
        self.protocol.register_handler(
            ReputationProtocol.slash_propose, self.handle_slash_propose)
        self.protocol.register_handler(
            ReputationProtocol.slash_sign, self.handle_slash_sign)
        self.protocol.register_handler(
            ReputationProtocol.slash_final, self.handle_slash_final)
        self.protocol.register_handler(
            ReputationProtocol.checkpoint_propose, self.handle_checkpoint_propose)
        self.protocol.register_handler(
            ReputationProtocol.checkpoint_sign, self.handle_checkpoint_sign)
        self.protocol.register_handler(
            ReputationProtocol.checkpoint_final, self.handle_checkpoint_final)
        self.history = TransactionHistory()
        # Gateway reputation tree: one child chain per child group this
        # node gateways (keyed by group-uuid string). Empty on rank-1
        # leaf nodes — every code path below degrades to the single
        # self.history chain when this is empty, so leaves are
        # byte-for-byte unchanged. Lazily populated by _chain_for_group
        # the first time a commit routes to a known child group. See
        # doc/architecture/gateway-reputation-tree.md.
        self.child_histories: dict[str, TransactionHistory] = {}
        # Per-paxos-round group binding (idx -> group-uuid string). Set
        # by the proposer in _start_paxos so handle_grant / handle_accepted
        # / _paxos_timeout size the quorum and route the commit against
        # the round's own group rather than the conflated self.peers.all.
        self.round_group: dict[tuple, str] = {}
        self.my_requests: dict[tuple[int, int], TxCount] = {}
        self.requests: list[tuple[int, int]] = []
        self.proposals: dict[tuple[int, int], TransactionScore] = {}
        self.acceptances: dict[UUID, list[TransactionScore]] = {}
        self.last_id = None
        self.last_value = None
        self.backoff = {}
        # Prime from the persisted/seeded reputation snapshot when present
        # (warm-start). Previously this was always a fresh empty
        # Reputations, so reputation.cfg.json (written by
        # _persist_reputations and by tools/seed_dod_cohort.py) was loaded
        # into self.configs but never actually used — warm-start priors
        # and the consensus baseline both went missing. Fall back to an
        # empty store on a cold start.
        loaded_reps = self.configs.get(CfgIds.reputation)
        self.reputations = (loaded_reps
                            if isinstance(loaded_reps, Reputations)
                            else Reputations())
        # Idle-decay bookkeeping. _last_interaction maps peer-uuid-str ->
        # epoch seconds of our most recent committed transaction with that
        # peer; the staleness sweep relaxes idle peers toward almost-
        # neutral (see the REPUTATION_DECAY_* constants). _seed_idle_from_
        # snapshot below back-dates the warm-started cohort to the persisted
        # snapshot's mtime and applies the offline-gap decay at start-up.
        self._last_interaction: dict[str, float] = {}
        self._last_decay_sweep = 0.0
        self._seed_idle_from_snapshot()
        # Sticky consensus memory: peer-uuid-str -> last real (chain-derived)
        # consensus score. The tx chain is a bounded window, so an idle
        # peer's transactions evict within ~one window of sustained
        # activity; without this its consensus would snap back to 0.5 the
        # moment its last tx ages out. Stickiness holds the last computed
        # value until NEW transactions update it — so a peer that stops
        # interacting (out of range) keeps its earned reputation (incl. a
        # low one for a corrupt node) instead of decaying to neutral.
        self._consensus_last: dict[str, float] = {}
        # Persistent per-peer running consensus EMA over the PRIMARY chain
        # (peer-uuid-str -> ema), folded once per committed bilateral tx and
        # tracked by the highest chain index already folded
        # (_consensus_folded_idx). Unlike the from-scratch recompute in
        # _consensus_reputation, this retains history that has since evicted
        # from the bounded window, so a sliding window can no longer reshape a
        # peer's score — which is what produced the synchronized dashboard
        # "Trust Dynamics" sawtooth. See _running_consensus.
        self._consensus_ema: dict[str, float] = {}
        self._consensus_folded_idx: dict[str, int] = {}
        self.requested_reps = []
        self.updates = {}
        self.num_updates = 3
        # Last published trust tier per peer uuid-string. Suppresses
        # redundant tier_update IPC when the tier hasn't changed.
        self.peer_tiers: dict[str, int] = {}
        # Per-task transaction_weight cache (task_id_str -> int). Populated
        # when a TransactionScore enters the system (locally submitted via
        # _start_paxos, or arriving via handle_transaction). Read by
        # _pure_reputation / _consensus_reputation to weight each
        # transaction's contribution by its capability's transaction_weight.
        # See doc/architecture/trust-tiers.md §5. Default 1 when the task's
        # capability is unknown locally (legacy, or peer late-joiner that
        # only saw the committed broadcast). Bounded by tying eviction to
        # the TransactionHistory chain (see _evict_task_weight below).
        self.task_weights: dict[str, int] = {}
        # Per-task capability tier, populated alongside task_weights from the
        # TS capability_name. Feeds the per-tier consensus view
        # (_consensus_reputation_by_tier, trust-tiers §12 / deferred.md §2.3).
        # Same FIFO bound as task_weights. Default tier 0 when the capability
        # is unknown locally.
        self.task_tiers: dict[str, int] = {}
        # Last computed {tier: score} per peer (str uuid -> dict), refreshed by
        # _consensus_reputation_by_tier so a dashboard / query can read the
        # per-tier breakdown without recomputing.
        self._per_tier_last: dict[str, dict[int, float]] = {}
        # (peer_uuid, score) pairs produced by _compute_reputation in
        # spawned threads, drained by the main `process` loop where
        # `queues` is in scope. Same pattern as `requested_reps`.
        self.pending_tiers: list = []
        # Paxos rounds already committed locally — prevents
        # handle_accepted from re-firing its commit block on every
        # late ACCEPTED that arrives after majority is reached.
        # Without this, each round triggers `len(peers.all)-majority+1`
        # redundant commit broadcasts, and duplicate broadcasts
        # corrupt the resulting Transaction (p1 and p2 both end up
        # holding the proposer's uuid because TransactionHistory.update
        # doesn't dedup by peer_id).
        #
        # OrderedDict (used as an ordered set; values are ignored)
        # so we can FIFO-evict at COMMITTED_ROUNDS_CAP — the
        # underlying set was append-only and grew without bound. The
        # dedup only needs to outlive in-flight ACCEPTED reorder,
        # which is well under the cap.
        self.committed_paxos_rounds: 'OrderedDict[tuple, None]' = OrderedDict()
        # Per-peer latch for the CTFT/pure-reputation dispatch.
        # False = CTFT, True = pure. Combined with COOP_ENTER /
        # COOP_EXIT to give the mode switch hysteresis.
        self._coop_mode: dict[UUID, bool] = {}
        # --- Slashing (fast-penalty path) ---------------------------------
        # Applied floors: target-uuid-str -> (floor_score, epoch). Consulted
        # at the TOP of _consensus_reputation / _compute_reputation so a
        # slashed peer reads its floor regardless of chain/EMA/baseline.
        # Volatile (not persisted): a process restart clears slashes, which
        # matches the persist model (a slashed peer is simply below
        # REPUTATION_PERSIST_THRESHOLD and isn't carried over).
        self._slashed: dict[str, tuple] = {}
        # Proposer-side co-signature accumulation: slash-key -> set of
        # voter-uuid-str. Seeded with the slasher itself on initiation.
        self._slash_sigs: dict[tuple, set] = {}
        # Proposer-side pending attestations awaiting quorum: key -> attestation.
        self._slash_pending: dict[tuple, SlashAttestation] = {}
        # Dedup for finalized slashes (FIFO bounded), so a re-broadcast
        # slash_final is a cheap no-op. Mirrors committed_paxos_rounds.
        self._slashed_seen: 'OrderedDict[tuple, None]' = OrderedDict()
        # Monotonic epoch for slashes this node originates (distinguishes a
        # re-slash of the same target). Phase 2 will tie this to checkpoint
        # epochs; standalone counter suffices for Phase 0.
        self._slash_epoch = 0

        # --- Phase 2: quorum-signed Merkle checkpoints --------------------
        # Latest finalized checkpoint of OUR window (the agreed commitment a
        # gateway parent / slash adjudicator verifies inclusion proofs
        # against). None until the first checkpoint finalizes. Volatile.
        self._checkpoint: 'Checkpoint | None' = None
        # Proposer-side co-signature accumulation: checkpoint-key -> set of
        # voter-uuid-str (only members whose own window_root matched). Seeded
        # with the proposer itself on initiation.
        self._checkpoint_sigs: dict[tuple, set] = {}
        # Proposer-side pending checkpoints awaiting quorum: key -> Checkpoint.
        self._checkpoint_pending: dict[tuple, Checkpoint] = {}
        # Dedup for finalized checkpoints (FIFO bounded) so a re-broadcast
        # checkpoint_final is a cheap no-op. Mirrors _slashed_seen.
        self._checkpoint_seen: 'OrderedDict[tuple, None]' = OrderedDict()
        # Monotonic epoch for checkpoints this node originates.
        self._checkpoint_epoch = 0

    @property
    def peers(self):
        return self.protocol.peers

    @property
    def group(self):
        return self.protocol.group

    @property
    def child_groups(self):
        # dict[group-uuid-str -> Group] for the cohorts this node
        # gateways. Empty for leaf nodes (Protocol.child_groups defaults
        # empty), which keeps every multi-group code path inert here.
        return getattr(self.protocol, 'child_groups', {}) or {}

    def _group_by_uuid(self, group_uuid):
        """Resolve a group-uuid string to its Group (primary or child),
        or None when unknown."""
        if group_uuid is None:
            return self.group
        key = str(group_uuid)
        if self.group is not None and key == str(self.group.uuid):
            return self.group
        return self.child_groups.get(key)

    def _members_of_group(self, group):
        """Peers (from self.peers.all) whose address is in this group's
        address map. Used to size per-group Paxos quorum on a gateway
        whose self.peers.all spans several groups."""
        if group is None:
            return list(self.peers.all)
        try:
            addrs = set(group.addresses)
        except Exception:
            return list(self.peers.all)
        return [p for p in self.peers.all
                if getattr(p, 'address', None) in addrs]

    def _quorum_for_group(self, group_uuid):
        """Majority threshold (floor(N/2)) for a round in the given group.

        Back-compat: a non-gateway node (no child_groups) always uses the
        historical len(self.peers.all)//2, so leaf quorum math is
        unchanged. Only a gateway — whose self.peers.all conflates the
        members of every group it belongs to — sizes per-group."""
        if not self.child_groups:
            return len(self.peers.all) // 2
        grp = self._group_by_uuid(group_uuid)
        if grp is None:
            return len(self.peers.all) // 2
        return len(self._members_of_group(grp)) // 2

    def _chain_for_group(self, group_uuid):
        """Return the TransactionHistory for a group-uuid, defaulting to
        the primary chain (self.history).

        Unknown / None group-uuids and the primary group resolve to
        self.history — so a leaf node (no child_groups) always operates
        on its single chain exactly as before. A commit tagged with a
        known child group's uuid routes to that child's chain, created
        lazily on first use."""
        if group_uuid is None:
            return self.history
        key = str(group_uuid)
        if self.group is not None and key == str(self.group.uuid):
            return self.history
        if key in self.child_groups:
            if key not in self.child_histories:
                self.child_histories[key] = TransactionHistory()
            return self.child_histories[key]
        return self.history

    @staticmethod
    def _paxos_id_index(id1, id2):
        return (id1, id2)  # use tuple key to avoid float equality issues

    def handle_request(self, queues, message):
        if message.function == ReputationProtocol.request:
            id1, id2, peer_id = from_json_string(message.obj)
            if peer_id in [p.uuid for p in self.peers.all]:
                try:
                    if self.last_id is None or self.last_id < id1:
                        if len(self.history) + 1 == id2:
                            self.requests.append(self._paxos_id_index(id1, id2))
                            # Ack carries the PRIOR last_id so the proposer
                            # sees the state-before-this-grant; matches C's
                            # `*out_last_id = inst->last_id;` capture in
                            # paxos.c:114 (before the update at :123).
                            ack = ((id1, id2, peer_id), (self.last_id, len(self.history)), self.last_value)
                            msg = Message(self.name, ReputationProtocol.grant,
                                          to_json_string(ack), message.from_whom,
                                          from_whom=self.identity)
                            queues[CfgIds.network].put(msg, block=True, timeout=self.q_cadence)
                            self.logger.debug('Request granted')
                            # Pin the ballot — second-grant guard. Without
                            # this, a duplicate (id1, id2) ask would re-pass
                            # the `last_id is None or last_id < id1` check
                            # and grant again, double-appending to
                            # self.requests. C's paxos_handle_request sets
                            # `inst->last_id = id1` here (paxos.c:123); the
                            # missing update was the cross-language
                            # asymmetry tracked as BUGS.md P6.
                            self.last_id = id1
                        else:
                            msg = Message(self.name, ReputationProtocol.backdate,
                                          message.obj, message.from_whom,
                                          from_whom=self.identity)
                            queues[CfgIds.network].put(msg, block=True, timeout=self.q_cadence)
                            self.logger.debug('Request backdated')
                    else:
                        msg = Message(self.name, ReputationProtocol.nack,
                                      message.obj, message.from_whom,
                                      from_whom=self.identity)
                        queues[CfgIds.network].put(msg, block=True, timeout=self.q_cadence)
                        self.logger.debug('Request refused')
                except Full:
                    self.logger.error('handle_request: Network queue full')
            else:
                self.logger.debug('Reputation request from non-peer: %s' % peer_id)
            return True
        return False

    def _paxos_timeout(self, queues, pax_id):
        retry = True
        idx = self._paxos_id_index(pax_id[0], pax_id[1])
        quorum = self._quorum_for_group(self.round_group.get(idx))
        start = now()
        while (now() - start).total_seconds() < self.protocol_timeout:
            if idx not in self.my_requests:
                retry = False  # already completed by handle_grant
                break
            if self.my_requests[idx].count >= quorum:
                retry = False
                break
            time.sleep(self.cadence)
        if retry and idx in self.my_requests:
            try:
                self._start_paxos(queues, self.my_requests[idx].score)
            except (Full, KeyError):
                self.logger.error('paxos_timeout: Network queue full')

    def handle_grant(self, queues, message):
        if message.function == ReputationProtocol.grant:
            (id1, id2, peer_id), (last_id, last_idx), last_val = from_json_string(message.obj)
            if peer_id != self.identity.uuid:  # ignore not-mine
                self.logger.debug('Grant not for me')
                return True
            if (last_id is not None and last_id >= id1) or last_idx != len(self.history):  # peer is faulty
                self.peers.demote(message.from_whom)
                self.logger.debug('Grant from faulty peer')
                self._spawn(self._paxos_timeout, args=(queues, (id1, id2, peer_id)))
                return True
            idx = self._paxos_id_index(id1, id2)
            if idx not in self.my_requests:
                self.logger.debug('Grant for already-completed request')
                return True
            self.my_requests[idx].count += 1
            if self.my_requests[idx].count >= self._quorum_for_group(
                    self.round_group.get(idx)):
                try:
                    score = (id1, id2, peer_id), self.my_requests[idx].score
                    msg = Message(self.name, ReputationProtocol.transaction,
                                  to_json_string(score), self.group,
                                  from_whom=self.identity)
                    queues[CfgIds.network].put(msg, block=True, timeout=self.q_cadence)
                    self.logger.debug('Submit transaction score')
                    if idx in self.backoff:
                        del self.backoff[idx]
                    del self.my_requests[idx]
                except Full:
                    self.logger.error('handle_grant: Network queue full')
            return True
        return False

    def _try_again(self, wait, queues, score):
        start = now()
        while (now() - start).total_seconds() < wait:
            time.sleep(self.cadence)
        try:
            self._start_paxos(queues, score)
        except Full:
            self.logger.error('try_again: Network queue full')

    def handle_nack(self, queues, message):
        if message.function == ReputationProtocol.nack:
            id1, id2, _ = from_json_string(message.obj)
            idx = self._paxos_id_index(id1, id2)
            if idx not in self.my_requests:
                # Nack for an already-completed (grant succeeded, removed
                # from my_requests) or never-issued (foreign id) request.
                # Drop without retrying.
                self.logger.debug('Nack for unknown or completed request')
                return True
            if idx not in self.backoff:
                self.backoff[idx] = 1
            if self.backoff[idx] < self.backoff_max:
                self.backoff[idx] *= self.backoff_mult
            self._spawn(self._try_again,
                        args=(self.backoff[idx], queues, self.my_requests[idx].score))
            return True
        return False

    def _request_update(self, queues, n=3):
        self.num_updates = n
        for peer in self.peers.find_top_n(n):
            msg = Message(self.name, ReputationProtocol.outdated,
                          str(len(self.history)), peer,
                          from_whom=self.identity)
            queues[CfgIds.network].put(msg, block=True, timeout=self.q_cadence)

    def handle_backdate(self, queues, message):
        if message.function == ReputationProtocol.backdate:
            try:
                self._request_update(queues)
            except Full:
                self.logger.error('request_update: Network queue full')
            return True
        return False

    # Bound on self.task_weights — twice the TransactionHistory chain
    # cap, so a freshly-submitted task is unlikely to need a weight
    # that's already been evicted. Tied to DEFAULT_MAX_CHAIN_LEN via
    # default; tunable via AT_TX_HISTORY_CAP picks the same factor.
    _TASK_WEIGHTS_CAP = 2 * TransactionHistory.DEFAULT_MAX_CHAIN_LEN

    def _resolve_tx_weight(self, score: TransactionScore) -> int:
        """Map a TS's capability_name to its transaction_weight, with a
        graceful default. The lookup goes through the local Capabilities
        registry (self.protocol.capabilities); peers that don't have
        the capability registered locally treat the weight as 1.
        Returns at least 1 (the 0-sentinel from proto3 is normalised to
        1 in Capability.sync_from_message; this is a defence in depth).
        """
        cap_name = getattr(score, 'capability_name', None)
        if not cap_name:
            return 1
        try:
            cap = self.protocol.capabilities[cap_name]
        except (KeyError, AttributeError, TypeError):
            return 1
        w = getattr(cap, 'transaction_weight', 1) or 1
        return max(1, int(w))

    def _record_task_weight(self, task_id, weight: int) -> None:
        """Insert into self.task_weights with FIFO eviction at the cap.
        Insertion order is preserved by dict semantics (Py 3.7+), so
        the oldest entry is `next(iter(...))` when over cap."""
        key = str(task_id)
        # If the key already exists, refresh insertion order by
        # popping-then-inserting so a recent update isn't immediately
        # evicted by an unrelated insert.
        if key in self.task_weights:
            del self.task_weights[key]
        self.task_weights[key] = int(weight)
        while len(self.task_weights) > self._TASK_WEIGHTS_CAP:
            self.task_weights.pop(next(iter(self.task_weights)))

    def _resolve_tx_tier(self, score: TransactionScore) -> int:
        """Map a TS's capability_name to the capability's required_tier, with
        a graceful default of 0 (mirrors _resolve_tx_weight). Peers that don't
        have the capability registered locally treat the tier as 0. Used to
        bucket transactions for the per-tier consensus view."""
        cap_name = getattr(score, 'capability_name', None)
        if not cap_name:
            return 0
        try:
            cap = self.protocol.capabilities[cap_name]
        except (KeyError, AttributeError, TypeError):
            return 0
        t = getattr(cap, 'required_tier', 0) or 0
        return max(0, int(t))

    def _record_task_tier(self, task_id, tier: int) -> None:
        """Insert into self.task_tiers with the same FIFO eviction as
        task_weights (kept in lockstep so a task's weight and tier evict
        together)."""
        key = str(task_id)
        if key in self.task_tiers:
            del self.task_tiers[key]
        self.task_tiers[key] = int(tier)
        while len(self.task_tiers) > self._TASK_WEIGHTS_CAP:
            self.task_tiers.pop(next(iter(self.task_tiers)))

    def _start_paxos(self, queues, score: TransactionScore, group_uuid=None):
        id1 = int(now().timestamp() * 1000)
        id2 = len(self.history) + 1
        idx = self._paxos_id_index(id1, id2)
        pax_id = (id1, id2, self.identity.uuid)
        self.my_requests[idx] = TxCount(score, 0)
        # Bind this round to its group so quorum + commit routing use
        # the round's own group, not the conflated self.peers.all.
        # Defaults to the primary group (the gateway's own/parent
        # cohort), which is correct for the demo where a gateway's
        # self-initiated transactions are with its command cohort.
        if group_uuid is None and self.group is not None:
            group_uuid = str(self.group.uuid)
        self.round_group[idx] = group_uuid
        pax_msg = Message(self.name, ReputationProtocol.request,
                          to_json_string(pax_id), self.group,
                          from_whom=self.identity)
        queues[CfgIds.network].put(pax_msg, block=True, timeout=self.q_cadence)
        self.proposals[idx] = score
        # Cache the weight for this task so _pure_reputation can later
        # aggregate it correctly (Slice 3 / trust-tiers.md §5), and the tier
        # so the per-tier consensus view can bucket it (§2.3).
        self._record_task_weight(score.task_id, self._resolve_tx_weight(score))
        self._record_task_tier(score.task_id, self._resolve_tx_tier(score))
        self.logger.debug('Start a Paxos round')

    def handle_transaction(self, queues, message):
        if message.function == ReputationProtocol.transaction:
            (id1, id2, peer_id), score = from_json_string(message.obj)
            idx = self._paxos_id_index(id1, id2)
            if idx not in self.requests:
                return True  # not granted, drop
            self.requests.remove(idx)
            if not message.verified:
                self.logger.warning(f"Rejecting unverified Paxos proposal from {message.from_whom}")
                return True  # drop unverified proposal
            if idx not in self.proposals:
                self.proposals[idx] = score
                self.logger.debug("Tx to proposals ")
            # Cache the weight for this task — incoming TS payload carries
            # capability_name (Slice 1). Receivers that don't register the
            # capability locally fall back to weight 1.
            if hasattr(score, 'task_id'):
                self._record_task_weight(score.task_id, self._resolve_tx_weight(score))
                self._record_task_tier(score.task_id, self._resolve_tx_tier(score))
            msg = Message(self.name, ReputationProtocol.accepted,
                          to_json_string((id1, id2, peer_id)),
                          message.from_whom, from_whom=self.identity)
            queues[CfgIds.network].put(msg, block=True, timeout=self.q_cadence)
            return True
        return False

    def forward_transaction(self, queues, message):
        if isinstance(message, TransactionScore):
            try:
                # Don't write to history here.  The C twin
                # _forward_transaction (rep_proc.c:1081-1102) only
                # stages the score in my_requests and kicks off Paxos
                # — history is updated solely from handle_accepted
                # when the round commits.  The previous Python
                # behaviour wrote (task_id, self_uuid, self_score)
                # immediately, then handle_accepted re-wrote the same
                # tuple on the proposer's own round, filling both
                # p1=self and p2=self.  Any subsequent peer
                # submission for the same task_id was then silently
                # dropped by TransactionHistory.update (len(tx)==2),
                # so the proposer's local history could never record
                # a bilateral transaction with another peer.
                self._start_paxos(queues, message)
            except Full:
                self.logger.error('handle_transaction: Network queue full')
            return True
        return False

    def handle_accepted(self, queues, message):
        if message.function == ReputationProtocol.accepted:
            id1, id2, peer_id = from_json_string(message.obj)
            idx = self._paxos_id_index(id1, id2)
            score = self.proposals[idx]
            self.logger.debug('Tx accepted')
            if score.task_id not in self.acceptances:
                self.acceptances[score.task_id] = []
            if message.from_whom not in self.acceptances[score.task_id]:
                if not message.verified:
                    self.logger.warning(f"Rejecting unverified Paxos acceptance from {message.from_whom}")
                    return True  # drop unverified acceptance
                self.acceptances[score.task_id].append(message.from_whom)
            round_group_uuid = self.round_group.get(idx)
            if len(self.acceptances[score.task_id]) > self._quorum_for_group(
                    round_group_uuid):
                # Idempotency guard: every ACCEPTED that arrives
                # after the majority threshold has been crossed would
                # otherwise re-fire the commit-and-broadcast block.
                # That fanned out ~N-majority extra `committed`
                # broadcasts per round, and duplicate broadcasts
                # corrupt the resulting Transaction (p1 and p2 both
                # end up = proposer because TransactionHistory.update
                # doesn't dedup by peer_id) — making the txs look
                # bilateral on paper but actually single-peer, which
                # CTFT's `p1==peer && p2==self` check then rejects.
                if idx in self.committed_paxos_rounds:
                    return True
                self.committed_paxos_rounds[idx] = None
                while (len(self.committed_paxos_rounds)
                        > self.COMMITTED_ROUNDS_CAP):
                    self.committed_paxos_rounds.popitem(last=False)
                # The proposer writes their own entry here.  The
                # `committed` broadcast below makes the acceptors do
                # the same on their end, so the resulting
                # Transaction has both p1 and p2 filled across all
                # peers' histories (see ReputationProtocol.committed
                # for the rationale). Route to the round's group chain
                # — primary for leaf nodes, a child chain on a gateway.
                self._chain_for_group(round_group_uuid).update(
                    score.task_id, peer_id, score.score)
                # Fold-on-commit: keep the dashboard running consensus EMA
                # current the moment a tx completes (primary chain only).
                self._fold_committed_tx(
                    score.task_id, self._chain_for_group(round_group_uuid))
                self._note_interaction(peer_id)
                # Bumped to info to make demo debugging tractable —
                # without a commit log, "no movement on reputations"
                # is indistinguishable from "no paxos commits".
                _routed = self._chain_for_group(round_group_uuid)
                # Bumped to info to make demo debugging tractable —
                # without a commit log, "no movement on reputations"
                # is indistinguishable from "no paxos commits".
                self.logger.info(
                    'Transaction committed: task=%s peer=%s score=%.2f '
                    'group=%s (chain now %d txs, %d task_maps)',
                    str(getattr(score, "task_id", ""))[:8],
                    str(peer_id)[:8], score.score,
                    str(round_group_uuid)[:8],
                    len(_routed),
                    len(_routed._task_mapping))
                try:
                    # Pass task_id and peer_id through unchanged —
                    # ConfigJSONEncoder round-trips UUID objects with
                    # a __type__ tag, so handle_committed receives
                    # the same types we put in.  Stringifying here
                    # would break that round-trip. The trailing
                    # group_uuid lets receivers route the commit to the
                    # right chain; handle_committed unpacks it
                    # length-tolerantly so legacy 3-tuples still work.
                    commit_msg = Message(
                        self.name, ReputationProtocol.committed,
                        to_json_string(
                            (score.task_id, peer_id, score.score,
                             round_group_uuid)),
                        self._group_by_uuid(round_group_uuid) or self.group,
                        from_whom=self.identity)
                    queues[CfgIds.network].put(
                        commit_msg, block=True, timeout=self.q_cadence)
                except Full:
                    self.logger.error(
                        'handle_accepted: Network queue full broadcasting commit')
            return True
        return False

    def handle_committed(self, _, message):
        """Phase 3 — receive a committed-transaction broadcast from
        a proposer that just reached majority acceptance.  Write
        (task_id, peer_id, score) to local history.

        The proposer's own broadcast bounces back to itself; we skip
        the self-update because handle_accepted already wrote the
        entry locally.  TransactionHistory.update is idempotent
        against a second arrival (the len(tx)==2 guard), so
        duplicate or out-of-order committed messages from network
        retries are safe."""
        if message.function == ReputationProtocol.committed:
            try:
                parsed = from_json_string(message.obj)
                # Length-tolerant: new payloads carry a trailing
                # group_uuid; legacy 3-tuples resolve to the primary
                # chain (group_uuid None -> _chain_for_group default).
                task_id, peer_id, score = parsed[0], parsed[1], parsed[2]
                group_uuid = parsed[3] if len(parsed) > 3 else None
            except Exception:
                self.logger.warning(
                    'handle_committed: malformed payload %r', message.obj)
                return True
            if str(peer_id) == str(self.identity.uuid):
                return True
            chain = self._chain_for_group(group_uuid)
            chain.update(task_id, peer_id, float(score))
            # Fold-on-commit: advance the dashboard running consensus EMA as
            # soon as this tx completes (primary chain only; idempotent).
            self._fold_committed_tx(task_id, chain)
            self._note_interaction(peer_id)
            self.logger.info(
                'Recorded committed tx from %s: task=%s score=%.2f '
                'group=%s (chain now %d txs, %d task_maps)',
                str(peer_id)[:8], str(task_id)[:8], float(score),
                str(group_uuid)[:8],
                len(chain),
                len(chain._task_mapping))
            return True
        return False

    # --- Slashing (fast-penalty path) ---------------------------------
    # Three-phase shape mirroring transaction/accepted/committed:
    #   forward_slash  : local detector originates -> self-apply + broadcast
    #                    slash_propose, seeding its own co-signature.
    #   slash_propose  : members co-sign (slash_sign) back to the slasher.
    #   slash_sign     : slasher tallies; on > quorum, broadcasts slash_final.
    #   slash_final    : every node floors the target's reputation.
    # Phase 0 trusts the transport-verified detector (message.verified);
    # Merkle-evidence verification + quorum-signature checking land in
    # Phase 3. Default-off: absent in legacy scenarios, so byte-pinned
    # corpora are unaffected.

    def _slash_quorum(self, group_uuid=None):
        """Co-signers required to finalize a slash; reuses Paxos majority
        sizing. '> quorum' total signers (including the slasher) finalizes,
        mirroring handle_accepted."""
        return self._quorum_for_group(group_uuid)

    def _slash_target_ok(self, attestation) -> bool:
        """Reject self-slash adoption and degenerate slasher==target."""
        if str(attestation.target_uuid) == str(self.identity.uuid):
            return False
        if str(attestation.slasher_uuid) == str(attestation.target_uuid):
            return False
        return True

    def build_slash_evidence(self, task_id):
        """Phase 3: build the Merkle inclusion evidence for the committed tx
        ``task_id``, tying a slash to a checkpoint-committed offending entry.

        Returns a JSON-friendly dict ``{task_id, leaf, proof, root}`` where
        ``leaf`` is the tx's ``entry_hash`` (hex), ``proof`` the RFC 6962 audit
        path ([[sibling_hex, sibling_is_left], ...]) against the current
        ``window_root``, and ``root`` that window root (hex). Returns None if
        the task is not resident in the window. A detector attaches this to a
        ``SlashAttestation.evidence_ref`` so peers can verify the accusation
        against a quorum-finalized checkpoint instead of trusting the detector
        (reputation-vs-blockchain-analysis.md §2.1 / §3)."""
        tx = self.history._task_mapping.get(task_id)
        if tx is None or tx.index is None:
            return None
        proof = self.history.inclusion_proof(tx.index)
        if proof is None:
            return None
        root = self.history.window_root()
        return {
            'task_id': str(task_id),
            'leaf': tx.entry_hash().decode('ascii'),
            'proof': [[s.decode('ascii') if isinstance(s, bytes) else s,
                       bool(left)] for s, left in proof],
            'root': root.decode('ascii') if isinstance(root, bytes) else str(root),
        }

    def _verify_slash_evidence(self, attestation) -> bool:
        """Phase 3: gate a slash on Merkle evidence.

        - No ``evidence_ref`` -> True (Phase 0 trust-the-detector fallback, so
          legacy / evidence-free slashes are unaffected).
        - With ``evidence_ref`` -> the offending tx's inclusion proof must
          verify against a root this node has FINALIZED as a checkpoint
          (``self._checkpoint.root``). Tying it to our own quorum-agreed
          checkpoint — not a root chosen by the accuser — is what makes the
          evidence trustworthy. Any malformed / mismatched / unverifiable
          evidence returns False and the slash is refused."""
        ev = attestation.evidence_ref
        if ev is None:
            return True
        if self._checkpoint is None:
            return False  # nothing to verify against
        try:
            leaf = ev['leaf']
            leaf = leaf.encode('ascii') if isinstance(leaf, str) else leaf
            root = ev['root']
            root = root.encode('ascii') if isinstance(root, str) else root
            proof = [(s.encode('ascii') if isinstance(s, str) else s, bool(left))
                     for s, left in ev['proof']]
        except (KeyError, TypeError, ValueError):
            return False
        ck_root = self._checkpoint.root
        if isinstance(ck_root, str):
            ck_root = ck_root.encode('ascii')
        # The evidence must be proven against OUR finalized checkpoint root.
        if root != ck_root:
            return False
        return TransactionHistory.verify_inclusion(leaf, proof, root)

    def _apply_slash(self, attestation):
        """Pin (or, for 'rehabilitate', lift) the target's reputation floor
        and queue a tier recompute so tier_lost flows through the existing
        path. Idempotent per (target, epoch)."""
        key = attestation.key()
        if key in self._slashed_seen:
            return
        target = str(attestation.target_uuid)
        if attestation.reason == SlashAttestation.REASON_REHABILITATE:
            self._slashed.pop(target, None)
            # Drop sticky floor so the score recomputes from chain/EMA.
            self._consensus_last.pop(target, None)
        else:
            floor = float(attestation.floor_score)
            self._slashed[target] = (floor, int(attestation.epoch))
            # Reflect the floor in the canonical reputation store too, so
            # the verdict is observable to persistence, tier publication,
            # and any reader of self.reputations (e.g. the conformance
            # `reputation_of` assertion) — not only lazily at scoring time.
            # A floored peer is below REPUTATION_PERSIST_THRESHOLD so it is
            # not carried across a restart, matching the volatile intent.
            try:
                self.reputations.update(attestation.target_uuid, floor)
            except Exception:
                self.logger.debug('apply_slash: reputations.update failed',
                                  exc_info=True)
        self._slashed_seen[key] = None
        while len(self._slashed_seen) > self.COMMITTED_ROUNDS_CAP:
            self._slashed_seen.popitem(last=False)
        # Queue a tier recompute (drained in process()): _compute_reputation
        # now short-circuits on the floor and publishes tier 0 / tier_lost.
        self.pending_tiers.append(
            (attestation.target_uuid, float(attestation.floor_score)))
        self.logger.info(
            'Slash %s: target=%s reason=%s floor=%.2f epoch=%d',
            'lifted' if attestation.reason
            == SlashAttestation.REASON_REHABILITATE else 'applied',
            target[:8], attestation.reason,
            float(attestation.floor_score), int(attestation.epoch))

    def forward_slash(self, queues, message):
        """Entry point for a locally-originated slash: a detector (e.g. the
        dod_mission coordinator) puts a SlashAttestation on the reputation
        queue. Stamp epoch/nonce, sign, apply to our OWN view immediately
        (a node always trusts its own detection — this is what the
        detector's dashboard reads), seed the co-signature set with
        ourself, and broadcast slash_propose to collect a quorum. Mirrors
        forward_transaction's role for TransactionScore."""
        if isinstance(message, SlashAttestation):
            try:
                att = message
                att.slasher_uuid = self.identity.uuid
                self._slash_epoch += 1
                att.epoch = self._slash_epoch
                if att.nonce is None:
                    att.nonce = os.urandom(8)
                try:
                    att.signature = self.identity.sign(att.designation)
                except Exception:
                    att.signature = None
                key = att.key()
                self._slash_pending[key] = att
                self._slash_sigs[key] = {str(self.identity.uuid)}
                # Self-apply now so the detector's own consensus view (the
                # dashboard) floors the target immediately, independent of
                # co-sign round-trip latency.
                self._apply_slash(att)
                if self.group is not None:
                    msg = Message(self.name, ReputationProtocol.slash_propose,
                                  to_json_string(att), self.group,
                                  from_whom=self.identity)
                    queues[CfgIds.network].put(
                        msg, block=True, timeout=self.q_cadence)
                self.logger.info(
                    'Initiated slash: target=%s reason=%s floor=%.2f',
                    str(att.target_uuid)[:8], att.reason,
                    float(att.floor_score))
            except Full:
                self.logger.error('forward_slash: network queue full')
            return True
        return False

    def handle_slash_propose(self, queues, message):
        if message.function == ReputationProtocol.slash_propose:
            if not message.verified:
                self.logger.warning(
                    'Rejecting unverified slash_propose from %s',
                    message.from_whom)
                return True
            # Message auto-deserializes a top-level Configuration payload
            # into message.obj (see Message.__init__), so this is usually
            # already a SlashAttestation; tolerate a raw JSON string too.
            att = (message.obj if isinstance(message.obj, SlashAttestation)
                   else from_json_string(message.obj))
            # Don't co-sign our own bounce-back, and don't adopt a self-slash.
            if str(att.slasher_uuid) == str(self.identity.uuid):
                return True
            if not self._slash_target_ok(att):
                return True
            # Phase 3: if the slash carries Merkle evidence, refuse to co-sign
            # unless the offending tx's inclusion proof verifies against our
            # own finalized checkpoint. Evidence-free slashes fall back to the
            # Phase 0 trust-the-detector path (_verify_slash_evidence -> True).
            if not self._verify_slash_evidence(att):
                self.logger.warning(
                    'Declining slash_propose: evidence failed verification')
                return True
            try:
                sig = self.identity.sign(att.designation)
            except Exception:
                sig = None
            tgt, epoch = att.key()
            ack = (tgt, epoch, str(self.identity.uuid), sig)
            try:
                msg = Message(self.name, ReputationProtocol.slash_sign,
                              to_json_string(ack), message.from_whom,
                              from_whom=self.identity)
                queues[CfgIds.network].put(
                    msg, block=True, timeout=self.q_cadence)
            except Full:
                self.logger.error('handle_slash_propose: queue full')
            return True
        return False

    def handle_slash_sign(self, queues, message):
        if message.function == ReputationProtocol.slash_sign:
            if not message.verified:
                return True
            payload = message.obj
            if isinstance(payload, str):
                payload = from_json_string(payload)
            tgt, epoch, voter, _sig = payload
            key = (str(tgt), int(epoch))
            att = self._slash_pending.get(key)
            if att is None:
                return True  # not our round, or already finalized
            self._slash_sigs.setdefault(key, set()).add(str(voter))
            grp_uuid = str(self.group.uuid) if self.group is not None else None
            if len(self._slash_sigs[key]) > self._slash_quorum(grp_uuid):
                signed = SignedSlash(attestation=att, sigs={})
                try:
                    msg = Message(
                        self.name, ReputationProtocol.slash_final,
                        to_json_string(signed),
                        self._group_by_uuid(grp_uuid) or self.group,
                        from_whom=self.identity)
                    queues[CfgIds.network].put(
                        msg, block=True, timeout=self.q_cadence)
                    self.logger.info(
                        'Slash finalized & broadcast: target=%s signers=%d',
                        str(att.target_uuid)[:8], len(self._slash_sigs[key]))
                except Full:
                    self.logger.error(
                        'handle_slash_sign: queue full broadcasting final')
                # Drop pending so later signs are no-ops (finality dedup).
                del self._slash_pending[key]
            return True
        return False

    def handle_slash_final(self, _, message):
        if message.function == ReputationProtocol.slash_final:
            if not message.verified:
                self.logger.warning(
                    'Rejecting unverified slash_final from %s',
                    message.from_whom)
                return True
            signed = (message.obj if isinstance(message.obj, SignedSlash)
                      else from_json_string(message.obj))
            att = getattr(signed, 'attestation', None)
            if att is None:
                return True
            # The slasher already self-applied; skip the bounce-back.
            if str(att.slasher_uuid) == str(self.identity.uuid):
                return True
            if not self._slash_target_ok(att):
                return True
            # Phase 3: an evidence-bearing slash is applied only if its
            # inclusion proof verifies against our finalized checkpoint;
            # evidence-free slashes keep the Phase 0 trust-the-finalizer path.
            if not self._verify_slash_evidence(att):
                self.logger.warning(
                    'Rejecting slash_final: evidence failed verification')
                return True
            self._apply_slash(att)
            return True
        return False

    # ----- Phase 2: quorum-signed Merkle checkpoints ----------------------
    # Lifecycle (mirrors the slash three-phase shape):
    #   forward_checkpoint    : a node originates -> stamps epoch/root over its
    #                           own window, signs, seeds its own co-signature,
    #                           broadcasts checkpoint_propose.
    #   handle_checkpoint_propose: a member co-signs (checkpoint_sign) ONLY if
    #                           its own window_root matches the proposed root.
    #   handle_checkpoint_sign : proposer tallies matching signers; on > quorum
    #                           broadcasts checkpoint_final.
    #   handle_checkpoint_final: every node stores the SignedCheckpoint as the
    #                           latest agreed commitment to the committed window.

    def _checkpoint_quorum(self, group_uuid=None):
        """Co-signers required to finalize a checkpoint; reuses Paxos majority
        sizing. '> quorum' matching signers (including the proposer) finalize."""
        return self._quorum_for_group(group_uuid)

    def forward_checkpoint(self, queues, message):
        """Entry point for a locally-originated checkpoint: putting a
        ``Checkpoint`` on the reputation queue triggers a proposal over THIS
        node's current ``window_root``. Any fields on the trigger object are
        ignored — the proposer always commits to its own live window. Mirrors
        ``forward_slash``."""
        if isinstance(message, Checkpoint):
            try:
                self._checkpoint_epoch += 1
                window = self.history._indexed_window()
                root = self.history.window_root()
                first = window[0].index if window else self.history._next_index
                ckpt = Checkpoint(
                    proposer_uuid=self.identity.uuid, root=root,
                    epoch=self._checkpoint_epoch,
                    first_index=first, count=len(window),
                    nonce=os.urandom(8))
                try:
                    ckpt.signature = self.identity.sign(ckpt.designation)
                except Exception:
                    ckpt.signature = None
                key = ckpt.key()
                self._checkpoint_pending[key] = ckpt
                self._checkpoint_sigs[key] = {str(self.identity.uuid)}
                # Self-store immediately so a single-node group (or the
                # originator's own view) has a finalized checkpoint without a
                # co-sign round-trip, matching forward_slash's self-apply.
                self._store_checkpoint(ckpt)
                if self.group is not None:
                    msg = Message(self.name,
                                  ReputationProtocol.checkpoint_propose,
                                  to_json_string(ckpt), self.group,
                                  from_whom=self.identity)
                    queues[CfgIds.network].put(
                        msg, block=True, timeout=self.q_cadence)
                self.logger.info(
                    'Proposed checkpoint: epoch=%d count=%d root=%s',
                    ckpt.epoch, ckpt.count,
                    (root.decode() if isinstance(root, bytes) else str(root))[:12])
            except Full:
                self.logger.error('forward_checkpoint: network queue full')
            return True
        return False

    def _store_checkpoint(self, ckpt):
        """Record ``ckpt`` as the latest finalized checkpoint (idempotent on
        re-broadcast via the seen-dedup ring)."""
        key = ckpt.key()
        if key in self._checkpoint_seen:
            return
        self._checkpoint = ckpt
        self._checkpoint_seen[key] = None
        while len(self._checkpoint_seen) > self.COMMITTED_ROUNDS_CAP:
            self._checkpoint_seen.popitem(last=False)

    def handle_checkpoint_propose(self, queues, message):
        if message.function == ReputationProtocol.checkpoint_propose:
            if not message.verified:
                self.logger.warning(
                    'Rejecting unverified checkpoint_propose from %s',
                    message.from_whom)
                return True
            ckpt = (message.obj if isinstance(message.obj, Checkpoint)
                    else from_json_string(message.obj))
            # Don't co-sign our own bounce-back.
            if str(ckpt.proposer_uuid) == str(self.identity.uuid):
                return True
            # Consensus check: co-sign ONLY if our own committed window
            # produces the SAME Merkle root. A divergent window declines
            # silently (no signature), so a checkpoint finalizes only when a
            # quorum genuinely observed the same committed history.
            proposed = ckpt.root
            if isinstance(proposed, str):
                proposed = proposed.encode()
            mine = self.history.window_root()
            if mine != proposed:
                self.logger.debug(
                    'checkpoint_propose: window_root mismatch, declining')
                return True
            try:
                sig = self.identity.sign(ckpt.designation)
            except Exception:
                sig = None
            proposer, epoch = ckpt.key()
            ack = (proposer, epoch, str(self.identity.uuid), sig)
            try:
                msg = Message(self.name, ReputationProtocol.checkpoint_sign,
                              to_json_string(ack), message.from_whom,
                              from_whom=self.identity)
                queues[CfgIds.network].put(
                    msg, block=True, timeout=self.q_cadence)
            except Full:
                self.logger.error('handle_checkpoint_propose: queue full')
            return True
        return False

    def handle_checkpoint_sign(self, queues, message):
        if message.function == ReputationProtocol.checkpoint_sign:
            if not message.verified:
                return True
            payload = message.obj
            if isinstance(payload, str):
                payload = from_json_string(payload)
            proposer, epoch, voter, _sig = payload
            key = (str(proposer), int(epoch))
            ckpt = self._checkpoint_pending.get(key)
            if ckpt is None:
                return True  # not our round, or already finalized
            self._checkpoint_sigs.setdefault(key, set()).add(str(voter))
            grp_uuid = str(self.group.uuid) if self.group is not None else None
            if len(self._checkpoint_sigs[key]) > self._checkpoint_quorum(grp_uuid):
                signed = SignedCheckpoint(checkpoint=ckpt, sigs={})
                try:
                    msg = Message(
                        self.name, ReputationProtocol.checkpoint_final,
                        to_json_string(signed),
                        self._group_by_uuid(grp_uuid) or self.group,
                        from_whom=self.identity)
                    queues[CfgIds.network].put(
                        msg, block=True, timeout=self.q_cadence)
                    self.logger.info(
                        'Checkpoint finalized & broadcast: epoch=%d signers=%d',
                        ckpt.epoch, len(self._checkpoint_sigs[key]))
                except Full:
                    self.logger.error(
                        'handle_checkpoint_sign: queue full broadcasting final')
                # Drop pending so later signs are no-ops (finality dedup).
                del self._checkpoint_pending[key]
            return True
        return False

    def handle_checkpoint_final(self, _, message):
        if message.function == ReputationProtocol.checkpoint_final:
            if not message.verified:
                self.logger.warning(
                    'Rejecting unverified checkpoint_final from %s',
                    message.from_whom)
                return True
            signed = (message.obj if isinstance(message.obj, SignedCheckpoint)
                      else from_json_string(message.obj))
            ckpt = getattr(signed, 'checkpoint', None)
            if ckpt is None:
                return True
            # The proposer already self-stored; skip the bounce-back.
            if str(ckpt.proposer_uuid) == str(self.identity.uuid):
                return True
            # Phase 3 will verify signed.sigs against known member identities;
            # for now trust the transport-verified finalizer.
            self._store_checkpoint(ckpt)
            return True
        return False

    def handle_outdated(self, queues, message):
        if message.function == ReputationProtocol.outdated:
            try:
                length = message.obj
                if isinstance(length, bytes):
                    length = length.decode(encoding)
                index = int(length)
                chain = to_json_string(self.history.era(index))
                msg = Message(self.name, ReputationProtocol.update, chain,
                              message.from_whom, from_whom=self.identity)
                queues[CfgIds.network].put(msg, block=True, timeout=self.q_cadence)
                self.logger.debug('Sent update')
            except Full:
                self.logger.error('handle_outdated: Network queue full')
            return True
        return False

    def handle_update(self, queues, message):
        if message.function == ReputationProtocol.update:
            self.updates[message.from_whom.uuid] = from_json_string(message.obj)
            up_count = len(self.updates)
            if up_count >= self.num_updates:
                # Group reported chains by their serialized (canonical) form
                # so peers reporting the SAME committed history land in one
                # bucket. Comparing Transaction objects with `==` fell back to
                # identity (Configuration defines no __eq__), so deserialized
                # chains never grouped and the majority vote could never be
                # reached. The C twin already groups by JSON-dump string
                # (rep_proc.c handle_update); this brings Python in lockstep —
                # a prerequisite for the Phase 1 verifiable-catchup conformance
                # (reputation-vs-blockchain-analysis.md §2.1).
                grouping: 'dict[str, list]' = {}
                for update in self.updates.values():
                    key = to_json_string(update)
                    grouping.setdefault(key, []).append(update)
                best_key = max(grouping, key=lambda k: len(grouping[k]))
                best = grouping[best_key]
                self.logger.debug(grouping)
                if len(best) > up_count // 2:
                    chain = best[0]  # all entries in the bucket are identical
                    self.history.catchup(chain)
                    self.logger.debug('Updated')
                else:
                    self.logger.error('Closest %d peers unable to agree on history' % self.num_updates)
                    self._request_update(queues, len(self.peers.all))
            return True
        return False

    def _pure_reputation(self, peer):
        # Counterparty's-score weighted by counterparty's-reputation
        # AND by the originating capability's transaction_weight
        # (doc/architecture/trust-tiers.md §5). Default 0.5 on
        # no-history OR no-valid-tx (returning 0.0 would route the
        # peer back into CTFT mode on the next compute, the very
        # condition we supposedly graduated from). Counterparties
        # absent from self.reputations use a 0.5 fallback rather
        # than being silently skipped (skipping made the result
        # sensitive to whether the local reputations dict had caught
        # up to the history chain).
        # `peer` may be a Peer object (production sender path), a
        # raw UUID, or a uuid string (rep_req wire path — the
        # canonical object form's `peer_uuid` field is a string,
        # and Identity.uuid is also a string in this codebase).
        peer_uuid = peer if isinstance(peer, (UUID, str)) else peer.uuid
        try:
            txs = list(self.history.by_peer(peer_uuid))
        except KeyError:
            return 0.5
        total = 0.0
        total_weight = 0
        for tx in txs:
            if tx.p1_id is None or tx.p2_id is None:
                continue
            if tx.p1_id == peer_uuid:
                counterparty_id = tx.p2_id
                counterparty_score = tx.p2_score
            elif tx.p2_id == peer_uuid:
                counterparty_id = tx.p1_id
                counterparty_score = tx.p1_score
            else:
                continue
            cp_rep = self.reputations[counterparty_id] \
                if counterparty_id in self.reputations else 0.5
            w = self.task_weights.get(str(tx.task_id), 1)
            total += counterparty_score * cp_rep * w
            total_weight += w
        if total_weight == 0:
            return 0.5
        return total / total_weight

    def _contrite_tit_for_tat(self, peer):
        # peer_score is the score the PEER submitted in a bilateral
        # transaction; my_score is the score WE submitted. p1_score
        # belongs to whoever is p1, p2_score to p2 — so the side that
        # matches `peer.uuid` is the one whose score is "peer_score".
        # An earlier revision had these indices swapped relative to
        # the C twin (reputation.c:499-507), inverting the
        # peer-defected vs. self-defected branches.
        # `peer` may be a Peer object, a UUID, or a uuid string
        # (see _pure_reputation comment).
        peer_uuid = peer if isinstance(peer, (UUID, str)) else peer.uuid
        peer_scores = []
        my_scores = []
        try:
            for tx in self.history.by_peer(peer_uuid):
                if tx.p1_id == peer_uuid and tx.p2_id == self.identity.uuid:
                    peer_scores.append(tx.p1_score)
                    my_scores.append(tx.p2_score)
                elif tx.p2_id == peer_uuid and tx.p1_id == self.identity.uuid:
                    peer_scores.append(tx.p2_score)
                    my_scores.append(tx.p1_score)
        except KeyError:
            self.logger.debug('No transaction history for peer %s' % peer_uuid)
        if len(peer_scores) < 1 or len(my_scores) < 1:  # no bilateral w/ us
            # Cold-start: before any bilateral history WITH us exists, fall
            # back to a transaction-memory prior rather than a flat neutral.
            return self._prereputation_prior(peer_uuid)
        peer_standing = sum(peer_scores) / len(peer_scores)
        my_standing = sum(my_scores) / len(my_scores)
        if peer_scores[-1] < 0.5 and my_standing < 0.5:  # peer defected, but my standing sucks
            rep_score = max(0.51, peer_standing)
        elif peer_scores[-1] < 0.5 and my_standing >= 0.5:  # peer defected, my standing is ok
            rep_score = min(0.49, peer_standing)
        else:  # cooperate/cooperate (but digging out of a hole)
            rep_score = max(0.51, peer_standing)
        return rep_score

    def _prereputation_prior(self, peer_uuid):
        """Transaction-memory prior for the CTFT cold-start window.

        Before any *bilateral* history with us exists, a flat PREREP_NEUTRAL
        throws away what the chain already knows about the peer: the scores third
        parties have assigned it. Mine those (the counterparty-submitted
        score on each committed transaction the peer took part in — the same
        "assessment OF the peer" axis _pure_reputation uses), weight each by
        the counterparty's reputation and the task weight, and shrink the
        result toward PREREP_NEUTRAL by a pseudo-count of PREREP_SHRINKAGE_K.

        With zero usable observations this returns PREREP_NEUTRAL exactly, so
        a genuinely-unknown peer behaves exactly as before; a peer others
        have already transacted with gets an informed, conservatively-shrunk
        prior instead. Pure function of the chain + local reputations, so it
        stays deterministic across nodes with the same state.

        Mirror: reputation.c reputation_prereputation_prior.
        Kill switch: AT_PREREP_HEURISTIC=0 restores the flat default."""
        neutral = self.PREREP_NEUTRAL
        if os.environ.get('AT_PREREP_HEURISTIC') == '0':
            return neutral
        try:
            txs = list(self.history.by_peer(peer_uuid))
        except (KeyError, AttributeError):
            return neutral
        self_uuid = getattr(self.identity, 'uuid', None)
        total = 0.0
        total_weight = 0.0
        count = 0
        seen = set()  # by_peer can list a tx twice (mapped under p1 and p2);
        #               one transaction is one observation for the prior.
        for tx in txs:
            if tx.task_id in seen:
                continue
            if tx.p1_id == peer_uuid and tx.p2_id is not None:
                about_peer, counterparty_id = tx.p2_score, tx.p2_id
            elif tx.p2_id == peer_uuid and tx.p1_id is not None:
                about_peer, counterparty_id = tx.p1_score, tx.p1_id
            else:
                continue
            if about_peer is None or counterparty_id == self_uuid:
                continue
            seen.add(tx.task_id)
            # Weight each third-party observation by the counterparty's
            # reputation (an assessment from a trusted peer counts for more).
            # Unlike _pure_reputation we deliberately omit the capability
            # task-weight here: during cold-start the task-weight cache is
            # sparse, and keeping the prior a pure function of (chain, reps)
            # makes the C mirror a straight port of CTFT's inputs.
            cp_rep = self.reputations[counterparty_id] \
                if counterparty_id in self.reputations else 0.5
            if cp_rep <= 0:
                continue
            total += about_peer * cp_rep
            total_weight += cp_rep
            count += 1
        if count < 1 or total_weight <= 0:
            return neutral
        observed = total / total_weight
        n = float(count)
        k = self.PREREP_SHRINKAGE_K
        prior = (n * observed + k * neutral) / (n + k)
        return min(1.0, max(0.0, prior))

    @classmethod
    def _trust_tier(cls, score: float) -> int:
        """Map a reputation score to its trust tier.

        Walks TIER_FLOORS top-down, returning the highest tier whose
        floor is met. Scores below the lowest floor map to 0.
        """
        for floor, tier in reversed(cls.TIER_FLOORS):
            if score >= floor:
                return tier
        return 0

    def _note_interaction(self, peer_uuid):
        """Stamp 'we just transacted with peer_uuid' — resets its idle
        clock so the staleness sweep (_decay_reputations) leaves an
        actively-interacting peer alone. Self is ignored."""
        key = str(peer_uuid)
        if key == str(self.identity.uuid):
            return
        self._last_interaction[key] = now().timestamp()

    @classmethod
    def _decayed_score(cls, score, idle_seconds):
        """Relax an operational reputation toward almost-neutral as a
        function of idle time. ASYMMETRIC: a score at or below the
        asymptote is returned unchanged (absence never rehabilitates a
        distrusted node); a score above it decays exponentially toward
        the asymptote after the onset grace period, never overshooting
        below it. See the REPUTATION_DECAY_* constants."""
        if score is None or score <= cls.REPUTATION_DECAY_ASYMPTOTE:
            return score
        if idle_seconds <= cls.REPUTATION_DECAY_ONSET:
            return score
        elapsed = idle_seconds - cls.REPUTATION_DECAY_ONSET
        factor = 0.5 ** (elapsed / cls.REPUTATION_DECAY_HALF_LIFE)
        decayed = cls.REPUTATION_DECAY_ASYMPTOTE + \
            (score - cls.REPUTATION_DECAY_ASYMPTOTE) * factor
        return max(cls.REPUTATION_DECAY_ASYMPTOTE, decayed)

    def _seed_idle_from_snapshot(self):
        """At start-up, treat the persisted reputation snapshot's mtime as
        the moment of our last AT-bounded activity: seed every warm-started
        peer's idle clock to it and apply the offline-gap decay up front, so
        a long-dormant cohort comes up with faded (not stale-inflated)
        trust. No-op on a cold start (no snapshot on disk). No queues are
        available this early, so tier changes are not published here — the
        first live sweep / rep_req republishes from the decayed value."""
        try:
            path = os.path.join(Configuration.get_cfg_dir(),
                                CfgIds.reputation + Configuration.file_ext)
            mtime = os.path.getmtime(path)
        except (OSError, IOError):
            return
        present = now().timestamp()
        idle = max(0.0, present - mtime)
        self_uuid = str(self.identity.uuid)
        for u in list(self.reputations.current.keys()):
            if str(u) == self_uuid:
                continue
            self._last_interaction[str(u)] = mtime
            score = self.reputations.current.get(u)
            decayed = self._decayed_score(score, idle)
            if decayed is not None:
                self.reputations.current[u] = decayed

    def _decay_reputations(self, queues, present):
        """Periodic staleness sweep: pull idle peers' operational
        reputation toward almost-neutral. Throttled to one pass per
        REPUTATION_DECAY_SWEEP_INTERVAL. Skips self and slashed peers
        (their floor is authoritative). Republishes the trust tier on a
        floor crossing and persists if anything moved. The dashboard
        consensus channel (_consensus_last) is decayed in lock-step so the
        two views agree. See doc/architecture/persistent-cohort.md."""
        if present - self._last_decay_sweep < self.REPUTATION_DECAY_SWEEP_INTERVAL:
            return
        self._last_decay_sweep = present
        self_uuid = str(self.identity.uuid)
        changed = False
        for u in list(self.reputations.current.keys()):
            key = str(u)
            if key == self_uuid or key in self._slashed:
                continue
            score = self.reputations.current.get(u)
            if score is None or score <= self.REPUTATION_DECAY_ASYMPTOTE:
                continue
            idle = max(0.0, present - self._last_interaction.get(key, present))
            decayed = self._decayed_score(score, idle)
            if decayed is None or abs(decayed - score) <= 1e-9:
                continue
            self.reputations.current[u] = decayed
            prior = self._consensus_last.get(key)
            if prior is not None and prior > self.REPUTATION_DECAY_ASYMPTOTE:
                self._consensus_last[key] = self._decayed_score(prior, idle)
            self._publish_tier_change(queues, u, decayed)
            changed = True
        if changed:
            try:
                self._persist_reputations()
            except (OSError, IOError) as e:
                self.logger.warning(
                    'Could not persist reputations after decay: %s' % e)

    def _persist_reputations(self):
        """Write the reputation snapshot to disk, filtered by threshold.

        Only peers with score strictly above REPUTATION_PERSIST_THRESHOLD
        are persisted; self is always included regardless. The on-disk
        file is therefore the authoritative "trusted cohort" snapshot
        used by the warm-start path in IdentityProcess.choose_group()
        and by the dod-mission seed generator at
        tools/seed_dod_cohort.py.
        """
        keep_uuids = {self.identity.uuid}
        for u, score in self.reputations.current.items():
            if score is not None and score > REPUTATION_PERSIST_THRESHOLD:
                keep_uuids.add(u)
        snapshot = self.reputations.filtered_for_persist(keep_uuids)
        snapshot.to_file(os.path.join(Configuration.get_cfg_dir(),
                                      CfgIds.reputation + Configuration.file_ext))

    def _publish_tier_change(self, queues, peer_uuid, score):
        """Notify IdentityProcess of a trust-tier crossing.

        Suppressed if the tier hasn't changed from the last publication
        for this peer. Local IPC only — tier_update goes on the
        identity queue; on demotion, an additional tier_lost goes on
        the negotiation queue so in-flight tasks whose
        capability.required_tier now exceeds the peer's new tier can
        be cancelled. See doc/architecture/trust-tiers.md §7.2.
        """
        try:
            new_tier = self._trust_tier(score)
            key = str(peer_uuid)
            old_tier = self.peer_tiers.get(key)
            if old_tier == new_tier:
                return
            # Capture demotion before storing the new tier so
            # NegotiationProcess sees a coherent "old → new" event.
            is_demotion = (old_tier is not None and new_tier < old_tier)
            self.peer_tiers[key] = new_tier
            payload = to_json_string((key, new_tier))
            # Local IPC: no to_whom (the consumer is the local
            # IdentityProcess reading its own queue; no network egress).
            msg = Message(CfgIds.identity, IdentityProtocol.tier_update,
                          payload, to_whom=None, from_whom=self.identity)
            queues[CfgIds.identity].put(msg, block=True, timeout=self.q_cadence)
            self.logger.debug('Published tier_update for %s: %d (score=%.3f)' %
                              (key, new_tier, score))
            if is_demotion:
                lost_msg = Message(CfgIds.negotiation, IdentityProtocol.tier_lost,
                                   payload, to_whom=None, from_whom=self.identity)
                try:
                    queues[CfgIds.negotiation].put(
                        lost_msg, block=True, timeout=self.q_cadence)
                    self.logger.info(
                        'Published tier_lost for %s: %d -> %d',
                        key, old_tier, new_tier)
                except Full:
                    self.logger.error(
                        '_publish_tier_change: negotiation queue full')
        except Full:
            self.logger.error('_publish_tier_change: identity queue full')
        except Exception as err:
            self.logger.warning('_publish_tier_change failed: %s' % err)

    def _compute_reputation(self, peer, req_proc, requestor):
        _probes.counter('rep.compute', 'enter')
        try:
            # peer may be a Peer/Identity object (production), a UUID,
            # or a uuid string (rep_req wire path). Identity.uuid is a
            # string in this codebase, so the legacy `peer.uuid` branch
            # below also returns a string — `peer_uuid` is the same
            # type as the keys in self.reputations / self._coop_mode.
            peer_uuid = peer if isinstance(peer, (UUID, str)) else peer.uuid
            # Slash override (fast-penalty path): a finalized slash floors
            # the score immediately, bypassing the CTFT/pure EMA dispatch.
            # Force CTFT mode so that if the slash is later lifted the peer
            # re-earns trust from the punished regime rather than snapping
            # back into cooperation. Mirrors the commit tail below.
            slashed = self._slashed.get(str(peer_uuid))
            if slashed is not None:
                rep_score = float(slashed[0])
                self._coop_mode[peer_uuid] = False
                self.reputations.update(peer_uuid, rep_score)
                try:
                    self._persist_reputations()
                except (OSError, IOError) as e:
                    self.logger.warning('Could not persist reputations: %s' % e)
                self.pending_tiers.append((peer_uuid, rep_score))
                self.requested_reps.append(
                    (Reputation(peer_uuid, rep_score), req_proc, requestor))
                _probes.counter('rep.compute', 'slashed')
                return
            previous = 0.0
            if peer_uuid in self.reputations:
                previous = self.reputations[peer_uuid]
            in_coop = self._coop_mode.get(peer_uuid, False)
            if in_coop:
                use_pure = previous > self.COOP_EXIT
            else:
                use_pure = previous > self.COOP_ENTER
            self._coop_mode[peer_uuid] = use_pure
            if use_pure:
                self.logger.debug('Cooperation mode')
                rep_score = self._pure_reputation(peer)
            else:
                # Debug aid: how much bilateral history does this peer
                # actually have on this node?  CTFT returns 0.49 when
                # n<1, so the count below tells you whether you're
                # stuck at the no-history default or actually
                # computing against real data.
                try:
                    n_bilateral = sum(
                        1 for tx in self.history.by_peer(peer_uuid)
                        if ((tx.p1_id == peer_uuid
                             and tx.p2_id == self.identity.uuid)
                            or (tx.p2_id == peer_uuid
                                and tx.p1_id == self.identity.uuid)))
                except (KeyError, AttributeError):
                    n_bilateral = 0
                self.logger.info(
                    'Tit-for-tat mode for %s: %d bilateral txs in '
                    'local history (previous=%.2f)',
                    str(peer_uuid)[:8], n_bilateral, previous)
                rep_score = self._contrite_tit_for_tat(peer)
            self.reputations.update(peer_uuid, rep_score)
            try:
                self._persist_reputations()
            except (OSError, IOError) as e:
                self.logger.warning('Could not persist reputations: %s' % e)
            # Queue a tier-update for IdentityProcess; drained by the
            # process loop alongside forward_reputation. The spawned
            # _compute_reputation thread doesn't have access to queues
            # so it can't put directly.
            self.pending_tiers.append((peer_uuid, rep_score))
            self.requested_reps.append((Reputation(peer_uuid, rep_score), req_proc, requestor))
            _probes.counter('rep.compute', 'queued')
        except Exception as e:
            _probes.counter('rep.compute', 'exception', type(e).__name__)
            self.logger.warning('_compute_reputation failed: %s' % e)

    def _consensus_baseline(self, peer_uuid):
        """Cold-start baseline for a peer with no committed bilateral
        history yet.

        Priority: (1) the last real consensus value computed for this
        peer (stickiness — so an idle peer whose txs have evicted from
        the bounded chain keeps its earned score instead of resetting to
        0.5), (2) the locally-known reputation (a warm-start seeded prior
        from reputation.cfg.json, or a prior local compute), (3) the
        neutral 0.5. Used only when the consensus chain has nothing for
        the peer — once real bilateral txs exist, the EMA in
        _consensus_reputation dominates and refreshes the sticky value.
        Tolerates the str/UUID key ambiguity in self.reputations.current."""
        last = self._consensus_last.get(str(peer_uuid))
        if last is not None:
            return last
        try:
            cur = self.reputations.current
        except AttributeError:
            return 0.5
        for k in (peer_uuid, str(peer_uuid)):
            if k in cur and cur[k] is not None:
                return float(cur[k])
        try:
            u = UUID(str(peer_uuid))
            if u in cur and cur[u] is not None:
                return float(cur[u])
        except (ValueError, TypeError, AttributeError):
            pass
        return 0.5

    def _fold_tx_for_peer(self, peer_uuid, tx, alpha):
        """Fold one completed tx's counterparty-side score into ``peer_uuid``'s
        persistent running consensus EMA, exactly once (guarded by chain
        index). No-op for an incomplete/one-sided tx (index None), a peer not
        party to it, a missing counterparty score, an already-folded tx, or a
        slashed peer (its floor is authoritative — folding would drift the
        stored value the slash override masks, breaking resume-from-floor).
        Updates ``_consensus_ema``/``_consensus_folded_idx`` and keeps
        ``_consensus_last`` in step (read by the baseline path + idle decay)."""
        if tx is None or tx.index is None:
            return
        key = str(peer_uuid)
        if key in self._slashed:
            return
        if tx.index <= self._consensus_folded_idx.get(key, -1):
            return
        if tx.p1_id == peer_uuid:
            cp_score = tx.p2_score
        elif tx.p2_id == peer_uuid:
            cp_score = tx.p1_score
        else:
            return
        if cp_score is None:
            return
        ema = self._consensus_ema.get(key)
        # transaction_weight applied as w single-step folds (see
        # _consensus_reputation for why this preserves the [0,1] range).
        w = self.task_weights.get(str(tx.task_id), 1)
        for _ in range(max(1, int(w))):
            if ema is None:
                ema = float(cp_score)
            else:
                ema = alpha * float(cp_score) + (1.0 - alpha) * ema
        self._consensus_ema[key] = ema
        self._consensus_folded_idx[key] = tx.index
        self._consensus_last[key] = ema

    def _fold_committed_tx(self, task_id, chain):
        """Fold-on-commit hook: when a tx completes on the PRIMARY chain, fold
        it into BOTH counterparties' running consensus EMAs immediately, so the
        dashboard value is retained independently of when consensus is next
        queried. Idempotent (index-guarded), so it is safe to call after every
        chain.update — a still-incomplete tx (index None) folds nothing.
        Child-chain (gateway) commits are ignored here: those peers score via
        the pure from-scratch recompute in _consensus_reputation."""
        if chain is not self.history:
            return
        tx = chain._task_mapping.get(task_id)
        if tx is None or tx.index is None:
            return
        alpha = 1.0 - 0.5 ** (1.0 / float(self.CONSENSUS_EMA_HALF_LIFE))
        self._fold_tx_for_peer(tx.p1_id, tx, alpha)
        self._fold_tx_for_peer(tx.p2_id, tx, alpha)

    def _running_consensus(self, peer_uuid):
        """Persistent per-peer running consensus EMA over the PRIMARY chain.

        The value is built by folding each committed bilateral tx exactly once
        (``_fold_tx_for_peer``, tracked by chain index). Folding happens
        eagerly ON COMMIT (``_fold_committed_tx`` from the accept/commit
        handlers), so already-folded transactions stay reflected in the stored
        value even after they evict from the bounded window — the score changes
        ONLY when new transactions commit and never wobbles as the shared
        window slides. That is the fix for the synchronized "Trust Dynamics"
        sawtooth (the old from-scratch recompute, still used for gateway child
        chains in _consensus_reputation, re-derived the EMA over whatever subset
        of a peer's txs was resident, so every line rose/fell on the global
        eviction beat).

        This method just RETURNS the stored value; the resident-tx scan below
        is an idempotent safety net that folds any resident tx a commit handler
        missed (e.g. a catchup/replay path that appended without folding),
        while it is still resident.

        Equivalence: for a chain that has not yet evicted, the folded set/order/
        seed match the from-scratch recompute exactly, so the conformance/parity
        corpora (small, non-evicting) are unaffected. Determinism note: after
        eviction the value depends on which txs THIS node folded — a deliberate
        trade for a stable timeline. Slash override and cold-start baseline are
        handled by the caller / _consensus_baseline. C twin keeps the
        from-scratch form for now (parity follow-up)."""
        key = str(peer_uuid)
        alpha = 1.0 - 0.5 ** (1.0 / float(self.CONSENSUS_EMA_HALF_LIFE))
        try:
            txs = list(self.history.by_peer(peer_uuid))
        except KeyError:
            txs = []
        # Ascending chain-index order == commit order; already-folded txs are
        # skipped by the index guard, so this is a no-op on the normal path.
        for tx in sorted(txs, key=lambda t: (t.index if t.index is not None else 0)):
            self._fold_tx_for_peer(peer_uuid, tx, alpha)
        if key in self._consensus_ema:
            return self._consensus_ema[key]
        # No committed bilateral history folded yet -> cold-start baseline
        # (sticky last / seeded prior / neutral), same as the recompute.
        return self._consensus_baseline(peer_uuid)

    def _consensus_reputation(self, peer_uuid, chain=None):
        """Deterministic reputation score over a consensus tx chain.

        Walks committed bilateral transactions involving the peer in
        chain order and folds each counterparty-side score into an
        exponentially-weighted moving average.  Pure function of the
        ``chain`` (default ``self.history``) and ``peer_uuid`` — no
        dependence on ``self.identity``, ``self.reputations``, or any
        per-node latch — so every node with the same chain state
        arrives at the same number. The optional ``chain`` argument
        lets a gateway score a peer against one of its child-group
        chains; omitting it preserves the original single-chain
        behaviour exactly.

        Cold-start exception: when the chain has NO committed bilateral
        history for the peer, falls back to ``_consensus_baseline``
        (the locally-known/seeded prior) instead of a flat 0.5, so a
        warm-started cohort reads its primed rep on the dashboard
        rather than a uniform 0.5. This is the only point where the
        score depends on per-node state, and only until the first real
        tx lands — after that the EMA dominates and nodes reconverge.
        Intended for the inspector dashboard;
        ``rep_req`` callers continue to get the identity-dependent
        CTFT / _pure_reputation score from ``_compute_reputation``.

        The counterparty side is used (mirroring _pure_reputation's
        extraction) so the value reflects "what the network observed
        about this peer", not "what this peer self-reported".

        Slash override: a finalized slash floors the score here,
        bypassing the chain/EMA/baseline entirely (the fast-penalty
        path). _consensus_last is refreshed to the floor so a later
        rehabilitation won't snap back to a stale pre-slash value.
        """
        slashed = self._slashed.get(str(peer_uuid))
        if slashed is not None:
            floor = float(slashed[0])
            self._consensus_last[str(peer_uuid)] = floor
            # Keep the running EMA in step so a later rehabilitation resumes
            # from the floor rather than a stale pre-slash value.
            self._consensus_ema[str(peer_uuid)] = floor
            return floor
        # Primary chain (the dashboard/timeline path): a persistent per-peer
        # running EMA that folds each committed tx exactly once, so evicting
        # old txs can't reshape the score (no sawtooth). Gateway child-chain
        # scoring (chain is not None) keeps the pure from-scratch recompute
        # below, which the rep-tree/conformance path depends on.
        if chain is None:
            return self._running_consensus(peer_uuid)
        history = chain
        try:
            txs = list(history.by_peer(peer_uuid))
        except KeyError:
            return self._consensus_baseline(peer_uuid)
        alpha = 1.0 - 0.5 ** (1.0 / float(self.CONSENSUS_EMA_HALF_LIFE))
        ema = None
        # Sort by chain index (when present) so we get true commit
        # order even if by_peer's insertion order ever drifts from
        # the chain — e.g. catchup() replaying out of order.
        ordered = sorted(
            txs,
            key=lambda t: (t.index if t.index is not None else 0))
        for tx in ordered:
            if tx.p1_id is None or tx.p2_id is None:
                continue
            if tx.p1_id == peer_uuid:
                cp_score = tx.p2_score
            elif tx.p2_id == peer_uuid:
                cp_score = tx.p1_score
            else:
                continue
            if cp_score is None:
                continue
            # Apply the capability's transaction_weight by running the
            # EMA update `w` times — a tier-w transaction moves the
            # EMA exactly as far as w tier-1 transactions would. This
            # keeps the EMA's [0,1] range intact and avoids weighting
            # asymmetries that a single alpha*w step would introduce
            # for w > 1 (could push the next value above 1).
            w = self.task_weights.get(str(tx.task_id), 1)
            for _ in range(max(1, int(w))):
                if ema is None:
                    ema = float(cp_score)
                else:
                    ema = alpha * float(cp_score) + (1.0 - alpha) * ema
        if ema is None:
            return self._consensus_baseline(peer_uuid)
        # Refresh the sticky value so it survives later eviction of these
        # txs from the bounded chain window.
        self._consensus_last[str(peer_uuid)] = ema
        return ema

    def _consensus_reputation_by_tier(self, peer_uuid, chain=None):
        """Per-tier consensus reputation (trust-tiers §12 / deferred.md §2.3).

        Instead of collapsing every transaction into a single EMA, partition
        the peer's committed bilateral transactions by the **tier of the
        capability** that produced each one (``self.task_tiers``, populated
        alongside ``task_weights`` from the TS ``capability_name``) and fold
        each partition into its own weighted EMA. Returns ``{tier: score}``
        for every tier with at least one observation — e.g. ``{1: 0.92,
        3: 0.41}`` ("trusted at tier 1, untrusted at tier 3") — instead of one
        number.

        Additive: the collapsed ``_consensus_reputation`` is untouched and
        remains the system's single-number score. Same EMA/weighting as the
        collapsed view, applied within each tier bucket; deduped by task
        (``by_peer`` can list a tx twice). Pure function of the chain +
        ``task_tiers``/``task_weights`` caches, mirroring the collapsed view's
        dependence on ``task_weights``.

        Mirror: reputation.c ``reputation_consensus_by_tier``."""
        history = self.history if chain is None else chain
        try:
            txs = list(history.by_peer(peer_uuid))
        except KeyError:
            return {}
        alpha = 1.0 - 0.5 ** (1.0 / float(self.CONSENSUS_EMA_HALF_LIFE))
        ordered = sorted(
            txs, key=lambda t: (t.index if t.index is not None else 0))
        ema_by_tier: dict[int, float] = {}
        seen = set()
        for tx in ordered:
            if tx.p1_id is None or tx.p2_id is None:
                continue
            if tx.task_id in seen:
                continue
            if tx.p1_id == peer_uuid:
                cp_score = tx.p2_score
            elif tx.p2_id == peer_uuid:
                cp_score = tx.p1_score
            else:
                continue
            if cp_score is None:
                continue
            seen.add(tx.task_id)
            tier = self.task_tiers.get(str(tx.task_id), 0)
            w = self.task_weights.get(str(tx.task_id), 1)
            ema = ema_by_tier.get(tier)
            for _ in range(max(1, int(w))):
                if ema is None:
                    ema = float(cp_score)
                else:
                    ema = alpha * float(cp_score) + (1.0 - alpha) * ema
            ema_by_tier[tier] = ema
        if ema_by_tier:
            self._per_tier_last[str(peer_uuid)] = dict(ema_by_tier)
        return ema_by_tier

    def _subtree_roster(self, gateway_uuid):
        """Reputation roster for a node and everything below it in the
        cohort tree.

        Returns a list of Reputation. For a leaf node (no child chains)
        this is a single-element list — the node's own consensus score
        over the primary chain — which forward_reputation serialises as
        a bare Reputation, byte-identical to the pre-tree single-score
        reply. For a gateway it additionally includes a Reputation for
        every peer seen in each child-group chain, scored against that
        child chain (which the gateway holds as a multi-group member).

        Grandchildren (a child that is itself a gateway over a deeper
        group) are NOT recursed here — direct-children coverage is
        complete for the 2-level demo topology; deeper trees are a
        documented follow-up (recursive forward + aggregate).
        """
        roster = [Reputation(
            gateway_uuid, self._consensus_reputation(gateway_uuid))]
        seen = {str(gateway_uuid)}
        for grp_uuid, group in self.child_groups.items():
            # Lazily materialises an (empty) chain for this child group
            # so peers with no committed tx yet still score via the
            # consensus baseline rather than being omitted.
            chain = self._chain_for_group(grp_uuid)
            member_uuids = set()
            # Members known from the child group's address map — present
            # from t=0 (seeded), so the cohort appears in the roster
            # immediately at its baseline rep instead of only after the
            # first field-chain commit.
            try:
                member_uuids |= set(group._address_map.keys())
            except (AttributeError, TypeError):
                pass
            # Plus anyone already transacting in the child chain.
            try:
                member_uuids |= set(chain._peer_mapping.keys())
            except AttributeError:
                pass
            for child_uuid in member_uuids:
                if str(child_uuid) in seen:
                    continue
                seen.add(str(child_uuid))
                roster.append(Reputation(
                    child_uuid,
                    self._consensus_reputation(child_uuid, chain=chain)))
        return roster

    def _compute_consensus_reputation(self, peer, req_proc, requestor):
        _probes.counter('rep.consensus', 'enter')
        try:
            # See _compute_reputation for the peer-type contract.
            peer_uuid = peer if isinstance(peer, (UUID, str)) else peer.uuid
            # Return the full subtree roster: this node's own consensus
            # score plus a score for every peer in each child chain. A
            # leaf yields a one-element roster (a bare Reputation on the
            # wire). Deliberately not writing self.reputations[*] —
            # that dict feeds _compute_reputation's mode selection and
            # _pure_reputation's counterparty weighting, so overwriting
            # it with consensus values would corrupt the local trust
            # path for any rep_req caller.
            roster = self._subtree_roster(peer_uuid)
            self.requested_reps.append((roster, req_proc, requestor))
            _probes.counter('rep.consensus', 'queued')
        except Exception as e:
            _probes.counter('rep.consensus', 'exception', type(e).__name__)
            self.logger.warning(
                '_compute_consensus_reputation failed: %s' % e)

    def handle_consensus_reputation_request(self, _, message):
        if message.function != ReputationProtocol.consensus_rep_req:
            return False
        if isinstance(message.obj, str):
            parsed = from_json_string(message.obj)
        else:
            parsed = message.obj
        if isinstance(parsed, dict):
            ident = parsed.get('peer_uuid')
            req_proc = parsed.get('requesting_process')
        elif isinstance(parsed, (list, tuple)) and len(parsed) >= 2:
            ident, req_proc = parsed[0], parsed[1]
        else:
            self.logger.error(
                'handle_consensus_reputation_request: unsupported '
                'payload shape %r' % type(parsed).__name__)
            return True
        requestor = message.from_whom
        self._spawn(self._compute_consensus_reputation,
                    args=(ident, req_proc, requestor))
        return True

    def handle_reputation_request(self, _, message):
        if message.function == ReputationProtocol.rep_req:
            # Accept both wire forms (BUGS.md §P9B):
            #   object: {peer_uuid, requesting_process}  — canonical, matches C
            #   tuple : (peer_uuid_str, req_proc_str)    — legacy
            if isinstance(message.obj, str):
                parsed = from_json_string(message.obj)
            else:
                parsed = message.obj
            if isinstance(parsed, dict):
                ident = parsed.get('peer_uuid')
                req_proc = parsed.get('requesting_process')
            elif isinstance(parsed, (list, tuple)) and len(parsed) >= 2:
                ident, req_proc = parsed[0], parsed[1]
            else:
                self.logger.error(
                    'handle_reputation_request: unsupported payload shape %r'
                    % type(parsed).__name__)
                return True
            requestor = message.from_whom
            # Tag the requestor type so we can correlate
            # rep.handle_req with rep.compute and rep.forward.
            if requestor is None:
                _probes.counter('rep.handle_req', 'enter', 'requestor_none')
            elif isinstance(requestor, str):
                _probes.counter('rep.handle_req', 'enter', 'requestor_str')
            else:
                req_uuid = getattr(requestor, 'uuid', None)
                if req_uuid is None:
                    _probes.counter('rep.handle_req', 'enter',
                                    'no_uuid:' + type(requestor).__name__)
                elif str(req_uuid) == str(self.identity.uuid):
                    _probes.counter('rep.handle_req', 'enter', 'requestor_self')
                else:
                    _probes.counter('rep.handle_req', 'enter', 'requestor_other')
            self._spawn(self._compute_reputation,
                        args=(ident, req_proc, requestor))
            return True
        return False

    def forward_reputation(self, queues):
        while len(self.requested_reps) > 0:
            payload, req_proc, requestor = self.requested_reps.pop(0)
            self.logger.debug('Forward reps to %s at %s' % (req_proc, requestor))
            # payload is either a single Reputation (the rep_req /
            # _compute_reputation path) or a list[Reputation] (the
            # consensus subtree path). A 1-element roster is sent as a
            # bare Reputation so leaf nodes stay wire-identical to the
            # pre-tree behaviour; a multi-element roster is serialised
            # as a JSON array (automate.py unpacks it length-tolerantly).
            if isinstance(payload, list):
                reputation = (payload[0] if len(payload) == 1
                              else to_json_string(payload))
            else:
                reputation = payload
            try:
                # Route the rep_resp back where the rep_req came from.
                # If the requestor is a remote Identity (e.g. an Inspector
                # bridge issuing peer-to-peer rep_req over the network),
                # the response must traverse the network too — the
                # original code put the response on the LOCAL `main`
                # queue, where it was absorbed by this peer's own AT
                # main loop and never left the responder. For local
                # (loopback) requests, requestor is None or our own
                # identity, and the historical local-queue path is fine.
                msg = Message(req_proc, ReputationProtocol.rep_resp,
                              reputation, requestor, from_whom=self.identity)
                if (requestor is not None
                        and getattr(requestor, 'uuid', None) is not None
                        and str(requestor.uuid) != str(self.identity.uuid)):
                    _probes.counter('rep.forward', 'route_network')
                    queues[CfgIds.network].put(
                        msg, block=True, timeout=self.q_cadence)
                else:
                    # Local fallback. Distinguish the failure modes so we
                    # can tell "stranger sender lost on wire" (string IP
                    # requestor — Change-3 territory) from a genuine
                    # loopback rep_req.
                    if requestor is None:
                        _probes.counter('rep.forward', 'route_local', 'requestor_none')
                    elif isinstance(requestor, str):
                        _probes.counter('rep.forward', 'route_local', 'requestor_str')
                    elif getattr(requestor, 'uuid', None) is None:
                        _probes.counter('rep.forward', 'route_local',
                                        'no_uuid:' + type(requestor).__name__)
                    elif str(requestor.uuid) == str(self.identity.uuid):
                        _probes.counter('rep.forward', 'route_local', 'self')
                    else:
                        _probes.counter('rep.forward', 'route_local', 'other')
                    queues[req_proc].put(
                        msg, block=True, timeout=self.q_cadence)
            except Full:
                self.logger.error('forward_reputation: %s queue full' % req_proc)

    def process(self, queues, signal):
        # Drain budget per iter. Each handle_reputation_request spawns
        # a short-lived thread, so processing many per iter is cheap
        # and lets us stay ahead of inbound rep_req volume. The hard
        # cap prevents one process from monopolizing the GIL when the
        # queue is deeply backlogged.
        DRAIN_BUDGET = 64
        while self.keep_running(signal):
            try:
                drained = 0
                # First iteration blocks briefly so we don't hot-spin
                # when the queue is empty; subsequent iterations are
                # non-blocking so we drain bursts immediately.
                first = True
                while drained < DRAIN_BUDGET:
                    try:
                        if first:
                            message = queues[self.name].get(
                                block=True, timeout=self.q_cadence)
                            first = False
                        else:
                            message = queues[self.name].get_nowait()
                    except Empty:
                        break
                    drained += 1
                    if not self.protocol.run_message_handlers(queues, message):
                        if not self.forward_transaction(queues, message):
                            # Raw SlashAttestation objects (put on the queue
                            # by a local detector, e.g. the coordinator)
                            # route here, mirroring forward_transaction.
                            if not self.forward_slash(queues, message) \
                                    and not self.forward_checkpoint(queues, message):
                                if isinstance(message, Message):
                                    _probes.counter('proc.reputation', 'unhandled', message.function)
                                    _probes.trace_msg(message, 'unhandled', proc='reputation')
                                    self.logger.error('Unhandled message %s' % message.function)
                                else:
                                    _probes.counter('proc.reputation', 'unhandled', 'type:' + message.__class__.__name__)
                                    self.logger.error('Unhandled message of type %s' % message.__class__.__name__)  # noqa
                _probes.counter('proc.reputation', 'iter_drained', str(drained))
                self.forward_reputation(queues)
                # Drain tier updates queued by _compute_reputation.
                while self.pending_tiers:
                    peer_uuid, rep_score = self.pending_tiers.pop(0)
                    self._publish_tier_change(queues, peer_uuid, rep_score)

                present = now().timestamp()
                # Staleness sweep: relax idle peers' operational
                # reputation toward almost-neutral (warm-start memory
                # fades). Throttled internally to SWEEP_INTERVAL.
                self._decay_reputations(queues, present)
                for req in list(self.requests):
                    if present - req[0] > self.expiration:
                        self.requests.remove(req)
                for prop in dict(self.proposals):
                    if present - prop[0] > self.expiration:
                        del self.proposals[prop]
                for rnd in list(self.round_group):
                    if present - rnd[0] > self.expiration:
                        del self.round_group[rnd]
                # No sleep_until here: removing the 0.5 s cadence
                # throttle was the whole point. Pacing is already
                # provided by queue.get's q_cadence-second blocking
                # timeout when no work is pending.
            except Exception as err:
                self.logger.error(err)
                self.logger.error(traceback.format_exc())
        # Final flush on graceful shutdown — ensures the most-recent
        # reputation snapshot survives a SIGTERM/quit. Belt-and-suspenders
        # on top of the per-transaction save in _compute_reputation.
        try:
            self._persist_reputations()
            self.logger.debug('Final reputation flush on shutdown')
        except Exception as err:
            self.logger.warning('Final reputation flush failed: %s' % err)
