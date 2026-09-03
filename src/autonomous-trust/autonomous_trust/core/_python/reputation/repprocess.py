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

import base64
import json
import math
import os
import threading
import time
import traceback
from collections import OrderedDict
from queue import Empty, Full
from uuid import UUID
from dataclasses import dataclass

from nacl.encoding import HexEncoder
from nacl.exceptions import BadSignatureError

from ..network import Message, Network
from ..processes import Process, ProcMeta
from ..config import (Configuration, atomic_write, from_json_string,
                      to_json_string)
from ..identity.protocol import IdentityProtocol
from ..identity.identity import (public_identity_to_canonical,
                                 public_identity_from_canonical)
from ..identity.zta.zta_policy import ZtaPolicy
from ..identity.zta_standing import STANDING_PROVED, STANDING_FAILED
from .protocol import ReputationProtocol
from .reputation import (TransactionHistory, Reputation, Reputations,
                         TransactionScore, SlashAttestation, SignedSlash,
                         Checkpoint, SignedCheckpoint, validate_tx_score,
                         validate_tx_channel,
                         PeerReputation, EVIDENCE_FILE, SLASH_MARKS_FILE,
                         evidence_to_dict,
                         evidence_from_dict, RESOLVE_TTL_DEFAULT,
                         resolve_query_to_dict, resolve_query_from_dict,
                         resolved_to_dict, resolved_from_dict, verify_resolved,
                         consensus_score_from_window, tx_channel_weight)
from ..system import CfgIds, now, encoding, proc_idle_floor
from .. import _probes


def _env_float(name, default):
    """Read a reputation threshold from the environment, falling back to
    ``default``. Lets an operator re-adjust the trust thresholds (neutral,
    communication cut-off, decay asymptote, persist gate) without a code
    change -- e.g. for a demo or a differently-tuned deployment. A missing
    or unparseable value uses the default (logged nowhere -- this runs at
    import). The C twin mirrors these via getenv with identical names and
    defaults so Python<->C stay byte-comparable under the SAME environment.
    """
    raw = os.environ.get(name)
    if raw is None or raw == '':
        return default
    try:
        return float(raw)
    except (TypeError, ValueError):
        return default


# Reputation save gate: only peers strictly above this threshold survive a process
# restart. Self is always persisted regardless. See
# doc/architecture/persistent-cohort.md for the rationale. Override:
# AT_REP_PERSIST_THRESHOLD.
REPUTATION_PERSIST_THRESHOLD = _env_float('AT_REP_PERSIST_THRESHOLD', 0.5)

# Upper bound on how many subjects one `consensus_rep_batch_req` may name. The
# batch verb exists so an observer-by-subject sweep costs N messages instead of
# N**2, but each named subject costs a chain walk on the responder, so an
# unbounded list would let one small message ask for arbitrary work. 256 is far
# above any cohort this runs on and far below anything that hurts. Mirrored in C
# as AT_MAX_REP_BATCH_SUBJECTS.
MAX_REP_BATCH_SUBJECTS = 256


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
    # NOTE: trust tier is distinct from network rank (peer._rank) — rank is topology /
    # one-hop reachability, populated from identity.json. See
    # doc/architecture/trust-tiers.md §1 for the disambiguation.
    TIER_FLOORS = (
        (0.50, 1),
        (0.65, 2),
        (0.80, 3),
        (0.90, 4),
    )

    # --- Verifiable warm start (doc/architecture/reputation.md) ----------------------
    # Restoration is GRADED by whether the persisted score has evidence
    # behind it. `reputation.cfg.json` is a conclusion; on its own it says
    # only that some process with write access to the config directory
    # believed a number, which is exactly as true of a tampered file as of
    # an earned one. The evidence is `reputation-history.cfg.json`: the
    # hash-linked committed window plus the quorum-signed Merkle checkpoint
    # over it (_rebuild_from_evidence).
    #
    # Verified -> the peer's score is restored as persisted (still subject to
    # staleness decay, the orthogonal time axis). Unverified -> the score is
    # clamped so the peer holds no more than UNVERIFIED_RESTORE_TIER, and has
    # to earn elevation back through fresh in-session transactions.
    #
    # Tier 1 (presence/communication) is the clamp because an
    # authenticated-but-COMPROMISED asset passes ZTA admission by definition --
    # credentials are exactly what it holds -- so restoring a historically-earned high
    # tier the instant it is admitted re-opens the hole the system exists to close, and
    # for a short-lived asset there is no time for behavioural re-evaluation to catch it
    # first. See doc/architecture/reputation.md ("Hardening: floor, not full
    # restoration").
    UNVERIFIED_RESTORE_TIER = 1
    # Committed bilateral transactions a peer needs INSIDE the attested window
    # before the evidence bounds its score at all. Below this it is treated as
    # uncovered and clamped to the unverified tier.
    RESTORE_EVIDENCE_MIN_TX = 1
    # Pseudo-count shrinking the evidence-derived ceiling toward
    # PREREP_NEUTRAL (see _evidence_ceilings). This is the security parameter
    # of the whole mechanism: it sets how MUCH attested history a peer needs
    # before the window can justify an elevated restored tier, and so it is
    # what stops a forger from minting a two-entry window of perfect scores.
    # Larger -> more history required. Override: AT_REP_RESTORE_SHRINKAGE_K.
    RESTORE_SHRINKAGE_K = _env_float('AT_REP_RESTORE_SHRINKAGE_K', 3.0)

    # Seconds between checkpoint proposals this node originates (0 disables).
    # Checkpointing was previously reactive only -- a Checkpoint had to be put
    # on the reputation queue by something outside this process -- and nothing
    # ever did, so in a live deployment no checkpoint existed, which meant no
    # warm start could ever verify: the mechanism above would have been
    # unreachable in practice. Override: AT_REP_CHECKPOINT_SEC.
    #
    # The interval trades evidence freshness against protocol traffic (each
    # proposal draws a co-signature from every member). It also bounds what a
    # restart can attest: entries committed after the last checkpoint are
    # persisted but unattested, so they restore clamped.
    CHECKPOINT_INTERVAL = _env_float('AT_REP_CHECKPOINT_SEC', 300.0)

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
    # PREREP_NEUTRAL is the "no information" starting reputation on the
    # [0, 1] scale: a peer we know nothing about starts at NEUTRAL (0.2) — a
    # small leeway above the COMM_CUTOFF (0.1) communication cut-off so a
    # newcomer can make a minor mistake without being silenced — and must EARN
    # its way up toward 1.0, rather than being handed a near-threshold ~0.5
    # for free (which let unknown/newcomer peers read as almost-trusted and
    # made the trust graph a flat all-to-all mesh). A catastrophically-failed
    # peer is driven down to the slash floor (0.0), below the cut-off. The
    # transaction-memory prior (_prereputation_prior) shrinks a peer's observed
    # third-party standing toward this value by a pseudo-count of
    # PREREP_SHRINKAGE_K, so a truly-unknown peer (zero observations) reads
    # exactly PREREP_NEUTRAL while a peer others have already scored gets an
    # informed, conservatively-shrunk prior. This is the STARTING point only --
    # the CTFT bilateral pivots (min(0.49, .)/max(0.51, .) around the 0.5
    # per-transaction cooperate threshold) are the earned near-threshold
    # outputs and are deliberately unchanged (the per-tx task-score scale is
    # unchanged; only the aggregate-reputation thresholds move). Mirror:
    # reputation.c PREREP_NEUTRAL. Disable the heuristic via
    # AT_PREREP_HEURISTIC=0; re-adjust the neutral value via AT_REP_NEUTRAL.
    PREREP_NEUTRAL = _env_float('AT_REP_NEUTRAL', 0.2)
    PREREP_SHRINKAGE_K = 3.0

    # Communication cut-off (participation floor on the [0, 1] scale). A peer
    # whose aggregate reputation falls BELOW COMM_CUTOFF is EXCLUDED: gateways
    # stop forwarding to/for it and LAN/one-hop nodes ignore its messages
    # (enforced at the network process via the exclusion feed in
    # _publish_tier_change). The cut-off sits just above the slash floor (0.0),
    # so a slashed peer lands below it. Because an excluded peer can no longer
    # transact, it cannot earn its way back — exclusion is STICKY and recovery
    # is ONLY via a REASON_REHABILITATE slash-lift (operator/quorum), which
    # restores the score to PREREP_NEUTRAL and re-admits it. The excluded state
    # is persisted across restart (two-sided persist filter) so a restart
    # cannot silently rehabilitate. Mirror: reputation.c COMM_CUTOFF.
    # Re-adjust via AT_REP_COMM_CUTOFF.
    COMM_CUTOFF = _env_float('AT_REP_COMM_CUTOFF', 0.1)

    # EMA half-life (in committed bilateral txs) for the dashboard
    # consensus-reputation channel.  Smaller → faster crash on a peer
    # that starts producing bad scores, slower rebuild for the rest.
    # 20 txs gives α ≈ 0.034 — a hacked peer falls visibly within
    # a few seconds of demo time while honest peers recover gradually.
    CONSENSUS_EMA_HALF_LIFE = 20

    # --- Slashing: OFF unless armed (R+D.md §12.8) ---------------------
    # Slashing pins a peer's reputation from outside the EMA, on one
    # detector's say-so plus a quorum co-signature. Nothing arms it
    # automatically any more: the evidence-channel accusation that used to
    # (a hard-falsification channel scoring defection-grade) was removed at
    # the user's direction, because a transaction scored poorly WITH ITS
    # REASON is something every peer can see and judge for itself, and the
    # EMA plus the tier machinery is already graduated discipline.
    #
    # What remains is the behaviour governor's path (SOW Task 3), which is
    # human-on-the-loop by its own default (`auto_slash=False`), and an
    # operator's explicit exclude/rehabilitate. Both are deliberate acts, so
    # the protocol they use is deliberate too: with SLASH_ENABLED off this
    # node originates nothing, declines to co-sign a peer's proposal, and
    # ignores a finalized slash rather than applying its floor.
    #
    # The knob is read once per process, like the rest of this block. Set
    # AT_SLASH_ENABLED=1 fleet-wide to arm it -- a group where only some
    # members are armed will disagree about the floor, which is inherent to
    # the mechanism being a policy rather than a fact.
    SLASH_ENABLED = bool(os.environ.get('AT_SLASH_ENABLED'))

    # --- Deep resolution (doc/architecture/gateway-reputation-tree.md) ----------------------------
    # How long a relayed query stays in the pending table, and how long a
    # query we originated stays outstanding. A deep answer crosses several
    # hops and each may be a busy process loop, so this is generous; it is
    # a garbage-collection bound, not a latency target.
    RESOLVE_PENDING_TTL = _env_float('AT_REP_RESOLVE_TTL_SECS', 30.0)
    # Query-ids retained for loop detection. Bounded like every other FIFO
    # dedup ring here (_slashed_seen, _checkpoint_seen).
    RESOLVE_SEEN_MAX = 256
    # Distinct verified-and-trusted co-signers an answer must carry. This is
    # NOT a quorum test: quorum is a fraction of a membership that an opaque
    # subtree deliberately does not disclose (see verify_resolved). It is the
    # floor below which an answer is not evidence at all.
    RESOLVE_MIN_SIGNERS = int(_env_float('AT_REP_RESOLVE_MIN_SIGNERS', 1))

    # --- Idle reputation decay (warm-start staleness) -----------------
    # A peer's earned operational reputation is a *memory* of past
    # AT-bounded interaction. Memory should fade: the longer since we
    # last transacted with a peer, the closer its operational reputation
    # relaxes toward "almost-but-not-quite neutral" — never all the way
    # to neutral (0.20), so a long-known asset stays faintly preferred over
    # a true stranger, but its elevated trust tier lapses and must be re-earned
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
    # just above neutral (0.20), above COMM_CUTOFF. Override: AT_REP_DECAY_ASYMPTOTE.
    REPUTATION_DECAY_ASYMPTOTE = _env_float('AT_REP_DECAY_ASYMPTOTE', 0.21)
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
        self.protocol.register_handler(ReputationProtocol.app_roster_request,
                                       self.handle_app_roster_request)
        self.protocol.register_handler(
            ReputationProtocol.consensus_rep_req,
            self.handle_consensus_reputation_request)
        self.protocol.register_handler(
            ReputationProtocol.consensus_rep_batch_req,
            self.handle_consensus_reputation_batch_request)
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
        self.protocol.register_handler(
            ReputationProtocol.rep_resolve, self.handle_resolve)
        self.protocol.register_handler(
            ReputationProtocol.rep_resolved, self.handle_resolved)
        self.history = TransactionHistory()
        # Gateway reputation tree: one child chain per child group this node gateways
        # (keyed by group-uuid string). Empty on rank-1 leaf nodes — every code path
        # below degrades to the single self.history chain when this is empty, so leaves
        # are byte-for-byte unchanged. Lazily populated by _chain_for_group the first
        # time a commit routes to a known child group. See
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
        # Debug instrument (AT_REP_DUMP_SEC): throttle clock for the
        # per-node reputation-view dump emitted from process(). See
        # _dump_reputation_trace. 0 == last dump not yet taken.
        self._last_rep_dump = 0.0
        self._seed_idle_from_snapshot()
        # Communication-cut-off exclusion set (peer-uuid-str). A peer whose
        # aggregate reputation is below COMM_CUTOFF is excluded from the
        # network: gateways stop forwarding to/for it and LAN/one-hop nodes
        # ignore its messages. The set is maintained by _publish_tier_change
        # as scores cross the cut-off and fed to the network process, and is
        # seeded here at boot from the persisted (warm-started) snapshot so a
        # peer excluded before shutdown stays excluded across restart --
        # recovery is explicit-only (REASON_REHABILITATE).
        self._excluded: set[str] = set()
        self._seed_exclusions_from_snapshot()
        # One-shot guard: the boot-seeded exclusion set (above) is pushed
        # to the network process on the first process() iteration, once
        # IPC queues exist (they don't at __init__ time).
        self._exclusions_synced = False
        # Sticky consensus memory: peer-uuid-str -> last real (chain-derived)
        # consensus score. The tx chain is a bounded window, so an idle
        # peer's transactions evict within ~one window of sustained
        # activity; without this its consensus would snap back to neutral
        # (0.2) the moment its last tx ages out. Stickiness holds the last computed
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
        # The _slashed floor dict itself is volatile (a restart clears it),
        # BUT the floored score it writes into self.reputations is below
        # COMM_CUTOFF and so IS carried across a restart by the two-sided
        # persist filter (see _persist_reputations): the peer comes back up
        # excluded and is re-seeded into _excluded at boot, staying cut off
        # until explicit REASON_REHABILITATE. Only the fast-penalty CTFT
        # short-circuit (forcing re-earn from the punished regime) is lost on
        # restart; the exclusion itself survives.
        self._slashed: dict[str, tuple] = {}
        # ZTA hardening (doc/architecture/zta-integration.md). Volatile, like _slashed:
        # a restart re-derives standing from the admission gate rather than trusting a
        # file for it. _zta_proved_index: peer -> chain index at its last PROVED
        #     verification; the point a later failure unwinds back TO.
        #   _zta_acted:        peer -> the standing already acted on, so the
        #     hourly re-verification of an unchanged verdict is a no-op.
        self._zta_proved_index: dict[str, int] = {}
        self._zta_acted: dict[str, tuple] = {}
        # Proposer-side co-signature accumulation: slash-key -> {voter-uuid-str:
        # detached hex signature over the attestation's designation}. Seeded
        # with the slasher's OWN signature on initiation. Signatures, not bare
        # uuids: the map is what travels on slash_final, and a receiver that
        # cannot verify a co-signature must not count it (see
        # _verified_cosigners).
        self._slash_sigs: dict[tuple, dict] = {}
        # Proposer-side pending attestations awaiting quorum: key -> attestation.
        self._slash_pending: dict[tuple, SlashAttestation] = {}
        # Dedup for finalized slashes (FIFO bounded), so a re-broadcast
        # slash_final is a cheap no-op. Mirrors committed_paxos_rounds.
        #
        # Kept as a cheap first-line filter only. It is a RING, so on a busy
        # node an old key ages out -- and a slash whose key has aged out could
        # be replayed to re-floor a peer that had since been rehabilitated,
        # back into an exclusion that is sticky by design. _slash_hw below is
        # what actually bounds that; this stays because it is O(1) and stops
        # the common re-broadcast before any of the work below.
        self._slashed_seen: 'OrderedDict[tuple, None]' = OrderedDict()
        # Per-(target, slasher) high-water mark: the highest slash epoch this
        # node has ever APPLIED for that pair. Never evicted, unlike the ring
        # above -- it is sized by the cohort (targets x slashers), not by how
        # many rounds have passed, so there is no window for an old slash to
        # come back through. Persisted, because the guard is only as good as
        # its memory: see _persist_slash_marks.
        #
        # Keyed by slasher as well as target because the epoch is a
        # per-SLASHER counter (see forward_slash), so two detectors' epoch
        # sequences are independent and a single per-target mark would refuse
        # one detector's legitimate slash on the strength of the other's.
        self._slash_hw: dict[tuple, int] = {}
        # Monotonic epoch for slashes this node originates (distinguishes a
        # re-slash of the same target). Phase 2 will tie this to checkpoint
        # epochs; standalone counter suffices for Phase 0.
        #
        # Resumed from the persisted marks below rather than restarting at 0.
        # Receivers hold high-water marks that our own restart does not reset,
        # so a node that began again at epoch 1 would have its next several
        # slashes refused as replays -- the same trap the checkpoint counter
        # documents in _rebuild_from_evidence.
        self._slash_epoch = 0

        # --- Phase 2: quorum-signed Merkle checkpoints --------------------
        # The finalized checkpoint per chain lives in self._checkpoints below;
        # `self._checkpoint` is a read-only property naming the primary one.
        # Proposer-side co-signature accumulation: checkpoint-key ->
        # {voter-uuid-str: detached hex signature over the checkpoint's
        # designation}, holding only members whose own window_root matched.
        # Seeded with the proposer's own signature on initiation; the map
        # travels on checkpoint_final and is re-verified by each receiver.
        self._checkpoint_sigs: dict[tuple, dict] = {}
        # Proposer-side pending checkpoints awaiting quorum: key -> Checkpoint.
        self._checkpoint_pending: dict[tuple, Checkpoint] = {}
        # --- Per-chain finalized checkpoint state -------------------------
        # A gateway keeps one chain per child group beside its primary one, and
        # each chain gets its own checkpoints: its own epoch counter, its own
        # quorum (sized against that group's members), its own evidence file.
        # These are keyed by CHAIN KEY -- '' for the primary chain, a
        # group-uuid string for a child -- so a leaf node simply has a
        # one-entry dict and behaves exactly as before.
        #
        # The co-signatures are kept beyond the live round because they travel
        # in the persisted evidence: a boot-time rebuild has to verify the same
        # quorum a live receiver does, and a root with no signatures beside it
        # is a number anyone with write access to the file could have chosen.
        self._checkpoints: dict[str, Checkpoint] = {}
        self._checkpoint_sigs_final: dict[str, dict] = {}
        self._checkpoint_epochs: dict[str, int] = {}
        # Dedup for finalized checkpoints (FIFO bounded) so a re-broadcast
        # checkpoint_final is a cheap no-op. Mirrors _slashed_seen.
        self._checkpoint_seen: 'OrderedDict[tuple, None]' = OrderedDict()
        # Periodic-origination clocks (see _maybe_checkpoint). 0.0 == the
        # phase offset has not been taken yet. The head map is per chain, so a
        # busy child group is checkpointed while an idle primary chain is not.
        self._next_checkpoint_at = 0.0
        self._last_checkpoint_heads: dict[str, int] = {}
        # Child-group chains already attempted by _restore_child_evidence, and
        # the persisted score each clamped peer was clamped away FROM -- the
        # upper bound on any later lift, so late evidence restores standing
        # instead of inventing it.
        self._child_evidence_tried: set[str] = set()
        self._restore_clamped: dict[str, float] = {}

        # --- Deep resolution: one peer, on demand
        # (doc/architecture/gateway-reputation-tree.md) --------
        # A query we are RELAYING: query-id -> (answer-to uuid-str, deadline,
        # requesting_process). This is the only state the whole capability
        # adds anywhere, and it exists because the answer travels back along
        # the path the query took -- nobody outside a boundary ever exchanges
        # a message with anybody inside it, so each hop has to remember which
        # neighbour to hand the answer to. Entries expire (they are not
        # cleared by an answer that never comes), which is what keeps a
        # gateway's table bounded when a subtree goes dark.
        self._resolve_pending: 'OrderedDict[str, tuple]' = OrderedDict()
        # Query-ids already seen, as a FIFO ring. The loop guard: a tree that
        # is briefly cyclic (a stale hierarchy claim naming a peer that is
        # actually above us) would otherwise circulate a query until its TTL
        # burned down at every node it touched.
        self._resolve_seen: 'OrderedDict[str, None]' = OrderedDict()
        # Queries WE originated: query-id -> (peer-uuid-str, deadline).
        self._resolve_outstanding: dict[str, tuple] = {}
        # Answers we accepted, peer-uuid-str -> (score, verified, reason).
        # `reason` is kept beside the boolean deliberately: an operator
        # reading "unverified" needs to know which gate failed, and a caller
        # may knowingly accept a weaker answer (feedback_operator_diagnostics).
        self.resolved_reps: dict[str, tuple] = {}
        self._zta_policy_cache = None
        self._zta_anchor_cache = None

        # Slash replay marks, before any message can be handled. Also resumes
        # our own slash epoch, so this has to precede the first forward_slash.
        self._load_slash_marks()

        # Verifiable warm start: adopt the persisted committed history if its
        # checkpoint verifies, and clamp every restored score the evidence
        # does not cover. LAST in __init__ deliberately -- it reads the
        # loaded reputation snapshot, the peer roster and the checkpoint
        # state above, and it revises self.history.
        self._rebuild_from_evidence()

    @property
    def peers(self):
        return self.protocol.peers

    @property
    def group(self):
        return self.protocol.group

    @property
    def _checkpoint(self):
        """The finalized checkpoint over the PRIMARY chain, or None.

        Kept as a property because most of this class only ever cares about
        the primary chain (slash evidence, the app-facing observables, the
        conformance adapters), and because it keeps every prior reader working
        unchanged now that the store is per chain."""
        return self._checkpoints.get('')

    @_checkpoint.setter
    def _checkpoint(self, ckpt):
        """Assigning the primary checkpoint directly is a fixture / test path.
        The live path goes through ``_store_checkpoint``, which also retains
        the co-signatures and writes the evidence file."""
        if ckpt is None:
            self._checkpoints.pop('', None)
        else:
            self._checkpoints[''] = ckpt

    def _chain_key(self, group_uuid) -> str:
        """The per-chain bookkeeping key for a group-uuid: '' for the primary
        chain, the group-uuid string for a child chain.

        Resolves through the same rules as ``_chain_for_group``, so a None or
        unrecognized group-uuid -- and the node's own primary group's uuid --
        all land on the primary chain. Anything else is only a child key if we
        actually gateway that group; an unknown uuid must not mint a chain."""
        if group_uuid is None:
            return ''
        key = str(group_uuid)
        if not key:
            return ''
        if self.group is not None and key == str(self.group.uuid):
            return ''
        if key in self.child_groups:
            return key
        return ''

    def _chain_for_key(self, chain_key: str):
        """The TransactionHistory a chain key names."""
        if not chain_key:
            return self.history
        return self._chain_for_group(chain_key)

    def _chain_keys(self):
        """Every chain this node maintains: the primary, then any child-group
        chains a gateway has materialized."""
        return [''] + [k for k in self.child_histories]

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
                self.logger.debug('Reputation request from non-peer: %s', peer_id)
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

    def _resolve_tx_weight(self, score: TransactionScore, local: bool = False) -> int:
        """Map a TS to its EMA weight: the capability's transaction_weight,
        times the evidence channel's multiplier when the evidence is ours.

        The capability half looks up the local Capabilities registry
        (self.protocol.capabilities); peers that don't have the capability
        registered locally treat the weight as 1. Returns at least 1 (the
        0-sentinel from proto3 is normalised to 1 in
        Capability.sync_from_message; this is a defence in depth).

        *local* says this score was produced ON THIS NODE — the IPC path from
        our own subsystems (`forward_transaction`), never the wire path
        (`handle_transaction`). Only then does the channel multiply
        (R+D.md §12.8): the scorer chooses its own channel, so honoring a
        remote tag would let any peer treble the weight of a score it
        fabricated against any other. See `tx_channel_weight`.
        """
        cap_name = getattr(score, 'capability_name', None)
        weight = 1
        if cap_name:
            try:
                cap = self.protocol.capabilities[cap_name]
            except (KeyError, AttributeError, TypeError):
                cap = None
            if cap is not None:
                weight = max(1, int(getattr(cap, 'transaction_weight', 1) or 1))
        if local:
            weight *= tx_channel_weight(getattr(score, 'channel', None))
        return max(1, int(weight))

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
        # so the per-tier consensus view can bucket it (doc/architecture/network-wire-format.md).
        # local=True: every _start_paxos is OUR OWN proposal (the wire path
        # replies from `handle_transaction` and never lands here), so this is
        # the one weighting site where the evidence channel counts.
        self._record_task_weight(score.task_id,
                                 self._resolve_tx_weight(score, local=True))
        self._record_task_tier(score.task_id, self._resolve_tx_tier(score))
        self.logger.debug('Start a Paxos round')

    def handle_transaction(self, queues, message):
        if message.function == ReputationProtocol.transaction:
            try:
                (id1, id2, peer_id), score = from_json_string(message.obj)
            except ValueError as err:
                # An out-of-range score is rejected in TransactionScore's
                # constructor (doc/architecture/reputation.md), which `from_json_string` runs. Dropping
                # here rather than letting it propagate: the payload is
                # peer-supplied, so a raise escaping into the process loop would
                # hand a remote a lever on this node's reputation process.
                self.logger.warning(
                    'Dropping Paxos proposal from %s: %s', message.from_whom, err)
                return True
            idx = self._paxos_id_index(id1, id2)
            if idx not in self.requests:
                return True  # not granted, drop
            self.requests.remove(idx)
            if not message.verified:
                self.logger.warning('Rejecting unverified Paxos proposal from %s', message.from_whom)
                return True  # drop unverified proposal
            if idx not in self.proposals:
                self.proposals[idx] = score
                self.logger.debug("Tx to proposals ")
            # Cache the weight for this task — incoming TS payload carries
            # capability_name (Slice 1). Receivers that don't register the
            # capability locally fall back to weight 1. No `local=True`: the
            # channel on a peer's score is legibility only (R+D.md §12.8).
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
                    self.logger.warning('Rejecting unverified Paxos acceptance from %s', message.from_whom)
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
                    score.task_id, peer_id, score.score, score.channel)
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
                    #
                    # The channel rides along as element 5 (R+D.md §12.8):
                    # without it an acceptor writes the score and drops the
                    # reason, and "every peer can judge a poor score for
                    # itself" is only true if the reason reaches every peer.
                    # It is also part of the entry hash on both sides, so a
                    # commit that arrived without it and one that arrived
                    # with `task_outcome` must hash the same -- which they do,
                    # since both normalize to no channel block.
                    commit_msg = Message(
                        self.name, ReputationProtocol.committed,
                        to_json_string(
                            (score.task_id, peer_id, score.score,
                             round_group_uuid, score.channel)),
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
                # Element 5, appended the same length-tolerant way the
                # group_uuid was: a legacy 3- or 4-tuple has no channel, which
                # is `task_outcome` by construction (R+D.md §12.8).
                channel = parsed[4] if len(parsed) > 4 else None
            except Exception:
                self.logger.warning(
                    'handle_committed: malformed payload %r', message.obj)
                return True
            if str(peer_id) == str(self.identity.uuid):
                return True
            try:
                # doc/architecture/reputation.md: this payload is a BARE float on the wire, not a
                # TransactionScore, so it bypasses the constructor's check --
                # and this is the path that writes history on every acceptor.
                # An out-of-range score here would be averaged into a
                # reputation by an unbounded amount.
                score = validate_tx_score(score, 'handle_committed')
            except ValueError as err:
                self.logger.warning(
                    'Dropping committed tx from %s: %s', str(peer_id)[:8], err)
                return True
            try:
                # Validated BEFORE the write, and the whole commit is dropped
                # on failure rather than the channel being coerced away. The
                # channel is part of `_canonical_bytes` now, so accepting an
                # unknown spelling would either fork this node's entry hash
                # away from the rest of the group or silently rewrite the
                # reason -- and a peer sending one is speaking a vocabulary
                # this node does not have, which is exactly the case the
                # closed set exists to catch.
                channel = validate_tx_channel(channel, 'handle_committed')
            except ValueError as err:
                self.logger.warning(
                    'Dropping committed tx from %s: %s', str(peer_id)[:8], err)
                return True
            chain = self._chain_for_group(group_uuid)
            chain.update(task_id, peer_id, score, channel)
            # Fold-on-commit: advance the dashboard running consensus EMA as
            # soon as this tx completes (primary chain only; idempotent).
            self._fold_committed_tx(task_id, chain)
            self._note_interaction(peer_id)
            self.logger.info(
                'Recorded committed tx from %s: task=%s score=%.2f via %s '
                'group=%s (chain now %d txs, %d task_maps)',
                str(peer_id)[:8], str(task_id)[:8], float(score), channel,
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

    # ----- Quorum co-signatures (slash + checkpoint) -----------------------
    # A three-phase quorum round is only worth what its RECEIVERS can check.
    # Before this, the co-signature bytes were collected and thrown away:
    # handle_*_sign credited the voter uuid CLAIMED in the payload, the
    # finalizer broadcast ``sigs={}``, and handle_*_final applied the decision
    # on transport authentication alone. So any single admitted member could
    # finalize whatever it liked -- and because a slash floors a peer below
    # COMM_CUTOFF into exclusion that is sticky (recovery only via explicit
    # REASON_REHABILITATE), that was an insider primitive for permanently
    # excluding any peer. Signatures are now retained, attributed to the
    # authenticated sender, and verified by every receiver. See
    # doc/architecture/reputation.md (Quorum attestation).
    #
    # Signature form follows the partition-probe idiom (idprocess.py): the
    # signer emits ``identity.sign(designation).signature`` as ASCII hex, and
    # the verifier hex-decodes and calls the raw-bytes
    # ``signature.public.verify`` -- Identity.verify's two-arg form
    # double-encodes under nacl.

    @staticmethod
    def _detached_sig(identity, designation):
        """This node's detached signature over ``designation``, ASCII hex."""
        return identity.sign(designation).signature.decode('ascii')

    def _cosigner_identity(self, voter_uuid):
        """Resolve a co-signer uuid to the Identity holding its public key:
        self first (a proposer counts its own signature), then the peer
        roster. None when the claimed voter is unknown to us -- an unknown
        voter's signature cannot be verified, so it cannot count."""
        key = str(voter_uuid)
        if key == str(self.identity.uuid):
            return self.identity
        for peer in self.peers.all:
            if str(peer.uuid) == key:
                return peer
        return None

    def _verify_cosignature(self, designation, voter_uuid, sig) -> bool:
        """True iff ``sig`` is ``voter_uuid``'s signature over
        ``designation``. Any malformed / unknown / bad-signature case is
        False: a co-signature that cannot be checked must never be counted."""
        ident = self._cosigner_identity(voter_uuid)
        if ident is None or sig is None:
            return False
        try:
            if isinstance(sig, str):
                sig = sig.encode('ascii')
            ident.signature.public.verify(designation, HexEncoder.decode(sig))
        except (BadSignatureError, ValueError, TypeError, AttributeError):
            return False
        return True

    def _verified_cosigners(self, designation, sigs) -> set:
        """The DISTINCT voters in ``sigs`` whose signature over
        ``designation`` verifies against a key we hold. Counting the set of
        verified signers -- rather than tallying arriving messages -- is what
        makes one peer's replayed signature worth exactly one vote."""
        if not isinstance(sigs, dict):
            return set()
        return {str(voter) for voter, sig in sigs.items()
                if self._verify_cosignature(designation, voter, sig)}

    def _attributed_voter(self, message, claimed, where: str):
        """The uuid-str a ``*_sign`` ack may be credited to, or None.

        The vote belongs to the AUTHENTICATED sender (``message.from_whom``),
        never to the uuid the payload claims. Measured: this is defense in
        depth, not the primary check -- ``_verify_cosignature`` already bounds
        the tally to signatures the sender could actually obtain. What it adds
        is the case where those differ: co-signatures are broadcast on
        ``*_final`` and so are not secret, and binding the vote to the sender
        stops a harvested genuine signature from being relayed under its
        signer's name by somebody else. It also catches the plain bug of a node
        mislabelling its own ack. A claim that disagrees with the sender is
        refused rather than silently re-attributed: the two disagreeing is
        either a bug or an attempt, and neither should quietly become a vote."""
        sender = getattr(message.from_whom, 'uuid', None)
        if sender is None:
            self.logger.warning(
                '%s: unattributable ack (no sender identity); not counted',
                where)
            return None
        sender = str(sender)
        if claimed is not None and str(claimed) != sender:
            self.logger.warning(
                '%s: ack claims voter %s but was sent by %s; refused',
                where, str(claimed)[:8], sender[:8])
            return None
        return sender

    def _quorum_met(self, designation, sigs, group_uuid=None) -> bool:
        """Receiver-side quorum test over retained co-signatures: more than
        ``_quorum_for_group`` distinct voters must have signed the exact bytes
        this node re-derives. Sized against OUR OWN view of the group, so the
        finalizer cannot also choose the bar it has to clear."""
        return len(self._verified_cosigners(designation, sigs)) > \
            self._quorum_for_group(group_uuid)

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
        - An ``evidence_ref`` that is not an inclusion proof at all -> also the
          Phase-0 path. A detector's own verdict (the behaviour governor's
          per-feature attribution, ``kind='behavioural_anomaly'``) is evidence
          for a HUMAN, not something a co-signer can check, and running it
          through the Merkle branch refused it on a missing 'leaf' key --
          which quietly made every governor slash un-cosignable, i.e. the
          SOW Task 3 path stopped at the proposer's own view. Accepting it
          opens no hole that is not already open: a slasher wanting to dodge
          the Merkle branch can simply send no evidence at all.
        - With a Merkle ``evidence_ref`` -> the offending tx's inclusion proof must
          verify against a root this node has FINALIZED as a checkpoint. Tying
          it to our own quorum-agreed checkpoint — not a root chosen by the
          accuser — is what makes the evidence trustworthy. Any malformed /
          mismatched / unverifiable evidence returns False and the slash is
          refused.

        ANY of our finalized roots counts, not only the primary chain's: a
        gateway finalizes a checkpoint per child group, and an offending tx
        committed in a child group is anchored in that group's root. Accepting
        only the primary root would refuse every legitimate subtree slash while
        adding no security — each root cleared the same quorum test."""
        ev = attestation.evidence_ref
        if ev is None:
            return True
        # Kind dispatch before the Merkle branch: only an inclusion proof is
        # verifiable here, and only an inclusion proof claims to be. A dict
        # that carries no proof is a detector's own account of what it saw.
        if isinstance(ev, dict) and not ({'leaf', 'proof', 'root'} <= set(ev)):
            return True
        if not self._checkpoints:
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
        finalized = set()
        for ck in self._checkpoints.values():
            if ck is None or not ck.root:
                continue
            ck_root = ck.root
            if isinstance(ck_root, str):
                ck_root = ck_root.encode('ascii')
            finalized.add(ck_root)
        # The evidence must be proven against one of OUR finalized roots.
        if root not in finalized:
            return False
        return TransactionHistory.verify_inclusion(leaf, proof, root)

    def _apply_slash(self, attestation):
        """Pin (or, for 'rehabilitate', lift) the target's reputation floor
        and queue a tier recompute so tier_lost flows through the existing
        path. Idempotent per (target, epoch).

        Replay-bounded per (target, slasher): a slash is applied only if its
        epoch EXCEEDS every epoch already applied from that slasher against
        that target. Since each slasher numbers its own slashes upward, a
        second presentation of any earlier decision -- including one whose
        ring entry has aged out, and including a punitive slash replayed after
        a rehabilitation lifted it -- cannot move the floor again."""
        key = attestation.key()
        if key in self._slashed_seen:
            return
        target = str(attestation.target_uuid)
        slasher = str(attestation.slasher_uuid)
        epoch = int(attestation.epoch)
        hw_key = (target, slasher)
        # Epochs are assigned pre-incremented from 1 (forward_slash), so 0 is
        # the never-seen floor and an attestation claiming epoch <= 0 is
        # malformed; both land on the same refusal.
        if epoch <= self._slash_hw.get(hw_key, 0):
            self.logger.warning(
                'Refusing slash for %s from %s: epoch %d not above applied '
                'high-water %d (replay)',
                target[:8], slasher[:8], epoch,
                self._slash_hw.get(hw_key, 0))
            return
        if attestation.reason == SlashAttestation.REASON_REHABILITATE:
            self._slashed.pop(target, None)
            # Drop the sticky floor AND the running-EMA latch so the score
            # recomputes from the lifted value rather than the floored one.
            # The slash-override in _consensus_reputation pins BOTH
            # _consensus_last and _consensus_ema to the floor; clearing only
            # the former would leave _running_consensus returning the stale
            # floored EMA and the lift below would be invisible.
            self._consensus_last.pop(target, None)
            self._consensus_ema.pop(target, None)
            self._consensus_folded_idx.pop(target, None)
            # Lift the score to neutral (PREREP_NEUTRAL, above the comm
            # cut-off) so the peer is re-admitted to the network and then
            # must re-earn elevated trust from neutral -- rather than
            # snapping back to a stale pre-failure value or being left below
            # the cut-off (still excluded) by a rehab attestation whose
            # floor_score is the punitive floor. The tier recompute below
            # (score above the cut-off) drives the readmit through
            # _publish_tier_change.
            pending_score = self.PREREP_NEUTRAL
            try:
                self.reputations.update(attestation.target_uuid, pending_score)
            except Exception:
                self.logger.debug('apply_slash: reputations.update (rehab) '
                                  'failed', exc_info=True)
        else:
            floor = float(attestation.floor_score)
            pending_score = floor
            self._slashed[target] = (floor, int(attestation.epoch))
            # Reflect the floor in the canonical reputation store too, so
            # the verdict is observable to persistence, tier publication,
            # and any reader of self.reputations (e.g. the conformance
            # `reputation_of` assertion) — not only lazily at scoring time.
            # A floored peer is below COMM_CUTOFF, so the two-sided persist
            # filter DOES carry it across a restart (it stays excluded until
            # explicit rehabilitation); the volatile _slashed floor itself is
            # not persisted, but the sub-cut-off score is.
            try:
                self.reputations.update(attestation.target_uuid, floor)
            except Exception:
                self.logger.debug('apply_slash: reputations.update failed',
                                  exc_info=True)
        self._slashed_seen[key] = None
        while len(self._slashed_seen) > self.COMMITTED_ROUNDS_CAP:
            self._slashed_seen.popitem(last=False)
        # Advance the durable mark and write it out. Recorded for a
        # rehabilitation too: a rehab is itself a decision that must not be
        # replayable, and leaving the mark behind would let the punitive slash
        # it superseded back in at the same epoch.
        self._slash_hw[hw_key] = epoch
        self._persist_slash_marks()
        # Queue a tier recompute (drained in process()): _compute_reputation
        # short-circuits on a floor and publishes tier 0 / tier_lost; a rehab
        # lift republishes the restored (neutral) tier and readmits.
        self.pending_tiers.append((attestation.target_uuid, pending_score))
        self.logger.info(
            'Slash %s: target=%s reason=%s score=%.2f epoch=%d',
            'lifted' if attestation.reason
            == SlashAttestation.REASON_REHABILITATE else 'applied',
            target[:8], attestation.reason,
            pending_score, int(attestation.epoch))

    def forward_slash(self, queues, message):
        """Entry point for a locally-originated slash: a detector (e.g. the
        dod_mission coordinator) puts a SlashAttestation on the reputation
        queue. Stamp epoch/nonce, sign, apply to our OWN view immediately
        (a node always trusts its own detection — this is what the
        detector's dashboard reads), seed the co-signature set with
        ourself, and broadcast slash_propose to collect a quorum. Mirrors
        forward_transaction's role for TransactionScore.

        Refuses unless slashing is armed (``SLASH_ENABLED``). A detector on an
        unarmed node keeps its own view and its own log and asks nobody for a
        floor -- see the SLASH_ENABLED comment for why the default is off."""
        if isinstance(message, SlashAttestation):
            if not self.SLASH_ENABLED:
                self.logger.warning(
                    'Slash NOT originated (slashing disarmed): target=%s '
                    'reason=%s -- set AT_SLASH_ENABLED=1 to arm',
                    str(getattr(message, 'target_uuid', ''))[:8],
                    getattr(message, 'reason', None))
                return True
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
                # Seed the co-signature map with OUR OWN detached signature,
                # not a bare uuid: every entry that will travel on
                # slash_final has to be verifiable by its recipients, the
                # proposer's included.
                self._slash_sigs[key] = {}
                try:
                    self._slash_sigs[key][str(self.identity.uuid)] = \
                        self._detached_sig(self.identity, att.designation)
                except Exception:
                    self.logger.error(
                        'forward_slash: cannot sign own attestation; '
                        'this slash cannot reach quorum')
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
            # Declining to co-sign is the disarmed node's whole contribution:
            # it neither vouches for the accusation nor argues with it, and
            # the proposer simply fails to reach quorum if enough of the group
            # is disarmed. Handled (returns True) rather than passed on, so
            # the message is consumed and logged instead of falling through to
            # another handler.
            if not self.SLASH_ENABLED:
                self.logger.info(
                    'Not co-signing slash_propose from %s (slashing disarmed)',
                    message.from_whom)
                return True
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
                sig = self._detached_sig(self.identity, att.designation)
            except Exception:
                self.logger.error(
                    'handle_slash_propose: cannot sign; declining to co-sign')
                return True
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
            tgt, epoch, claimed, sig = payload
            key = (str(tgt), int(epoch))
            att = self._slash_pending.get(key)
            if att is None:
                return True  # not our round, or already finalized
            voter = self._attributed_voter(message, claimed, 'slash_sign')
            if voter is None:
                return True
            # A co-signature that does not verify is not a vote. Without this
            # the tally counted assertions rather than signatures.
            if not self._verify_cosignature(att.designation, voter, sig):
                self.logger.warning(
                    'handle_slash_sign: co-signature from %s failed '
                    'verification; not counted', voter[:8])
                return True
            self._slash_sigs.setdefault(key, {})[voter] = sig
            grp_uuid = str(self.group.uuid) if self.group is not None else None
            if len(self._slash_sigs[key]) > self._slash_quorum(grp_uuid):
                signed = SignedSlash(attestation=att,
                                     sigs=dict(self._slash_sigs[key]))
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
            # A disarmed node does not apply a floor it declined to co-sign.
            # This is the half that makes the knob a real policy rather than
            # decoration: origination and co-signing can both be refused and a
            # quorum elsewhere in the group would still pin the peer here.
            if not self.SLASH_ENABLED:
                self.logger.info(
                    'Ignoring slash_final from %s (slashing disarmed)',
                    message.from_whom)
                return True
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
            # Quorum is verified HERE, by us, against the retained
            # co-signatures. Transport authentication says only that some
            # admitted member sent this; it says nothing about whether a
            # majority agreed, and a slash floors a peer into sticky
            # exclusion. A finalizer carrying no verifiable co-signatures is
            # refused -- the flag day noted in reputation.md.
            sigs = getattr(signed, 'sigs', None)
            if not self._quorum_met(att.designation, sigs):
                self.logger.warning(
                    'Rejecting slash_final for %s: %d verified co-signature(s) '
                    'do not meet quorum',
                    str(att.target_uuid)[:8],
                    len(self._verified_cosigners(att.designation, sigs)))
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
            # The trigger object's fields are ignored EXCEPT group_uuid, which
            # selects which of our chains to commit to (a gateway has more than
            # one). Everything else always comes from our own live window.
            self._originate_checkpoint(
                queues, self._chain_key(getattr(message, 'group_uuid', '')))
            return True
        return False

    def _originate_checkpoint(self, queues, chain_key: str = ''):
        """Propose a checkpoint over the chain ``chain_key`` names.

        Broadcast goes to THAT chain's group: a child-group checkpoint is only
        meaningful to that group's members, who are the ones holding the same
        window to compare roots against, and they are also who sizes its
        quorum."""
        try:
            chain = self._chain_for_key(chain_key)
            epoch = self._checkpoint_epochs.get(chain_key, 0) + 1
            self._checkpoint_epochs[chain_key] = epoch
            window = chain._indexed_window()
            root = chain.window_root()
            first = window[0].index if window else chain._next_index
            ckpt = Checkpoint(
                proposer_uuid=self.identity.uuid, root=root,
                epoch=epoch, first_index=first, count=len(window),
                nonce=os.urandom(8), group_uuid=chain_key)
            try:
                ckpt.signature = self.identity.sign(ckpt.designation)
            except Exception:
                ckpt.signature = None
            key = ckpt.key()
            self._checkpoint_pending[key] = ckpt
            # Our own detached signature, for the same reason as
            # forward_slash: every entry travelling on checkpoint_final
            # must be verifiable by its recipients.
            self._checkpoint_sigs[key] = {}
            try:
                self._checkpoint_sigs[key][str(self.identity.uuid)] = \
                    self._detached_sig(self.identity, ckpt.designation)
            except Exception:
                self.logger.error(
                    'forward_checkpoint: cannot sign own checkpoint; '
                    'this checkpoint cannot reach quorum')
            # Self-store immediately so a single-node group (or the
            # originator's own view) has a finalized checkpoint without a
            # co-sign round-trip, matching forward_slash's self-apply.
            # Only OUR signature exists yet, which is deliberately not
            # special-cased: at boot the same quorum rule applies, so this
            # self-store attests a genuinely single-node group and nothing
            # more. The quorum map replaces it in handle_checkpoint_sign.
            self._store_checkpoint(ckpt, self._checkpoint_sigs[key])
            to_whom = (self._group_by_uuid(chain_key) if chain_key
                       else self.group)
            if to_whom is not None:
                msg = Message(self.name,
                              ReputationProtocol.checkpoint_propose,
                              to_json_string(ckpt), to_whom,
                              from_whom=self.identity)
                queues[CfgIds.network].put(
                    msg, block=True, timeout=self.q_cadence)
            self.logger.info(
                'Proposed checkpoint: chain=%s epoch=%d count=%d root=%s',
                chain_key[:8] or 'primary', ckpt.epoch, ckpt.count,
                (root.decode() if isinstance(root, bytes) else str(root))[:12])
        except Full:
            self.logger.error('forward_checkpoint: network queue full')

    def _store_checkpoint(self, ckpt, sigs=None):
        """Record ``ckpt`` as the latest finalized checkpoint (idempotent on
        re-broadcast via the seen-dedup ring).

        ``sigs`` are the co-signatures that finalized it, retained because the
        persisted evidence has to carry them: a boot-time rebuild verifies the
        same quorum a live receiver does, and without the signatures there is
        nothing to verify (see _rebuild_from_evidence).

        This is also where the evidence file is written, and deliberately so:
        at this instant the resident window and the agreed root describe each
        other. Writing on every commit instead would be both hotter (~16/s in
        the DoD demo) and *less* useful, since a chain that has moved past its
        checkpoint is exactly a chain the rebuild cannot attest.
        """
        key = ckpt.key()
        chain_key = self._chain_key(getattr(ckpt, 'group_uuid', ''))
        if key in self._checkpoint_seen:
            # Idempotent on re-broadcast, with one exception: a fuller
            # co-signature set is an upgrade, not a duplicate. The proposer
            # self-stores at propose time holding only its OWN signature (so a
            # single-node group needs no round trip), and the quorum map only
            # exists later.
            held = self._checkpoint_sigs_final.get(chain_key, {})
            if sigs and len(sigs) > len(held):
                self._checkpoint_sigs_final[chain_key] = dict(sigs)
                self._persist_history(chain_key)
            return
        self._checkpoints[chain_key] = ckpt
        self._checkpoint_sigs_final[chain_key] = dict(sigs or {})
        self._checkpoint_seen[key] = None
        while len(self._checkpoint_seen) > self.COMMITTED_ROUNDS_CAP:
            self._checkpoint_seen.popitem(last=False)
        self._persist_history(chain_key)

    def _slash_marks_path(self):
        """The file holding the per-(target, slasher) slash high-water marks."""
        return os.path.join(Configuration.get_cfg_dir(),
                            SLASH_MARKS_FILE + Configuration.file_ext)

    def _persist_slash_marks(self):
        """Write the slash high-water marks.

        Unlike the chain evidence, this is NOT an optimization of trust: the
        marks are what stop a superseded slash from being replayed into a
        sticky exclusion, so losing them reopens that window. A write failure
        is therefore logged at warning, not debug -- but it is still swallowed,
        because the alternative is taking down the reputation process over a
        full disk and leaving the node with no reputation at all.

        Flat "target|slasher" keys: JSON has no tuple key, and the pair is
        already two uuid strings.
        """
        try:
            doc = {'%s|%s' % (t, s): int(e)
                   for (t, s), e in self._slash_hw.items()}
            with atomic_write(self._slash_marks_path()) as f:
                json.dump(doc, f, indent=2)
        except (OSError, IOError, ValueError, TypeError) as e:
            self.logger.warning('Could not persist slash marks: %s', e)

    def _load_slash_marks(self):
        """Restore the marks and resume our own slash epoch past them.

        A missing file is the cold-start case and not an error: the marks are
        empty and the first slash from any slasher is accepted, which is the
        behaviour a node with no history has to have. A CORRUPT file is
        different -- it is refused loudly and left in place rather than being
        silently treated as empty, because "no marks" is exactly the state an
        attacker would want to induce.
        """
        path = self._slash_marks_path()
        if not os.path.exists(path):
            return
        try:
            with open(path) as f:
                doc = json.load(f)
            if not isinstance(doc, dict):
                raise ValueError('not an object')
            marks = {}
            for flat, epoch in doc.items():
                target, _, slasher = str(flat).partition('|')
                if not target or not slasher:
                    raise ValueError('malformed key %r' % flat)
                marks[(target, slasher)] = int(epoch)
        except (OSError, IOError, ValueError, TypeError) as e:
            self.logger.error(
                'Slash marks unreadable (%s); replay protection for slashes '
                'starts from empty this boot', e)
            return
        self._slash_hw = marks
        # Resume our own counter past anything we have already emitted, so our
        # next slash clears the high-water marks our peers are holding for us.
        # This is the same trap _rebuild_from_evidence documents for checkpoint
        # epochs, and the reason the marks record our OWN slashes too.
        me = str(self.identity.uuid)
        mine = [e for (_, slasher), e in self._slash_hw.items() if slasher == me]
        if mine:
            self._slash_epoch = max(self._slash_epoch, max(mine))
        self.logger.debug(
            'Slash marks restored: %d pair(s), own epoch resumed at %d',
            len(self._slash_hw), self._slash_epoch)

    def _evidence_path(self, chain_key: str = ''):
        """The evidence file for one chain.

        One file per chain rather than one file holding every chain: it mirrors
        the ``group_child_<name>.cfg.json`` convention already used for child
        groups, keeps the primary file's shape byte-for-byte what it was, and
        means a corrupt or stale child file costs that subtree its attestation
        and nothing else."""
        name = EVIDENCE_FILE
        if chain_key:
            name = '%s-%s' % (EVIDENCE_FILE, chain_key)
        return os.path.join(Configuration.get_cfg_dir(),
                            name + Configuration.file_ext)

    def _persist_history(self, chain_key: str = ''):
        """Write the evidence behind one chain: its resident hash-linked window
        plus the quorum-signed checkpoint over it.

        Failure is logged and swallowed. The evidence is an *optimization of
        trust* -- its absence costs a warm start its elevated tiers (see
        _rebuild_from_evidence) and nothing else -- so it must never be able to
        take down the reputation process.
        """
        try:
            ckpt = self._checkpoints.get(chain_key)
            signed = None
            if ckpt is not None:
                signed = SignedCheckpoint(
                    checkpoint=ckpt,
                    sigs=dict(self._checkpoint_sigs_final.get(chain_key, {})))
            doc = evidence_to_dict(self._chain_for_key(chain_key), signed)
            with atomic_write(self._evidence_path(chain_key)) as f:
                json.dump(doc, f, indent=2)
        except (OSError, IOError, ValueError, TypeError) as e:
            self.logger.warning('Could not persist reputation evidence: %s', e)

    def _checkpoint_phase(self) -> float:
        """A per-node offset into the checkpoint interval, so members do not
        all propose on the same tick.

        Every member co-signs every proposal, so N nodes proposing together
        cost N² messages in one burst; spread over the interval they cost the
        same total at a fraction of the peak. Derived from our own uuid rather
        than drawn randomly: the phase then survives a restart, which keeps a
        restarted node from colliding with whichever node has drifted into its
        slot."""
        try:
            seed = UUID(str(self.identity.uuid)).int
        except (ValueError, AttributeError, TypeError):
            return 0.0
        return float(seed % max(1, int(self.CHECKPOINT_INTERVAL)))

    def _maybe_checkpoint(self, queues, present):
        """Originate a checkpoint over each of our committed windows, on the
        interval, for every chain whose window has actually moved.

        Two guards, both about not spending a group's bandwidth for nothing.
        An empty window has nothing to attest. A window whose head has not
        advanced since the last checkpoint is already attested -- re-signing
        it produces a new epoch that commits to the same root, which no
        verifier can use for anything the previous one could not.

        A gateway runs this per chain, so an idle primary chain is skipped
        while a busy child group is checkpointed, and each round is confined to
        the group that can actually co-sign it."""
        if self.CHECKPOINT_INTERVAL <= 0:
            return
        if self._next_checkpoint_at == 0.0:
            self._next_checkpoint_at = present + self._checkpoint_phase()
            return
        if present < self._next_checkpoint_at:
            return
        self._next_checkpoint_at = present + self.CHECKPOINT_INTERVAL
        for chain_key in self._chain_keys():
            window = self._chain_for_key(chain_key)._indexed_window()
            if not window:
                continue
            head = window[-1].index
            last = self._last_checkpoint_heads.get(chain_key)
            if last is not None and head <= last:
                continue
            self._last_checkpoint_heads[chain_key] = head
            self._originate_checkpoint(queues, chain_key)

    # ----- Verifiable warm start (doc/architecture/reputation.md) ------------------------

    def _rebuild_from_evidence(self):
        """At start-up, re-establish the committed history from the persisted
        evidence and grade the restored reputations by whether that evidence
        VERIFIES. Called last in ``__init__``: it needs the loaded snapshot,
        the peer roster (to resolve co-signers) and the checkpoint state.

        Three questions, in order, and every negative answer degrades to the
        same safe outcome rather than raising:

        1. Does the chain's hash-linkage hold? A broken link means the file
           was altered or truncated.
        2. Does the recomputed Merkle root over the checkpoint's window equal
           the root the checkpoint commits to? This is what ties the entries
           on disk to the thing that was signed.
        3. Does a quorum of co-signatures over that checkpoint verify against
           keys WE hold? Same test ``handle_checkpoint_final`` applies live,
           for the same reason: without it the root is a number whoever wrote
           the file chose.

        Only if all three hold is the chain adopted and the persisted scores
        allowed to stand. The chain is NOT loaded on failure, and that is the
        load-bearing part: hash-linkage is computable by anyone (the digests
        are public), so a self-consistent chain proves nothing on its own.
        Loading one would let CTFT re-derive the very elevated scores the
        clamp below exists to withhold -- the clamp would be decoration.
        """
        # Only the PRIMARY chain here. A gateway's child groups arrive later,
        # over IPC (`ChildGroupSet` from IdentityProcess), so at __init__ time
        # this node does not yet know which subtrees are its own — and reading a
        # file for a group we may not gateway is exactly what
        # _persisted_chain_keys refuses to do. The child chains are restored by
        # _restore_child_evidence once the group set lands.
        ceilings: dict = {}
        self._rebuild_one_chain('', ceilings)
        self._grade_restored_reputations(ceilings)

    def _persisted_chain_keys(self):
        """Child-group chain keys with evidence on disk.

        Driven by ``child_groups`` rather than by globbing the directory: a file
        naming a group we do not gateway is not ours to adopt, and reading only
        what we are configured for keeps a stale file from resurrecting a
        subtree we have left."""
        return [group_uuid for group_uuid in self.child_groups
                if os.path.exists(self._evidence_path(group_uuid))]

    def _restore_child_evidence(self, queues):
        """Restore a gateway's child-group chains once the group set has
        arrived, one attempt per group (doc/architecture/gateway-reputation-tree.md).

        This runs late by necessity -- ``child_groups`` is delivered over IPC
        after ``__init__`` -- which shapes what it may do to a live score. It
        only ever LIFTS, and never above what was persisted: a peer attested
        solely in a child group was clamped at boot as uncovered, and this
        returns it to what its subtree's evidence bears out. Lowering here
        would be wrong twice over -- the peer may have earned standing in this
        session since boot, and late-arriving evidence is not a reason to
        discount it.
        """
        for chain_key in self._persisted_chain_keys():
            if chain_key in self._child_evidence_tried:
                continue
            self._child_evidence_tried.add(chain_key)
            ceilings: dict = {}
            self._rebuild_one_chain(chain_key, ceilings)
            for peer, ceiling in ceilings.items():
                try:
                    peer_uuid = UUID(peer)
                except (ValueError, TypeError):
                    continue
                current = self.reputations.current.get(peer_uuid)
                if current is None:
                    continue
                # Bounded by the persisted value we clamped away from, so this
                # restores standing rather than inventing it.
                lift = min(self._restore_clamped.get(peer, current), ceiling)
                # doc/architecture/zta-integration.md: child-group evidence can restore standing, but not
                # past what ZTA proved about the peer holding it. Evidence that
                # a peer behaved well is not evidence it is who it claims.
                lift = self._apply_zta_ceiling(peer_uuid, lift)
                if lift <= current:
                    continue
                self.reputations.current[peer_uuid] = lift
                self.logger.info(
                    'Warm start: child-group evidence lifted %s %.3f -> %.3f',
                    peer[:8], current, lift)
                self._publish_tier_change(queues, peer_uuid, lift)
                self._publish_reputation_change(queues, peer_uuid, lift)

    def _rebuild_one_chain(self, chain_key: str, ceilings: dict) -> None:
        """Verify and (only then) adopt one chain's persisted evidence, folding
        its per-peer ceilings into ``ceilings``.

        Where two attested windows bound the same peer, the HIGHER bound wins.
        Both are quorum-attested statements about that peer, and the restored
        score is a single scalar: letting one group's thin window suppress
        standing another group's quorum actually witnessed would penalize the
        peer for our topology rather than for its behaviour."""
        try:
            with open(self._evidence_path(chain_key)) as f:
                doc = json.load(f)
        except (OSError, IOError):
            # No evidence on disk: a cold start, or a warm start from a
            # snapshot written before checkpointing ever ran. Persisted
            # scores are unattested, so they are clamped.
            return
        except ValueError as e:
            self.logger.warning('Reputation evidence is not valid JSON: %s', e)
            return
        try:
            chain, signed = evidence_from_dict(doc)
        except (ValueError, KeyError, TypeError) as e:
            self.logger.warning('Unusable reputation evidence: %s', e)
            return
        # A file must cover the chain it is named for. A child document
        # claiming the primary chain (or another group's) would otherwise be
        # adopted as that chain's history on the strength of signatures made
        # over different bytes.
        ckpt = getattr(signed, 'checkpoint', None)
        if ckpt is not None and \
                self._chain_key(getattr(ckpt, 'group_uuid', '')) != chain_key:
            self.logger.warning(
                'Reputation evidence for chain %s names chain %s; refusing it',
                chain_key[:8] or 'primary',
                str(getattr(ckpt, 'group_uuid', ''))[:8] or 'primary')
            return
        found = self._attested_ceilings(chain, signed)
        if found is None:
            return
        # Verified: adopt the chain, and with it the checkpoint that attests
        # it, so this node resumes with a history a peer can audit and an
        # anchor slash evidence can be measured against.
        if chain_key:
            self.child_histories[chain_key] = TransactionHistory(_chain=chain)
        else:
            self.history = TransactionHistory(_chain=chain)
        self._checkpoints[chain_key] = ckpt
        self._checkpoint_sigs_final[chain_key] = dict(signed.sigs or {})
        self._checkpoint_seen[ckpt.key()] = None
        # Resume our own epoch counter past the persisted checkpoint. Peers
        # dedup on (proposer, epoch, chain) and their rings are NOT reset by
        # our restart, so a restarted proposer that began again at epoch 1
        # would have its first several proposals discarded as re-broadcasts.
        if str(ckpt.proposer_uuid) == str(self.identity.uuid):
            self._checkpoint_epochs[chain_key] = max(
                self._checkpoint_epochs.get(chain_key, 0), int(ckpt.epoch))
        for peer, ceiling in found.items():
            if ceiling > ceilings.get(peer, -1.0):
                ceilings[peer] = ceiling
        self.logger.info(
            'Reputation warm start VERIFIED: chain=%s, %d committed entries, '
            'checkpoint epoch=%d, %d evidence-backed peer(s)',
            chain_key[:8] or 'primary', len(chain), int(ckpt.epoch),
            len(found))

    def _attested_ceilings(self, chain, signed):
        """The per-peer score ceilings the persisted evidence supports (see
        ``_evidence_ceilings``), or None if the evidence does not verify.

        None and an empty mapping are deliberately distinct: None means "no
        usable evidence", so nothing may be adopted, whereas an empty mapping
        means the evidence verified but bounds no peer -- a genuine empty
        window -- which lets the chain be adopted while every score still
        restores clamped."""
        if not TransactionHistory.verify_chain_links(chain):
            self.logger.warning(
                'Reputation evidence chain failed hash-link verification; '
                'discarding it and restoring at tier %d',
                self.UNVERIFIED_RESTORE_TIER)
            return None
        ckpt = getattr(signed, 'checkpoint', None)
        if ckpt is None:
            self.logger.info(
                'Reputation evidence carries no checkpoint; restoring at '
                'tier %d', self.UNVERIFIED_RESTORE_TIER)
            return None
        window = self._checkpoint_window(chain, ckpt)
        if window is None:
            self.logger.warning(
                'Reputation evidence does not cover checkpoint window '
                '[%d, %d); restoring at tier %d', int(ckpt.first_index),
                int(ckpt.first_index) + int(ckpt.count),
                self.UNVERIFIED_RESTORE_TIER)
            return None
        recomputed = TransactionHistory._mth([tx.entry_hash() for tx in window])
        expected = ckpt.root if ckpt.root else b''
        if isinstance(expected, str):
            expected = expected.encode('ascii')
        if recomputed != expected:
            self.logger.warning(
                'Reputation evidence root mismatch (checkpoint commits to '
                '%s, entries hash to %s); restoring at tier %d',
                expected[:12].decode('ascii', 'replace'),
                recomputed[:12].decode('ascii', 'replace'),
                self.UNVERIFIED_RESTORE_TIER)
            return None
        # The quorum bar is sized against OUR OWN roster, exactly as on the
        # live path, so whoever wrote the file cannot also set the bar it has
        # to clear. A roster we have not yet loaded resolves no co-signers,
        # which fails closed: the warm start is capped, not forged.
        if not self._quorum_met(ckpt.designation, signed.sigs):
            self.logger.warning(
                'Reputation evidence checkpoint epoch=%s has %d verified '
                'co-signature(s), short of quorum; restoring at tier %d',
                str(ckpt.epoch),
                len(self._verified_cosigners(ckpt.designation, signed.sigs)),
                self.UNVERIFIED_RESTORE_TIER)
            return None
        return self._evidence_ceilings(window)

    def _evidence_ceilings(self, window) -> dict:
        """Per-peer upper bound on a restored score, derived from the attested
        window and NOTHING else: ``{peer-uuid-str: ceiling}``.

        Appearing in an attested window is not the same as having earned a
        number. Verifying only presence leaves the original hole open -- a
        score hand-raised in `reputation.cfg.json` would still be restored in
        full, because the peer really does transact. So the evidence has to
        bound the value, not merely vouch for the peer.

        The bound is the mean of the counterparty-side scores the window
        records for the peer, shrunk toward PREREP_NEUTRAL by a pseudo-count
        (the ``_prereputation_prior`` idiom). Shrinkage is what makes a SHORT
        attested history unable to justify a high restored score: two
        transactions at 0.9 are two data points, not a track record, and
        without the pseudo-count they would license the same standing as two
        hundred.

        Deliberately independent of ``self.reputations`` and of any running
        EMA. Deriving the bound from state the persisted file feeds would be
        circular -- the file would end up vouching for itself, which is the
        one thing this must not do.
        """
        self_uuid = str(self.identity.uuid)
        totals: dict = {}
        counts: dict = {}
        for tx in window:
            if len(tx) < 2:
                continue  # not bilateral: no counterparty agreed to it
            # A peer's score in a tx is the COUNTERPARTY's side of it, as in
            # _fold_tx_for_peer: p1's standing is what p2 scored it.
            for peer, score in ((tx.p1_id, tx.p2_score),
                                (tx.p2_id, tx.p1_score)):
                key = str(peer)
                if key == self_uuid or score is None:
                    continue
                totals[key] = totals.get(key, 0.0) + float(score)
                counts[key] = counts.get(key, 0) + 1
        ceilings = {}
        k = self.RESTORE_SHRINKAGE_K
        neutral = self.PREREP_NEUTRAL
        for key, n in counts.items():
            if n < self.RESTORE_EVIDENCE_MIN_TX:
                continue
            observed = totals[key] / n
            ceilings[key] = min(1.0, max(0.0,
                                         (n * observed + k * neutral) / (n + k)))
        return ceilings

    @staticmethod
    def _checkpoint_window(chain, ckpt):
        """The ``chain`` slice the checkpoint commits to, or None when the
        chain cannot produce it.

        A persisted chain may legitimately run PAST its checkpoint (commits
        land after the checkpoint finalizes and the file is rewritten on the
        co-signature upgrade), so the window is selected by absolute index
        rather than taken as the whole chain. It may not fall SHORT: a
        missing entry means the root cannot be reproduced, so demand exactly
        ``count`` contiguous entries."""
        first = int(ckpt.first_index)
        count = int(ckpt.count)
        if count < 0:
            return None
        window = [tx for tx in chain
                  if tx.index is not None and first <= tx.index < first + count]
        if len(window) != count:
            return None
        return window

    def _grade_restored_reputations(self, ceilings):
        """Clamp each restored score to what the evidence supports for that
        peer: its ``_evidence_ceilings`` entry, or -- for a peer the evidence
        does not cover at all -- the ``UNVERIFIED_RESTORE_TIER`` ceiling.

        Self is never clamped (our own score is not a peer judgement).
        Clamping is one-directional -- a score already at or below its ceiling
        is untouched -- so this can only withhold standing, never confer it.
        It composes with staleness decay: decay is the time-out-of-contact
        axis, this is the "nothing here shows you earned that" axis.

        There is no separate release step. The clamped value is where the peer
        resumes climbing, so fresh in-session transactions re-earn the
        elevated tier through the ordinary scoring path."""
        unattested = self._tier_ceiling(self.UNVERIFIED_RESTORE_TIER)
        self_uuid = str(self.identity.uuid)
        clamped = []
        for peer_uuid in list(self.reputations.current.keys()):
            key = str(peer_uuid)
            if key == self_uuid:
                continue
            ceiling = ceilings.get(key, unattested)
            score = self.reputations.current.get(peer_uuid)
            if score is None or score <= ceiling:
                continue
            self.reputations.current[peer_uuid] = ceiling
            self._restore_clamped[key] = score
            clamped.append((key, score, ceiling))
        if clamped:
            self.logger.info(
                'Warm start: clamped %d peer score(s) to what the evidence '
                'supports (%s)', len(clamped),
                ', '.join('%s %.3f->%.3f' % (k[:8], s, c)
                          for k, s, c in clamped[:8]))

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
            # Compare against the chain the proposal NAMES, not always our
            # primary one: a gateway holds several, and comparing the wrong
            # window would decline every honest child-group proposal (and, in
            # the degenerate case where two chains share a root, accept one
            # that says nothing about the chain it claims to cover).
            chain_key = self._chain_key(getattr(ckpt, 'group_uuid', ''))
            mine = self._chain_for_key(chain_key).window_root()
            if mine != proposed:
                self.logger.debug(
                    'checkpoint_propose: window_root mismatch on chain %s, '
                    'declining', chain_key[:8] or 'primary')
                return True
            try:
                sig = self._detached_sig(self.identity, ckpt.designation)
            except Exception:
                self.logger.error(
                    'handle_checkpoint_propose: cannot sign; '
                    'declining to co-sign')
                return True
            proposer, epoch, group = ckpt.key()
            # The ack carries the chain too: the proposer needs it to find the
            # right pending round, and it is inside the bytes we just signed.
            # Length-tolerant on the far side, so a 4-tuple from an older peer
            # still resolves to the primary chain.
            ack = (proposer, epoch, str(self.identity.uuid), sig, group)
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
            # Length-tolerant: a 5th element names the chain (see the ack built
            # in handle_checkpoint_propose); a 4-tuple is the primary chain.
            proposer, epoch, claimed, sig = payload[0], payload[1], payload[2], payload[3]
            group = str(payload[4]) if len(payload) > 4 and payload[4] else ''
            key = (str(proposer), int(epoch), group)
            ckpt = self._checkpoint_pending.get(key)
            if ckpt is None:
                return True  # not our round, or already finalized
            voter = self._attributed_voter(message, claimed, 'checkpoint_sign')
            if voter is None:
                return True
            if not self._verify_cosignature(ckpt.designation, voter, sig):
                self.logger.warning(
                    'handle_checkpoint_sign: co-signature from %s failed '
                    'verification; not counted', voter[:8])
                return True
            self._checkpoint_sigs.setdefault(key, {})[voter] = sig
            # Quorum is sized by the group whose chain this is: a child-group
            # checkpoint must clear that group's majority, not the conflated
            # roster a gateway sees across every group it belongs to.
            grp_uuid = group or (str(self.group.uuid)
                                 if self.group is not None else None)
            if len(self._checkpoint_sigs[key]) > self._checkpoint_quorum(grp_uuid):
                signed = SignedCheckpoint(
                    checkpoint=ckpt, sigs=dict(self._checkpoint_sigs[key]))
                # Upgrade our own stored copy from the lone self-signature to
                # the quorum map, so the evidence we persist is attested by the
                # group rather than only by us.
                self._store_checkpoint(ckpt, signed.sigs)
                try:
                    msg = Message(
                        self.name, ReputationProtocol.checkpoint_final,
                        to_json_string(signed),
                        self._group_by_uuid(grp_uuid) or self.group,
                        from_whom=self.identity)
                    queues[CfgIds.network].put(
                        msg, block=True, timeout=self.q_cadence)
                    self.logger.info(
                        'Checkpoint finalized & broadcast: chain=%s epoch=%d '
                        'signers=%d', group[:8] or 'primary', ckpt.epoch,
                        len(self._checkpoint_sigs[key]))
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
            # Verify the retained co-signatures against member identities we
            # hold. This root is the anchor _verify_slash_evidence measures
            # slash evidence against, precisely so the root is "not chosen by
            # the accuser" -- which only holds if a quorum is checked here. A
            # checkpoint_final without verifiable co-signatures is refused.
            sigs = getattr(signed, 'sigs', None)
            # Sized against the group whose chain this covers, for the same
            # reason the propose handler compares that chain's own root.
            group = self._chain_key(getattr(ckpt, 'group_uuid', ''))
            if not self._quorum_met(ckpt.designation, sigs, group or None):
                self.logger.warning(
                    'Rejecting checkpoint_final chain=%s epoch=%s from %s: %d '
                    'verified co-signature(s) do not meet quorum',
                    group[:8] or 'primary', str(ckpt.epoch),
                    str(ckpt.proposer_uuid)[:8],
                    len(self._verified_cosigners(ckpt.designation, sigs)))
                return True
            self._store_checkpoint(ckpt, sigs)
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
                    self.logger.error('Closest %d peers unable to agree on history', self.num_updates)
                    self._request_update(queues, len(self.peers.all))
            return True
        return False

    def _pure_reputation(self, peer):
        # Counterparty's-score weighted by counterparty's-reputation AND by the
        # originating capability's transaction_weight (doc/architecture/trust-tiers.md
        # §5). Default PREREP_NEUTRAL (0.2) on no-history OR no-valid-tx (returning a
        # lower value would route the peer back into CTFT mode on the next compute, the
        # very condition we supposedly graduated from). Counterparties absent from
        # self.reputations use the PREREP_NEUTRAL fallback rather than being silently
        # skipped (skipping made the result sensitive to whether the local reputations
        # dict had caught up to the history chain). `peer` may be a Peer object
        # (production sender path), a raw UUID, or a uuid string (rep_req wire path —
        # the canonical object form's `peer_uuid` field is a string, and Identity.uuid
        # is also a string in this codebase).
        peer_uuid = peer if isinstance(peer, (UUID, str)) else peer.uuid
        try:
            txs = list(self.history.by_peer(peer_uuid))
        except KeyError:
            return self.PREREP_NEUTRAL
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
                if counterparty_id in self.reputations else self.PREREP_NEUTRAL
            w = self.task_weights.get(str(tx.task_id), 1)
            total += counterparty_score * cp_rep * w
            total_weight += w
        if total_weight == 0:
            return self.PREREP_NEUTRAL
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
            self.logger.debug('No transaction history for peer %s', peer_uuid)
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
                if counterparty_id in self.reputations else self.PREREP_NEUTRAL
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

    @classmethod
    def _tier_ceiling(cls, tier: int) -> float:
        """The highest score that still maps to ``tier`` -- i.e. the next
        tier's floor, stepped down by one representable double.

        Derived from TIER_FLOORS rather than written as a literal so
        retuning the ladder cannot leave a stale ceiling behind that quietly
        grants the tier above. ``nextafter`` (not a hand-picked epsilon)
        because the clamp has to satisfy ``_trust_tier(ceiling) == tier``
        exactly: an epsilon too small rounds back onto the floor and grants
        the very tier the clamp exists to withhold. The top tier has no
        ceiling, so it returns 1.0."""
        for floor, t in cls.TIER_FLOORS:
            if t == tier + 1:
                return math.nextafter(floor, 0.0)
        return 1.0

    @classmethod
    def _is_excluded(cls, score) -> bool:
        """True if `score` is below the communication cut-off, i.e. the
        peer is excluded from the network (gateways stop forwarding
        to/for it, LAN/one-hop nodes ignore it). Recovery is
        explicit-only (REASON_REHABILITATE)."""
        return score is not None and score < cls.COMM_CUTOFF

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

    def _seed_exclusions_from_snapshot(self):
        """Re-establish the exclusion set at start-up from the persisted
        (warm-started) reputation snapshot: any peer whose score is below
        COMM_CUTOFF was excluded before shutdown and must stay excluded,
        because recovery is explicit-only (REASON_REHABILITATE) and an
        excluded peer -- being ignored -- can never transact its way back.
        Called after _seed_idle_from_snapshot so it reads post-offline-gap
        scores; decay never lifts a sub-asymptote score, so an excluded peer
        cannot idle its way above the cut-off. No queues exist this early, so
        the network process is not notified here -- the exclusion set is read
        by the first outbound/inbound gate and republished on the first live
        tier change."""
        self_uuid = str(self.identity.uuid)
        for u, score in self.reputations.current.items():
            if str(u) == self_uuid:
                continue
            if self._is_excluded(score):
                self._excluded.add(str(u))

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
            self._publish_reputation_change(queues, u, decayed)
            changed = True
        if changed:
            try:
                self._persist_reputations()
            except (OSError, IOError) as e:
                self.logger.warning(
                    'Could not persist reputations after decay: %s', e)

    def _persist_reputations(self):
        """Write the reputation snapshot to disk, filtered two-sided.

        Persisted cohorts: (1) self, always; (2) the TRUSTED cohort --
        peers with score strictly above REPUTATION_PERSIST_THRESHOLD (the
        authoritative warm-start snapshot used by IdentityProcess.
        choose_group() and the dod-mission seed generator at
        tools/seed_dod_cohort.py); and (3) the EXCLUDED cohort -- peers
        below COMM_CUTOFF. The excluded cohort must be carried across a
        restart so a peer that was cut off before shutdown comes back up
        still excluded; otherwise a restart would silently rehabilitate it
        (recovery is meant to be explicit-only, via REASON_REHABILITATE).
        The mid-band (cut-off .. persist-threshold) is not persisted -- an
        ordinary peer warm-starts from cold rather than carrying a stale
        middling score.
        """
        keep_uuids = {self.identity.uuid}
        for u, score in self.reputations.current.items():
            if score is None:
                continue
            if score > REPUTATION_PERSIST_THRESHOLD or self._is_excluded(score):
                keep_uuids.add(u)
        snapshot = self.reputations.filtered_for_persist(keep_uuids)
        snapshot.to_file(os.path.join(Configuration.get_cfg_dir(),
                                      CfgIds.reputation + Configuration.file_ext))

    def _publish_reputation(self, queues, peer_uuid, score, rated):
        """Emit one peer's reputation toward the app (doc/architecture/app-peer-carrier.md).

        Mirror of the C twin's `_publish_reputation` (`rep_proc.c`): local IPC to
        the main loop — `CfgIds.main` is Python's `AT_MAIN_QUEUE` — which owns the
        outward hop to `external_feedback`. `rated` travels beside the score
        because an unrated peer reads as PREREP_NEUTRAL, which is also a score a
        peer can genuinely earn; `PeerReputation` zeroes the score when unrated so
        a consumer ignoring the flag cannot read a plausible number.
        """
        try:
            queues[CfgIds.main].put(
                PeerReputation(str(peer_uuid), score, rated),
                block=True, timeout=self.q_cadence)
        except KeyError:
            # No main queue in this configuration (unit tests, embedded use).
            # Not an error: nothing is listening for an app feed.
            pass
        except Full:
            self.logger.warning('_publish_reputation: main queue full for %s', str(peer_uuid)[:8])

    def _publish_reputation_change(self, queues, peer_uuid, score):
        """A score this process just computed is by construction rated."""
        self._publish_reputation(queues, peer_uuid, score, True)

    def emit_all_reputations(self, queues):
        """Emit one message per known peer, rated or not; returns the count.

        Mirror of C's `reputation_emit_all`. A peer with no rating is reported AS
        unrated rather than skipped — silence would leave a consumer unable to
        tell "we hold no rating" from "the message was lost" — and this pull is
        the ONLY path on which `rated=False` can cross, since every change-driven
        emission is rated by construction.
        """
        emitted = 0
        for peer in list(self.peers.all) + [self.identity]:
            peer_uuid = getattr(peer, 'uuid', peer)
            key = UUID(str(peer_uuid)) if not isinstance(peer_uuid, UUID) \
                else peer_uuid
            rated = key in self.reputations
            score = self.reputations[key] if rated else 0.0
            self._publish_reputation(queues, peer_uuid, score, rated)
            emitted += 1
        return emitted

    def handle_app_roster_request(self, queues, message):
        """The app asked for the current peer view (C: handle_app_roster_request)."""
        if message.function != ReputationProtocol.app_roster_request:
            return False
        count = self.emit_all_reputations(queues)
        self.logger.debug('Emitted %d peer reputations for an app pull', count)
        return True

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
            key = str(peer_uuid)
            # Communication cut-off crossing. This is checked BEFORE the
            # tier early-return because the cut-off (0.1) lies WITHIN tier 0
            # (which spans [0, 0.5)): a 0.15 -> 0.05 crossing is a
            # tier-0 -> tier-0 no-op for the tier logic, yet it must
            # exclude the peer. Exclusion state is the authority; the
            # network process is notified only on an actual crossing.
            now_excluded = self._is_excluded(score)
            was_excluded = key in self._excluded
            if now_excluded and not was_excluded:
                self._excluded.add(key)
                self._publish_exclusion(queues, peer_uuid, True)
            elif was_excluded and not now_excluded:
                self._excluded.discard(key)
                self._publish_exclusion(queues, peer_uuid, False)
            new_tier = self._trust_tier(score)
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
            self.logger.debug('Published tier_update for %s: %d (score=%.3f)', key, new_tier, score)
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
            self.logger.warning('_publish_tier_change failed: %s', err)

    def _publish_exclusion(self, queues, peer_uuid, excluded):
        """Tell the network process to exclude (or readmit) a peer whose
        reputation has crossed the communication cut-off. Resolves the
        peer's address from the live roster and sends a local-IPC
        Network.exclude / Network.readmit control message; the network
        process then drops the peer's inbound frames and filters it out
        of outbound targets. No-op if the address is unknown (nothing to
        key the network-layer gate on)."""
        try:
            # Peer uuids are strings in this codebase, but callers may hand
            # us a UUID (pending_tiers) or a Peer/Identity object; resolve
            # tolerantly across all three, matching self.reputations keying.
            peer = None
            if isinstance(peer_uuid, (str, UUID)):
                peer = (self.peers.find_by_uuid(peer_uuid)
                        or self.peers.find_by_uuid(str(peer_uuid)))
            else:
                peer = peer_uuid  # already a Peer/Identity
            address = getattr(peer, 'address', None)
            if not address:
                self.logger.debug(
                    'Exclusion %s for %s: no address, network gate skipped',
                    'add' if excluded else 'remove', str(peer_uuid)[:8])
                return
            func = Network.exclude if excluded else Network.readmit
            msg = Message(CfgIds.network, func, address,
                          to_whom=None, from_whom=self.identity)
            queues[CfgIds.network].put(
                msg, block=True, timeout=self.q_cadence)
            self.logger.info('Reputation %s %s (%s) at the network layer',
                             'excluded' if excluded else 'readmitted',
                             str(peer_uuid)[:8], address)
        except Full:
            self.logger.error('_publish_exclusion: network queue full')
        except Exception as err:
            self.logger.warning('_publish_exclusion failed: %s', err)

    def _current_chain_index(self) -> int:
        """The absolute index the next committed transaction will take.

        Used as the "everything before here is already recorded" watermark when
        ZTA proves a peer. Read off the history's own counter, with a fallback
        derived from the resident chain so a history implementation without the
        private counter still anchors somewhere truthful rather than at 0 --
        anchoring at 0 would silently mean "unwind everything".
        """
        nxt = getattr(self.history, '_next_index', None)
        if isinstance(nxt, int):
            return nxt
        highest = -1
        for tx in self.history:
            idx = getattr(tx, 'index', None)
            if isinstance(idx, int) and idx > highest:
                highest = idx
        return highest + 1

    def _zta_unwind_ceiling(self, peer_uuid, anchor_index):
        """What the peer's standing may be, judged ONLY on evidence that
        predates its last proved verification (doc/architecture/zta-integration.md).

        This is the "how far back" answer: back to the last point ZTA actually
        proved something, and no further. Standing earned before that point was
        earned by a peer whose credential verified, so it is not in question;
        standing earned after it was earned while nobody could confirm the peer
        was who it claimed, and a later affirmative failure is what calls it in.

        Deliberately a recomputation from the pre-anchor window rather than a
        stored "score as of then" -- no such score is checkpointed (a
        ``Checkpoint`` commits to a history WINDOW, not to per-peer values), and
        inventing one would be the circularity ``_evidence_ceilings`` exists to
        avoid. Reusing that same routine also means the unwind inherits its
        shrinkage: a short pre-anchor history cannot justify a high score.

        Falls back to the unverified-restore tier when there is no usable
        pre-anchor evidence -- including the case where the chain has evicted
        it. Absent evidence bounds a peer low; it does not excuse it.
        """
        floor_tier = self._tier_ceiling(self.UNVERIFIED_RESTORE_TIER)
        if anchor_index is None:
            # Never proved at all: nothing this peer holds rests on a verified
            # credential, so none of it survives the failure.
            return floor_tier
        window = [tx for tx in self.history
                  if isinstance(getattr(tx, 'index', None), int)
                  and tx.index < anchor_index]
        if not window:
            return floor_tier
        return self._evidence_ceilings(window).get(str(peer_uuid), floor_tier)

    def _apply_zta_standings(self, queues):
        """Act on ZTA findings that have landed since the last sweep.

        Idempotent by design: it runs every process iteration (like
        ``_restore_child_evidence``) and acts only on a standing it has not
        already acted on for that peer. A repeated identical verdict -- which
        periodic re-verification produces by the hour -- must not re-unwind a
        peer that was already unwound.
        """
        standing = getattr(self.protocol, 'zta_standing', None)
        if not standing:
            return
        for key, found in list(standing.items()):
            mark = (found.status, found.ceiling, found.verified_at, found.reason)
            if self._zta_acted.get(key) == mark:
                continue
            self._zta_acted[key] = mark
            if found.status == STANDING_PROVED:
                # Advance the anchor: everything committed up to now was
                # observed while this peer's credential verified.
                self._zta_proved_index[key] = self._current_chain_index()
                self.logger.info(
                    'ZTA: %s proved; unwind anchor set at chain index %d',
                    key[:8], self._zta_proved_index[key])
            elif found.status == STANDING_FAILED:
                self._unwind_zta_failure(queues, key, found)

    def _unwind_zta_failure(self, queues, key, found):
        """A peer that operated unproved has now affirmatively FAILED: unwind
        its standing to what pre-anchor evidence supports, and let the tier
        machinery demote it (doc/architecture/zta-integration.md).

        No scalar penalty is sent. A ZTA verdict is an authority finding, not
        an interaction outcome, and AT's [0, 1] scale has no representation for
        one -- which is why the previous attempt, a ``score = -0.8``
        TRANSACTION_SCORE, was rejected at the boundary and did nothing at all.
        Bounding the value and republishing the tier is the action; demotion,
        and exclusion below the cut-off, follow from the score the tier
        machinery already reacts to.
        """
        anchor = self._zta_proved_index.get(key)
        peer_uuid = None
        for candidate in self.reputations.current:
            if str(candidate) == key:
                peer_uuid = candidate
                break
        if peer_uuid is None:
            # Nothing scored for this peer yet; record the ceiling so the first
            # score it does earn is bounded, and leave it at that.
            self.logger.info('ZTA: %s failed (%s); no score to unwind',
                             key[:8], found.reason)
            return
        current = self.reputations.current.get(peer_uuid)
        unwound = self._zta_unwind_ceiling(peer_uuid, anchor)
        if current is not None and current <= unwound:
            self.logger.info(
                'ZTA: %s failed (%s); score %.3f already at or below what '
                'pre-verification evidence supports (%.3f)',
                key[:8], found.reason, current, unwound)
            return
        self.reputations.update(peer_uuid, unwound)
        # Force CTFT so a peer whose credential is later repaired re-earns
        # trust from the punished regime instead of snapping back into
        # cooperation -- the same reasoning as the slash override.
        self._coop_mode[peer_uuid] = False
        self.logger.warning(
            'ZTA: %s FAILED (%s); unwound %.3f -> %.3f (anchor %s)',
            key[:8], found.reason,
            -1.0 if current is None else current, unwound,
            'none — never proved' if anchor is None else 'chain index %d' % anchor)
        _probes.counter('rep.compute', 'zta_unwound')
        try:
            self._persist_reputations()
        except (OSError, IOError) as e:
            self.logger.warning('Could not persist reputations: %s', e)
        self._publish_tier_change(queues, peer_uuid, unwound)
        self._publish_reputation_change(queues, peer_uuid, unwound)

    def _zta_ceiling(self, peer_uuid):
        """Highest reputation this peer may hold given what ZTA actually proved
        (doc/architecture/zta-integration.md), or None for "no bound".

        None covers three different situations that all mean the same thing
        here: ZTA proved the peer, ZTA is switched off, or IdentityProcess has
        not spoken about this peer at all. A deployment that has not turned ZTA
        on is not bounded by it, which is the no-change-in-behavior setting.

        Read off `protocol.zta_standing`, which is this node's OWN finding
        delivered over IPC -- never anything the peer asserted about itself, so
        a peer cannot raise its own ceiling.
        """
        standing = getattr(self.protocol, 'zta_standing', None)
        if not standing:
            return None
        found = standing.get(str(peer_uuid))
        return None if found is None else found.ceiling

    def _apply_zta_ceiling(self, peer_uuid, score):
        """Bound `score` by the peer's ZTA ceiling, if it has one.

        The bound is applied where the score is WRITTEN rather than where it is
        read, so every consumer -- tier computation, persistence, the app-facing
        carrier, a peer answering a rep_req -- sees one consistent number. A
        ceiling enforced only at read time would leave the stored score above
        it and leak the unbounded value the moment some other path reported it.
        """
        ceiling = self._zta_ceiling(peer_uuid)
        if ceiling is None or score is None or score <= ceiling:
            return score
        self.logger.info(
            'ZTA: %s capped %.3f -> %.3f (credential not proved)',
            str(peer_uuid)[:8], score, ceiling)
        _probes.counter('rep.compute', 'zta_capped')
        return ceiling

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
                    self.logger.warning('Could not persist reputations: %s', e)
                self.pending_tiers.append((peer_uuid, rep_score))
                self.requested_reps.append(
                    (Reputation(peer_uuid, rep_score), req_proc, requestor))
                _probes.counter('rep.compute', 'slashed')
                return
            previous = self.PREREP_NEUTRAL
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
            # doc/architecture/zta-integration.md: an unproved credential bounds how far this peer may rise,
            # whichever regime produced the score above.
            rep_score = self._apply_zta_ceiling(peer_uuid, rep_score)
            self.reputations.update(peer_uuid, rep_score)
            try:
                self._persist_reputations()
            except (OSError, IOError) as e:
                self.logger.warning('Could not persist reputations: %s', e)
            # Queue a tier-update for IdentityProcess; drained by the
            # process loop alongside forward_reputation. The spawned
            # _compute_reputation thread doesn't have access to queues
            # so it can't put directly.
            self.pending_tiers.append((peer_uuid, rep_score))
            self.requested_reps.append((Reputation(peer_uuid, rep_score), req_proc, requestor))
            _probes.counter('rep.compute', 'queued')
        except Exception as e:
            _probes.counter('rep.compute', 'exception', type(e).__name__)
            self.logger.warning('_compute_reputation failed: %s', e)

    def _consensus_baseline(self, peer_uuid):
        """Cold-start baseline for a peer with no committed bilateral
        history yet.

        Priority: (1) the last real consensus value computed for this
        peer (stickiness — so an idle peer whose txs have evicted from
        the bounded chain keeps its earned score instead of resetting to
        neutral), (2) the locally-known reputation (a warm-start seeded
        prior from reputation.cfg.json, or a prior local compute), (3) the
        neutral PREREP_NEUTRAL (0.2). Used only when the consensus chain
        has nothing for the peer — once real bilateral txs exist, the EMA
        in _consensus_reputation dominates and refreshes the sticky value.
        Tolerates the str/UUID key ambiguity in self.reputations.current."""
        last = self._consensus_last.get(str(peer_uuid))
        if last is not None:
            return last
        try:
            cur = self.reputations.current
        except AttributeError:
            return self.PREREP_NEUTRAL
        for k in (peer_uuid, str(peer_uuid)):
            if k in cur and cur[k] is not None:
                return float(cur[k])
        try:
            u = UUID(str(peer_uuid))
            if u in cur and cur[u] is not None:
                return float(cur[u])
        except (ValueError, TypeError, AttributeError):
            pass
        return self.PREREP_NEUTRAL

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
        # Determination instrumentation (AT_REP_TRACE): record every fold so
        # we can tell a peer whose consensus EMA is actually MOVING (real
        # bilateral txs folding in) from one stuck at baseline (never folds).
        # Off unless the env flag is set; logging only, no behaviour change.
        if os.environ.get('AT_REP_TRACE'):
            self.logger.info(
                'REPTRACE fold peer=%s cp_score=%.3f -> ema=%.4f idx=%d w=%d',
                key[:8], float(cp_score), ema, tx.index, max(1, int(w)))

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
        base = self._consensus_baseline(peer_uuid)
        # Determination instrumentation (AT_REP_TRACE): a peer that keeps
        # landing here has NO folded bilateral txs — its dashboard score is
        # pure baseline, never its earned performance. Distinguishes the
        # "validator verdict never reaches the subject" hypothesis from a
        # mean-dilution effect. Logging only.
        if os.environ.get('AT_REP_TRACE'):
            self.logger.info(
                'REPTRACE baseline peer=%s (0 folded bilateral txs) -> %.4f',
                key[:8], base)
        return base

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
        (the locally-known/seeded prior) instead of a flat neutral, so a
        warm-started cohort reads its primed rep on the dashboard
        rather than a uniform neutral (0.2). This is the only point where the
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

    # --- Deep resolution: one peer, on demand
    # (doc/architecture/gateway-reputation-tree.md) -----------
    #
    # The subtree roster below covers this node's DIRECT children, which is
    # everything it can score: a peer two levels down transacts in a chain
    # this node is not a member of. Enumerating the whole tree to reach it
    # would cost the size of the tree on every query to satisfy a need that
    # is one peer, so instead the query is relayed to whoever holds the
    # chain and the answer comes back carrying its own proof.

    def _chain_holding(self, peer_uuid):
        """The key of the chain whose window holds committed bilateral
        entries for ``peer_uuid``, or None if no chain of ours does.

        Primary chain first, so a peer we transact with directly is always
        answered from the chain that actually knows it rather than from a
        child chain that merely mentions it."""
        target = str(peer_uuid)
        for key in self._chain_keys():
            chain = self._chain_for_key(key)
            for tx in list(chain):
                if tx.index is None or tx.p1_id is None or tx.p2_id is None:
                    continue
                if target in (str(tx.p1_id), str(tx.p2_id)):
                    return key
        return None

    def _resolve_signers(self, sigs):
        """The co-signer identities an answer carries, in the DRY canonical
        public form. Only signers we actually hold an identity for: a uuid we
        cannot produce a key for would travel as an unverifiable name, which
        is worse than absent -- the receiver would count a signature it has
        no way to check, or spend time deciding not to."""
        out = []
        for voter in (sigs or {}):
            ident = self._cosigner_identity(voter)
            if ident is None:
                continue
            try:
                canon = public_identity_to_canonical(ident)
            except Exception:
                continue
            if canon:
                out.append(canon)
        return out

    def _resolve_answer(self, query_id, peer_uuid, chain_key):
        """Build the answer for a peer we hold a chain for, or None when that
        chain has no finalized checkpoint.

        No checkpoint means no answer at all, deliberately. The window would
        still be true, but nothing would attest it, and a receiver two hops
        away has no way to tell an unattested truth from a fabrication -- so
        sending one would only teach requestors to accept unverifiable
        answers."""
        ckpt = self._checkpoints.get(chain_key)
        if ckpt is None:
            self.logger.debug(
                'resolve %s: chain %s has no finalized checkpoint; no answer',
                str(peer_uuid)[:8], chain_key[:8] or 'primary')
            return None
        sigs = self._checkpoint_sigs_final.get(chain_key) or {}
        chain = self._chain_for_key(chain_key)
        window = [tx for tx in list(chain) if tx.index is not None]
        score = self._consensus_reputation(
            peer_uuid, chain=chain if chain_key else None)
        return resolved_to_dict(
            query_id, peer_uuid, window,
            SignedCheckpoint(checkpoint=ckpt, sigs=sigs),
            signers=self._resolve_signers(sigs), score=score)

    def _prune_resolve_state(self):
        """Expire relayed and outstanding queries. Called from the process
        loop: an answer that never arrives is the normal case for a subtree
        that has gone dark, and nothing else would ever clear these."""
        stamp = now().timestamp()
        for qid in [q for q, v in self._resolve_pending.items() if v[1] <= stamp]:
            self._resolve_pending.pop(qid, None)
        for qid in [q for q, v in self._resolve_outstanding.items() if v[1] <= stamp]:
            peer, _ = self._resolve_outstanding.pop(qid)
            self.logger.info('Deep resolve of %s timed out', str(peer)[:8])

    def _mark_resolve_seen(self, query_id) -> bool:
        """Record a query-id, returning False if it was already seen (the
        caller must then drop it). FIFO-bounded like the other dedup rings."""
        if query_id in self._resolve_seen:
            return False
        self._resolve_seen[query_id] = None
        while len(self._resolve_seen) > self.RESOLVE_SEEN_MAX:
            self._resolve_seen.popitem(last=False)
        return True

    def resolve_reputation(self, queues, peer_uuid, ttl=RESOLVE_TTL_DEFAULT,
                           query_id=None):
        """Ask the tree for one peer's reputation. Returns the query id.

        Fire-and-forget by design: the answer arrives later on
        ``rep_resolved`` and lands in ``self.resolved_reps``. Nothing here
        blocks, so a caller that needs the value polls that dict or waits for
        the timeout to log.

        ``query_id`` is caller-chosen so a test or conformance step can
        correlate the answer it feeds back; production leaves it None. Mirrors
        C ``reputation_deep_resolve``, which takes the same argument for the
        same reason."""
        qid = query_id or '%s-%s' % (str(self.identity.uuid)[:8],
                                     str(now().timestamp()).replace('.', ''))
        query = resolve_query_to_dict(qid, peer_uuid, ttl=ttl,
                                      requesting_process=self.name)
        self._resolve_outstanding[qid] = (
            str(peer_uuid), now().timestamp() + self.RESOLVE_PENDING_TTL)
        self._mark_resolve_seen(qid)
        self._forward_resolve(queues, query)
        return qid

    def _forward_resolve(self, queues, query):
        """Send a query one level DOWN: to each child group we gateway.

        Addressed to the child GROUP rather than to a chosen child gateway.
        The reputation process holds each child group (over the ChildGroupSet
        IPC) but not the rank data the identity process picks a gateway with,
        and asking the group is the same answer without a second, drifting
        copy of that derivation living here. Everyone in the group sees that
        somebody asked about a peer -- not who asked, since the query carries
        no originator -- and whoever holds the chain answers.

        Returns the number of groups the query went to; 0 means this branch
        is a dead end and no answer will ever come back through us."""
        if int(query.get('ttl', 0)) <= 0:
            return 0
        onward = dict(query)
        onward['ttl'] = int(query['ttl']) - 1
        sent = 0
        for grp_uuid, group in self.child_groups.items():
            try:
                msg = Message(self.name, ReputationProtocol.rep_resolve,
                              to_json_string(onward), group,
                              from_whom=self.identity)
                queues[CfgIds.network].put(msg, block=True, timeout=self.q_cadence)
                sent += 1
            except Full:
                self.logger.error('_forward_resolve: Network queue full')
            except Exception as err:
                self.logger.warning('Could not forward resolve to %s: %s',
                                    str(grp_uuid)[:8], err)
        return sent

    def handle_resolve(self, queues, message):
        """Answer a deep query, or relay it one level down.

        Never blocks awaiting a child: the relay records who to answer and
        returns immediately, and the answer is an independent message that
        arrives (or does not) later. That is the same non-blocking model the
        identity roster walk was designed around -- a handler that waited on
        a child would stall this process's whole loop for the depth of the
        subtree."""
        if message.function != ReputationProtocol.rep_resolve:
            return False
        if not message.verified:
            self.logger.warning('Rejecting unverified rep_resolve from %s',
                                message.from_whom)
            return True
        try:
            payload = message.obj
            if isinstance(payload, str):
                payload = from_json_string(payload)
            query = resolve_query_from_dict(payload)
        except (ValueError, TypeError) as err:
            self.logger.warning('Malformed rep_resolve: %s', err)
            return True
        qid = query['query_id']
        if not self._mark_resolve_seen(qid):
            return True  # already handled; a loop or a duplicate leg
        sender = getattr(message.from_whom, 'uuid', None)
        if sender is None:
            self.logger.warning('rep_resolve with no sender identity; dropped')
            return True
        chain_key = self._chain_holding(query['peer_uuid'])
        if chain_key is not None:
            answer = self._resolve_answer(qid, query['peer_uuid'], chain_key)
            if answer is not None:
                self._send_resolved(queues, message.from_whom, answer,
                                    query.get('requesting_process'))
                return True
            # Held the chain but cannot attest it: fall through and let a
            # deeper node that can answer instead.
        if self._forward_resolve(queues, query):
            self._resolve_pending[qid] = (
                str(sender), now().timestamp() + self.RESOLVE_PENDING_TTL,
                query.get('requesting_process') or '')
        return True

    def _send_resolved(self, queues, to_whom, answer, requesting_process=None):
        try:
            msg = Message(requesting_process or self.name,
                          ReputationProtocol.rep_resolved,
                          to_json_string(answer), to_whom,
                          from_whom=self.identity)
            queues[CfgIds.network].put(msg, block=True, timeout=self.q_cadence)
        except Full:
            self.logger.error('_send_resolved: Network queue full')
        except Exception as err:
            self.logger.warning('Could not send resolved answer: %s', err)

    def handle_resolved(self, queues, message):
        """Take an answer: relay it back one hop, or accept it if it is ours.

        An answer for a query-id we never relayed and never sent is dropped
        unread. Answers are unsolicited-by-construction on a relay path, so
        the pending table is the only thing distinguishing an answer we are
        carrying from one somebody injected."""
        if message.function != ReputationProtocol.rep_resolved:
            return False
        if not message.verified:
            self.logger.warning('Rejecting unverified rep_resolved from %s',
                                message.from_whom)
            return True
        try:
            payload = message.obj
            if isinstance(payload, str):
                payload = from_json_string(payload)
            qid, peer, score, chain, signed, signers = \
                resolved_from_dict(payload)
        except (ValueError, TypeError, KeyError) as err:
            self.logger.warning('Malformed rep_resolved: %s', err)
            return True
        relay = self._resolve_pending.pop(qid, None)
        if relay is not None:
            answer_to = self._identity_for_uuid(relay[0])
            if answer_to is None:
                self.logger.warning(
                    'rep_resolved %s: cannot relay, %s no longer known',
                    qid[:8], relay[0][:8])
                return True
            # Relayed VERBATIM, not re-serialized from parsed parts: the
            # signatures are over bytes, and a re-encode that reordered a key
            # or renormalized a float would invalidate evidence this node has
            # no business invalidating. Relays carry, they do not curate.
            self._send_resolved(queues, answer_to, payload, relay[2] or None)
            return True
        outstanding = self._resolve_outstanding.pop(qid, None)
        if outstanding is None:
            self.logger.debug('Unsolicited rep_resolved %s; dropped', qid[:8])
            return True
        self._accept_resolved(peer, score, chain, signed, signers)
        return True

    def _identity_for_uuid(self, uuid_str):
        """A peer identity by uuid string, for addressing a relay hop."""
        for peer in self.peers.all:
            if str(peer.uuid) == str(uuid_str):
                return peer
        return None

    def _accept_resolved(self, peer, claimed_score, chain, signed, signers):
        """Verify an answer to a query we made and record the result.

        The recorded score is the one WE compute from the attested window,
        not the number the holder sent. The holder's value travels only as a
        cross-check, because the weighting that produced it comes from a
        node-local capability cache that is not part of any hashed entry and
        so cannot be re-derived here (see consensus_score_from_window)."""
        ok, reason = verify_resolved(
            chain, signed, signers, self._resolve_verify_signature,
            trust_signer=self._resolve_trust_signer,
            min_signers=self.RESOLVE_MIN_SIGNERS)
        if not ok:
            self.logger.warning('Deep resolve of %s REFUSED: %s',
                                str(peer)[:8], reason)
            self.resolved_reps[str(peer)] = (None, False, reason)
            return
        score = consensus_score_from_window(
            peer, chain, self.CONSENSUS_EMA_HALF_LIFE)
        if score is None:
            self.resolved_reps[str(peer)] = (
                None, True, 'attested window holds no bilateral entry for peer')
            return
        note = reason
        if claimed_score is not None and abs(float(claimed_score) - score) > 1e-9:
            # Not a failure: the holder weights by capability tier and we
            # cannot. Worth surfacing, because a large gap is also what a
            # holder shading its own subtree would look like.
            note = ('%s; holder reported %.4f vs %.4f unweighted here'
                    % (reason, float(claimed_score), score))
        self.resolved_reps[str(peer)] = (score, True, note)
        self.logger.info('Deep resolve of %s = %.4f (%s)',
                         str(peer)[:8], score, note)

    def _resolve_verify_signature(self, designation, voter, sig, signer):
        """Verify one co-signature, preferring an identity we already hold
        over the one the answer supplied. Our own copy cannot have been
        chosen by the sender; the carried one is the fallback that makes a
        cross-boundary answer checkable at all."""
        ident = self._cosigner_identity(voter)
        if ident is None and isinstance(signer, dict):
            try:
                ident = public_identity_from_canonical(signer)
            except Exception:
                ident = None
        if ident is None or sig is None:
            return False
        try:
            if isinstance(sig, str):
                sig = sig.encode('ascii')
            ident.signature.public.verify(designation, HexEncoder.decode(sig))
        except (BadSignatureError, ValueError, TypeError, AttributeError):
            return False
        return True

    def _resolve_trust_signer(self, voter, signer):
        """Whether a co-signer may count toward an answer's evidence.

        A peer we already hold counts: it cleared admission. Otherwise the
        carried identity must present a credential that chains to one of OUR
        configured trust anchors -- the doc/architecture/zta-integration.md rule, applied to evidence
        instead of to federation. Without this gate an answer could ship its
        own freshly-minted signers and satisfy every signature check in
        ``verify_resolved`` with keys it generated a moment earlier."""
        if self._cosigner_identity(voter) is not None:
            return True
        if not isinstance(signer, dict):
            return False
        cred = signer.get('zta_credential')
        if not cred:
            return False
        try:
            der = base64.b64decode(cred)
        except Exception:
            return False
        for _name, verifier, _is_op in self._resolve_anchor_verifiers():
            try:
                if verifier.verify(der):
                    return True
            except Exception:
                continue
        return False

    def _resolve_anchor_verifiers(self):
        """Anchor verifiers for evidence signers, built once per process from
        the same ZTA policy the identity process admits peers with."""
        if self._zta_anchor_cache is None:
            if self._zta_policy_cache is None:
                cfg = (self.configs.get(ZtaPolicy.CONFIG_KEY)
                       if hasattr(self.configs, 'get') else None)
                if isinstance(cfg, ZtaPolicy):
                    self._zta_policy_cache = cfg
                else:
                    try:
                        self._zta_policy_cache = ZtaPolicy.load()
                    except Exception:
                        self._zta_policy_cache = ZtaPolicy.defaults()
            try:
                self._zta_anchor_cache = \
                    self._zta_policy_cache.create_anchor_verifiers()
            except Exception:
                self._zta_anchor_cache = []
        return self._zta_anchor_cache

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
                '_compute_consensus_reputation failed: %s', e)

    def _compute_consensus_reputation_batch(self, peer_uuids, req_proc, requestor):
        """Answer one batched consensus request with a single deduplicated roster.

        Equivalent to running _compute_consensus_reputation once per named
        subject and concatenating, minus the duplication: a gateway's
        _subtree_roster carries its child-group members alongside the requested
        subject, and those entries do not depend on which subject was asked, so
        naming N subjects would otherwise repeat them N times.

        Our own uuid is skipped. The caller is sweeping observer-by-subject and
        has no use for a self-pair, and skipping it here is what lets one request
        body (hence one signature) serve every observer in a round.
        """
        _probes.counter('rep.consensus_batch', 'enter')
        try:
            roster = []
            seen = set()
            my_uuid = str(self.identity.uuid)
            for peer_uuid in peer_uuids:
                if str(peer_uuid) == my_uuid:
                    continue
                for rep in self._subtree_roster(peer_uuid):
                    key = str(rep.peer_id)
                    if key in seen or key == my_uuid:
                        continue
                    seen.add(key)
                    roster.append(rep)
            if not roster:
                _probes.counter('rep.consensus_batch', 'empty')
                return
            self.requested_reps.append((roster, req_proc, requestor))
            _probes.counter('rep.consensus_batch', 'queued', str(len(roster)))
        except Exception as e:
            _probes.counter('rep.consensus_batch', 'exception', type(e).__name__)
            self.logger.warning(
                '_compute_consensus_reputation_batch failed: %s', e)

    def handle_consensus_reputation_batch_request(self, _, message):
        if message.function != ReputationProtocol.consensus_rep_batch_req:
            return False
        if isinstance(message.obj, str):
            parsed = from_json_string(message.obj)
        else:
            parsed = message.obj
        if isinstance(parsed, dict):
            uuids = parsed.get('peer_uuids')
            req_proc = parsed.get('requesting_process')
        elif isinstance(parsed, (list, tuple)) and len(parsed) >= 2:
            uuids, req_proc = parsed[0], parsed[1]
        else:
            self.logger.error(
                'handle_consensus_reputation_batch_request: unsupported '
                'payload shape %r', type(parsed).__name__)
            return True
        if not isinstance(uuids, (list, tuple)):
            self.logger.error(
                'handle_consensus_reputation_batch_request: peer_uuids must be '
                'a list, got %r', type(uuids).__name__)
            return True
        if len(uuids) > MAX_REP_BATCH_SUBJECTS:
            # Each named subject costs a chain walk, so an unbounded list turns
            # one cheap message into arbitrary work for the responder. Truncated
            # rather than refused: a legitimate oversized cohort still gets a
            # partial answer, and the count is logged so the cause is visible
            # instead of appearing as a silently incomplete graph.
            self.logger.warning(
                'consensus reputation batch from %s named %d subjects; '
                'answering the first %d only (MAX_REP_BATCH_SUBJECTS bounds the '
                'work one message may ask for)',
                getattr(message.from_whom, 'nickname', '?'), len(uuids),
                MAX_REP_BATCH_SUBJECTS)
            _probes.counter('rep.consensus_batch', 'truncated')
            uuids = list(uuids)[:MAX_REP_BATCH_SUBJECTS]
        requestor = message.from_whom
        self._spawn(self._compute_consensus_reputation_batch,
                    args=(uuids, req_proc, requestor))
        return True

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
                'payload shape %r', type(parsed).__name__)
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
                    'handle_reputation_request: unsupported payload shape %r', type(parsed).__name__)
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
            self.logger.debug('Forward reps to %s at %s', req_proc, requestor)
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
                self.logger.error('forward_reputation: %s queue full', req_proc)

    def _dump_reputation_trace(self, present):
        """Debug instrument: emit THIS node's own reputation view of every
        peer it knows, as a single parseable JSON log line, so a host-side
        harvester (examples/multi_agency/log_harvest.py) can reconstruct the
        full observer->subject bilateral matrix by union-ing every node's
        self-report — WITHOUT relaying scores peer-to-peer over the mesh.

        Opt-in and throttled via ``AT_REP_DUMP_SEC`` (float seconds; unset or
        <= 0 disables). Emits at INFO so it reaches container stdout/stderr
        (``docker logs`` / ``kubectl logs``). Python reputation backend only —
        a native-C run won't emit these (same limitation as AT_REP_TRACE).

        Line shape (one complete record per line)::

            AT_REPDUMP {"t":<sec>,"self":"<uuid>","view":[
                {"s":"<subj_uuid>","nick":"<subj_nick>","con":<own-view score>,
                 "rep":<aggregate rep or null>,"n":<n_tx>,"coop":<n>,"def":<n>,
                 "tier":<int>,"exc":<bool>}, ... ]}

        ``con`` is this node's OWN computed consensus of the subject (the
        Trust-Dynamics value); ``n``/``coop``/``def`` are the raw CTFT inputs
        (committed bilateral txs involving the subject, split at the 0.5
        cooperate threshold) that produced it.
        """
        interval = _env_float('AT_REP_DUMP_SEC', 0.0)
        if interval <= 0:
            return
        if self._last_rep_dump and present - self._last_rep_dump < interval:
            return
        self._last_rep_dump = present
        try:
            me = str(self.identity.uuid)
            # Subjects = the known cohort plus anyone we hold a reputation or
            # tx history for (a peer that has since left the group still has
            # an earned score worth revealing).
            subjects: dict[str, UUID] = {}
            try:
                for p in self.peers.all:
                    subjects[str(p.uuid)] = p.uuid
            except Exception:
                pass
            for uid in list(self.reputations.current.keys()):
                subjects.setdefault(str(uid), uid)
            view = []
            for key, subj in subjects.items():
                if key == me:
                    continue
                try:
                    con = float(self._running_consensus(subj))
                except Exception:
                    con = None
                rep = float(self.reputations[subj]) \
                    if subj in self.reputations else None
                n = coop = defect = 0
                try:
                    for tx in self.history.by_peer(subj):
                        if tx.p1_id == subj:
                            s = tx.p1_score
                        elif tx.p2_id == subj:
                            s = tx.p2_score
                        else:
                            continue
                        if s is None:
                            continue
                        n += 1
                        if s >= 0.5:
                            coop += 1
                        else:
                            defect += 1
                except Exception:
                    # by_peer raises KeyError for a peer with no committed
                    # bilateral txs yet — leave the tallies at zero.
                    pass
                nick = None
                try:
                    peer = self.peers.find_by_uuid(subj)
                    nick = getattr(peer, 'nickname', None) if peer else None
                except Exception:
                    nick = None
                view.append({
                    's': key,
                    'nick': nick,
                    'con': None if con is None else round(con, 4),
                    'rep': None if rep is None else round(rep, 4),
                    'n': n, 'coop': coop, 'def': defect,
                    'tier': int(self.peer_tiers.get(key, 0)),
                    'exc': key in self._excluded,
                })
            rec = {'t': round(present, 3), 'self': me, 'view': view}
            self.logger.info('AT_REPDUMP %s', to_json_string(rec))
        except Exception as err:
            self.logger.error('reputation dump failed: %s', err)

    def process(self, queues, signal):
        # Drain budget per iter. Each handle_reputation_request spawns
        # a short-lived thread, so processing many per iter is cheap
        # and lets us stay ahead of inbound rep_req volume. The hard
        # cap prevents one process from monopolizing the GIL when the
        # queue is deeply backlogged.
        DRAIN_BUDGET = 64
        while self.keep_running(signal):
            try:
                # Push boot-seeded exclusions (warm-started peers below the
                # cut-off) to the network process now that queues exist, so
                # a peer excluded before shutdown is re-gated at the network
                # layer on restart -- recovery is explicit-only.
                if not self._exclusions_synced:
                    for key in list(self._excluded):
                        self._publish_exclusion(queues, key, True)
                    self._exclusions_synced = True
                # A gateway's child groups arrive over IPC after __init__, so
                # their persisted evidence is restored here rather than at boot
                # (idempotent per group; see _restore_child_evidence).
                if self.child_groups:
                    self._restore_child_evidence(queues)
                # ZTA findings arrive over IPC from IdentityProcess; act on any
                # that are new (doc/architecture/zta-integration.md). Idempotent, so it is safe every pass.
                self._apply_zta_standings(queues)
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
                                    self.logger.error('Unhandled message %s', message.function)
                                else:
                                    _probes.counter('proc.reputation', 'unhandled', 'type:' + message.__class__.__name__)
                                    self.logger.error('Unhandled message of type %s', message.__class__.__name__)  # noqa
                _probes.counter('proc.reputation', 'iter_drained', str(drained))
                self.forward_reputation(queues)
                # Drain tier updates queued by _compute_reputation.
                while self.pending_tiers:
                    peer_uuid, rep_score = self.pending_tiers.pop(0)
                    self._publish_tier_change(queues, peer_uuid, rep_score)
                    # Beside the tier change, exactly as the C twin does
                    # (rep_proc.c: _publish_tier_change then
                    # _publish_reputation_change): the tier is coarse, and an
                    # app watching a score needs every change, not only the four
                    # that step over a floor.
                    self._publish_reputation_change(queues, peer_uuid, rep_score)

                present = now().timestamp()
                # Expire deep-resolution state. A relayed query whose subtree
                # never answers is the ordinary case, not an error, and this
                # is the only thing that clears it.
                self._prune_resolve_state()
                # Staleness sweep: relax idle peers' operational
                # reputation toward almost-neutral (warm-start memory
                # fades). Throttled internally to SWEEP_INTERVAL.
                self._decay_reputations(queues, present)
                # Periodically commit to our own window so the persisted
                # evidence carries a quorum-signed root (verifiable warm
                # start). Throttled internally to CHECKPOINT_INTERVAL.
                self._maybe_checkpoint(queues, present)
                # Debug instrument: emit this node's own reputation view for
                # a host-side log harvester (opt-in, throttled internally).
                self._dump_reputation_trace(present)
                for req in list(self.requests):
                    if present - req[0] > self.expiration:
                        self.requests.remove(req)
                for prop in dict(self.proposals):
                    if present - prop[0] > self.expiration:
                        del self.proposals[prop]
                for rnd in list(self.round_group):
                    if present - rnd[0] > self.expiration:
                        del self.round_group[rnd]
                # Guarantee a CPU-yield floor. queue.get's q_cadence timeout
                # only sleeps when the queue is idle for a full window; under
                # continuous traffic there is no idle window and this loop
                # would spin at 100%. sleep_until(proc_idle_floor) yields the
                # rest of a ~10ms window when the iteration wasn't saturated,
                # without the old sleep_until(cadence)=0.5s throughput cap.
                # (AT_PROC_IDLE_FLOOR_SEC=0 restores the un-throttled loop.)
                self.sleep_until(proc_idle_floor)
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
            self.logger.warning('Final reputation flush failed: %s', err)
