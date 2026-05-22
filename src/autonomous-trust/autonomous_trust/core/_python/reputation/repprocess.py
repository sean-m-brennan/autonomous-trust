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
from .reputation import TransactionHistory, Reputation, Reputations, TransactionScore
from ..system import CfgIds, now, encoding
from .. import _probes


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

    # EMA half-life (in committed bilateral txs) for the dashboard
    # consensus-reputation channel.  Smaller → faster crash on a peer
    # that starts producing bad scores, slower rebuild for the rest.
    # 20 txs gives α ≈ 0.034 — a hacked peer falls visibly within
    # a few seconds of demo time while honest peers recover gradually.
    CONSENSUS_EMA_HALF_LIFE = 20

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
        self.history = TransactionHistory()
        self.my_requests: dict[tuple[int, int], TxCount] = {}
        self.requests: list[tuple[int, int]] = []
        self.proposals: dict[tuple[int, int], TransactionScore] = {}
        self.acceptances: dict[UUID, list[TransactionScore]] = {}
        self.last_id = None
        self.last_value = None
        self.backoff = {}
        self.reputations = Reputations()
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

    @property
    def peers(self):
        return self.protocol.peers

    @property
    def group(self):
        return self.protocol.group

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
        start = now()
        while (now() - start).total_seconds() < self.protocol_timeout:
            if idx not in self.my_requests:
                retry = False  # already completed by handle_grant
                break
            if self.my_requests[idx].count >= len(self.peers.all) // 2:
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
            if self.my_requests[idx].count >= len(self.peers.all) // 2:
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

    def _start_paxos(self, queues, score: TransactionScore):
        id1 = int(now().timestamp() * 1000)
        id2 = len(self.history) + 1
        idx = self._paxos_id_index(id1, id2)
        pax_id = (id1, id2, self.identity.uuid)
        self.my_requests[idx] = TxCount(score, 0)
        pax_msg = Message(self.name, ReputationProtocol.request,
                          to_json_string(pax_id), self.group,
                          from_whom=self.identity)
        queues[CfgIds.network].put(pax_msg, block=True, timeout=self.q_cadence)
        self.proposals[idx] = score
        # Cache the weight for this task so _pure_reputation can later
        # aggregate it correctly (Slice 3 / trust-tiers.md §5).
        self._record_task_weight(score.task_id, self._resolve_tx_weight(score))
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
            if len(self.acceptances[score.task_id]) > len(self.peers.all) // 2:
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
                # for the rationale).
                self.history.update(score.task_id, peer_id, score.score)
                # Bumped to info to make demo debugging tractable —
                # without a commit log, "no movement on reputations"
                # is indistinguishable from "no paxos commits".
                self.logger.info(
                    'Transaction committed: task=%s peer=%s score=%.2f '
                    '(history now %d txs, %d task_maps)',
                    str(getattr(score, "task_id", ""))[:8],
                    str(peer_id)[:8], score.score,
                    len(self.history),
                    len(self.history._task_mapping))
                try:
                    # Pass task_id and peer_id through unchanged —
                    # ConfigJSONEncoder round-trips UUID objects with
                    # a __type__ tag, so handle_committed receives
                    # the same types we put in.  Stringifying here
                    # would break that round-trip.
                    commit_msg = Message(
                        self.name, ReputationProtocol.committed,
                        to_json_string(
                            (score.task_id, peer_id, score.score)),
                        self.group, from_whom=self.identity)
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
                task_id, peer_id, score = from_json_string(message.obj)
            except Exception:
                self.logger.warning(
                    'handle_committed: malformed payload %r', message.obj)
                return True
            if str(peer_id) == str(self.identity.uuid):
                return True
            self.history.update(task_id, peer_id, float(score))
            self.logger.info(
                'Recorded committed tx from %s: task=%s score=%.2f '
                '(history now %d txs, %d task_maps)',
                str(peer_id)[:8], str(task_id)[:8], float(score),
                len(self.history),
                len(self.history._task_mapping))
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
                grouping = []
                for update in self.updates.values():
                    grouped = False
                    for grp in grouping:
                        if update == grp[0]:
                            grp.append(update)
                            grouped = True
                    if not grouped:
                        grouping.append([update])
                grouping.sort(key=len)
                self.logger.debug(grouping)
                if len(grouping[-1]) > up_count // 2:
                    chain = grouping[-1][0]  # all entries are identical; use one
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
        if len(peer_scores) < 1 or len(my_scores) < 1:  # not enough info
            return 0.49
        peer_standing = sum(peer_scores) / len(peer_scores)
        my_standing = sum(my_scores) / len(my_scores)
        if peer_scores[-1] < 0.5 and my_standing < 0.5:  # peer defected, but my standing sucks
            rep_score = max(0.51, peer_standing)
        elif peer_scores[-1] < 0.5 and my_standing >= 0.5:  # peer defected, my standing is ok
            rep_score = min(0.49, peer_standing)
        else:  # cooperate/cooperate (but digging out of a hole)
            rep_score = max(0.51, peer_standing)
        return rep_score

    # TODO can we use the transaction memory to do better than CTFT before reputation kicks in?

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
                self.reputations.to_file(os.path.join(Configuration.get_cfg_dir(),
                                                      CfgIds.reputation + Configuration.file_ext))
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

    def _consensus_reputation(self, peer_uuid):
        """Deterministic reputation score over the consensus tx chain.

        Walks committed bilateral transactions involving the peer in
        chain order and folds each counterparty-side score into an
        exponentially-weighted moving average.  Pure function of
        ``self.history`` and ``peer_uuid`` — no dependence on
        ``self.identity``, ``self.reputations``, or any per-node
        latch — so every node with the same chain state arrives at
        the same number.  Intended for the inspector dashboard;
        ``rep_req`` callers continue to get the identity-dependent
        CTFT / _pure_reputation score from ``_compute_reputation``.

        The counterparty side is used (mirroring _pure_reputation's
        extraction) so the value reflects "what the network observed
        about this peer", not "what this peer self-reported".
        """
        try:
            txs = list(self.history.by_peer(peer_uuid))
        except KeyError:
            return 0.5
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
        return 0.5 if ema is None else ema

    def _compute_consensus_reputation(self, peer, req_proc, requestor):
        _probes.counter('rep.consensus', 'enter')
        try:
            # See _compute_reputation for the peer-type contract.
            peer_uuid = peer if isinstance(peer, (UUID, str)) else peer.uuid
            rep_score = self._consensus_reputation(peer_uuid)
            # Deliberately not writing self.reputations[peer_uuid] —
            # that dict feeds _compute_reputation's mode selection
            # and _pure_reputation's counterparty weighting, so
            # overwriting it with the consensus value would corrupt
            # the local trust path for any rep_req caller.
            self.requested_reps.append(
                (Reputation(peer_uuid, rep_score), req_proc, requestor))
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
            reputation, req_proc, requestor = self.requested_reps.pop(0)
            self.logger.debug('Forward reps to %s at %s' % (req_proc, requestor))
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
                for req in list(self.requests):
                    if present - req[0] > self.expiration:
                        self.requests.remove(req)
                for prop in dict(self.proposals):
                    if present - prop[0] > self.expiration:
                        del self.proposals[prop]
                # No sleep_until here: removing the 0.5 s cadence
                # throttle was the whole point. Pacing is already
                # provided by queue.get's q_cadence-second blocking
                # timeout when no work is pending.
            except Exception as err:
                self.logger.error(err)
                self.logger.error(traceback.format_exc())
