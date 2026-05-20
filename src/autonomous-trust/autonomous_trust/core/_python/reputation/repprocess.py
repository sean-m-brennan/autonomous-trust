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
    # Reputation-tied rank elevation (BUGS.md §P2). Each tier is
    # (score_floor, rank); scores below the lowest floor map to rank 0.
    # Sorted ascending so _rank_tier can iterate and pick the highest
    # matching tier. Tunable, but keep monotonically increasing.
    RANK_TIERS = (
        (0.50, 1),
        (0.65, 2),
        (0.80, 3),
        (0.90, 4),
    )

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
        # Last published rank per peer uuid-string. Suppresses redundant
        # rank_update IPC when the tier hasn't changed (BUGS.md §P2).
        self.peer_ranks: dict[str, int] = {}
        # (peer_uuid, score) pairs produced by _compute_reputation in
        # spawned threads, drained by the main `process` loop where
        # `queues` is in scope. Same pattern as `requested_reps`.
        self.pending_ranks: list = []
        # Paxos rounds already committed locally — prevents
        # handle_accepted from re-firing its commit block on every
        # late ACCEPTED that arrives after majority is reached.
        # Without this, each round triggers `len(peers.all)-majority+1`
        # redundant commit broadcasts, and duplicate broadcasts
        # corrupt the resulting Transaction (p1 and p2 both end up
        # holding the proposer's uuid because TransactionHistory.update
        # doesn't dedup by peer_id).
        self.committed_paxos_rounds: set = set()

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
                self.committed_paxos_rounds.add(idx)
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
        # Mirror reputation.c:412-457: counterparty's-score weighted
        # by counterparty's-reputation, default 0.5 on no-history
        # OR no-valid-tx (returning 0.0 would route the peer back
        # into CTFT mode on the next compute, the very condition we
        # supposedly graduated from).  Counterparties absent from
        # ``self.reputations`` use a 0.5 fallback rather than being
        # silently skipped (skipping made the result sensitive to
        # whether the local reputations dict had caught up to the
        # history chain).
        peer_uuid = peer.uuid
        try:
            txs = list(self.history.by_peer(peer_uuid))
        except KeyError:
            return 0.5
        total = 0.0
        valid = 0
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
            total += counterparty_score * cp_rep
            valid += 1
        if valid == 0:
            return 0.5
        return total / valid

    def _contrite_tit_for_tat(self, peer):
        # peer_score is the score the PEER submitted in a bilateral
        # transaction; my_score is the score WE submitted. p1_score
        # belongs to whoever is p1, p2_score to p2 — so the side that
        # matches `peer.uuid` is the one whose score is "peer_score".
        # An earlier revision had these indices swapped relative to
        # the C twin (reputation.c:499-507), inverting the
        # peer-defected vs. self-defected branches.
        peer_scores = []
        my_scores = []
        try:
            for tx in self.history.by_peer(peer.uuid):
                if tx.p1_id == peer.uuid and tx.p2_id == self.identity.uuid:
                    peer_scores.append(tx.p1_score)
                    my_scores.append(tx.p2_score)
                elif tx.p2_id == peer.uuid and tx.p1_id == self.identity.uuid:
                    peer_scores.append(tx.p2_score)
                    my_scores.append(tx.p1_score)
        except KeyError:
            self.logger.debug('No transaction history for peer %s' % peer.uuid)
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
    def _rank_tier(cls, score: float) -> int:
        """Map a reputation score to its rank tier.

        Walks RANK_TIERS top-down, returning the highest tier whose
        floor is met. Scores below the lowest floor map to 0.
        """
        for floor, rank in reversed(cls.RANK_TIERS):
            if score >= floor:
                return rank
        return 0

    def _publish_rank_change(self, queues, peer_uuid, score):
        """Notify IdentityProcess of a tier crossing (BUGS.md §P2).

        Suppressed if the tier hasn't changed from the last publication
        for this peer. Local IPC only — message goes on the identity
        queue with `IdentityProtocol.rank_update`.
        """
        try:
            new_rank = self._rank_tier(score)
            key = str(peer_uuid)
            if self.peer_ranks.get(key) == new_rank:
                return
            self.peer_ranks[key] = new_rank
            payload = to_json_string((key, new_rank))
            # Local IPC: no to_whom (the consumer is the local
            # IdentityProcess reading its own queue; no network egress).
            msg = Message(CfgIds.identity, IdentityProtocol.rank_update,
                          payload, to_whom=None, from_whom=self.identity)
            queues[CfgIds.identity].put(msg, block=True, timeout=self.q_cadence)
            self.logger.debug('Published rank_update for %s: %d (score=%.3f)' %
                              (key, new_rank, score))
        except Full:
            self.logger.error('_publish_rank_change: identity queue full')
        except Exception as err:
            self.logger.warning('_publish_rank_change failed: %s' % err)

    def _compute_reputation(self, peer, req_proc, requestor):
        _probes.counter('rep.compute', 'enter')
        try:
            peer_uuid = peer if isinstance(peer, UUID) else peer.uuid
            previous = 0.0
            if peer_uuid in self.reputations:
                previous = self.reputations[peer_uuid]
            if previous > 0.5:
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
            # Queue a rank-update for IdentityProcess; drained by the
            # process loop alongside forward_reputation. The spawned
            # _compute_reputation thread doesn't have access to queues
            # so it can't put directly.
            self.pending_ranks.append((peer_uuid, rep_score))
            self.requested_reps.append((Reputation(peer_uuid, rep_score), req_proc, requestor))
            _probes.counter('rep.compute', 'queued')
        except Exception as e:
            _probes.counter('rep.compute', 'exception', type(e).__name__)
            self.logger.warning('_compute_reputation failed: %s' % e)

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
                # Drain rank updates queued by _compute_reputation.
                while self.pending_ranks:
                    peer_uuid, rep_score = self.pending_ranks.pop(0)
                    self._publish_rank_change(queues, peer_uuid, rep_score)

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
