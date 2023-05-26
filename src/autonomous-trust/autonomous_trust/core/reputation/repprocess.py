import os
import threading
import time
from queue import Empty, Full
from uuid import UUID
from dataclasses import dataclass

from ..network import Message
from ..processes import Process, ProcMeta
from ..config import Configuration, CfgIds, from_yaml_string, to_yaml_string
from .protocol import ReputationProtocol
from .reputation import TransactionHistory, Reputation, Reputations, TransactionScore
from ..system import now, encoding


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

    def __init__(self, configurations, subsystems, log_q, **kwargs):
        super().__init__(configurations, subsystems, log_q,
                         dependencies=[CfgIds.network, CfgIds.identity, CfgIds.negotiation], **kwargs)
        self.identity = self.configs[CfgIds.identity]
        self.protocol = ReputationProtocol(self.name, self.logger, configurations[CfgIds.peers])
        self.protocol.register_handler(ReputationProtocol.request, self.handle_request)
        self.protocol.register_handler(ReputationProtocol.grant, self.handle_grant)
        self.protocol.register_handler(ReputationProtocol.nack, self.handle_nack)
        self.protocol.register_handler(ReputationProtocol.backdate, self.handle_backdate)
        self.protocol.register_handler(ReputationProtocol.transaction, self.handle_transaction)
        self.protocol.register_handler(ReputationProtocol.accepted, self.handle_accepted)
        self.protocol.register_handler(ReputationProtocol.outdated, self.handle_outdated)
        self.protocol.register_handler(ReputationProtocol.update, self.handle_update)
        self.protocol.register_handler(ReputationProtocol.rep_req, self.handle_reputation_request)
        self.history = TransactionHistory()
        self.my_requests: dict[int, TxCount] = {}
        self.requests: list[int] = []
        self.proposals: dict[int, TransactionScore] = {}
        self.acceptances: dict[UUID, list[TransactionScore]] = {}
        self.last_id = None
        self.last_value = None
        self.backoff = {}
        self.reputations = Reputations()
        self.requested_reps = []
        self.updates = {}
        self.num_updates = 3

    @property
    def peers(self):
        return self.protocol.peers

    @property
    def group(self):
        return self.protocol.group

    @staticmethod
    def _paxos_id_index(id1, id2):
        x = 10 ** len(str(id2))
        return id1 + (id2 / x)  # convert to int for accurate expiration

    def handle_request(self, queues, message):
        if message.function == ReputationProtocol.request:
            id1, id2, peer_id = from_yaml_string(message.obj)
            if peer_id in [p.uuid for p in self.peers.all]:
                try:
                    if self.last_id is None or self.last_id < id1:
                        if len(self.history) + 1 == id2:
                            self.requests.append(self._paxos_id_index(id1, id2))
                            ack = ((id1, id2, peer_id), (self.last_id, len(self.history)), self.last_value)
                            msg = Message(self.name, ReputationProtocol.grant,
                                          to_yaml_string(ack), message.from_whom)
                            queues[CfgIds.network].put(msg, block=True, timeout=self.q_cadence)
                            self.logger.debug('Request granted')
                        else:
                            msg = Message(self.name, ReputationProtocol.backdate, message.obj, message.from_whom)
                            queues[CfgIds.network].put(msg, block=True, timeout=self.q_cadence)
                            self.logger.debug('Request backdated')
                    else:
                        msg = Message(self.name, ReputationProtocol.nack, message.obj, message.from_whom)
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
        while now() - start < self.protocol_timeout:
            if self.my_requests[idx].count >= len(self.peers.all) // 2:
                retry = False
                break
            time.sleep(self.cadence)
        if retry:
            try:
                self._start_paxos(queues, self.my_requests[idx].score)
            except Full:
                self.logger.error('paxos_timeout: Network queue full')

    def handle_grant(self, queues, message):
        if message.function == ReputationProtocol.grant:
            (id1, id2, peer_id), (last_id, last_idx), last_val = from_yaml_string(message.obj)
            if peer_id != self.identity.uuid:  # ignore not-mine
                self.logger.debug('Grant not for me')
                return True
            if (last_id is not None and last_id >= id1) or last_idx != len(self.history):  # peer is faulty
                self.peers.demote(message.from_whom)
                self.logger.debug('Grant from faulty peer')
                threading.Thread(target=self._paxos_timeout, args=(queues, (id1, id2, peer_id)), daemon=True).start()
                return True
            idx = self._paxos_id_index(id1, id2)
            self.my_requests[idx].count += 1
            if self.my_requests[idx].count >= len(self.peers.all) // 2:
                try:
                    score = (id1, id2, peer_id), self.my_requests[idx].score
                    msg = Message(self.name, ReputationProtocol.transaction, to_yaml_string(score), self.group)
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
        while start - now() < wait:
            time.sleep(self.cadence)
        try:
            self._start_paxos(queues, score)
        except Full:
            self.logger.error('try_again: Network queue full')

    def handle_nack(self, queues, message):
        if message.function == ReputationProtocol.nack:
            id1, id2, _ = from_yaml_string(message.obj)
            idx = self._paxos_id_index(id1, id2)
            if idx not in self.backoff:
                self.backoff[idx] = 1
            if self.backoff[idx] < self.backoff_max:
                self.backoff[idx] *= self.backoff_mult
            threading.Thread(target=self._try_again,
                             args=(self.backoff[idx], queues, self.requests[idx][0]), daemon=True).start()
            return True
        return False

    def _request_update(self, queues, n=3):
        self.num_updates = n
        for peer in self.peers.find_top_n(n):
            msg = Message(self.name, ReputationProtocol.outdated, str(len(self.history)), peer)
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
        pax_msg = Message(self.name, ReputationProtocol.request, to_yaml_string(pax_id), self.group)
        queues[CfgIds.network].put(pax_msg, block=True, timeout=self.q_cadence)
        self.proposals[idx] = score
        self.logger.debug('Start a Paxos round')

    def handle_transaction(self, queues, message):
        if message.function == ReputationProtocol.transaction:
            (id1, id2, peer_id), score = from_yaml_string(message.obj)
            idx = self._paxos_id_index(id1, id2)
            if idx not in self.requests:
                return True  # not granted, drop
            self.requests.remove(idx)
            # FIXME check sig
            if idx not in self.proposals:
                self.proposals[idx] = score
                self.logger.debug("Tx to proposals ")
            msg = Message(self.name, ReputationProtocol.accepted,
                          to_yaml_string((id1, id2, peer_id)), message.from_whom)
            queues[CfgIds.network].put(msg, block=True, timeout=self.q_cadence)
            return True
        return False

    def forward_transaction(self, queues, message):
        if isinstance(message, TransactionScore):
            try:
                self.history.update(message.task_id, self.identity.uuid, message.score)
                self._start_paxos(queues, message)
            except Full:
                self.logger.error('handle_transaction: Network queue full')
            return True
        return False

    def handle_accepted(self, _, message):
        if message.function == ReputationProtocol.accepted:
            id1, id2, peer_id = from_yaml_string(message.obj)
            idx = self._paxos_id_index(id1, id2)
            score = self.proposals[idx]
            self.logger.debug('Tx accepted')
            if score.task_id not in self.acceptances:
                self.acceptances[score.task_id] = []
            if message.from_whom not in self.acceptances[score.task_id]:
                # FIXME validate sig
                self.acceptances[score.task_id].append(message.from_whom)
            if len(self.acceptances[score.task_id]) > len(self.peers.all) // 2:
                self.history.update(score.task_id, peer_id, score.score)
                self.logger.debug('Transaction committed')
            return True
        return False

    def handle_outdated(self, queues, message):
        if message.function == ReputationProtocol.outdated:
            try:
                length = message.obj
                if isinstance(length, bytes):
                    length = length.decode(encoding)
                index = int(length)
                chain = to_yaml_string(self.history.era(index))
                msg = Message(self.name, ReputationProtocol.update, chain, message.from_whom)
                queues[CfgIds.network].put(msg, block=True, timeout=self.q_cadence)
                self.logger.debug('Sent update')
            except Full:
                self.logger.error('handle_outdated: Network queue full')
            return True
        return False

    def handle_update(self, queues, message):
        if message.function == ReputationProtocol.update:
            self.updates[message.from_whom.uuid] = from_yaml_string(message.obj)
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
                    chain = grouping[-1]
                    self.history.catchup(chain)
                    self.logger.debug('Updated')
                else:
                    self.logger.error('Closest %d peers unable to agree on history' % self.num_updates)
                    self._request_update(queues, len(self.peers.all))
            return True
        return False

    def _pure_reputation(self, peer):
        total = 0
        count = 0.0
        for tx in self.history.by_peer(peer.uuid):
            if tx.p1_id == peer.uuid and tx.p2_id in self.reputations:
                total += tx.p2_score * self.reputations[tx.p2_id]
                count += 1
            elif tx.p2_id == peer.uuid and tx.p1_id in self.reputations:
                total += tx.p1_score * self.reputations[tx.p1_id]
                count += 1
        return total / count

    def _contrite_tit_for_tat(self, peer):
        peer_scores = []
        my_scores = []
        try:
            for tx in self.history.by_peer(peer.uuid):
                if tx.p1_id == peer.uuid and tx.p2_id == self.identity.uuid:
                    peer_scores.append(tx.p2_score)
                    my_scores.append(tx.p1_score)
                elif tx.p2_id == peer.uuid and tx.p1_id == self.identity.uuid:
                    peer_scores.append(tx.p1_score)
                    my_scores.append(tx.p2_score)
        except KeyError:
            pass
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

    def _compute_reputation(self, peer, req_proc, requestor):
        previous = 0.0
        if peer.uuid in self.reputations:
            previous = self.reputations[peer.uuid]
        if previous > 0.5:
            self.logger.debug('Cooperation mode')
            rep_score = self._pure_reputation(peer)
        else:
            self.logger.debug('Tit-for-tat mode')
            rep_score = self._contrite_tit_for_tat(peer)
        self.reputations.update(peer.uuid, rep_score)
        self.reputations.to_file(os.path.join(Configuration.get_cfg_dir(),
                                              CfgIds.reputation + Configuration.yaml_file_ext))
        self.requested_reps.append((Reputation(peer.uuid, rep_score), req_proc, requestor))

    def handle_reputation_request(self, _, message):
        if message.function == ReputationProtocol.rep_req:
            if isinstance(message.obj, str):
                ident, req_proc = from_yaml_string(message.obj)
            else:
                ident, req_proc = message.obj
            threading.Thread(target=self._compute_reputation,
                             args=(ident, req_proc, message.from_whom), daemon=True).start()
            return True
        return False

    def forward_reputation(self, queues):
        while len(self.requested_reps) > 0:
            reputation, req_proc, requestor = self.requested_reps.pop(0)
            self.logger.debug('Forward reps to %s at %s' % (req_proc, requestor))
            try:
                msg = Message(req_proc, ReputationProtocol.rep_resp, reputation, requestor)
                queues[req_proc].put(msg, block=True, timeout=self.q_cadence)
            except Full:
                self.logger.error('forward_reputation: %s queue full' % req_proc)

    def process(self, queues, signal):
        while self.keep_running(signal):
            try:
                message = queues[self.name].get(block=True, timeout=self.q_cadence)
            except Empty:
                message = None
            if message:
                if not self.protocol.run_message_handlers(queues, message):
                    if not self.forward_transaction(queues, message):
                        if isinstance(message, Message):
                            self.logger.error('Unhandled message %s' % message.function)
                        else:
                            self.logger.error('Unhandled message of type %s' % message.__class__.__name__)  # noqa
            self.forward_reputation(queues)

            present = now().timestamp()
            for req in list(self.requests):
                if present - int(req) > self.expiration:
                    self.requests.remove(req)
            for prop in dict(self.proposals):
                if present - int(prop) > self.expiration:
                    del self.proposals[prop]

            self.sleep_until(self.cadence)
