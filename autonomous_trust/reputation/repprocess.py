from queue import Empty, Full

import composable_paxos as paxos

from ..network import Message
from ..identity import Group, Peers
from ..processes import Process, ProcMeta
from ..config import CfgIds
from .protocol import ReputationProtocol


class ByzPax(paxos.PaxosInstance):
    def __init__(self, network_uid, quorum_size):
        super().__init__(network_uid, quorum_size)


class ReputationProcess(Process, metaclass=ProcMeta,
                        proc_name='reputation', description='Reputation tracking', cfg_name=CfgIds.reputation):
    def __init__(self, configurations, subsystems, log_q):
        super().__init__(configurations, subsystems, log_q,
                         dependencies=[CfgIds.network, CfgIds.identity, CfgIds.negotiation])
        self.pax = ByzPax(configurations[CfgIds.network], 3)
        self.protocol = ReputationProtocol(self.name, self.logger, configurations[CfgIds.peers])
        self.protocol.register_handler(ReputationProtocol.transaction, self.handle_local_transaction)

    @property
    def peers(self):
        return self.protocol.peers

    @property
    def group(self):
        return self.protocol.group

    def handle_local_transaction(self, queues, message):
        if message.function == ReputationProtocol.transaction:
            return True
        return False

    def process(self, queues, signal):
        while self.keep_running(signal):
            try:
                message = queues[self.name].get(block=True, timeout=self.q_cadence)
            except Empty:
                message = None
            if message:
                if not self.protocol.run_message_handlers(queues, message):
                    pass  # FIXME reputatiom handling
            #try:
            #    if False:
            #        msg = 'test'  # FIXME
            #        queues[CfgIds.network].put(msg, block=True, timeout=self.q_cadence)
            #except Full:
            #    self.logger.error('Reputation: network queue is full')

            self.sleep_until(self.cadence)
