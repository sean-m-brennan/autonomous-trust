import time
from queue import Empty, Full

import composable_paxos as paxos

from ..network import Message
from ..identity import Group, Peers
from ..processes import Process, ProcMeta
from ..config import CfgIds


class ByzPax(paxos.PaxosInstance):
    def __init__(self, network_uid, quorum_size):
        super().__init__(network_uid, quorum_size)


class ReputationProcess(Process, metaclass=ProcMeta,
                        proc_name='reputation', description='Reputation tracking', cfg_name=CfgIds.reputation.value):
    def __init__(self, configurations, subsystems, log_q):
        super().__init__(configurations, subsystems, log_q,
                         dependencies=[CfgIds.network.value, CfgIds.identity.value, CfgIds.negotiation.value])
        self.pax = ByzPax(configurations[CfgIds.network.value], 3)
        self.peers = configurations[CfgIds.peers.value]

    def _run_handlers(self, queues, message):
        if isinstance(message, Group):
            self.group = message
            self.logger.debug('Updated group')
            return True
        if isinstance(message, Peers):
            self.peers = message
            self.logger.debug('Updated peers')
            return True
        if isinstance(message, Message):
            # FIXME handle network message
            # transactions
            return True
        return False

    def process(self, queues, signal):
        while self.keep_running(signal):
            try:
                message = queues[self.name].get(block=True, timeout=self.q_cadence)
            except Empty:
                message = None
            if message:
                self._run_handlers(queues, message)

            # FIXME reputatiom handling
            try:
                if False:
                    msg = 'test'  # FIXME
                    queues[CfgIds.network.value].put(msg, block=True, timeout=self.q_cadence)
            except Full:
                self.logger.error('Reputation: network queue is full')

            time.sleep(self.cadence)
