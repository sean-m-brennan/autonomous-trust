import time

import composable_paxos as paxos

from .processes import Process, ProcMeta
from .configuration import CfgIds


class ByzPax(paxos.PaxosInstance):
    def __init__(self, network_uid, quorum_size):
        super().__init__(network_uid, quorum_size)


class ReputationProcess(Process, metaclass=ProcMeta,
                        proc_name='reputation', description='Reputation tracking', cfg_name=CfgIds.reputation.value):
    def __init__(self, configurations):
        super().__init__(configurations, dependencies=[CfgIds.network.value, CfgIds.identity.value])
        self.pax = ByzPax(configurations[CfgIds.network.value], 3)

    def listen(self, queues, output, signal):
        while self.keep_running(signal):
            message = queues[self.name].get(block=True)
            self.info(message)  # FIXME
            time.sleep(self.cadence)

    def speak(self, queues, output, signal):
        while self.keep_running(signal):
            msg = ''  # FIXME
            queues[CfgIds.network.value].put(msg, block=True)
            time.sleep(self.cadence)
