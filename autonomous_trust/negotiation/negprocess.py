import time
from queue import Empty

from ..identity import Peers, Group
from ..network import Message
from ..processes import Process, ProcMeta
from ..config import CfgIds


class NegotiationProcess(Process, metaclass=ProcMeta,
                         proc_name=CfgIds.negotiation.value, description='Negotiate transactions'):
    """
    Handle transaction agreement negotiations
    """
    def __init__(self, configurations, subsystems, log_q):
        super().__init__(configurations, subsystems, log_q,
                         dependencies=[CfgIds.network.value, CfgIds.identity.value])
        self.peers = configurations[CfgIds.peers.value]

    def _run_handlers(self, queues, message):
        if isinstance(message, Group):
            # ignore
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

            time.sleep(self.cadence)
