import os
from queue import Empty

from autonomous_trust.core import AutonomousTrust, Process, ProcMeta, LogLevel
from autonomous_trust.core.config import Configuration, CfgIds, to_yaml_string
from autonomous_trust.core.config.generate import random_config
from autonomous_trust.core.system import queue_cadence
from autonomous_trust.core.network import Network, Message
from autonomous_trust.core.reputation.protocol import ReputationProtocol

from .viz.server import VizServer
from .viz.live_graph import LiveData


class InspectorProcess(Process, metaclass=ProcMeta,
                       proc_name='monitor', description='Silent system activity monitor'):
    command_deck = [item.value for item in CfgIds] + ['package_hash', 'log-level', 'processes']

    def __init__(self, configurations, subsystems, log_q, dependencies):
        super().__init__(configurations, subsystems, log_q, dependencies=dependencies)

    def process(self, queues, signal):
        while self.keep_running(signal):
            try:
                cmd = queues[self.name].get(block=True, timeout=self.q_cadence)
                if isinstance(cmd, str):
                    if cmd in self.command_deck:
                        obj = self.configs[cmd]
                        msg_str = str(obj)  # FIXME convert to json
                        # send straight to viz server
                        queues['main'].put(msg_str, block=True, timeout=self.q_cadence)
            except Empty:
                pass


class Inspector(AutonomousTrust):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.add_worker(InspectorProcess, self.system_dependencies)
        self.viz = None
        self.data_queue = self.queue_type()

    def init_tasking(self, queues):
        viz_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'viz'))
        self.viz = VizServer(viz_dir, 8000, data_q=self.data_queue, finished=self.cleanup)
        self.viz.run()

    def autonomous_tasking(self, queues):
        if self.tasking_tick(1):  # every 30 sec
            for peer in self.peers.all:
                query = Message(CfgIds.reputation, ReputationProtocol.rep_req,
                                to_yaml_string((peer, self.proc_name)), self.identity)
                queues[CfgIds.reputation].put(query, block=True, timeout=queue_cadence)
                ping = Message(CfgIds.network, Network.ping, 5, peer, return_to=self.name)
                queues[CfgIds.network].put(ping, block=True, timeout=queue_cadence)
        if self.tasking_tick(2, 5.0):  # every 5 sec
            # FIXME peer connections?? (i.e. peers of peers of ...)
            for peer_id in self.latest_reputation:
                self.data_queue.put((LiveData.reputation, self.latest_reputation[peer_id]),
                                    block=True, timeout=queue_cadence)
            for message in list(self.unhandled_messages):
                if message.function == Network.ping:
                    self.unhandled_messages.remove(message)
                    self.data_queue.put((LiveData.latencies, message.obj),
                                        block=True, timeout=queue_cadence)
            self._report_unhandled()

    def cleanup(self):
        self.viz.stop()


if __name__ == '__main__':
    random_config(os.path.join(os.path.dirname(__file__)), 'monitor')
    Inspector(log_level=LogLevel.INFO, logfile=Configuration.log_stdout).run_forever()
