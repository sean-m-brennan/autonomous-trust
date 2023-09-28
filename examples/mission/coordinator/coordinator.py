import os
import sys

from autonomous_trust.core import AutonomousTrust, LogLevel
from autonomous_trust.core.config import Configuration, CfgIds, to_yaml_string
from autonomous_trust.core.system import queue_cadence
from autonomous_trust.core.network import Network, Message
from autonomous_trust.core.reputation.protocol import ReputationProtocol
from autonomous_trust.inspector.peer.daq import Cohort, CohortTracker

from autonomous_trust.simulator.dash_components.map_display import MapDisplay
from autonomous_trust.simulator.video.client import VideoSimRcvr


class MissionVisualizer(MapDisplay):
    # simulator must be started separately *first*
    def __init__(self, cohort: Cohort, finished=None):
        super().__init__(cohort)


class MissionCoordinator(AutonomousTrust):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.cohort = Cohort(self)
        self.add_worker(CohortTracker, self.system_dependencies, cohort=self.cohort)
        self.add_worker(VideoSimRcvr, self.system_dependencies, cohort=self.cohort)

        self.viz = None
        self.viz_queue = self.queue_type()

    def init_tasking(self, queues):
        self.viz = MissionVisualizer(self.cohort, finished=self.cleanup)
        self.viz.run()

    #def autonomous_tasking(self, queues):
    #    if self.tasking_tick(1):  # every 30 sec
    #        for peer in self.peers.all:
    #            if peer not in self.data_queues:
    #                self.data_queues[peer] = self.queue_type()

    #            query = Message(CfgIds.reputation, ReputationProtocol.rep_req,
    #                            to_yaml_string((peer, self.proc_name)), self.identity)
    #            queues[CfgIds.reputation].put(query, block=True, timeout=queue_cadence)
    #           ping = Message(CfgIds.network, Network.ping, 5, peer, return_to=self.name)
    #            queues[CfgIds.network].put(ping, block=True, timeout=queue_cadence)
    #    if self.tasking_tick(2, 5.0):  # every 5 sec
    #       # FIXME peer connections?? (i.e. peers of peers of ...)
    #       for peer_id in self.latest_reputation:
    #           self.viz_queue.put((LiveData.reputation, self.latest_reputation[peer_id]),
    #                                block=True, timeout=queue_cadence)
    #        for message in list(self.unhandled_messages):
    #            if message.function == Network.ping:
    #                self.unhandled_messages.remove(message)
    #                self.viz_queue.put((LiveData.latencies, message.obj),
    #                                    block=True, timeout=queue_cadence)
    #        self._report_unhandled()

    def cleanup(self):
        self.viz.halt = True


if __name__ == '__main__':
    cfg_dir = os.path.join(os.path.dirname(__file__))
    os.environ[Configuration.VARIABLE_NAME] = cfg_dir
    MissionCoordinator(log_level=LogLevel.INFO, logfile=Configuration.log_stdout).run_forever()
