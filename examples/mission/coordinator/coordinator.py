import os
import sys
import threading

from autonomous_trust.core import AutonomousTrust, LogLevel, CfgIds, to_yaml_string
from autonomous_trust.core.config import Configuration
from autonomous_trust.core.config.generate import generate_identity, generate_worker_config
from autonomous_trust.core.system import queue_cadence
from autonomous_trust.core.network import Message
from autonomous_trust.core.reputation.protocol import ReputationProtocol
from autonomous_trust.inspector.peer.daq import Cohort, CohortTracker
from autonomous_trust.services.data.client import DataRcvr
from autonomous_trust.services.video.client import VideoRecv

from autonomous_trust.simulator.dash_components.map_display import MapDisplay, MapUI
from autonomous_trust.simulator.video.client import VideoSimRcvr


class MissionCoordinator(AutonomousTrust):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.cohort = Cohort(self.queue_pool)
        self.add_worker(CohortTracker, self.system_dependencies, cohort=self.cohort)
        self.add_worker(VideoSimRcvr, self.system_dependencies, cohort=self.cohort)  # TODO noise?
        self.add_worker(DataRcvr, self.system_dependencies, cohort=self.cohort)

        self.viz = None
        self.vthread = None

    def init_tasking(self, queues):
        self.viz = MapDisplay(self.cohort)
        self.vthread = threading.Thread(target=self.viz.run, kwargs={'logger': self.logger})
        self.vthread.start()

    def autonomous_tasking(self, queues):
        if self.tasking_tick(1):  # every 30 sec
            for peer in self.peers.all:
                query = Message(CfgIds.reputation, ReputationProtocol.rep_req,
                                to_yaml_string((peer, self.proc_name)), self.identity)
                queues[CfgIds.reputation].put(query, block=True, timeout=queue_cadence)

        if self.tasking_tick(2, 5.0):  # every 5 sec
            for peer_id in self.latest_reputation:
                msg = Message(self.name, ReputationProtocol.rep_resp, self.latest_reputation[peer_id])
                queues['daq'].put(msg, block=True, timeout=queue_cadence)

        self._report_unhandled()

    def cleanup(self):
        self.viz.halt = True
        self.vthread.join()


if __name__ == '__main__':
    # There can be only one
    os.environ[Configuration.VARIABLE_NAME] = os.path.dirname(__file__)
    cfg_dir = Configuration.get_cfg_dir()
    os.makedirs(cfg_dir, exist_ok=True)
    dat_dir = Configuration.get_data_dir()
    os.makedirs(os.path.dirname(dat_dir), exist_ok=True)

    generate_identity(cfg_dir, preserve=True, defaults=True)  # does nothing if files present (always regen network)
    if '--setup' in sys.argv:
        for cfg_name, klass in ((VideoSimRcvr.name, VideoRecv), (MapDisplay.name, MapUI)):
            generate_worker_config(cfg_dir, cfg_name, klass, True)
    MissionCoordinator(log_level=LogLevel.DEBUG, logfile=os.path.join(dat_dir, 'coordinator.log')).run_forever()
