import os
import sys

from autonomous_trust.core import AutonomousTrust, Configuration, LogLevel
from autonomous_trust.services.network_statistics import NetStatsSource
from autonomous_trust.services.video import VideoSource
from autonomous_trust.simulator.sim_client import SimClient
from autonomous_trust.simulator.peer.peer_metadata import SimMetadataSource


class MissionCoordinator(AutonomousTrust):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.sim_host = kwargs['sim-host']
        self.sim_port = kwargs['sim-port']
        video_path = kwargs['video-path']  # FIXME ?
        self.sim = SimClient()
        self.add_worker(SimMetadataSource, self.system_dependencies, sim=self.sim)  # position_source=
        self.add_worker(NetStatsSource, self.system_dependencies)  # network_source=
        self.add_worker(VideoSource, self.system_dependencies, path=video_path, size=320)

        # FIXME data streams
        self.sim = None
        self.viz_queue = self.queue_type()

    def init_tasking(self, queues):
        self.sim.run(self.sim_host, self.sim_port)

    def cleanup(self):
        self.sim.halt = True


if __name__ == '__main__':
    cfg_dir = os.path.join(os.path.dirname(__file__), '', sys.argv[1])
    os.environ[Configuration.VARIABLE_NAME] = cfg_dir
    MissionCoordinator(log_level=LogLevel.INFO, logfile=Configuration.log_stdout).run_forever()
