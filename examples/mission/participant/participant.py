import os
import sys

from autonomous_trust.core import AutonomousTrust, Configuration, LogLevel
from autonomous_trust.core.config.generate import generate_identity, generate_worker_config
from autonomous_trust.services.data.server import DataSource, DataSrc
from autonomous_trust.services.network_statistics import NetStatsSource
from autonomous_trust.services.video import VideoSource
from autonomous_trust.simulator.data_server import DataSimSource
from autonomous_trust.simulator.peer.peer_metadata import SimMetadataSource, SimMetadata
from autonomous_trust.simulator.video.server import SimVideoSrc


class MissionParticipant(AutonomousTrust):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.add_worker(SimMetadataSource, self.system_dependencies)  # FIXME SimClient is a problem?
        self.add_worker(NetStatsSource, self.system_dependencies)
        self.add_worker(VideoSource, self.system_dependencies)
        self.add_worker(DataSimSource, self.system_dependencies)


if __name__ == '__main__':
    idx = 1
    if len(sys.argv) > 1:
        idx = int(sys.argv[1])
    number = str(idx).zfill(3)

    os.environ[Configuration.VARIABLE_NAME] = os.path.join(os.path.dirname(__file__), number)
    cfg_dir = Configuration.get_cfg_dir()
    os.makedirs(cfg_dir, exist_ok=True)
    dat_dir = Configuration.get_data_dir()
    os.makedirs(os.path.dirname(dat_dir), exist_ok=True)
    if not os.path.exists(dat_dir):
        os.symlink(os.path.join(os.path.dirname(__file__), Configuration.DATA_PATH), dat_dir)

    generate_identity(cfg_dir, preserve=True, defaults=True)  # does nothing if files present
    for cfg_name, klass in ((SimMetadataSource.name, SimMetadata),
                            (VideoSource.name, SimVideoSrc), (DataSource.name, DataSrc)):
        generate_worker_config(cfg_dir, cfg_name, klass, True)

    MissionParticipant(log_level=LogLevel.DEBUG, logfile=Configuration.log_stdout).run_forever()
