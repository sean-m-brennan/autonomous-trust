# ******************
#  Copyright 2024 TekFive, Inc. and contributors
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
# ******************

import os
import random
import sys
import time

from autonomous_trust.core import AutonomousTrust, Configuration, LogLevel
from autonomous_trust.core.config.generate import generate_identity, generate_worker_config
from autonomous_trust.services.data.server import DataProcess, DataConfig
from autonomous_trust.services.network_statistics import NetStatsSource
from autonomous_trust.services.video import VideoProcess
from autonomous_trust.simulator.data_server import DataSimSource
from autonomous_trust.simulator.peer.peer_metadata import SimMetadataSource, SimMetadata
from autonomous_trust.simulator.video.server import SimVideoSrc


class MissionParticipant(AutonomousTrust):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.add_worker(SimMetadataSource, self.system_dependencies)  # metadata-source.cfg.yaml
        self.add_worker(NetStatsSource, self.system_dependencies)  # no config
        # FIXME
        #if os.path.exists(os.path.join(Configuration.get_cfg_dir(),
        #                               VideoSource.name + Configuration.file_ext)):
        #    self.add_worker(VideoSource, self.system_dependencies)  # video-source.cfg.yaml
        if os.path.exists(os.path.join(Configuration.get_cfg_dir(),
                                       DataSimSource.name + Configuration.file_ext)):
            self.add_worker(DataSimSource, self.system_dependencies)  # data-source.cfg.yaml


if __name__ == '__main__':
    idx = 1
    if len(sys.argv) > 1:
        idx = int(sys.argv[1])
    number = str(idx).zfill(3)

    os.environ[Configuration.ROOT_VARIABLE_NAME] = os.path.join(os.path.dirname(__file__), number)
    cfg_dir = Configuration.get_cfg_dir()
    os.makedirs(cfg_dir, exist_ok=True)
    dat_dir = Configuration.get_data_dir()
    os.makedirs(os.path.dirname(dat_dir), exist_ok=True)
    if not os.path.exists(dat_dir):
        os.symlink(os.path.join(os.path.dirname(__file__), Configuration.DATA_PATH), dat_dir)

    generate_identity(cfg_dir, preserve=True, defaults=True)  # does nothing if files present (always regen network)
    if '--setup' in sys.argv:
        for cfg_name, klass in ((SimMetadataSource.name, SimMetadata),
                                (VideoProcess.name, SimVideoSrc),
                                (DataProcess.name, DataConfig)):  # FIXME DataSrc does nothing (see Metadata.data_meta)
            generate_worker_config(cfg_dir, cfg_name, klass, True)

    time.sleep(random.randint(10, 120))  # delay up to two minutes, but at least ten seconds
    MissionParticipant(log_level=LogLevel.DEBUG,
                       logfile=os.path.join(dat_dir, 'participant%s.log' % number)).run_forever()
