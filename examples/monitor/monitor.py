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
from queue import Empty

from autonomous_trust.core import AutonomousTrust, Process, ProcMeta, Configuration, LogLevel
from autonomous_trust.core.config.generate import random_config


class MonitorProcess(Process, metaclass=ProcMeta,
                     proc_name='monitor', description='Silent system activity monitor'):
    def __init__(self, configurations, subsystems, log_q, dependencies):
        super().__init__(configurations, subsystems, log_q, dependencies=dependencies)

    def process(self, queues, signal):
        while self.keep_running(signal):
            try:
                message = queues[self.name].get(block=True, timeout=self.q_cadence)
                self.logger.info(message)  # FIXME interpret
            except Empty:
                pass


class Monitor(AutonomousTrust):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.add_worker(MonitorProcess, self.system_dependencies)


if __name__ == '__main__':
    random_config(os.path.join(os.path.dirname(__file__)))
    Monitor(log_level=LogLevel.INFO, logfile=Configuration.log_stdout).run_forever()
