import os
from queue import Empty

from autonomous_trust import AutonomousTrust, Process, ProcMeta, Configuration, LogLevel
from autonomous_trust.config.generate import random_config


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
    random_config(os.path.join(os.path.dirname(__file__)), 'monitor')
    Monitor(log_level=LogLevel.INFO, logfile=Configuration.log_stdout).run_forever()
