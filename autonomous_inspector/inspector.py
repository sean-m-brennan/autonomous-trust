import os
import time
from queue import Empty

from autonomous_trust import AutonomousTrust, Process, ProcMeta, Configuration, LogLevel, CfgIds
from autonomous_trust.config.generate import random_config

from .viz.server import VizServer


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
        self.signals = {}

    def cleanup(self):
        for sig in self.signals.values():
            sig.put_nowait(Process.sig_quit)

    def autonomous_loop(self, results, queues, signals):
        self.signals = signals
        viz_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'viz'))
        viz = VizServer(viz_dir, 8000, data_q=queues['main'], finished=self.cleanup)
        viz.run()
        viz.stop()


if __name__ == '__main__':
    random_config(os.path.join(os.path.dirname(__file__)), 'monitor')
    Inspector(log_level=LogLevel.INFO, logfile=Configuration.log_stdout).run_forever()
