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

import multiprocessing
import os
import time
from queue import Empty, Full
from multiprocessing import get_context

from autonomous_trust.core import AutonomousTrust, Process, ProcMeta, LogLevel, CfgIds
from autonomous_trust.core.config.generate import random_config


class RequestorProcess(Process, metaclass=ProcMeta,
                       proc_name='requestor', description='Interactive system monitor'):
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
                        msg_str = str(obj)
                        queues['main'].put(msg_str, block=True, timeout=self.q_cadence)
            except Empty:
                pass
            time.sleep(self.cadence)


class Requestor(AutonomousTrust):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.add_worker(RequestorProcess, self.system_dependencies)

    @staticmethod
    def usage():
        return """
        AutonomousTrust Commander
        Usage:
            help         this assistance text
            quit | exit  halt this agent
                no other commands yet
        """

    def autonomous_loop(self, results, queues, signals):
        if self.external_control not in queues or self.external_feedback not in queues:
            print('setup error')
            return
        extern_out = queues[self.external_control]
        extern_in = queues[self.external_feedback]
        while True:
            try:
                self._monitor_processes(results)
                try:
                    cmd = extern_out.get(block=True, timeout=0.01)
                    if cmd == Process.sig_quit:
                        print('Quitting')
                        self.logger.debug(self.name + ": External signal to quit")
                        for sig in signals.values():
                            sig.put_nowait(Process.sig_quit)
                        break
                    elif cmd in ['h', 'help']:
                        answer = self.usage()
                    else:
                        if cmd in RequestorProcess.command_deck:
                            queues[RequestorProcess.name].put(cmd, block=True, timeout=0.01)
                            answer = queues['main'].get(block=True, timeout=1)
                            while not isinstance(answer, str):
                                answer = queues['main'].get(block=True, timeout=1)
                        else:
                            answer = "Not a command: '%s'" % cmd
                    extern_in.put(answer, block=True, timeout=0.01)  # noqa
                except Empty:
                    pass
                time.sleep(Process.cadence)
            except KeyboardInterrupt:
                for sig in signals.values():
                    sig.put_nowait(Process.sig_quit)
                break


class Commander(object):
    """
    An unnecessarily complex class to demonstrate using AT as a subsidiary system.
    """
    def __init__(self, **kwargs):
        self.ctx = get_context('forkserver')
        manager = self.ctx.Manager()
        self.q_type = manager.Queue
        self.input_queue = self.q_type()
        self.req_in_queue = self.q_type()
        self.req_out_queue = self.q_type()
        self.req = Requestor(**kwargs)

    def run_forever(self):
        req = multiprocessing.Process(target=self.req.run_forever,
                                      args=(self.req_in_queue, self.req_out_queue))
        req.start()
        time.sleep(0.5)
        while True:
            try:
                cmdline = input('(autonomous_trust) %s: ' % self.__class__.__name__.lower())
                cmdline = cmdline.strip()
                try:
                    if len(cmdline) > 0:
                        if cmdline in ['q', 'quit', 'exit']:
                            self.req_in_queue.put_nowait(Process.sig_quit)
                            break
                        self.req_in_queue.put(cmdline, block=True, timeout=0.01)
                    answer = self.req_out_queue.get(block=True, timeout=2)
                    print(answer)
                except Empty:
                    print('unknown')
                except Full:
                    print('busy')
            except KeyboardInterrupt:
                self.req_in_queue.put_nowait(Process.sig_quit)
                break
        req.join(Process.exit_timeout)


if __name__ == '__main__':
    random_config(os.path.join(os.path.dirname(__file__)))
    Commander(log_level=LogLevel.DEBUG).run_forever()
