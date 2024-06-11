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

import atexit
import logging
import threading
import time
from queue import Queue
from typing import Callable

from autonomous_trust.inspector.peer.daq import CohortInterface
from autonomous_trust.inspector.dash_components.core import DashControl
from ..sim_client import SimClient
from .. import default_port
from ..sim_data import SimState


class SimulationInterface(CohortInterface):
    cadence = 1

    def __init__(self, dash_info: DashControl, sim_host: str = '127.0.0.1', sim_port: int = default_port,
                 sync_objects: list[CohortInterface] = None, log_level: int = logging.INFO, logfile: str = None):
        super().__init__(log_level=log_level, logfile=logfile)
        self.tick = 0
        self.ctl = dash_info
        self.app = dash_info.app
        self.client = SimClient(callback=self.state_to_queue(), logger=self.logger, passive=False)
        self.client_thread = threading.Thread(target=self.client.run, args=(sim_host, sim_port))
        self.sim_thread = threading.Thread(target=self.run)
        self.queue = Queue(maxsize=1)
        self.can_reset = False
        self.halt = False
        self.sync_objects = sync_objects
        if sync_objects is None:
            self.sync_objects: list[CohortInterface] = []
        self.reset_handlers: list[Callable] = []  # additional work to do at reset, set externally
        self.end_handlers: list[Callable] = []  # work to do upon end (before reset)
        self.update_handlers: list[Callable[[SimState], None]] = []  # work to do on each update
        atexit.register(self.interrupt)

    def start(self):
        self.client_thread.start()
        self.sim_thread.start()

    def stop(self):
        self.halt = True
        self.client.halt = True

    def register_update_handler(self, handler: Callable):
        self.update_handlers.append(handler)

    def register_end_handler(self, handler: Callable):
        self.end_handlers.append(handler)

    def register_reset_handler(self, handler: Callable):
        self.reset_handlers.append(handler)

    @property
    def resolution(self):
        return self.client.resolution

    @resolution.setter
    def resolution(self, res):
        self.client.resolution = res

    def interrupt(self):
        self.stop()
        #if self.client.sock is not None:  # FIXME remove
        #    self.client.sock.close()
        #self.client_thread.join()

    def state_to_queue(self):
        def cb(state):
            if state is not None:
                self.tick = self.client.tick
                self.queue.put(state, block=True, timeout=None)
        return cb

    def update(self, initial=False):
        """May be called only once per timestep, i.e. synced with UI; does not use state data"""
        state = self.queue.get()
        for obj in self.sync_objects:
            obj.update()  # FIXME also sync paused
        for handler in self.update_handlers:
            handler(state)
        if state.blank:
            self.logger.debug('Sim update; reset %s' % state.blank)
            self.paused = True
            for obj in self.sync_objects:  # FIXME
                obj.paused = self.paused
            self.can_reset = True
            for handler in self.end_handlers:
                handler()
            while self.paused:
                time.sleep(0.1)
            self.can_reset = False
            for handler in self.reset_handlers:
                handler()
            for obj in self.sync_objects:
                obj.paused = self.paused

    def acquire_data(self):
        pass  # update() is overridden above

    def run(self):
        while not self.halt:
            if not self.paused:
                self.update()
            time.sleep(self.cadence)