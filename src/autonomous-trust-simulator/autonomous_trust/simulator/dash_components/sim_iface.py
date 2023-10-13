import atexit
import logging
import threading
import time
from queue import Queue
from typing import Optional, Callable

from autonomous_trust.inspector.peer.daq import CohortInterface
from ..sim_client import SimClient
from .. import default_port


class SimulationInterface(CohortInterface):
    def __init__(self, sim_host: str = '127.0.0.1', sim_port: int = default_port,
                 sync_objects: list[CohortInterface] = None, log_level: int = logging.INFO, logfile: str = None):
        super().__init__(log_level=log_level, logfile=logfile)
        self.client = SimClient(callback=self.state_to_queue(), logger=self.logger)
        self.queue = Queue(maxsize=1)
        self.state = None
        self.can_reset = False
        self.paused = False
        self.tick = 0
        self.sync_objects = sync_objects
        if sync_objects is None:
            self.sync_objects = []
        self.reset_handler: Optional[Callable] = lambda: None  # additional work to do at reset, set externally

        self.thread = threading.Thread(target=self.client.run, args=(sim_host, sim_port))
        self.thread.start()
        atexit.register(self.interrupt)

    def register_reset_handler(self, handler: Optional[Callable]):
        self.reset_handler = handler

    @property
    def resolution(self):
        return self.client.resolution

    @resolution.setter
    def resolution(self, res):
        self.client.resolution = res

    def interrupt(self):
        self.client.halt = True
        if self.client.sock is not None:
            self.client.sock.close()
        self.thread.join()

    def state_to_queue(self):
        def cb(state):
            if state is not None:
                self.tick = self.client.tick
                self.queue.put(state, block=True, timeout=None)
        return cb

    def update(self, initial=False):
        """May be called only once per timestep, i.e. synced with UI, synchronizes others"""
        self.state = self.queue.get()
        for obj in self.sync_objects:
            obj.tick = self.tick
        if self.state.blank:
            self.paused = True
            for obj in self.sync_objects:
                obj.paused = self.paused
            self.can_reset = True
            while self.paused:
                time.sleep(0.1)
            self.can_reset = False
            self.reset_handler()
            for obj in self.sync_objects:
                obj.paused = self.paused
