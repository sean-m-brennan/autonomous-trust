import atexit
import logging
import os
import threading
from queue import Queue

from autonomous_trust.inspector.peer.daq import PeerDataAcq, CohortInterface
from autonomous_trust.services.peer.metadata import PeerData
from .mock_sources import SimVideoSource, SimDataSource
from .. import default_port
from ..sim_client import SimClient

"""
Mock cohort, strictly for interactive testing of the UI.
This file is for the 'false-sim', i.e. autonomous_trust.simulator.dash_components.__main__
"""


class MockIdentity(object):
    def __init__(self, nickname, fullname):
        self.nickname = nickname
        self.fullname = fullname


class SimCohort(CohortInterface):
    """Simplified stand-in for AutonomousTrust clearinghouse process"""
    def __init__(self, sim_host: str = '127.0.0.1', sim_port: int = default_port,
                 log_level: int = logging.INFO, logfile: str = None):
        super().__init__(log_level=log_level, logfile=logfile)
        self.halt = False
        self.client = SimClient(callback=self.state_to_queue(), logger=self.logger)
        self.queue = Queue(maxsize=1)
        self.thread = threading.Thread(target=self.client.run, args=(sim_host, sim_port))
        self.thread.start()
        self.current_tick = 0
        self.state = None
        self.servers = []
        self.threads = []
        self.vid_map = {0: 15, 1: 17, 2: 18, 3: 20, 4: 21}
        atexit.register(self.interrupt)

    def interrupt(self):
        for serv in self.servers:
            serv.halt = True
        for thread in self.threads:
            thread.join()
        self.client.halt = True
        if self.client.sock is not None:
            self.client.sock.close()
        self.thread.join()

    def state_to_queue(self):
        def cb(state):
            if state is not None:
                self.queue.put(state, block=True, timeout=None)
        return cb

    def update(self):  # called many times per step
        if self.current_tick <= self.tick:
            self.state = self.queue.get()
            self.current_tick += 1
        if self.state is None:
            return
        if self.state.blank:
            self.current_tick = 0
            self.state = None
            return
        self.time = self.state.time
        self.center = self.state.center
        for idx, uuid in enumerate(self.state.peers):
            if uuid not in self.peers:
                # intentionally abusing daq object
                vid_dir = os.path.join(os.path.dirname(__file__),
                                       '../../../../examples/mission/participant/var/at/video')
                vid = os.path.join(vid_dir, '220505_02_MTB_4k_0%d.mp4' % self.vid_map[idx])
                video = SimVideoSource(os.path.abspath(vid))
                data = SimDataSource()
                self.servers.append(video)
                thread = threading.Thread(target=video.run)  # FIXME extra processing
                thread.start()
                self.threads.append(thread)
                thread = threading.Thread(target=data.run)
                thread.start()
                self.threads.append(thread)
                kind = 'microdrone'
                if idx == 3:
                    kind = 'recon'
                self.peers[uuid] = PeerDataAcq(uuid, MockIdentity('nickname', 'fullname'),
                                               PeerData(self.state.time, self.state.center, kind), self,
                                               video.queue, data.queue)
            self.peers[uuid].metadata.time = self.state.time
            self.peers[uuid].metadata.position = self.state.peers[uuid]
