import atexit
import logging
import os
import random
import threading
import time
from collections import deque
from queue import Queue, Empty

from autonomous_trust.inspector.peer.daq import PeerDataAcq, CohortInterface
from autonomous_trust.services.peer.metadata import PeerData
from autonomous_trust.services.network_statistics import NetworkStats
from .mock_sources import SimVideoSource, SimDataSource
from .. import default_port
from ..sim_client import SimClient
from ..sim_data import SimState

"""
Mock cohort, strictly for interactive testing of the UI.
This file is for the 'false-sim', i.e. autonomous_trust.simulator.dash_components.__main__
"""

def clamp(n, min_n, max_n):
    return max(min(max_n, n), min_n)


class MockIdentity(object):
    def __init__(self, nickname, fullname):
        self.nickname = nickname
        self.fullname = fullname


class SimCohort(CohortInterface):
    """Simplified stand-in for AutonomousTrust clearinghouse process"""

    def __init__(self, sim_host: str = '127.0.0.1', sim_port: int = default_port,
                 log_level: int = logging.INFO, logfile: str = None,
                 disable_video: bool = False, disable_data: bool = False):
        super().__init__(log_level=log_level, logfile=logfile)
        self.halt = False
        self.client = SimClient(callback=self.state_to_queue(), logger=self.logger)
        self.thread = threading.Thread(target=self.client.run, args=(sim_host, sim_port), kwargs={'cadence': 1})
        self.queue = Queue(maxsize=1)
        self.state = None
        self.servers = []
        self.threads = []
        self.vid_map = {0: 15, 1: 17, 2: 18, 3: 20, 4: 21}
        self.disables = []
        #if disable_video:
        #    self.disables.append('video')
        if disable_data:
            self.disables.append('data')
        atexit.register(self.interrupt)

    def start(self):
        self.thread.start()

    def stop(self):
        self.client.halt = True

    def interrupt(self):
        for serv in self.servers:
            serv.halt = True
        # for thread in self.threads:
        #    thread.join()
        self.client.halt = True
        if self.client.sock is not None:
            self.client.sock.close()
        # self.thread.join()

    def state_to_queue(self):
        def cb(state):
            if state is not None:
                self.queue.put(state, block=True, timeout=None)

        return cb

    def populate_data(self):
        while not self.halt:
            for idx, uuid in enumerate(self.state.peers):
                if uuid in self.peers:
                    # FIXME reputation
                    if len(self.peers[uuid].reputation_history) == 0:
                        self.peers[uuid].reputation_history.append(.5)
                    else:
                        prev = self.peers[uuid].reputation_history[-1]
                        next_val = clamp(prev + (random.uniform(-1., 1,) * .01), 0., 1.)
                        self.peers[uuid].reputation_history.append(next_val)
                    for uuid2 in self.state.peers:
                        if uuid != uuid2:
                            up = random.random() * 100
                            dn = random.random() * 100
                            if uuid2 not in self.peers[uuid].network_history:
                                self.peers[uuid].network_history[uuid2] = deque([], PeerDataAcq.max_history)
                                self.peers[uuid].network_history[uuid2].append(NetworkStats(up, dn, int(up), int(dn), 0, 0))
                            else:
                                prev = self.peers[uuid].network_history[uuid2][-1]
                                self.peers[uuid].network_history[uuid2].append(NetworkStats(up, dn, prev.sent + int(up), prev.recv + int(dn), 0, 0))
            time.sleep(1)

    def acquire_data(self):
        try:
            self.state: SimState = self.queue.get(block=False)
        except Empty:
            return
        if self.state is None:
            return
        if self.state.blank:
            self.state = None
            return
        thread = threading.Thread(target=self.populate_data)
        thread.start()
        self.threads.append(thread)
        self._time = self.state.time
        self._center = self.state.center
        for idx, uuid in enumerate(self.state.peers):
            if uuid not in self.peers:
                peer_id = self.state.peers[uuid]
                vid_q = deque(maxlen=1)
                data_q = deque(maxlen=1)

                # intentionally abusing daq object
                # FIXME merge video and data sources
                video = None
                if idx in self.vid_map:
                    vid_dir = os.path.join(os.path.dirname(__file__),
                                           '../../../examples/mission/participant/var/at/video')
                                           #'../../../../examples/mission/participant/var/at/video')
                    vid = os.path.abspath(os.path.join(vid_dir, '220505_02_MTB_4k_0%d.mp4' % self.vid_map[idx]))
                    video = SimVideoSource(vid)
                    if 'video' not in self.disables:
                        self.servers.append(video)
                        thread = threading.Thread(target=video.run)  # FIXME extra processing
                        thread.start()
                        vid_q = video.buffer
                        print('serve video %s' % vid)
                        self.threads.append(thread)
                data = SimDataSource()
                if 'data' not in self.disables:
                    thread = threading.Thread(target=data.run)
                    thread.start()
                    data_q = data.buffer
                    self.threads.append(thread)
                peer_data = PeerData(self.state.time, self.state.center, 0., peer_id.kind, 'mock', 1)
                self.peers[uuid] = PeerDataAcq(uuid, idx, MockIdentity(peer_id.nickname, peer_id.nickname),  # noqa intentional
                                               peer_data, self, vid_q, data_q)
                if video is not None:
                    video.connect(self.peers[uuid])
            self.peers[uuid].active = uuid in self.state.active  # strictly a simulation thing
            self.peers[uuid].metadata.time = self.state.time
            if self.state.peers[uuid].position is not None:
                self.peers[uuid].metadata.position = self.state.peers[uuid].position
            if self.state.peers[uuid].speed is not None:
                self.peers[uuid].metadata.speed = self.state.peers[uuid].speed
