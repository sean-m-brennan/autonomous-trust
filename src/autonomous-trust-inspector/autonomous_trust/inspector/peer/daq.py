import threading
from datetime import datetime
from queue import Queue, Empty

from autonomous_trust.inspector.peer.position import Position
from autonomous_trust.simulator.sim_client import SimClient, SimSync  # FIXME remove


class PeerDataAcq(object):
    """AT network connection to peer, conditionally acquires data, also locally tracks trust"""
    def __init__(self, uuid):
        # FIXME connection to peer
        self.uuid = uuid
        self.kind = 'microdrone'
        if uuid == 'df5a182d-852e-4481-bd97-22218e732368':  # FIXME of course
            self.kind = 'recon'
        self.name = ''
        self.nickname = ''
        self.network_history: dict[str, list[float]] = {}
        self.others = []
        self.position = Position(0, 0)  # FIXME needs initial
        self.time = datetime.now()
        # FIXME need dynamic time and position

    def trust_matrix(self):
        # FIXME compute trust levels per each other
        return {}


class Cohort(SimSync):
    def __init__(self, peer_list: list[PeerDataAcq]):
        super().__init__()
        sim_host: str = '127.0.0.1'  # FIXME
        sim_port: int = 8778

        self.peers = {}
        for peer in peer_list:
            self.peers[peer.uuid] = peer
        self._time = datetime.now()  # FIXME
        self._center = None

        # FIXME temporary
        self.client = SimClient(callback=self.state_to_queue())
        self.queue = Queue(maxsize=1)
        self.thread = threading.Thread(target=self.client.run, args=(sim_host, sim_port))
        self.thread.start()

    def state_to_queue(self):  # FIXME temporary
        def cb(state):
            if state is not None:
                self.queue.put(state, block=True, timeout=None)
        return cb

    def update(self, block: bool = True):
        if 1 < self.tick < self.client.tick:
            return self  # may be called asynchronously

        # ####################
        if not self.paused:
            if block:
                state = self.queue.get()
            else:
                try:
                    state = self.queue.get_nowait()
                except Empty:
                    return self
            if state.blank:
                self.paused = True
            self._time = state.time
            self._center = state.center
            for uuid in state.peers:
                if uuid not in self.peers:
                    self.peers[uuid] = PeerDataAcq(uuid)
                self.peers[uuid].position = state.peers[uuid]
        # FIXME properly update time, position, data across all peers (not the above)
        return self

    @property
    def center(self) -> Position:
        # FIXME compute collective center
        return self._center

    @property
    def time(self) -> datetime:
        # FIXME compute collective datetime
        return self._time
