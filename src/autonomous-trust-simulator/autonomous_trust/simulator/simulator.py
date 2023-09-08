import os.path
import socket
import time
from datetime import timedelta

from .peer.peer import Peer
from .peer.position import GeoPosition, Position
from .sim_data import SimConfig, SimState, Map, Matrix
from .sim_client import SimClient
from . import net_util as net


class Simulator(net.SelectServer):
    header_fmt = SimClient.header_fmt
    time_resolution = 'seconds'
    cadence = 1

    def __init__(self, cfg_file_path: str, max_time_steps: int = 100):
        super().__init__()
        self.max_time_steps = max_time_steps

        if not os.path.isabs(cfg_file_path):
            cfg_file_path = os.path.join(os.path.dirname(__file__), cfg_file_path)
        with open(cfg_file_path, 'r') as cfg_file:
            self.cfg = SimConfig.load(cfg_file.read())
        self.start_time = self.cfg.time
        self.peers: dict[str, Peer] = {}
        for peer_info in self.cfg.peers:
            self.peers[peer_info.uuid] = Peer(self.max_time_steps, self.cadence, peer_info.path)
        self.state = SimState()
        self.pre_state: dict[int, tuple[GeoPosition, float, Map, Matrix]] = {}

        # precompute network changes
        for tick in range(1, self.max_time_steps+1):
            mapp: Map = {}
            matrix: Matrix = {}
            max_dist = 0
            for peer in self.cfg.peers:
                mapp[peer.uuid] = self.peers[peer.uuid].move(tick)  # position
            # all must move first
            for peer in self.cfg.peers:
                matrix[peer.uuid] = {}
                for other in self.cfg.peers:
                    if peer == other:
                        continue
                    matrix[peer.uuid][other.uuid] = peer.can_reach(other)  # connectivity
                    dist = mapp[peer.uuid].distance(mapp[other.uuid])
                    if max_dist < dist:
                        max_dist = dist
            center: GeoPosition = Position.middle(list(mapp.values())).convert(GeoPosition)
            self.pre_state[tick] = (center, max_dist, mapp, matrix)
        self.tick = 0

    def recv_data(self, sock: socket.socket):
        sock.recv(1024)  # should be empty
        message = self.prepend_header(self.header_fmt, self.state.to_yaml_string())
        sock.sendall(message)

    def send_data(self, sock: socket.socket):
        pass  # do nothing

    def process(self, **kwargs):
        while not self.halt and self.tick <= self.max_time_steps:
            cur_time = self.start_time + timedelta(**{self.time_resolution: self.tick})
            self.state = SimState(cur_time, *self.pre_state[self.tick])
            self.tick += 1
            time.sleep(self.cadence)


if __name__ == '__main__':  # FIXME remove
    Simulator('config.cfg').run(8888)  # FIXME create config
