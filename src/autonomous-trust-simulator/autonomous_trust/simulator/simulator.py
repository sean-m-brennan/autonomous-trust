import os.path
import socket
import struct
import time
from datetime import timedelta

from .peer.peer import Peer
from .peer.position import GeoPosition, UTMPosition
from .sim_data import SimConfig, SimState, Map, Matrix
from .sim_client import SimClient
from . import net_util as net

from .peer.dash_config import create_config


class Simulator(net.SelectServer):
    seq_fmt = SimClient.seq_fmt
    time_resolution = 'seconds'
    cadence = 1

    # FIXME logging + info output

    def __init__(self, cfg_file_path: str, max_time_steps: int = 100,
                 geo: bool = False, debug: bool = False):
        super().__init__(debug)
        self.max_time_steps = max_time_steps
        self.return_geo = geo

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
        for tick in range(0, self.max_time_steps):
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
            mid = UTMPosition.middle(list(mapp.values()))
            center: GeoPosition = mid.convert(GeoPosition)
            self.pre_state[tick] = (center, max_dist, mapp, matrix)
        self.tick = 0

    def send_state(self, tick, sock: socket.socket):
        cur_time = self.start_time + timedelta(**{self.time_resolution: tick})
        try:
            state = SimState(cur_time, *self.pre_state[tick])
        except KeyError:
            self.send_all(sock, 'end'.encode())
            return
        if self.return_geo:
            state = state.convert()
        data = state.to_yaml_string().encode()
        self.send_all(sock, data)

    def recv_data(self, sock: socket.socket):  # asynchronous
        seq_len = struct.calcsize(self.seq_fmt)
        try:
            seq_data = self._read(sock, seq_len)
        except net.ReceiveError:
            return None
        seq_num = struct.unpack(self.seq_fmt, seq_data)[0]
        self.send_state(seq_num, sock)
        return seq_num

    def send_data(self, sock: socket.socket):
        pass  # do nothing

    def process(self, **kwargs):  # synchronous alternative
        while not self.halt and self.tick < self.max_time_steps:
            if not isinstance(self, net.SelectServer):
                for client_socket in self.clients:
                    self.send_state(self.tick, client_socket)
                self.tick += 1
            time.sleep(self.cadence)
        self.halt = True


if __name__ == '__main__':
    sim_config = create_config('full')
    try:
        Simulator(sim_config, 120).run(8778)
    finally:
        if os.path.exists(sim_config):
            os.remove(sim_config)
