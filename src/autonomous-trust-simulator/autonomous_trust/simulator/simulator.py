import logging
import os.path
import socket
import struct
import sys
import time
from datetime import timedelta

from autonomous_trust.services.peer.position import GeoPosition, UTMPosition
from .peer.peer import PeerMovement
from .sim_data import SimConfig, SimState, Map, Matrix
from .sim_client import SimClient
from . import sim_net as net


class Simulator(net.SelectServer):
    """Given a scenario config, simulate peer movement and connectivity."""
    seq_fmt = SimClient.seq_fmt
    time_resolution = 'seconds'
    cadence = 1

    def __init__(self, cfg_file_path: str, max_time_steps: int = 100, geo: bool = False,
                 log_level: int = logging.INFO, logfile: str = None):
        if logfile is None:
            handler = logging.StreamHandler(sys.stdout)
        else:
            handler = logging.FileHandler(logfile)
        handler.setFormatter(logging.Formatter('%(asctime)s.%(msecs)03d - %(levelname)s %(message)s',
                                               '%Y-%m-%d %H:%M:%S'))
        handler.setLevel(log_level)
        self.logger = logging.getLogger(__name__)
        self.logger.addHandler(handler)
        super().__init__(self.logger)

        self.max_time_steps = max_time_steps
        self.return_geo = geo
        if not os.path.isabs(cfg_file_path):
            cfg_file_path = os.path.join(os.path.dirname(__file__), cfg_file_path)
        with open(cfg_file_path, 'r') as cfg_file:
            self.cfg = SimConfig.load(cfg_file.read())
        self.peers: dict[str, PeerMovement] = {}
        self.start_time = self.cfg.time
        self.state = SimState()
        self.pre_state: dict[int, tuple[GeoPosition, float, Map, Matrix]] = {}
        self.tick = 0
        self.precompute_network()

    def precompute_network(self):
        self.pre_state = {}
        self.peers = {}
        for peer_info in self.cfg.peers:
            self.peers[peer_info.uuid] = PeerMovement(self.max_time_steps, self.cadence, peer_info.path)
        for tick in range(0, self.max_time_steps):
            mapp: Map = {}
            matrix: Matrix = {}
            max_dist = 0
            for peer in self.cfg.peers:
                mapp[peer.uuid] = self.peers[peer.uuid].move(tick)  # position
            # all must move first before looping for connectivity
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
        self.logger.info('Ready')

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
        seq_num, steps = struct.unpack(self.seq_fmt, seq_data)
        if steps > 0:  # new resolution
            self.max_time_steps = steps
            self.precompute_network()
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
    from .config import create_config

    sim_config = create_config('full')
    try:
        Simulator(sim_config, 120).run(8778)
    finally:
        if os.path.exists(sim_config):
            os.remove(sim_config)
