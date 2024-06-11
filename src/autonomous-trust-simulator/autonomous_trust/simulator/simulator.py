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

import logging
import os.path
import socket
import struct
import sys
import time
import traceback
from datetime import timedelta

from autonomous_trust.core import Configuration
from autonomous_trust.services.peer.position import GeoPosition, UTMPosition
from .peer.peer import PeerMovement
from .sim_data import SimConfig, SimState, Map, Matrix, Ident
from .sim_client import SimClient
from . import sim_net as net
from . import default_port, default_steps


class Simulator(net.SelectServer):
    """Given a scenario config, simulate peer movement and connectivity."""
    seq_fmt = SimClient.seq_fmt
    time_resolution = 'seconds'

    def __init__(self, cfg_file_path: str, max_time_steps: int = None, geo: bool = False, precompute: bool = False,
                 log_level: int = logging.INFO, logfile: str = None, **kwargs):
        if max_time_steps is None:
            max_time_steps = default_steps
        if logfile is None:
            handler = logging.StreamHandler(sys.stdout)
        else:
            if not os.path.isabs(logfile):
                cfg_dir = Configuration.get_cfg_dir()
                if not os.path.exists(cfg_dir):
                    os.makedirs(cfg_dir, exist_ok=True)
                logfile = os.path.join(cfg_dir, logfile)
            handler = logging.FileHandler(logfile)
        handler.setFormatter(logging.Formatter('%(asctime)s.%(msecs)03d - %(levelname)s %(message)s',
                                               '%Y-%m-%d %H:%M:%S'))
        handler.setLevel(log_level)
        self.logger = logging.getLogger(__name__)
        self.logger.addHandler(handler)
        self.logger.setLevel(log_level)
        super().__init__(self.logger, **kwargs)

        self.max_time_steps = max_time_steps
        self.return_geo = geo
        self.precompute = precompute
        if not os.path.exists(cfg_file_path) and not os.path.isabs(cfg_file_path):
            cfg_file_path = os.path.join(os.path.dirname(__file__), cfg_file_path)
        self.cfg_file = cfg_file_path
        with open(cfg_file_path, 'r') as cfg_file:
            self.cfg = SimConfig.load(cfg_file.read())
        self.tick = 0
        self.peers: dict[str, PeerMovement] = {}
        self.start_time = self.cfg.start
        self.end_time = self.cfg.end
        self.cadence = (self.end_time - self.start_time).total_seconds() / self.max_time_steps
        self.state = SimState()
        self.pre_state: dict[int, tuple[GeoPosition, float, Map, Matrix, list[str]]] = {}
        if self.precompute:
            self.precompute_network()
        else:
            self.init_computation()
        self.active_len = 0

    def init_computation(self):
        self.tick = 0
        self.pre_state = {}
        self.peers = {}
        for peer_info in self.cfg.peers:
            self.peers[peer_info.uuid] = PeerMovement(self.start_time, self.cadence, peer_info.path_list)

    def compute_step(self, tick):
        current_time = self.start_time + timedelta(seconds=self.cadence * tick)
        mapp: Map = {}
        matrix: Matrix = {}
        max_dist = 0
        active = []
        for peer in self.cfg.peers:
            if peer.initial_time <= current_time <= peer.last_seen:
                active.append(peer.uuid)
            position, speed = self.peers[peer.uuid].move(tick)
            mapp[peer.uuid] = Ident(position, speed, peer.kind, peer.nickname)
        # all must move first before looping for connectivity
        for peer in self.cfg.peers:
            if current_time < peer.initial_time or current_time > peer.last_seen or \
                    mapp[peer.uuid].position is None:
                continue
            matrix[peer.uuid] = {}
            for other in self.cfg.peers:
                if peer == other or current_time < other.initial_time or current_time > other.last_seen or \
                        mapp[other.uuid].position is None:
                    continue
                matrix[peer.uuid][other.uuid] = peer.can_reach(other)  # connectivity
                dist = mapp[peer.uuid].position.distance(mapp[other.uuid].position)
                if max_dist < dist:
                    max_dist = dist
        mid = UTMPosition.middle(list(map(lambda x: x.position, [v for v in mapp.values() if v.position is not None])))
        center: GeoPosition = mid.convert(GeoPosition)
        return center, max_dist, mapp, matrix, active

    def precompute_network(self):
        self.init_computation()
        for tick in range(0, self.max_time_steps):
            self.pre_state[tick] = self.compute_step(tick)

    def send_state(self, tick, sock: socket.socket):
        cur_time = self.start_time + timedelta(**{self.time_resolution: tick * self.cadence})
        try:
            if self.precompute:
                state = SimState(cur_time, *self.pre_state[tick])
            else:
                if tick > self.max_time_steps:
                    raise KeyError
                state = SimState(cur_time, *self.compute_step(tick))
            self.active_len = len(state.active)
        except KeyError as e:
            self.send_all(sock, 'end'.encode())
            self.init_computation()
            return
        if self.return_geo:
            state = state.convert()
        data = state.to_yaml_string().encode()
        self.send_all(sock, data)

    def recv_data(self, sock: socket.socket):  # asynchronous
        seq_len = struct.calcsize(self.seq_fmt)
        seq_data = self._read(sock, seq_len)
        seq_num, num_steps = struct.unpack(self.seq_fmt, seq_data)
        if seq_num > 0:
            self.tick = seq_num - 1  # convert to zero-base
        if num_steps > 0:  # new resolution
            self.max_time_steps = num_steps
            if self.precompute:
                self.precompute_network()
        self.send_state(self.tick, sock)
        return seq_num

    def send_data(self, sock: socket.socket):
        pass  # do nothing

    def process(self, **kwargs):  # synchronous alternative
        while not self.halt: # and self.tick < self.max_time_steps:  # FIXME continuous
            if not isinstance(self, net.SelectServer):
                for client_socket in self.clients:
                    self.send_state(self.tick, client_socket)
                self.tick += 1
            time.sleep(self.cadence)
        self.halt = True

    def run(self, port: int, **kwargs):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        self.logger.info('Simulation at %s:%d for %s' % (s.getsockname()[0], port, self.cfg_file))
        s.close()
        super().run(port, **kwargs)


if __name__ == '__main__':
    from .config import create_config

    log_lvl = logging.INFO
    steps = default_steps
    if len(sys.argv) > 2:
        steps = int(sys.argv[2])
    if len(sys.argv) > 1:
        sim_config = sys.argv[1]
    else:
        sim_config = create_config('full')

    try:
        Simulator(sim_config, steps, log_level=log_lvl).run(default_port)
    finally:
        if os.path.exists(sim_config):
            os.remove(sim_config)
