# ******************
#  Copyright 2023 TekFive, Inc., Sean M. Brennan, and contributors
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
import math
import os.path
import random
import socket
import struct
import sys
import time
import traceback
from datetime import timedelta

from autonomous_trust.core import Configuration
from autonomous_trust.services.peer.position import GeoPosition, UTMPosition
from .peer.peer import PeerMovement
from .radio.space_link import free_space_path_loss_db, sun_occluded, light_delay_s
from .sim_data import SimConfig, SimState, Map, Matrix, SignalMatrix, DelayMatrix, GatewayMap, Ident
from .sim_client import SimClient
from . import sim_net as net
from . import default_port, default_steps


class Simulator(net.SelectServer):
    """Given a scenario config, simulate peer movement and connectivity."""
    seq_fmt = SimClient.seq_fmt
    time_resolution = 'seconds'

    # Default finite comms-range cutoff in metres (ISSUES.md §6). Applied when
    # a scenario leaves SimConfig.max_range_m unset (opt-OUT: finite range is
    # the default). 200 km is generous enough to leave every current
    # terrestrial demo fully connected (the widest, dod_mission, spans ~135 km)
    # while bounding the legacy inverse-square model's effectively-infinite
    # reach so the reachability graph reflects real radio range. Beyond this
    # distance a pair is treated as unreachable. Set max_range_m <= 0 in a
    # scenario to disable the cutoff entirely.
    DEFAULT_MAX_RANGE_M = 200_000.0

    # Periodic heartbeat in send_state: log one INFO line every N ticks
    # so operators can tell the simulator is alive and which sim-time
    # it's on. The simulator otherwise only logs on connect/disconnect
    # and runs entirely in response to client polls, so a busy demo
    # produces no progress output. Override via AT_SIM_HEARTBEAT_TICKS=N
    # at startup; 0 disables.
    _HEARTBEAT_TICKS = int(os.environ.get('AT_SIM_HEARTBEAT_TICKS', '30'))

    def __init__(self, cfg_file_path: str, max_time_steps: int = None, geo: bool = False, precompute: bool = False,
                 log_level: int = logging.INFO, logfile: str = None, **kwargs):
        if max_time_steps is None:
            max_time_steps = default_steps
        fmt = logging.Formatter('%(asctime)s.%(msecs)03d - %(levelname)s %(message)s',
                                '%Y-%m-%d %H:%M:%S')
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(log_level)
        # Always attach a stdout handler so `kubectl logs` / `docker logs` /
        # Tilt's per-pod UI sees simulator progress (heartbeat ticks,
        # new-client/disconnect lines). When --log <file> is also passed,
        # the file handler is added alongside; previously file-mode
        # replaced stdout entirely, leaving the deployment "silent".
        stdout_handler = logging.StreamHandler(sys.stdout)
        stdout_handler.setFormatter(fmt)
        stdout_handler.setLevel(log_level)
        self.logger.addHandler(stdout_handler)
        if logfile is not None:
            if not os.path.isabs(logfile):
                cfg_dir = Configuration.get_cfg_dir()
                if not os.path.exists(cfg_dir):
                    os.makedirs(cfg_dir, exist_ok=True)
                logfile = os.path.join(cfg_dir, logfile)
            file_handler = logging.FileHandler(logfile)
            file_handler.setFormatter(fmt)
            file_handler.setLevel(log_level)
            self.logger.addHandler(file_handler)
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
        self.pre_state: dict[int, tuple[GeoPosition, float, Map, Matrix, list[str], SignalMatrix, DelayMatrix, GatewayMap]] = {}
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

    def _effective_max_range(self) -> float:
        """Finite comms-range cutoff in metres (ISSUES.md §6, opt-OUT).

        `SimConfig.max_range_m` unset (None) -> ``DEFAULT_MAX_RANGE_M``; a
        positive value overrides it; a value <= 0 DISABLES the cutoff, returning
        ``inf`` to restore the legacy all-pairs, infinite-range behaviour.
        """
        r = getattr(self.cfg, 'max_range_m', None)
        if r is None:
            return self.DEFAULT_MAX_RANGE_M
        if r <= 0:
            return math.inf
        return float(r)

    @staticmethod
    def _grid_candidate_pairs(eligible, mapp, cell):
        """Yield ordered (peer, other) pairs that a finite-range link could
        connect, using a uniform spatial grid (cell edge = comms range).

        Any pair whose separation is <= ``cell`` differs by at most one grid
        index on each axis, so it is guaranteed to be emitted; distant pairs are
        never enumerated. This is the O(n + candidates) replacement for the
        O(n^2) all-pairs scan. Correctness never depends on the grid — the
        caller still applies the exact distance/``can_reach`` test — so if
        positions are not planar metres (e.g. raw GeoPosition), the grid merely
        degrades toward O(n^2) while staying correct. Keyed on position .x/.y
        (UTM easting/northing for the simulator's internal frame).
        """
        grid: dict[tuple[int, int], list] = {}
        for peer in eligible:
            pos = mapp[peer.uuid].position
            grid.setdefault((int(pos.x // cell), int(pos.y // cell)), []).append(peer)
        for peer in eligible:
            pos = mapp[peer.uuid].position
            cx, cy = int(pos.x // cell), int(pos.y // cell)
            for dx in (-1, 0, 1):
                for dy in (-1, 0, 1):
                    for other in grid.get((cx + dx, cy + dy), ()):
                        if other.uuid != peer.uuid:
                            yield peer, other

    def _connectivity_space(self, eligible, mapp, matrix, sig_quality, delay_matrix):
        """Space mode: dynamic FSPL + light-delay for EVERY pair. Interplanetary
        links span AUs, so no range pruning applies -- this stays the full
        all-pairs computation and emits a dense matrix (True/False per pair)."""
        max_dist = 0
        for peer in eligible:
            matrix[peer.uuid] = {}
            sig_quality[peer.uuid] = {}
            delay_matrix[peer.uuid] = {}
            for other in eligible:
                if peer.uuid == other.uuid:
                    continue
                dist = mapp[peer.uuid].position.distance(mapp[other.uuid].position)
                if max_dist < dist:
                    max_dist = dist
                delay_matrix[peer.uuid][other.uuid] = light_delay_s(dist)
                if self.cfg.sun_position and sun_occluded(
                        mapp[peer.uuid].position, mapp[other.uuid].position,
                        self.cfg.sun_position):
                    # Sun occultation: link blocked
                    fspl = 999.0
                else:
                    fspl = free_space_path_loss_db(dist, self.cfg.comm_freq_hz or 8.4e9)
                sig_quality[peer.uuid][other.uuid] = fspl
                matrix[peer.uuid][other.uuid] = peer.can_reach(other, fspl)
        return max_dist

    def _connectivity_terrestrial(self, eligible, mapp, matrix, sig_quality, path_loss):
        """Terrestrial mode (ISSUES.md §6): emit a SPARSE, reachable-only matrix.

        With a finite comms range (the opt-out default) a uniform spatial grid
        limits candidate pairs to spatial neighbours, so cost scales with actual
        connectivity rather than O(n^2); pairs beyond the range are simply
        omitted (absent == unreachable, which routing.py default-denies). With
        the range disabled (max_range_m <= 0) it falls back to the exact
        all-pairs scan. Within range, reachability is unchanged from before
        (per-pair `can_reach`, terrain path-loss when available).
        """
        max_range = self._effective_max_range()
        finite = not math.isinf(max_range)
        if finite:
            candidate_pairs = self._grid_candidate_pairs(eligible, mapp, max_range)
        else:
            candidate_pairs = ((peer, other) for peer in eligible for other in eligible
                               if peer.uuid != other.uuid)
        max_dist = 0
        for peer, other in candidate_pairs:
            dist = mapp[peer.uuid].position.distance(mapp[other.uuid].position)
            if finite and dist > max_range:
                continue  # beyond radio range -> unreachable (omitted == sparse)
            if max_dist < dist:
                max_dist = dist
            terrain_loss = None
            if path_loss is not None:
                peer_row = path_loss.get(peer.uuid)
                if peer_row is not None:
                    terrain_loss = peer_row.get(other.uuid)
            if peer.can_reach(other, terrain_loss):
                matrix.setdefault(peer.uuid, {})[other.uuid] = True
                if terrain_loss is not None:
                    sig_quality.setdefault(peer.uuid, {})[other.uuid] = terrain_loss
        return max_dist

    def compute_step(self, tick):
        current_time = self.start_time + timedelta(seconds=self.cadence * tick)
        mapp: Map = {}
        matrix: Matrix = {}
        sig_quality: SignalMatrix = {}
        delay_matrix: DelayMatrix = {}
        active = []
        path_loss = self.cfg.path_loss_matrix
        for peer in self.cfg.peers:
            if peer.initial_time <= current_time <= peer.last_seen:
                active.append(peer.uuid)
            position, speed = self.peers[peer.uuid].move(tick)
            mapp[peer.uuid] = Ident(position, speed, peer.kind, peer.petname)
        # All must move first before computing connectivity. Reachability is
        # computed only among peers active in this window and with a known
        # position (the "eligible" set).
        eligible = [peer for peer in self.cfg.peers
                    if peer.initial_time <= current_time <= peer.last_seen
                    and mapp[peer.uuid].position is not None]
        if self.cfg.space_mode:
            max_dist = self._connectivity_space(eligible, mapp, matrix, sig_quality, delay_matrix)
        else:
            max_dist = self._connectivity_terrestrial(eligible, mapp, matrix, sig_quality, path_loss)

        positions = [v.position for v in mapp.values() if v.position is not None]
        mid = UTMPosition.middle(positions)
        if self.cfg.space_mode:
            # Space mode uses dummy UTM zone with AU-scale coordinates;
            # utm.to_latlon would crash on these values.  Return a sentinel
            # GeoPosition so downstream serialization (which expects GeoPosition)
            # still works without hitting the utm library.
            center = GeoPosition(0.0, 0.0, 0.0)
        else:
            center = mid.convert(GeoPosition)
        # Build gateway map: which nodes have active internet uplinks this tick
        gateways: GatewayMap = {}
        for peer in self.cfg.peers:
            if peer.uplink is not None and random.random() < peer.uplink.reliability:
                gateways[peer.uuid] = peer.uplink

        return center, max_dist, mapp, matrix, active, sig_quality, delay_matrix, gateways

    def precompute_network(self):
        self.init_computation()
        for tick in range(0, self.max_time_steps):
            self.pre_state[tick] = self.compute_step(tick)

    @staticmethod
    def _make_state(cur_time, step_result):
        center, max_dist, mapp, matrix, active, sig_quality, delay, gateways = step_result
        gateway_count = len(gateways)
        agg_down = sum(gw.bandwidth_down_mbps for gw in gateways.values())
        agg_up = sum(gw.bandwidth_up_mbps for gw in gateways.values())
        active_count = len(active) if active else 1
        per_node = agg_down / active_count if active_count > 0 else 0.0
        return SimState(cur_time, center, max_dist, mapp, matrix, active,
                        signal_quality=sig_quality, delay=delay,
                        gateways=gateways, gateway_count=gateway_count,
                        aggregate_uplink_down_mbps=agg_down,
                        aggregate_uplink_up_mbps=agg_up,
                        per_node_down_mbps=per_node)

    def send_state(self, tick, sock: socket.socket):
        cur_time = self.start_time + timedelta(**{self.time_resolution: tick * self.cadence})
        try:
            if self.precompute:
                state = self._make_state(cur_time, self.pre_state[tick])
            else:
                if tick > self.max_time_steps:
                    raise KeyError
                state = self._make_state(cur_time, self.compute_step(tick))
            self.active_len = len(state.active)
        except KeyError as e:
            self.send_all(sock, 'end'.encode())
            self.init_computation()
            return
        # Heartbeat: one INFO line per _HEARTBEAT_TICKS so operators can
        # confirm the simulator is alive and which sim-time it's on.
        # Logged before the wire send so the line lands even if the
        # client socket has gone away mid-tick (send_all errors get
        # swallowed by SelectServer's listen loop).
        if (self._HEARTBEAT_TICKS > 0
                and tick > 0 and tick % self._HEARTBEAT_TICKS == 0):
            self.logger.info(
                'tick=%d sim_time=%s active_peers=%d clients=%d max_steps=%d',
                tick, cur_time.isoformat(timespec='seconds'),
                len(state.active or []), len(self.clients),
                self.max_time_steps,
            )
        if self.return_geo:
            state = state.convert()
        data = state.to_json_string().encode()
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
        # Supported mode: continuous run until `self.halt` is set (decided
        # 2026-07-01). The synchronous server streams state open-endedly for
        # live demos and does NOT self-terminate at `max_time_steps`; callers
        # stop it via `halt`. (The asynchronous `send_state` path is the one
        # that bounds itself at `max_time_steps` and emits 'end'.)
        while not self.halt:
            if not isinstance(self, net.SelectServer):
                for client_socket in self.clients:
                    self.send_state(self.tick, client_socket)
                self.tick += 1
            time.sleep(self.cadence)
        self.halt = True

    def run(self, port: int, **kwargs):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
        except OSError:
            local_ip = '127.0.0.1'
        self.logger.info('Simulation at %s:%d for %s', local_ip, port, self.cfg_file)
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
