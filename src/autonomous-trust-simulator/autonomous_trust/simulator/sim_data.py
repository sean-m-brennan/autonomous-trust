# ******************
#  Copyright 2025 Sean M. Brennan and contributors
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

from collections import namedtuple
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from autonomous_trust.core.config import Configuration
from autonomous_trust.core.protobuf.simulator import sim_data_pb2
from autonomous_trust.services.peer.position import Position, GeoPosition
from .peer.peer import PeerInfo, GatewayUplink

Matrix = dict[str, dict[str, bool]]
SignalMatrix = dict[str, dict[str, float]]  # peer_id -> {peer_id: path_loss_dB}
DelayMatrix = dict[str, dict[str, float]]  # peer_id -> {peer_id: delay_seconds}
GatewayMap = dict[str, GatewayUplink]


class Ident(Configuration):
    def __init__(self, position: Position, speed: float, kind: str, nickname: str):
        super().__init__(sim_data_pb2.Ident)
        self.position = position
        self.speed = speed
        self.kind = kind
        self.nickname = nickname


Map = dict[str, Ident]


class SimState(Configuration):
    """Communicates sim state snapshot"""

    def __init__(self, time: Optional[datetime] = None, center: Optional[GeoPosition] = None,
                 scale: Optional[float] = None, peers: Optional[Map] = None,
                 reachable: Optional[Matrix] = None, active: Optional[list[str]] = None,
                 blank: bool = False, signal_quality: Optional[SignalMatrix] = None,
                 delay: Optional[DelayMatrix] = None,
                 gateways: Optional[GatewayMap] = None,
                 gateway_count: int = 0,
                 aggregate_uplink_down_mbps: float = 0.0,
                 aggregate_uplink_up_mbps: float = 0.0,
                 per_node_down_mbps: float = 0.0):
        super().__init__(sim_data_pb2.SimState)
        self.time = time
        if time is None:
            self.time = datetime.now()
        self.center = center
        self.scale = scale
        self.peers = peers
        if peers is None:
            self.peers: Map = {}
        self.reachable = reachable
        if reachable is None:
            self.reachable: Matrix = {}
        self.active = active
        if active is None:
            self.active = []
        self.blank = blank
        self.signal_quality = signal_quality
        if signal_quality is None:
            self.signal_quality: SignalMatrix = {}
        self.delay = delay
        if delay is None:
            self.delay: DelayMatrix = {}
        self.gateways = gateways
        if gateways is None:
            self.gateways: GatewayMap = {}
        self.gateway_count = gateway_count
        self.aggregate_uplink_down_mbps = aggregate_uplink_down_mbps
        self.aggregate_uplink_up_mbps = aggregate_uplink_up_mbps
        self.per_node_down_mbps = per_node_down_mbps

    def convert(self) -> 'SimState':
        state = SimState(**self.to_dict())
        for peer_id in state.peers:
            state.peers[peer_id].position = state.peers[peer_id].position.convert(GeoPosition)
        return state


class SimConfig(Configuration):
    """Just the sim scenario"""

    def __init__(self, **kwargs):
        super().__init__()
        self.start: datetime = kwargs['start']
        self.end: datetime = kwargs['end']
        self.peers: list[PeerInfo] = kwargs['peers']
        self.path_loss_matrix: Optional[SignalMatrix] = kwargs.get('path_loss_matrix')
        self.space_mode: bool = kwargs.get('space_mode', False)
        self.comm_freq_hz: Optional[float] = kwargs.get('comm_freq_hz')
        self.sun_position: Optional[Position] = kwargs.get('sun_position')

    @classmethod
    def load(cls, data: str) -> 'SimConfig':
        return cls.from_json_string(data)
