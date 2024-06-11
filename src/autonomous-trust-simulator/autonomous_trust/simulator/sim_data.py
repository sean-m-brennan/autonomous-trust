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

from collections import namedtuple
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from autonomous_trust.core.config import Configuration
from autonomous_trust.services.peer.position import Position, GeoPosition
from .peer.peer import PeerInfo

Matrix = dict[str, dict[str, bool]]


class Ident(Configuration):
    def __init__(self, position: Position, speed: float, kind: str, nickname: str):
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
                 blank: bool = False):
        super().__init__()
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

    @classmethod
    def load(cls, data: str) -> 'SimConfig':
        return cls.from_yaml_string(data)
