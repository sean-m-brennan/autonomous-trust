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

from datetime import datetime, timedelta
from uuid import uuid4

from autonomous_trust.simulator.peer.path import BezierData, PathData, Variability, EllipseData, LineData, BeziergonData
from autonomous_trust.simulator.peer.peer import PeerInfo
from autonomous_trust.services.peer.position import GeoPosition, UTMPosition
from autonomous_trust.simulator.radio.iface import Antenna, NetInterface
from autonomous_trust.simulator.sim_data import SimConfig


def test_sim_config():
    t5 = GeoPosition(34.669650, -86.575907, 182).convert(UTMPosition)
    uah = GeoPosition(34.725279, -86.639962, 198).convert(UTMPosition)
    mid = t5.midpoint(uah)
    one = UTMPosition(t5.zone, t5.easting, uah.northing, mid.alt)
    two = UTMPosition(t5.zone, uah.easting, t5.northing, mid.alt)
    start = datetime.now()
    end = datetime.now() + timedelta(minutes=30)
    shape1 = LineData(t5, uah)
    path1 = PathData(start, end, shape1, Variability.BROWNIAN, 4.4, Variability.UNIFORM)
    peer1 = PeerInfo(str(uuid4()), 'drone', '192.168.0.1', path1.shape.start, -200.,
                     Antenna.YAGI, NetInterface.MEDIUM, start, end, path1, [])
    shape2 = BezierData(t5, uah, [one, two])
    path2 = PathData(start, end, shape2, Variability.GAUSSIAN, 4.4, Variability.UNIFORM)
    peer2 = PeerInfo(str(uuid4()), 'drone', '192.168.0.2', path2.shape.start, -200.,
                     Antenna.DIPOLE, NetInterface.SMALL, start, end, path2, [])
    shape3 = BeziergonData(t5, [one, two], 2)
    path3 = PathData(start, end, shape3, Variability.GAUSSIAN, 4.4, Variability.UNIFORM)
    peer3 = PeerInfo(str(uuid4()), 'drone', '192.168.0.3', path3.shape.start, -200.,
                     Antenna.DIPOLE, NetInterface.SMALL, start, end, path3, [])
    shape4 = EllipseData(uah, 1000, 600, -45., 2)
    path4 = PathData(start, end, shape4, Variability.GAUSSIAN, 4.4, Variability.UNIFORM)
    peer4 = PeerInfo(str(uuid4()), 'drone', '192.168.0.4', path4.shape.start, -200.,
                     Antenna.DIPOLE, NetInterface.SMALL, start, end, path4, [])
    config = SimConfig(time=start, peers=[peer1, peer2, peer3, peer4])
    s = config.to_yaml_string()
    config2 = SimConfig.load(s)
    assert repr(config) == repr(config2)
