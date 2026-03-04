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

import importlib

import pytest

from autonomous_trust.core.protobuf.services import position_pb2, metadata_pb2
from autonomous_trust.core.protobuf.simulator import sim_data_pb2

has_services = importlib.util.find_spec('autonomous_trust.services') is not None
has_simulator = importlib.util.find_spec('autonomous_trust.simulator') is not None

services_skip = pytest.mark.skipif(not has_services, reason='autonomous_trust.services not installed')
simulator_skip = pytest.mark.skipif(not has_simulator, reason='autonomous_trust.simulator not installed')


# ---- Proto message classes are generated correctly ----

def test_position_pb2_has_messages():
    assert hasattr(position_pb2, 'Position')
    assert hasattr(position_pb2, 'GeoPosition')
    assert hasattr(position_pb2, 'UTMPosition')


def test_metadata_pb2_has_messages():
    assert hasattr(metadata_pb2, 'PeerData')
    assert hasattr(metadata_pb2, 'NetworkStats')


def test_sim_data_pb2_has_messages():
    assert hasattr(sim_data_pb2, 'Ident')
    assert hasattr(sim_data_pb2, 'SimState')
    assert hasattr(sim_data_pb2, 'ReachabilityRow')


# ---- Python classes get message attribute of correct proto type ----

@services_skip
def test_geo_position_has_message():
    from autonomous_trust.services.peer.position import GeoPosition
    pos = GeoPosition(1.0, 2.0, 3.0)
    assert hasattr(pos, 'message')
    assert isinstance(pos.message, position_pb2.GeoPosition)


@services_skip
def test_utm_position_has_message():
    from autonomous_trust.services.peer.position import UTMPosition
    pos = UTMPosition('17N', 500000.0, 4000000.0, 100.0)
    assert hasattr(pos, 'message')
    assert isinstance(pos.message, position_pb2.UTMPosition)


@services_skip
def test_position_base_no_message():
    from autonomous_trust.services.peer.position import Position
    pos = Position(1.0, 2.0, 3.0)
    assert not hasattr(pos, 'message')


@services_skip
def test_peer_data_has_message():
    from autonomous_trust.services.peer.metadata import PeerData
    from autonomous_trust.services.peer.position import GeoPosition
    from datetime import datetime
    pd = PeerData(datetime.now(), GeoPosition(1.0, 2.0), 5.0, 'sensor', 'video', 1)
    assert hasattr(pd, 'message')
    assert isinstance(pd.message, metadata_pb2.PeerData)


@services_skip
def test_network_stats_has_message():
    from autonomous_trust.services.network_statistics import NetworkStats
    ns = NetworkStats(1.0, 2.0, 100, 200, 0, 0)
    assert hasattr(ns, 'message')
    assert isinstance(ns.message, metadata_pb2.NetworkStats)


@simulator_skip
def test_ident_has_message():
    from autonomous_trust.simulator.sim_data import Ident
    from autonomous_trust.services.peer.position import GeoPosition
    ident = Ident(GeoPosition(1.0, 2.0), 5.0, 'sensor', 'alice')
    assert hasattr(ident, 'message')
    assert isinstance(ident.message, sim_data_pb2.Ident)


@simulator_skip
def test_sim_state_has_message():
    from autonomous_trust.simulator.sim_data import SimState
    state = SimState()
    assert hasattr(state, 'message')
    assert isinstance(state.message, sim_data_pb2.SimState)
