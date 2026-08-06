# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
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

from datetime import datetime

import pytest

try:
    from autonomous_trust.core.protobuf.services import position_pb2, metadata_pb2
    _has_proto = True
except (ImportError, ModuleNotFoundError):
    position_pb2 = metadata_pb2 = None
    _has_proto = False

pytestmark = pytest.mark.skipif(not _has_proto, reason='services protobuf not available')


def test_position_pb2_has_messages():
    assert hasattr(position_pb2, 'Position')
    assert hasattr(position_pb2, 'GeoPosition')
    assert hasattr(position_pb2, 'UTMPosition')


def test_metadata_pb2_has_messages():
    assert hasattr(metadata_pb2, 'PeerData')
    assert hasattr(metadata_pb2, 'NetworkStats')


def test_geo_position_has_message():
    from autonomous_trust.services.peer.position import GeoPosition
    pos = GeoPosition(1.0, 2.0, 3.0)
    assert hasattr(pos, 'message')
    assert isinstance(pos.message, position_pb2.GeoPosition)


def test_utm_position_has_message():
    from autonomous_trust.services.peer.position import UTMPosition
    pos = UTMPosition('17N', 500000.0, 4000000.0, 100.0)
    assert hasattr(pos, 'message')
    assert isinstance(pos.message, position_pb2.UTMPosition)


def test_position_base_no_message():
    from autonomous_trust.services.peer.position import Position
    pos = Position(1.0, 2.0, 3.0)
    assert not hasattr(pos, 'message')


def test_peer_data_has_message():
    from autonomous_trust.services.peer.metadata import PeerData
    from autonomous_trust.services.peer.position import GeoPosition
    pd = PeerData(datetime.now(), GeoPosition(1.0, 2.0), 5.0, 'sensor', 'video', 1)
    assert hasattr(pd, 'message')
    assert isinstance(pd.message, metadata_pb2.PeerData)


def test_network_stats_has_message():
    from autonomous_trust.services.network_statistics import NetworkStats
    ns = NetworkStats(1.0, 2.0, 100, 200, 0, 0)
    assert hasattr(ns, 'message')
    assert isinstance(ns.message, metadata_pb2.NetworkStats)
