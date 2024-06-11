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

import pytest

from autonomous_trust.services.peer.position import GeoPosition, UTMPosition


@pytest.fixture
def locations():
    t5 = GeoPosition(34.669650, -86.575907, 182)
    uah = GeoPosition(34.725279, -86.639962, 198)
    abq = GeoPosition(35.106499574, -106.605997576, 1558)
    return [t5, uah, abq]


def test_utm_pos_dist(locations):
    t5 = locations[0]
    zone = UTMPosition.get_zone(t5)
    utm1 = UTMPosition(zone, 105005.28, 1390650.76, 0)
    utm2 = UTMPosition(zone, 105005.28, 1390650.76, 345)
    utm3 = UTMPosition(zone, 112116.04, 1390000.19, 148.37418070513)
    dist1 = utm1.distance(utm2)
    assert dist1 == pytest.approx(345., rel=1e1)
    dist2 = utm2.distance(utm1)
    assert dist1 == dist2
    dist3 = utm3.distance(utm1)
    assert dist3 == pytest.approx(7142., rel=1e1)


def test_geo_pos_dist(locations):
    t5, uah, abq = locations
    dist1 = uah.distance(t5)
    assert dist1 == pytest.approx(8516.34, abs=1e-2)
    dist2 = t5.distance(uah)
    assert dist1 == dist2
    dist3 = abq.distance(t5)
    assert dist3 == pytest.approx(1828554., abs=1e1)


def test_utm_dist_across_zones(locations):
    t5, _, abq = locations
    zone1 = UTMPosition.get_zone(t5)
    zone2 = UTMPosition.get_zone(abq)
    utm1 = UTMPosition(zone1, 105005.28, 1390650.76, 182)
    utm2 = UTMPosition(zone2, 105005.28, 1390650.76, 1558)
    dist1 = utm1.distance(utm2)
    dist2 = utm2.distance(utm1)
    assert dist1 == dist2
    dist3 = t5.distance(abq)
    assert dist1 == pytest.approx(dist3, abs=1e6)


def test_position_conversion(locations):
    t5, uah, abq = locations
    dist1 = t5.distance(uah)
    utm1 = t5.convert(UTMPosition)
    utm2 = uah.convert(UTMPosition)
    dist2 = utm1.distance(utm2)
    assert dist2 == pytest.approx(dist1, rel=1e-2, abs=1e-2)

    dist3 = utm1.distance(uah)  # auto-convert
    assert dist2 == dist3

    dist4 = utm2.distance(t5)
    assert dist3 == dist4
    assert dist4 == pytest.approx(dist1, rel=1e-2, abs=1e-2)

    dist5 = abq.distance(t5)
    utm3 = abq.convert(UTMPosition)
    dist6 = utm3.distance(utm1)  # differing zones
    assert dist6 == pytest.approx(dist5, abs=1e1)
