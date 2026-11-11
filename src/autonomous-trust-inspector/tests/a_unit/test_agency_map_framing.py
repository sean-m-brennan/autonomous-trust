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
"""The vector agency map frames the peers, not the whole country.

Plotly 7 (plotly.js 3) no longer honors fitbounds under the "albers usa"
projection: the map drew all of the lower 48 with every peer packed into the
Washington corner, which the panel crops away. Mercator still fits the bounds
in plotly 6 and 7 alike.
"""
import pytest

from autonomous_trust.inspector.dashboard.disaster_response_map import (
    AgencyMap, MapPeer)


@pytest.fixture
def geo(monkeypatch):
    monkeypatch.delenv("MAPBOX", raising=False)
    m = AgencyMap()
    m.add_peer(MapPeer(name="noaa-1", agency="NOAA", kind="weather-sensor",
                       lat=47.1, lon=-122.9))
    return m.figure().layout.geo


def test_the_map_fits_its_peers(geo):
    assert geo.fitbounds == "locations"


def test_the_projection_is_one_plotly_7_fits(geo):
    assert geo.projection.type == "mercator"
    # State lines need a regional scope; "usa" forces albers usa.
    assert geo.scope == "north america"
    assert geo.showsubunits
