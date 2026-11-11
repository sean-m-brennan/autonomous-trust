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

"""The live coordinator draws the roster the deployment runs.

The compose and k8s generators deploy the evaluation scenario's peers
(noaa-1..4, usgs-1/2, fema-*, epa-1, in the Pacific Northwest). The
coordinator had drawn its map, trust graph and roster from the Hurricane
Helene scenario in examples/multi_agency/scenario.py (noaa-sensor-1..3, ...,
on the North Carolina coast), so only the FEMA names matched live data and
the other peers never took a live status.
"""
import re

from autonomous_trust.evaluation.scenarios.disaster_response import (
    DisasterResponseScenario as Deployed)
from autonomous_trust.evaluation.scenarios.disaster_response_compose import (
    generate_compose)
from examples.multi_agency import coordinator


def _positions(scenario):
    return {n: (r.position.lat, r.position.lon)
            for n, r in scenario.peers.items()}


def test_the_coordinator_roster_is_the_deployed_one():
    ours = coordinator.DisasterResponseScenario()
    deployed = set(re.findall(r'^      AT_PEER_NAME: "([^"]+)"$',
                              generate_compose(Deployed()), re.M))
    assert set(ours.peers) == deployed - {'coordinator'}


def test_the_coordinator_map_positions_are_the_deployed_ones():
    assert (_positions(coordinator.DisasterResponseScenario())
            == _positions(Deployed()))
