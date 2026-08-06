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

"""
FEMA data fusion task for the multi-agency disaster response demo.

The fusion center (fema-fusion in Raleigh) and field stations aggregate
data from weather and seismic streams to produce situational awareness
reports.  Fusion tasks require higher reputation (0.7+) because the
output is used for decision-making.
"""

from __future__ import annotations

from .data_sharing import TaskDefinition


WEATHER_FUSION = TaskDefinition(
    task_type="weather_fusion",
    description="Fuse weather observations from multiple NOAA stations "
                "into a regional weather picture",
    required_capabilities=["data_fusion"],
    consumer_capabilities=["weather_stream"],
    min_reputation=0.7,
    data_types=["regional_weather"],
    cadence_sec=15.0,
    priority=3,
    metadata={"sources": ["noaa-sensor-1", "noaa-sensor-2", "noaa-sensor-3"]},
)

SITUATION_REPORT = TaskDefinition(
    task_type="situation_report",
    description="Aggregate all environmental data into a unified "
                "situation report for emergency coordinators",
    required_capabilities=["situation_report", "data_fusion"],
    consumer_capabilities=[],  # anyone can consume
    min_reputation=0.7,
    data_types=["sitrep"],
    cadence_sec=30.0,
    priority=4,
    metadata={"includes": ["weather", "seismic", "airquality"]},
)

FUSION_TASKS = [WEATHER_FUSION, SITUATION_REPORT]
