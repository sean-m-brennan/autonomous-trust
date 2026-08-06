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
EPA air quality data generators for the multi-agency disaster response demo.

Produces air quality readings for coastal NC during hurricane conditions.
EPA joins the network late (Phase 7, T+6:00) so these generators only
produce data from that point forward.

Readings:
  - AQI (Air Quality Index, 0-500 scale)
  - PM2.5 (fine particulate matter, ug/m3)
  - Ozone (ground-level ozone, ppb)

During hurricane conditions, AQI is typically moderate (51-100) due to
wind dispersal of pollutants, but can spike from storm surge debris,
industrial releases, or post-storm fires.
"""

from __future__ import annotations

import math
from datetime import timedelta
from typing import Optional

from autonomous_trust.services.data import Reading
from autonomous_trust.evaluation.generators import DataGenerator, RandomWalkGenerator


class AQIGenerator(RandomWalkGenerator):
    """Air Quality Index generator.

    Post-hurricane AQI: moderate (50-80) with occasional spikes from
    debris or industrial releases.
    """

    def __init__(self, peer_name: str, seed: Optional[int] = None):
        super().__init__(
            peer_name=peer_name,
            data_type="aqi",
            unit="AQI",
            mean=65.0,
            step_size=5.0,
            bounds=(20.0, 200.0),
            trend=0.0,
            cadence_sec=10.0,
            noise_stddev=3.0,
            seed=seed,
        )


class PM25Generator(RandomWalkGenerator):
    """PM2.5 fine particulate generator.

    Correlates with AQI.  Normal: 5-15 ug/m3.
    Post-storm: elevated 20-40 ug/m3 from debris.
    """

    def __init__(self, peer_name: str, seed: Optional[int] = None):
        super().__init__(
            peer_name=peer_name,
            data_type="pm25",
            unit="ug/m3",
            mean=25.0,    # elevated for post-storm
            step_size=3.0,
            bounds=(2.0, 100.0),
            trend=0.0,
            cadence_sec=10.0,
            noise_stddev=2.0,
            seed=seed,
        )


class OzoneGenerator(DataGenerator):
    """Ground-level ozone generator.

    Ozone is typically LOW during hurricanes (high cloud cover, wind
    dispersal).  Normal: 20-40 ppb.  Post-storm recovery: slow rise.
    """

    def __init__(self, peer_name: str, seed: Optional[int] = None):
        super().__init__(
            peer_name=peer_name,
            data_type="ozone",
            unit="ppb",
            cadence_sec=15.0,
            noise_stddev=3.0,
            seed=seed,
        )

    def _generate_value(self, t: timedelta) -> float:
        # Low ozone during storm, recovering
        secs = t.total_seconds()
        base = 25.0
        # Slow recovery after EPA joins (T+6:00 = 360s)
        if secs > 360:
            recovery = min((secs - 360) / 120.0, 1.0)
            base += 10.0 * recovery
        return max(5.0, base)


class AirQualityGenerators:
    """Bundle of air quality generators for a single EPA monitor."""

    def __init__(self, peer_name: str, seed: Optional[int] = None):
        base_seed = seed or hash(peer_name) & 0xFFFF
        self.aqi = AQIGenerator(peer_name, seed=base_seed)
        self.pm25 = PM25Generator(peer_name, seed=base_seed + 100)
        self.ozone = OzoneGenerator(peer_name, seed=base_seed + 200)
        self._generators = [self.aqi, self.pm25, self.ozone]

    def tick(self, t: timedelta) -> list[Reading]:
        readings = []
        for gen in self._generators:
            r = gen.tick(t)
            if r is not None:
                readings.append(r)
        return readings
