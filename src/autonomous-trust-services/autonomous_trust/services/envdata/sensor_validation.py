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

"""Sensor cross-validation service.

Any peer that advertises this capability can answer a "does this reading
look plausible?" query. In the demo this is what lets honest NOAA/USGS
stations corroborate one another and drive the rogue sensor's reputation
down without a central validator.

The validator keeps a short sliding window of recent readings (by data
type) and answers queries with a plausibility score in [0, 1] based on
how far a new reading is from the window's mean (in stddev units).
"""

from __future__ import annotations

import math
from collections import defaultdict, deque
from datetime import timedelta
from functools import partial
from typing import Optional

from autonomous_trust.core import ProcMeta

from ..data.reading import Reading
from .base import EnvDataProcess


# Default window: 20 readings per data type, outside +/- 2sigma is "low".
_DEFAULT_WINDOW = 20
_LOW_PLAUSIBILITY_SIGMA = 2.0


class SensorValidationProcess(EnvDataProcess, metaclass=ProcMeta,
                              proc_name='sensor-validation',
                              description='Cross-source reading validator',
                              cfg_name='sensor-validation'):
    capability_name = 'sensor_validation'

    def __init__(self, configurations, subsystems, log_queue, dependencies):
        super().__init__(configurations, subsystems, log_queue,
                         dependencies=dependencies)
        # Per-peer, per-type running windows. `deque` with maxlen trims old.
        # Uses functools.partial (not a lambda) so the defaultdict pickles
        # cleanly when the AT pool ships this Process instance to a
        # forkserver worker.
        self._windows: dict[tuple[str, str], deque] = defaultdict(
            partial(deque, maxlen=_DEFAULT_WINDOW))

    # --- Statistical helpers ---

    @staticmethod
    def _mean_sd(values: list[float]) -> tuple[float, float]:
        n = len(values)
        if n == 0:
            return 0.0, 0.0
        mean = sum(values) / n
        if n < 2:
            return mean, 0.0
        var = sum((v - mean) ** 2 for v in values) / (n - 1)
        return mean, math.sqrt(var)

    # --- API ---

    def observe(self, reading: Reading):
        """Record an incoming reading into the peer/type window."""
        key = (reading.peer_name, reading.data_type)
        self._windows[key].append(reading.value)

    def plausibility(self, reading: Reading) -> float:
        """Return [0, 1] plausibility vs. known peers on the same data type.

        Uses all known peers' windows for this data_type EXCEPT the one
        making the claim. That's the cross-source corroboration signal.
        """
        dtype = reading.data_type
        cross_values: list[float] = []
        for (peer, t), window in self._windows.items():
            if t != dtype or peer == reading.peer_name:
                continue
            cross_values.extend(window)
        if not cross_values:
            return 1.0  # nothing to compare against: default trust
        mean, sd = self._mean_sd(cross_values)
        if sd == 0.0:
            # All corroborators identical: any deviation is 'suspicious'.
            return 1.0 if reading.value == mean else 0.0
        z = abs(reading.value - mean) / sd
        if z <= _LOW_PLAUSIBILITY_SIGMA:
            # Linear fade from 1.0 at z=0 to 0.5 at the 2-sigma boundary.
            return 1.0 - 0.5 * (z / _LOW_PLAUSIBILITY_SIGMA)
        # Beyond 2 sigma: exponential collapse, floors at 0.
        return max(0.0, 0.5 * math.exp(-(z - _LOW_PLAUSIBILITY_SIGMA)))

    def tick_once(self, elapsed: timedelta) -> Optional[dict]:
        """Validators don't originate streams -- they respond to queries."""
        return None
