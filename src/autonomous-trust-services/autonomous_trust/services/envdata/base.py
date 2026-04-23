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

"""Base process + config for environmental-data services.

EnvDataProcess replaces DataProcess's device-oriented config (video frame
size, channels) with a simple cadence + source-callable arrangement.
Subclasses set `capability_name` and typically inherit `acquire()`.

Sources are injected late (after Process construction) so the demo-side
code can compose an honest or compromised generator without needing to
go through the InitializableConfig system.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Callable, Optional

from autonomous_trust.core import (
    InitializableConfig, ProcMeta, to_yaml_string,
)

from ..data.server import DataProcess, DataProtocol  # noqa: F401  (re-exported)
from ..data.reading import Reading


# Source callable: takes scenario-elapsed timedelta, returns Reading or None.
AcquireFn = Callable[[timedelta], Optional[Reading]]


class EnvDataConfig(InitializableConfig):
    """Config for any EnvDataProcess.

    Attributes:
        peer_name:   Agency-specific peer id (e.g. "noaa-1").
        cadence_sec: Tick interval for acquire().
        source_name: Which source/generator to bind at runtime. This is a
                     human-readable hint used by demo wiring; the actual
                     callable is attached via set_source().
    """
    def __init__(self, peer_name: str, cadence_sec: float = 1.0,
                 source_name: str = ""):
        self.peer_name = peer_name
        self.cadence_sec = cadence_sec
        self.source_name = source_name

    @classmethod
    def initialize(cls, peer_name: str, cadence_sec: float = 1.0,
                   source_name: str = ""):
        return EnvDataConfig(peer_name, cadence_sec, source_name)


class EnvDataProcess(DataProcess, metaclass=ProcMeta,
                     proc_name='envdata-source',
                     description='Environmental data stream service',
                     cfg_name='envdata-source'):
    """Base class for environmental data services.

    The service becomes 'active' only when both:
      1. A config entry for `self.name` is in configurations, and
      2. A source callable has been attached via set_source().

    The scenario start-time baseline lets `acquire()` pass a scenario-
    relative timedelta to the generator (matching how generators advance
    through the demo timeline). If the peer came up late, set_start_time()
    lets the demo subclass align the baseline.
    """
    capability_name = 'envdata'

    def __init__(self, configurations, subsystems, log_queue, dependencies):
        super().__init__(configurations, subsystems, log_queue,
                         dependencies=dependencies)
        # `self.cfg` from DataProcess is a DataConfig. For envdata we carry
        # our own EnvDataConfig in parallel without touching the parent.
        self._env_cfg: Optional[EnvDataConfig] = None
        if self.name in configurations and isinstance(
                configurations[self.name], EnvDataConfig):
            self._env_cfg = configurations[self.name]
        self._source: Optional[AcquireFn] = None
        self._start_wall: Optional[datetime] = None

    # ------------------------------------------------------------------
    # Late binding for source + timeline
    # ------------------------------------------------------------------

    def set_source(self, source: AcquireFn):
        """Attach a source callable (scenario_elapsed -> Reading|None)."""
        self._source = source

    def set_start_time(self, wall_time: Optional[datetime] = None):
        """Baseline for scenario-relative time conversion.

        If unset, the first call to acquire() picks 'now' as T+0. This
        matches the simplest single-peer case but is wrong for multi-peer
        replay -- the scenario engine should call set_start_time()
        explicitly on every peer with the same moment.
        """
        self._start_wall = wall_time or datetime.utcnow()

    @property
    def env_cfg(self) -> Optional[EnvDataConfig]:
        return self._env_cfg

    @property
    def is_ready(self) -> bool:
        return self.active and self._source is not None

    # ------------------------------------------------------------------
    # DataProcess override
    # ------------------------------------------------------------------

    def acquire(self):
        """Tick the bound source at scenario time 'now - start'.

        Returns None (no frame) until:
          - A source is bound, and
          - The generator's cadence has elapsed.
        """
        if not self.is_ready:
            return None
        if self._start_wall is None:
            self.set_start_time()
        elapsed = datetime.utcnow() - self._start_wall
        # `self._source` is Optional by type; is_ready guarantees it's set.
        reading = self._source(elapsed)  # type: ignore[misc]
        if reading is None:
            return None
        # Payload sent over the wire: the to_yaml_string path in DataProcess
        # will serialize this dict cleanly without needing custom serde.
        return reading.to_dict()

    # Convenience for tests: emit a single reading synchronously.
    def tick_once(self, elapsed: timedelta) -> Optional[dict]:
        if not self._source:
            return None
        r = self._source(elapsed)
        return r.to_dict() if r is not None else None
