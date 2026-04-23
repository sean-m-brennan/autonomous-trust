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

"""Demo-specific AutonomousTrust subclass for the disaster-response scenario.

Per-peer lifecycle:

  1. The container's entrypoint sets agency/role env vars (AT_PEER_NAME,
     AT_AGENCY, AT_ROLE_KIND, AT_CAPABILITIES, AT_COMPROMISED*) via the
     compose/k8s manifests generated from disaster_response_compose.
  2. DisasterResponseDemoAT.__init__() reads those env vars, looks up
     the peer's role in the scenario, builds a matching generator
     roster, and adds the appropriate EnvData* Process worker.
  3. The Process subclasses below attach the generator as their source
     inside the Process's own __init__ (they live in the child process
     after fork).

The AT subclass and Process subclasses live together in this module so
both scenario- and service-layer hooks coexist without circular imports.
"""

from __future__ import annotations

import itertools
import logging
import os
from datetime import timedelta
from typing import Callable, Optional

from autonomous_trust.core._python.automate import AutonomousTrust
from autonomous_trust.services.data.reading import Reading
from autonomous_trust.services.envdata import (
    AirQualityStreamProcess,
    CompromiseConfig,
    CompromisedGenerator,
    DataFusionProcess,
    EnvDataProcess,
    SensorValidationProcess,
    SeismicStreamProcess,
    SituationReportProcess,
    WeatherStreamProcess,
    compromise_from_env,
)

from .disaster_response import DisasterResponseScenario
from .disaster_response_data import build_generators_for_scenario


logger = logging.getLogger(__name__)


# ----------------------------------------------------------------------
# Source-callable builders (factories)
# ----------------------------------------------------------------------

def _rotating_source(tickers) -> Callable[[timedelta], Optional[Reading]]:
    """Combine multiple tick-able generators into one source callable.

    Round-robins through the generators on each call. Any None from an
    inner tick is returned as-is -- callers treat None as "no frame yet".
    This is what lets a single WeatherStreamProcess emit 4 different
    data types (temperature / wind / pressure / precipitation) over the
    same channel; consumers filter by reading.data_type.
    """
    if not tickers:
        return lambda _t: None
    cycle = itertools.cycle(tickers)

    def source(t: timedelta) -> Optional[Reading]:
        # One call = one generator tick. Skip None returns so consumers
        # see a reading as often as any underlying cadence permits.
        for _ in range(len(tickers)):
            gen = next(cycle)
            reading = gen.tick(t) if hasattr(gen, "tick") else gen(t)
            if reading is not None:
                return reading
        return None

    return source


def _source_for_peer(peer_name: str,
                     scenario: Optional[DisasterResponseScenario] = None
                     ) -> Callable[[timedelta], Optional[Reading]]:
    """Build the merged source callable for `peer_name` from the scenario.

    Applies env-derived compromise configuration. If the scenario roster
    already wraps the rogue peer's generators (it does -- see
    build_generators_for_scenario), the env config is redundant; we still
    consult it so that operators running a non-compromised roster can
    flip a peer to rogue via env alone.
    """
    scenario = scenario or DisasterResponseScenario()
    roster = build_generators_for_scenario(scenario)
    tickers = list(roster.get(peer_name, []))

    env_cfg = compromise_from_env()
    if env_cfg is not None and not any(
            isinstance(g, CompromisedGenerator) for g in tickers):
        # Wrap honest generators so env-driven rogue mode still works.
        wrapped = []
        for g in tickers:
            fn = g.tick if hasattr(g, "tick") else g
            wrapped.append(CompromisedGenerator(fn, env_cfg))
        tickers = wrapped

    return _rotating_source(tickers)


# ----------------------------------------------------------------------
# Role -> EnvDataProcess subclass map
# ----------------------------------------------------------------------

class _DemoProcessMixin:
    """Mixin: on __init__, wire the per-peer source from env + scenario.

    Implementations MUST call `self._demo_wire_source()` after super()
    __init__ completes.
    """

    # Child classes inherit EnvDataProcess's self.active flag.
    active: bool

    def _demo_wire_source(self):
        peer_name = os.environ.get("AT_PEER_NAME", "")
        if not self.active or not peer_name:
            return
        try:
            source = _source_for_peer(peer_name)
            # set_source is provided by EnvDataProcess; fusion overrides it.
            self.set_source(source)  # type: ignore[attr-defined]
        except Exception:
            logger.exception("[%s] failed to wire demo source for %s",
                             type(self).__name__, peer_name)


class DisasterWeatherStreamProcess(_DemoProcessMixin, WeatherStreamProcess):
    def __init__(self, configurations, subsystems, log_queue, dependencies):
        super().__init__(configurations, subsystems, log_queue,
                         dependencies=dependencies)
        self._demo_wire_source()


class DisasterSeismicStreamProcess(_DemoProcessMixin, SeismicStreamProcess):
    def __init__(self, configurations, subsystems, log_queue, dependencies):
        super().__init__(configurations, subsystems, log_queue,
                         dependencies=dependencies)
        self._demo_wire_source()


class DisasterAirQualityStreamProcess(_DemoProcessMixin,
                                       AirQualityStreamProcess):
    def __init__(self, configurations, subsystems, log_queue, dependencies):
        super().__init__(configurations, subsystems, log_queue,
                         dependencies=dependencies)
        self._demo_wire_source()


class DisasterSituationReportProcess(_DemoProcessMixin,
                                       SituationReportProcess):
    def __init__(self, configurations, subsystems, log_queue, dependencies):
        super().__init__(configurations, subsystems, log_queue,
                         dependencies=dependencies)
        self._demo_wire_source()


# Role-kind -> (Process class, capability name)
_ROLE_PROCESS = {
    "weather-sensor":       (DisasterWeatherStreamProcess,
                             WeatherStreamProcess.capability_name),
    "seismic-monitor":      (DisasterSeismicStreamProcess,
                             SeismicStreamProcess.capability_name),
    "air-quality-monitor":  (DisasterAirQualityStreamProcess,
                             AirQualityStreamProcess.capability_name),
    "field-station":        (DisasterSituationReportProcess,
                             SituationReportProcess.capability_name),
    "fusion-node":          (DataFusionProcess,  # fusion has no generator
                             DataFusionProcess.capability_name),
}


# ----------------------------------------------------------------------
# AutonomousTrust subclass
# ----------------------------------------------------------------------

class DisasterResponseDemoAT(AutonomousTrust):
    """Agency-aware AutonomousTrust for the civilian demo.

    Honors AT_* env vars set by the compose/k8s generator. If none are
    present, falls back to a fixed peer name ("at-unknown") and no role
    wiring, which lets the class be used in unit tests without side
    effects.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._demo_peer_name = os.environ.get("AT_PEER_NAME", "")
        self._demo_agency = os.environ.get("AT_AGENCY", "")
        self._demo_role = os.environ.get("AT_ROLE_KIND", "")
        # AT_CAPABILITIES from the compose generator is a comma list; we
        # intersect it with the role's defaults so an operator can disable
        # a capability by omitting it from the env var without having to
        # modify the scenario.
        raw_caps = os.environ.get("AT_CAPABILITIES", "")
        self._demo_capabilities = [c.strip() for c in raw_caps.split(",")
                                   if c.strip()]

        # Always include the cross-validation service -- every peer in
        # the demo participates in peer-to-peer sanity checks.
        self._add_validation_worker()
        self._add_role_worker()

    # --- worker registration -----------------------------------------

    def _add_role_worker(self):
        """Add the role-matching EnvData Process to the multiprocess pool."""
        if not self._demo_role:
            return
        entry = _ROLE_PROCESS.get(self._demo_role)
        if entry is None:
            self.logger.warning(
                "Unknown AT_ROLE_KIND=%r; no demo worker added",
                self._demo_role)
            return
        proc_cls, _cap = entry
        try:
            self.add_worker(proc_cls)
        except Exception:
            self.logger.exception("Failed to register demo worker for %s",
                                  self._demo_role)

    def _add_validation_worker(self):
        """Every peer gets a sensor_validation service (cross-corroboration)."""
        try:
            self.add_worker(SensorValidationProcess)
        except Exception:
            self.logger.exception(
                "Failed to register SensorValidationProcess worker")

    # --- capability registration -------------------------------------

    def autonomous_ability(self, queues):
        """Advertise the peer's role-driven capabilities to the network.

        The Capabilities system in this codebase is dual-purpose: it
        tracks both executable RPC-style functions (via register_ability)
        and service-discovery capability_name strings (via the peer
        capability handshake). Here we register both:

          * Each advertised capability gets a no-op function so the
            Capability can flow through the capability announcement path.
          * The underlying Process workers (weather_stream, etc.) are
            already registered as Process classes via add_worker(); their
            capability_name attribute is what DataRcvr clients look up.

        The no-op function is required because Capability.execute() will
        call it for task-style requests. Streaming consumers go through
        DataRcvr, not the Task path, so this function is never invoked
        in normal operation.
        """
        super().autonomous_ability(queues)

        def _announce(*_args, **_kwargs):
            # Return an identifying marker; task-style execution is
            # not the path consumers use for streaming envdata.
            return {"peer": self._demo_peer_name,
                    "agency": self._demo_agency,
                    "role": self._demo_role}

        # Role default + env-specified capabilities.
        caps_to_advertise = set(self._demo_capabilities)
        role_entry = _ROLE_PROCESS.get(self._demo_role)
        if role_entry is not None:
            caps_to_advertise.add(role_entry[1])

        for cap_name in caps_to_advertise:
            try:
                self.capabilities.register_ability(cap_name, _announce)
            except Exception:
                self.logger.exception("Failed to register capability %s",
                                      cap_name)

    # --- tasking (minimal) -------------------------------------------

    def autonomous_tasking(self, queues):
        """Streaming data and service discovery drive the demo.

        We intentionally do NOT fire randomized negotiations like the
        base class does in test mode -- the reputation / exclusion path
        we're demonstrating comes from actual streaming behavior, not
        synthetic tasks.
        """
        # Tick clock so the base mechanics still run (reputation queries,
        # peer monitoring, etc).
        _ = self.tasking_tick(0)
        self._report_unhandled()
