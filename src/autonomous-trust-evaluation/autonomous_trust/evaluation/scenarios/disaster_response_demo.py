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

from autonomous_trust.core import ProcMeta
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
    """Mixin: lazily build a per-peer source on the first acquire() call.

    The mixin runs in the child process (via acquire()), not in the
    parent's add_worker / __init__ path. Two reasons:

      1. _source_for_peer() returns a closure containing itertools.cycle,
         which is not picklable. Wiring in __init__ would put a non-
         picklable attribute on the Process instance, and forkserver
         dispatch would fail at apply_async time.
      2. Building generators in the parent then pickling them across
         the process boundary doubles construction work and risks the
         RandomWalk / Sinusoidal generators carrying RNG state forward
         across the fork in surprising ways. Lazy build keeps each
         child's RNG self-contained.

    Honors AT_PEER_NAME from the env so the source matches the scenario
    role assigned by the compose generator.
    """

    # Child classes inherit EnvDataProcess's self.active flag.
    active: bool

    def acquire(self):
        if not getattr(self, "_demo_source_wired", False):
            self._demo_source_wired = True
            peer_name = os.environ.get("AT_PEER_NAME", "")
            if self.active and peer_name:
                try:
                    source = _source_for_peer(peer_name)
                    self.set_source(source)  # type: ignore[attr-defined]
                except Exception:
                    logger.exception(
                        "[%s] failed to wire demo source for %s",
                        type(self).__name__, peer_name)
        return super().acquire()  # type: ignore[misc]


class DisasterWeatherStreamProcess(_DemoProcessMixin, WeatherStreamProcess,
                                   metaclass=ProcMeta,
                                   proc_name='weather-stream',
                                   description='NOAA weather data stream',
                                   cfg_name='weather-stream'):
    pass


class DisasterSeismicStreamProcess(_DemoProcessMixin, SeismicStreamProcess,
                                   metaclass=ProcMeta,
                                   proc_name='seismic-stream',
                                   description='USGS seismic data stream',
                                   cfg_name='seismic-stream'):
    pass


class DisasterAirQualityStreamProcess(_DemoProcessMixin,
                                      AirQualityStreamProcess,
                                      metaclass=ProcMeta,
                                      proc_name='airquality-stream',
                                      description='EPA air quality data stream',
                                      cfg_name='airquality-stream'):
    pass


class DisasterSituationReportProcess(_DemoProcessMixin,
                                     SituationReportProcess,
                                     metaclass=ProcMeta,
                                     proc_name='situation-report',
                                     description='FEMA situation report stream',
                                     cfg_name='situation-report'):
    pass


def _capability_announce(*_args, **_kwargs):
    """Placeholder Capability.execute() target for advertised stream caps.

    Registered against every cap in `autonomous_ability`. Streaming
    consumers go through DataProtocol/DataRcvr, not the Task path, so
    this is never invoked in normal operation. It exists only because
    Capability.execute() requires a callable.

    MUST be module-level so `self.capabilities` (which holds it via the
    Capability registry) is picklable across the multiprocessing.manager
    queue boundary when the base class fan-puts caps onto every worker.
    A closure defined inside the method would crash every peer with
    `Can't get local object` at the first cap-broadcast tick.
    """
    return None


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
    """Agency-aware AutonomousTrust for the multi-agency demo.

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

        IMPORTANT: agency caps must be registered BEFORE `super()` runs.
        The base method (with testing=True) immediately fan-puts the
        current `self.capabilities` snapshot onto every subprocess queue
        — that snapshot is what the identity subprocess advertises to
        peers. If we register agency caps *after* super(), identity
        broadcasts mult/pow/pi only, peers never see weather_stream/
        seismic_stream/etc., and the inspector bridge's
        _subscribe_to_new_peers finds no caps to subscribe to.
        """
        # Role default + env-specified capabilities.
        caps_to_advertise = set(self._demo_capabilities)
        role_entry = _ROLE_PROCESS.get(self._demo_role)
        if role_entry is not None:
            caps_to_advertise.add(role_entry[1])

        for cap_name in caps_to_advertise:
            try:
                # _capability_announce is module-level so self.capabilities
                # remains picklable for the fan-put inside super(). Defining
                # it as a closure here would crash every peer with
                # "Can't get local object" at the first cap-broadcast tick.
                self.capabilities.register_ability(cap_name,
                                                   _capability_announce)
            except Exception:
                self.logger.exception("Failed to register capability %s",
                                      cap_name)

        super().autonomous_ability(queues)

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


# ----------------------------------------------------------------------
# Per-peer envdata config injection
# ----------------------------------------------------------------------

def _write_envdata_config(role_kind: str, peer_name: str,
                          cfg_dir: str) -> Optional[str]:
    """Write a per-role EnvDataConfig file into the peer's cfg_dir.

    Without this, EnvDataProcess.__init__ sees no entry under its proc_name
    and goes inactive — meaning add_worker registers a Process that never
    publishes readings. The compose generator only emits AT_PEER_NAME /
    AT_ROLE_KIND env vars; nobody else materializes those into a config
    file, so we do it here at peer startup before AutonomousTrust loads
    configs.

    Returns the written path, or None if the role has no envdata worker.
    """
    from autonomous_trust.core.config import Configuration
    from autonomous_trust.services.envdata import EnvDataConfig

    entry = _ROLE_PROCESS.get(role_kind)
    if entry is None or not peer_name:
        return None
    proc_cls, _cap = entry
    cfg_path = os.path.join(cfg_dir,
                            proc_cls.cfg_name + Configuration.file_ext)
    if os.path.exists(cfg_path):
        return cfg_path
    cfg = EnvDataConfig(peer_name=peer_name, cadence_sec=1.0,
                        source_name=role_kind)
    cfg.to_file(cfg_path)
    return cfg_path


# ----------------------------------------------------------------------
# Module entrypoint (peer container `python -m ...disaster_response_demo`)
# ----------------------------------------------------------------------

def _main(argv=None):
    import argparse
    import sys

    from autonomous_trust.core import LogLevel
    from autonomous_trust.core.config import Configuration
    from autonomous_trust.core.config.generate import random_config
    from autonomous_trust.core._python.system import dev_root_dir, CfgIds

    p = argparse.ArgumentParser(
        prog="python -m autonomous_trust.evaluation.scenarios.disaster_response_demo",
        description=("Multi-agency disaster-response peer entrypoint. Mirrors "
                     "the stock `python -m autonomous_trust` flags and "
                     "additionally injects per-role envdata configuration "
                     "from AT_PEER_NAME / AT_ROLE_KIND."))
    p.add_argument('ident', type=int, nargs='?', default=None,
                   help='optional integer for separating multiple node configs')
    p.add_argument('--exclude-logs', type=str, action='append',
                   help='exclude named classes from logging')
    p.add_argument('--test', action='store_true',
                   help='run limited testing application')
    p.add_argument('--live', action='store_true',
                   help='run in production environ')
    p.add_argument('--log-level', type=str, default='info',
                   choices=['critical', 'error', 'warning', 'info',
                            'debug', 'verbose'],
                   help='set logging level (default: info)')
    args = p.parse_args(argv if argv is not None else sys.argv[1:])

    if args.live:
        random_config(Configuration.get_cfg_dir(), args.ident)
    else:
        random_config(dev_root_dir, args.ident)

    role = os.environ.get("AT_ROLE_KIND", "")
    peer_name = os.environ.get("AT_PEER_NAME", "")
    written = _write_envdata_config(role, peer_name,
                                    Configuration.get_cfg_dir())
    if written is not None:
        print(f"[demo] envdata config for {peer_name} ({role}) -> {written}",
              flush=True)

    to_log = None
    if args.exclude_logs is not None:
        to_log = [cls for cls in list(CfgIds) if cls not in args.exclude_logs]
    level = LogLevel[args.log_level.upper()]
    DisasterResponseDemoAT(multiproc=True, log_level=level,
                           logfile=Configuration.log_stdout,
                           log_classes=to_log,
                           testing=args.test).run_forever()


if __name__ == '__main__':
    # Default to forkserver: 'fork' (Linux default through 3.13) forks a
    # multi-threaded process and can deadlock the child. Harmless on 3.14+.
    import multiprocessing as _mp
    _mp.set_start_method('forkserver', force=True)
    _main()
