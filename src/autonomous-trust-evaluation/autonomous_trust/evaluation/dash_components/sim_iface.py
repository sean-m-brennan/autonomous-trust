# ******************
#  Copyright 2023 TekFive, Inc., Sean M. Brennan, and contributors
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

import atexit
import logging
import threading
import time
from datetime import datetime
from queue import Queue
from typing import Callable, Optional

from autonomous_trust.inspector.peer.daq import CohortInterface
from autonomous_trust.inspector.dash_components.core import DashControl
from autonomous_trust.simulator.sim_client import SimClient
from autonomous_trust.simulator import default_port
from autonomous_trust.simulator.sim_data import SimState

from ..scenarios.scenario_iface import ScenarioInterface, ScenarioState


class SimulationInterface(CohortInterface, ScenarioInterface):
    """TCP-simulator-driven scenario source.

    Drains states pushed by an ``autonomous_trust.simulator`` instance
    over a TCP socket; fans them out to update / end / reset handlers.
    Used by mission/. The ``ScenarioInterface`` mixin lets this share
    typing with ``PlaybackInterface`` (the in-process equivalent for
    multi_agency/), so a Dash app can be written against the ABC.
    """

    cadence = 1

    # ScenarioInterface declares `paused` as an abstract read-only property,
    # but CohortInterface owns it as a plain read/write attribute set in its
    # __init__ -- and an instance attribute never satisfies an ABC, so without
    # this the class stays abstract and cannot be instantiated at all. Declared
    # at class level rather than as a property because toggle() (and the
    # sync_objects fan-out) assigns to it.
    paused = True

    def __init__(self, dash_info: DashControl, sim_host: str = '127.0.0.1', sim_port: int = default_port,
                 sync_objects: list[CohortInterface] = None, log_level: int = logging.INFO, logfile: str = None):
        # Initialize both bases. CohortInterface owns the AT-side
        # plumbing (peers/time/log); ScenarioInterface owns the
        # generic handler lists.
        CohortInterface.__init__(self, log_level=log_level, logfile=logfile)
        ScenarioInterface.__init__(self)
        # Frame index from SimClient (was previously named `tick` —
        # renamed to avoid colliding with ScenarioInterface.tick()).
        self.frame_idx = 0
        self.ctl = dash_info
        self.app = dash_info.app
        self.client = SimClient(callback=self.state_to_queue(), logger=self.logger, passive=False)
        self.client_thread = threading.Thread(target=self.client.run, args=(sim_host, sim_port))
        self.sim_thread = threading.Thread(target=self.run)
        self.queue = Queue(maxsize=1)
        self.can_reset = False
        self.halt = False
        self.sync_objects = sync_objects
        if sync_objects is None:
            self.sync_objects: list[CohortInterface] = []
        # Most recent SimState received; surfaced via current_time and
        # used by tick() snapshots.
        self._latest_state: Optional[SimState] = None
        atexit.register(self.interrupt)

    # --- legacy registration aliases (pre-ScenarioInterface code uses
    #     these list names; ScenarioInterface stores in
    #     _update_handlers / _end_handlers / _reset_handlers).
    @property
    def update_handlers(self) -> list:
        return self._update_handlers

    @property
    def end_handlers(self) -> list:
        return self._end_handlers

    @property
    def reset_handlers(self) -> list:
        return self._reset_handlers

    # --- ScenarioInterface contract ---------------------------------

    @property
    def current_time(self) -> float:
        """Latest SimState's time (seconds since epoch); 0 if none yet."""
        if self._latest_state is None or self._latest_state.time is None:
            return 0.0
        t = self._latest_state.time
        if isinstance(t, datetime):
            return t.timestamp()
        return float(t)

    def tick(self) -> ScenarioState:
        """Snapshot the latest SimState and fan out to update handlers.

        The simulator pushes states asynchronously via ``state_to_queue``,
        so tick() doesn't itself drive the timeline — it just exposes
        the most recent push to consumers that prefer pull semantics.
        """
        state = ScenarioState(
            time_seconds=self.current_time,
            playing=not self.paused,
            mode="simulator",
            source_specific={
                "frame_idx": self.frame_idx,
                "sim_state": self._latest_state,
            },
        )
        self._fire_update(state)
        return state

    def reset(self) -> None:
        """Fire reset handlers; lifecycle is otherwise driven by the
        simulator's blank-state signal in ``update()``."""
        self._fire_reset()

    def toggle(self) -> None:
        self.paused = not self.paused
        for obj in self.sync_objects:
            obj.paused = self.paused

    # --- lifecycle --------------------------------------------------

    def start(self):
        self.client_thread.start()
        self.sim_thread.start()

    def stop(self):
        self.halt = True
        self.client.halt = True

    @property
    def resolution(self):
        return self.client.resolution

    @resolution.setter
    def resolution(self, res):
        self.client.resolution = res

    def interrupt(self):
        self.stop()
        #if self.client.sock is not None:  # FIXME remove
        #    self.client.sock.close()
        #self.client_thread.join()

    def state_to_queue(self):
        def cb(state):
            if state is not None:
                self.frame_idx = self.client.tick
                self._latest_state = state
                self.queue.put(state, block=True, timeout=None)
        return cb

    def update(self, initial=False):
        """May be called only once per timestep, i.e. synced with UI; does not use state data"""
        state = self.queue.get()
        for obj in self.sync_objects:
            obj.update()
            obj.paused = self.paused
        for handler in self._update_handlers:
            handler(state)
        if state.blank:
            self.logger.debug('Sim update; reset %s', state.blank)
            self.paused = True
            for obj in self.sync_objects:
                obj.paused = self.paused
            self.can_reset = True
            for handler in self._end_handlers:
                handler()
            while self.paused:
                time.sleep(0.1)
            self.can_reset = False
            for handler in self._reset_handlers:
                handler()
            for obj in self.sync_objects:
                obj.paused = self.paused

    def acquire_data(self):
        pass  # update() is overridden above

    def run(self):
        while not self.halt:
            if not self.paused:
                self.update()
            time.sleep(self.cadence)
