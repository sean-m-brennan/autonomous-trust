# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
# ******************

"""In-process scenario source: ``PlaybackEngine`` + optional live bridge.

Used by the multi-agency demo (and any future in-process scenario): the
Dash callback ticks this interface, which advances the scenario engine,
drains the live-AT bridge queue (if any), and fans events out to
registered handlers. No threads, no sockets — pure poll-driven.

For the TCP-simulator-driven equivalent (mission/), see
``dash_components.sim_iface.SimulationInterface`` which is the other
``ScenarioInterface`` implementation.
"""

from __future__ import annotations

import atexit
import logging
import queue as _queue
from datetime import datetime, timedelta
from typing import Callable, Optional

from .playback_engine import PlaybackEngine, PlaybackMode
from .recording import EventRecorder
from .scenario import Scenario, ScenarioEvent
from .scenario_iface import ScenarioInterface, ScenarioState


logger = logging.getLogger(__name__)


# Handler for one drained bridge-queue tuple. The shape of the tuple
# depends on the tag (first element); see inspector/bridge.py for the
# canonical list. The handler is responsible for whatever
# UI-derived-state update it needs.
BridgeEventHandler = Callable[[tuple], None]

# Handler for one new entry appended to scenario._event_log. Fires for
# both scripted scenario events AND bridge-derived ANNOTATION records,
# so the UI's event-log panel can subscribe to a single stream.
EventLogHandler = Callable[[dict], None]

# Handler for engine-dispatched scenario events (the same listener
# shape as PlaybackEngine.on_event — used for KeyStatTracker etc.).
ScenarioEventHandler = Callable[[ScenarioEvent, timedelta], None]


class PlaybackInterface(ScenarioInterface):
    """Scenario interface backed by ``PlaybackEngine`` + optional bridge.

    Construction:
        scenario     — concrete ``Scenario`` instance
        playback_file — when set, switches to PLAYBACK mode and replays
                        the recorded JSON event log
        bridge_queue — multiprocessing queue from a live AT bridge; when
                        set, drained each tick and fanned to bridge
                        event handlers
        record_file  — when set (live mode only), every dispatched
                        scenario event is recorded; flushed on shutdown
    """

    def __init__(self,
                 scenario: Scenario,
                 *,
                 playback_file: Optional[str] = None,
                 bridge_queue=None,
                 record_file: Optional[str] = None):
        super().__init__()
        self._scenario = scenario
        self._playback_file = playback_file
        self._bridge_queue = bridge_queue
        self._record_file = record_file

        mode = (PlaybackMode.PLAYBACK
                if playback_file else PlaybackMode.LIVE)
        self._engine = PlaybackEngine(scenario, mode=mode)
        if playback_file:
            self._engine.load_recorded(playback_file)

        # Optional event recorder. Only attach in live mode; replaying
        # an existing JSON file with --record would just round-trip
        # the same events.
        self._event_recorder: Optional[EventRecorder] = None
        if record_file is not None and playback_file is None:
            self._event_recorder = EventRecorder()
            self._engine.on_event(
                lambda ev, t: self._event_recorder.record(ev))
            atexit.register(self._save_recording)

        # Bridge-side bookkeeping.
        self._bridge_seen: set[str] = set()
        self._event_log_seen: int = 0

        # Extension handler lists.
        self._scenario_event_handlers: list[ScenarioEventHandler] = []
        self._bridge_event_handlers: list[BridgeEventHandler] = []
        self._event_log_handlers: list[EventLogHandler] = []

        # Re-fire engine events to scenario_event_handlers.
        self._engine.on_event(self._dispatch_scenario_event)

    # --- read-only access for UI consumers --------------------------

    @property
    def scenario(self) -> Scenario:
        return self._scenario

    @property
    def engine(self) -> PlaybackEngine:
        return self._engine

    @property
    def mode(self) -> str:
        return self._engine.mode

    @property
    def has_bridge(self) -> bool:
        return self._bridge_queue is not None

    @property
    def event_recorder(self) -> Optional[EventRecorder]:
        return self._event_recorder

    # --- ScenarioInterface contract ---------------------------------

    @property
    def paused(self) -> bool:
        return not self._engine.playing

    @property
    def current_time(self) -> float:
        return self._engine.scenario_time.total_seconds()

    def start(self) -> None:
        """Begin advancing the scenario.

        LIVE mode auto-plays — the AT mesh is producing real-time
        observations regardless of the dashboard, so the scripted
        timeline should run at wall rate alongside it.

        PLAYBACK mode stays paused so the operator initiates the
        replay manually (typical demo flow).
        """
        if self._engine.mode == PlaybackMode.LIVE and not self._engine.playing:
            self._engine.play()

    def stop(self) -> None:
        # Idempotent flush of the recorder; noop if no recording.
        self._save_recording()

    def tick(self) -> ScenarioState:
        """Advance the engine, drain the bridge, fire handlers, return state."""
        self._engine.tick()
        tel = self._engine.telemetry()
        self._drain_bridge(tel.scenario_time)
        self._drain_event_log_tail()
        state = ScenarioState(
            time_seconds=tel.scenario_time,
            playing=tel.playing,
            phase_idx=tel.current_phase_idx,
            phase_name=tel.current_phase_name,
            duration_seconds=tel.scenario_duration,
            mode=tel.mode,
        )
        self._fire_update(state)
        return state

    def reset(self) -> None:
        """Return scenario + bridge bookkeeping to T+0; fire reset handlers."""
        self._engine.reset()
        self._bridge_seen.clear()
        self._event_log_seen = 0
        self._fire_reset()

    def toggle(self) -> None:
        self._engine.toggle()

    # --- transport passthroughs -------------------------------------

    def play(self) -> None:
        self._engine.play()

    def pause(self) -> None:
        self._engine.pause()

    def set_speed(self, speed: float) -> None:
        self._engine.set_speed(speed)

    def seek(self, t_seconds: float) -> None:
        self._engine.seek(t_seconds)

    def seek_to_phase(self, name: str) -> None:
        self._engine.seek_to_phase(name)

    def telemetry(self):
        """PlaybackTelemetry snapshot — for callers that want the
        engine's richer state object alongside ScenarioState."""
        return self._engine.telemetry()

    # --- extension handler registration -----------------------------

    def register_scenario_event_handler(self, h: ScenarioEventHandler) -> None:
        """Subscribe to engine-dispatched scenario events.

        Equivalent to ``engine.on_event`` — exposed here so consumers
        don't have to reach through the interface for it.
        """
        self._scenario_event_handlers.append(h)

    def register_bridge_event_handler(self, h: BridgeEventHandler) -> None:
        """Subscribe to live-bridge events drained from ``bridge_queue``.

        Each handler receives the raw tuple (tag, *payload). No-op
        when the interface was constructed without a bridge queue.
        """
        self._bridge_event_handlers.append(h)

    def register_event_log_handler(self, h: EventLogHandler) -> None:
        """Subscribe to new entries appended to scenario._event_log.

        Fires for both scripted events and bridge-derived ANNOTATION
        records, so a single subscriber can drive an event-log panel.
        """
        self._event_log_handlers.append(h)

    def on_engine_event(self, h: ScenarioEventHandler) -> None:
        """Direct passthrough to ``PlaybackEngine.on_event`` for
        listeners (e.g. KeyStatTracker) that want events as the engine
        dispatches them, before our scenario_event_handlers fire."""
        self._engine.on_event(h)

    def register_snapshot_handler(
            self, h: Callable[[dict, timedelta], None]) -> None:
        """Subscribe to recorded snapshot records (reputation samples,
        sensor readings, etc.) from the playback sidecar. Passthrough
        to ``PlaybackEngine.on_snapshot`` — exposed here so callers
        don't have to reach through the interface for it.
        """
        self._engine.on_snapshot(h)

    # --- internals ---------------------------------------------------

    def _dispatch_scenario_event(self, ev: ScenarioEvent,
                                 t: timedelta) -> None:
        for h in self._scenario_event_handlers:
            try:
                h(ev, t)
            except Exception:
                logger.exception("Scenario-event handler %r failed", h)

    def _fire_bridge_event(self, ev: tuple) -> None:
        for h in self._bridge_event_handlers:
            try:
                h(ev)
            except Exception:
                logger.exception("Bridge-event handler %r failed", h)

    def _fire_event_log(self, rec: dict) -> None:
        for h in self._event_log_handlers:
            try:
                h(rec)
            except Exception:
                logger.exception("Event-log handler %r failed", h)

    def _drain_bridge(self, scenario_time: float) -> None:
        """Pull bridge observations into the scenario's event log as
        ANNOTATION records and fire bridge_event_handlers for each
        raw tuple. UI-derived state (rep timeline, sensor history,
        streams panel) is updated by the registered handlers, not
        here."""
        if self._bridge_queue is None:
            return
        wall = datetime.utcnow().isoformat()
        while True:
            try:
                ev = self._bridge_queue.get_nowait()
            except _queue.Empty:
                break
            except Exception:
                break
            if not ev:
                continue
            tag = ev[0]
            # Fan the raw tuple to handlers first so UI consumers
            # can update their derived state in deterministic order.
            self._fire_bridge_event(ev)

            if tag == "peer_seen" and len(ev) >= 2:
                name = str(ev[1])
                if name in self._bridge_seen:
                    # Don't double-annotate the timeline for re-fires
                    # of the same peer.
                    continue
                self._bridge_seen.add(name)
                desc = f"[live] peer observed: {name}"
            elif tag == "reputation" and len(ev) >= 3:
                name = str(ev[1])
                score = float(ev[2])
                desc = f"[live] {name} reputation = {score:.2f}"
            elif tag == "rep_pair" and len(ev) >= 4:
                observer = str(ev[1])
                subject = str(ev[2])
                score = float(ev[3])
                if observer == subject:
                    continue
                desc = (f"[live] {observer} ↔ {subject} trust "
                        f"= {score:.2f}")
                name = subject
            elif tag == "ping_at" and len(ev) >= 3:
                # ("ping_at", name, rtt_ms, loss_pct, count, wall_t) — loss is
                # worth annotating: an average rtt alone reads the same whether
                # a peer answered every ping or one in five.
                name = str(ev[1])
                rtt = float(ev[2])
                desc = f"[live] {name} rtt = {rtt:.0f}ms"
                if len(ev) >= 4 and float(ev[3]) > 0.0:
                    desc += f", loss = {float(ev[3]):.0f}%"
            elif tag == "reading":
                # Streams fire ~1 Hz per peer per data_type — would
                # drown the timeline event log. Handlers above already
                # forwarded the raw reading; skip the annotation.
                continue
            else:
                continue
            self._scenario._event_log.append({     # noqa: SLF001
                "t": scenario_time,
                "type": "ANNOTATION",
                "peer": name,
                "description": desc,
                "data": {"source": "bridge", "tag": tag},
                "wall_time": wall,
            })

    def _drain_event_log_tail(self) -> None:
        """Drain new entries from scenario._event_log into event-log
        handlers. Each record is fired exactly once; we track an
        incrementing index so re-runs/seeks of the same scenario
        re-emit appropriately."""
        log = self._scenario._event_log   # noqa: SLF001
        n = len(log)
        if n <= self._event_log_seen:
            return
        for rec in log[self._event_log_seen:n]:
            self._fire_event_log(rec)
        self._event_log_seen = n

    def _save_recording(self) -> None:
        """atexit hook: flush the EventRecorder to disk. Idempotent —
        safe to call from multiple shutdown paths (atexit + signal)."""
        if self._event_recorder is None or self._record_file is None:
            return
        try:
            self._event_recorder.save(self._record_file,
                                      scenario=self._scenario)
            logger.info("Recorded %d scenario events to %s",
                        len(self._event_recorder.events),
                        self._record_file)
        except Exception:
            logger.exception("Failed to write recording to %s",
                             self._record_file)
        # Drop the recorder ref so a second call is a no-op.
        self._event_recorder = None
