# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
# ******************

"""Scenario playback engine -- drives the demo clock.

The dashboard (play / pause / speed / phase-jump) is the user-facing
control surface; this engine is the thing it actually commands. It
advances a scenario at an arbitrary realtime factor and fans out events
to any number of listeners (the event log, the map, the trust graph,
the narration overlay, etc.).

Two modes:

    live mode      -- drives a live scenario.advance_to() against a
                      real wall clock; peers run in AT processes that
                      emit real reputation/negotiation messages. The
                      engine only schedules events and controls pace.

    playback mode  -- reads a pre-recorded JSON event stream (written
                      by scenario.export_scenario_def() + the inspector's
                      event recorder). No K8s cluster required; the
                      dashboard is the same either way.

The engine is deliberately single-threaded -- the calling loop ticks
it. That keeps integration with Dash callbacks simple (each callback
fire = one tick) and avoids threading races with the scenario's own
event-log.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Callable, Optional

from .scenario import Scenario, ScenarioEvent


logger = logging.getLogger(__name__)


# Event callback signature. The second arg is the fresh scenario_time
# at the moment the event fires -- handy for listeners that want a
# single time source (don't trust ev.timestamp for replayed events
# that may have been slightly skewed).
EventListener = Callable[[ScenarioEvent, timedelta], None]

# Tick callback signature -- called every loop even if no event fires.
TickListener = Callable[[timedelta], None]

# Snapshot callback signature -- fired as scenario_time crosses each
# recorded snapshot's `t`. Receives the raw snapshot dict + the fresh
# scenario_time at the moment of firing.
SnapshotListener = Callable[[dict, timedelta], None]


class PlaybackMode:
    """String enum."""
    LIVE = "live"
    PLAYBACK = "playback"


# Standard playback speeds (must match playback_controls.PlaybackControls).
ALLOWED_SPEEDS = (1.0, 2.0, 5.0, 10.0)


@dataclass
class PlaybackTelemetry:
    """Snapshot of engine state for the top-bar and progress UI."""
    playing: bool
    speed: float
    scenario_time: float           # seconds
    scenario_duration: float       # seconds
    current_phase_idx: int
    current_phase_name: str
    mode: str                      # live or playback

    def progress_fraction(self) -> float:
        if self.scenario_duration <= 0:
            return 0.0
        return min(1.0, self.scenario_time / self.scenario_duration)


class PlaybackEngine:
    """Controls scenario advancement with pause/resume/seek/speed.

    Usage:
        engine = PlaybackEngine(DisasterResponseScenario())
        engine.on_event(log.add_from_scenario_event)
        engine.on_event(map_listener)
        engine.on_tick(timeline_listener)
        engine.play()
        while True:
            engine.tick()          # one UI frame
    """

    def __init__(self,
                 scenario: Scenario,
                 mode: str = PlaybackMode.LIVE,
                 initial_speed: float = 1.0):
        self._scenario = scenario
        self._mode = mode
        self._speed = self._clamp_speed(initial_speed)
        self._playing = False
        self._scenario_time: timedelta = timedelta(0)
        self._last_wall: Optional[float] = None
        self._event_listeners: list[EventListener] = []
        self._tick_listeners: list[TickListener] = []
        self._snapshot_listeners: list[SnapshotListener] = []
        self._wired = False
        # PLAYBACK mode: recorded events buffered here, consumed by tick()
        # as scenario time crosses each event's timestamp.
        self._deferred_events: list[ScenarioEvent] = []
        # Parallel buffer for recorded snapshots (reputation samples,
        # sensor readings, etc.). Time-sorted; tick() pops as
        # scenario_time advances past each entry's `t`.
        self._deferred_snapshots: list[dict] = []
        # Playback transport extent. A recorded session routinely runs PAST
        # the scenario's nominal `duration` (the live coordinator doesn't hard
        # -stop at it), so clamping playback to scenario.duration would freeze
        # the demo partway through — most of the recording (events, the rogue
        # collapse, the strike/exfil) would never replay. load_recorded sets
        # this to cover the last recorded event/snapshot so the full session
        # plays. None in live mode => fall back to scenario.duration.
        self._playback_duration: Optional[timedelta] = None
        self._wire_scenario_listener()

    @property
    def _effective_duration(self) -> timedelta:
        """Transport length: the recording's true extent in playback, else
        the scenario's nominal duration."""
        if self._playback_duration is not None:
            return self._playback_duration
        return self._scenario.duration

    # --- wiring ------------------------------------------------------

    def _wire_scenario_listener(self):
        if self._wired:
            return
        self._scenario.on_event(self._dispatch)
        self._wired = True

    def _dispatch(self, ev: ScenarioEvent):
        for lst in self._event_listeners:
            try:
                lst(ev, self._scenario_time)
            except Exception:
                logger.exception("Event listener failed for %s",
                                 ev.event_type)

    def on_event(self, listener: EventListener):
        self._event_listeners.append(listener)

    def on_tick(self, listener: TickListener):
        self._tick_listeners.append(listener)

    def on_snapshot(self, listener: SnapshotListener):
        """Register a callback for recorded snapshot records.

        Snapshots are non-PhaseEvent payloads (reputation samples,
        sensor readings, etc.) loaded via ``load_recorded``'s
        ``snapshots`` sidecar; they fire in time order as the engine
        ticks past each one.
        """
        self._snapshot_listeners.append(listener)

    # --- transport ---------------------------------------------------

    @property
    def scenario(self) -> Scenario:
        return self._scenario

    @property
    def playing(self) -> bool:
        return self._playing

    @property
    def speed(self) -> float:
        return self._speed

    @property
    def mode(self) -> str:
        return self._mode

    @property
    def scenario_time(self) -> timedelta:
        return self._scenario_time

    def play(self):
        self._playing = True
        self._last_wall = time.monotonic()

    def pause(self):
        self._playing = False
        self._last_wall = None

    def toggle(self):
        if self._playing:
            self.pause()
        else:
            self.play()

    def set_speed(self, speed: float):
        self._speed = self._clamp_speed(speed)

    def seek(self, t_seconds: float):
        """Jump to an absolute scenario time."""
        if t_seconds < 0:
            t_seconds = 0.0
        duration = self._effective_duration.total_seconds()
        if t_seconds > duration:
            t_seconds = duration
        self._scenario_time = timedelta(seconds=t_seconds)
        # When seeking forwards, let the scenario fire any missed events.
        self._scenario.advance_to(self._scenario_time)
        self._last_wall = time.monotonic() if self._playing else None

    def seek_to_phase(self, phase_name: str):
        """Jump to the start of a named phase (case-insensitive)."""
        for phase in self._scenario.phases:
            if phase.name.lower() == phase_name.lower():
                self.seek(phase.start.total_seconds())
                return
        logger.warning("seek_to_phase: unknown phase %r", phase_name)

    def reset(self):
        """Return to T+0. Clears the scenario's event log; listeners
        should re-render on the next tick."""
        self._scenario_time = timedelta(0)
        self._scenario._event_log.clear()  # noqa: SLF001 (intentional)
        self._scenario._current_phase_idx = 0  # noqa: SLF001
        for name in list(self._scenario._peer_states):  # noqa: SLF001
            from .scenario import PeerState
            self._scenario._peer_states[name] = PeerState.PENDING
        self._last_wall = time.monotonic() if self._playing else None

    # --- loop --------------------------------------------------------

    def tick(self) -> None:
        """Advance the scenario by the elapsed wall time * speed.

        Call this once per UI frame. No-op when paused. In playback
        mode the behavior is identical -- the canned event stream has
        already been replayed into the scenario via `load_recorded`,
        and the scenario's event dispatch path fires listeners the
        same way.
        """
        if not self._playing:
            return
        now = time.monotonic()
        if self._last_wall is None:
            self._last_wall = now
            return
        dt_wall = now - self._last_wall
        self._last_wall = now

        dt_scenario = dt_wall * self._speed
        new_t = self._scenario_time + timedelta(seconds=dt_scenario)
        # Only PLAYBACK mode has a finite transport: a recording ends at its
        # last event/snapshot, so clamp the clock there and stop. LIVE mode
        # free-runs -- the AT mesh keeps producing observations past the
        # scenario's nominal duration and the live coordinator never
        # hard-stops, so freezing at duration would just stall the demo
        # mid-run (the scripted timeline is exhausted by the last phase, but
        # the network keeps evolving).
        if self._mode == PlaybackMode.PLAYBACK:
            duration = self._effective_duration
            if new_t >= duration:
                new_t = duration
                self._playing = False

        self._scenario_time = new_t
        if self._mode == PlaybackMode.PLAYBACK:
            # In playback mode the recording is the source of truth --
            # don't let the scripted timeline fire its own events on top.
            while (self._deferred_events
                   and self._deferred_events[0].timestamp <= new_t):
                ev = self._deferred_events.pop(0)
                self._scenario._apply_event(ev)  # noqa: SLF001
        else:
            self._scenario.advance_to(new_t)

        # Snapshots fire independent of mode -- a live run with replayed
        # snapshots is nonsensical (the live AT mesh produces its own
        # reputation/reading stream), but the buffer will be empty in
        # that case so the loop is a no-op.
        while (self._deferred_snapshots
               and self._deferred_snapshots[0].get("t", 0.0)
               <= new_t.total_seconds()):
            snap = self._deferred_snapshots.pop(0)
            for lst in self._snapshot_listeners:
                try:
                    lst(snap, self._scenario_time)
                except Exception:
                    logger.exception("Snapshot listener failed for %r",
                                     snap.get("type"))

        for lst in self._tick_listeners:
            try:
                lst(self._scenario_time)
            except Exception:
                logger.exception("Tick listener failed")

    # --- telemetry ---------------------------------------------------

    def telemetry(self) -> PlaybackTelemetry:
        phase = self._scenario.current_phase
        phase_idx = self._scenario._current_phase_idx  # noqa: SLF001
        return PlaybackTelemetry(
            playing=self._playing,
            speed=self._speed,
            scenario_time=self._scenario_time.total_seconds(),
            scenario_duration=self._effective_duration.total_seconds(),
            current_phase_idx=phase_idx,
            current_phase_name=phase.name if phase else "",
            mode=self._mode,
        )

    # --- canned playback -------------------------------------------

    def load_recorded(self, path: str):
        """Replay an exported scenario event log into the scenario's
        event pipeline.

        Accepts either a raw event list or a {\"event_log\": [...]}
        wrapper from the inspector's recorder. When the wrapper also
        carries a ``snapshots`` sidecar (reputation samples, sensor
        readings, etc.) those are buffered for the snapshot listener
        path and fire in time order alongside the scripted events.
        """
        with open(path) as f:
            data = json.load(f)
        events = data.get("event_log") if isinstance(data, dict) else data
        if not isinstance(events, list):
            raise ValueError("recorded playback: expected list of events")

        # Buffer the events in-order; tick() consumes them as scenario
        # time crosses each one's timestamp. That gives animated
        # replay instead of jumping straight to final state.
        from .scenario import PhaseEvent
        buf: list[ScenarioEvent] = []
        for rec in events:
            try:
                et = getattr(PhaseEvent, rec["type"], None)
                if et is None:
                    continue
                buf.append(ScenarioEvent(
                    timestamp=timedelta(seconds=float(rec.get("t", 0))),
                    event_type=et,
                    peer_name=rec.get("peer"),
                    description=rec.get("description", ""),
                    data=dict(rec.get("data", {})),
                ))
            except Exception:
                logger.exception("Replay parse failed for event: %r", rec)
        buf.sort(key=lambda ev: ev.timestamp)
        self._deferred_events = buf

        snapshots = (data.get("snapshots")
                     if isinstance(data, dict) else None) or []
        if not isinstance(snapshots, list):
            logger.warning("recorded playback: snapshots not a list, ignoring")
            snapshots = []
        snap_buf: list[dict] = []
        for rec in snapshots:
            if not isinstance(rec, dict):
                continue
            try:
                rec = dict(rec)
                rec["t"] = float(rec.get("t", 0.0))
            except (TypeError, ValueError):
                logger.exception("Replay parse failed for snapshot: %r", rec)
                continue
            snap_buf.append(rec)
        snap_buf.sort(key=lambda r: r.get("t", 0.0))
        self._deferred_snapshots = snap_buf

        # Stretch the transport to cover the full recording. A live session
        # commonly runs past the scenario's nominal duration, so without this
        # tick() would clamp at scenario.duration and freeze playback partway
        # through (the bulk of events/snapshots never replaying). Take the
        # latest recorded timestamp across both streams, floored at the
        # nominal duration so a short recording still gets the authored length.
        last_event = (buf[-1].timestamp.total_seconds() if buf else 0.0)
        last_snap = (snap_buf[-1].get("t", 0.0) if snap_buf else 0.0)
        recorded_extent = max(last_event, last_snap)
        nominal = self._scenario.duration.total_seconds()
        self._playback_duration = timedelta(
            seconds=max(recorded_extent, nominal))
        logger.info("playback extent: %.0fs (recording) vs %.0fs (nominal) "
                    "-> transport runs to %.0fs",
                    recorded_extent, nominal,
                    self._playback_duration.total_seconds())

    # --- helpers -----------------------------------------------------

    @staticmethod
    def _clamp_speed(speed: float) -> float:
        # Snap to the nearest allowed speed -- Dash UI sends floats; we
        # don't want 2.0000001 vs 2.0 bugs in the "active" speed check.
        if speed in ALLOWED_SPEEDS:
            return speed
        # Fall back: clamp to nearest
        return min(ALLOWED_SPEEDS, key=lambda s: abs(s - speed))
