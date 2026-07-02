# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
# ******************

"""Common interface between a scenario data source and a Dash app.

A ``ScenarioInterface`` is anything that produces scenario state over
time and can be ticked once per UI cadence. Concrete implementations:

  - ``SimulationInterface``  — TCP simulator (``autonomous_trust.simulator``)
                                ; mission/ uses this.
  - ``PlaybackInterface``    — in-process ``PlaybackEngine`` (+ optional
                                live-bridge queue); multi_agency/ uses
                                this.

Adding a new scenario means implementing this ABC (or subclassing one
of the existing concrete sources) and supplying a Dash app that
consumes its update/reset/end handler streams.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, Optional


@dataclass
class ScenarioState:
    """Snapshot of scenario state pushed to update handlers each tick.

    The ``source_specific`` dict is the escape hatch for state that
    doesn't fit the common shape (e.g. simulator's per-peer telemetry,
    or playback's live-bridge events).
    """
    time_seconds: float = 0.0
    playing: bool = False
    phase_idx: int = -1
    phase_name: str = ""
    duration_seconds: float = 0.0
    mode: str = ""                 # e.g. "live" or "playback"
    source_specific: dict[str, Any] = field(default_factory=dict)


# Handler signatures.
UpdateHandler = Callable[[ScenarioState], None]
EndHandler = Callable[[], None]
ResetHandler = Callable[[], None]


class ScenarioInterface(ABC):
    """Abstract scenario data source.

    Concrete implementations own the scenario clock and any I/O (TCP
    simulator socket, in-process engine + queues, etc.). The Dash app
    drives ``tick()`` once per UI cadence and reads the returned state
    or registers handlers to be notified.

    Handler-registration is concrete on the ABC so subclasses don't
    have to redo the bookkeeping. Subclasses call ``_fire_*`` at the
    right points in their loop.
    """

    def __init__(self):
        self._update_handlers: list[UpdateHandler] = []
        self._end_handlers: list[EndHandler] = []
        self._reset_handlers: list[ResetHandler] = []

    # --- lifecycle ---------------------------------------------------

    @abstractmethod
    def start(self) -> None:
        """Begin serving updates. Called once before the first tick."""

    @abstractmethod
    def stop(self) -> None:
        """Graceful shutdown. Idempotent."""

    # --- tick / state ------------------------------------------------

    @abstractmethod
    def tick(self) -> ScenarioState:
        """Advance one step. Fires update handlers and returns the
        snapshot. May be a no-op when paused (still returns state)."""

    @abstractmethod
    def reset(self) -> None:
        """Return to T+0. Fires reset handlers."""

    @abstractmethod
    def toggle(self) -> None:
        """Play/pause toggle."""

    @property
    @abstractmethod
    def paused(self) -> bool:
        """True iff the source is currently NOT advancing."""

    @property
    @abstractmethod
    def current_time(self) -> float:
        """Current scenario-relative time in seconds."""

    # --- handler registration (concrete) -----------------------------

    def register_update_handler(self, h: UpdateHandler) -> None:
        """Subscribe to per-tick state snapshots."""
        self._update_handlers.append(h)

    def register_end_handler(self, h: EndHandler) -> None:
        """Subscribe to scenario-end notifications (called once)."""
        self._end_handlers.append(h)

    def register_reset_handler(self, h: ResetHandler) -> None:
        """Subscribe to reset notifications (fired on every ``reset()``)."""
        self._reset_handlers.append(h)

    def _fire_update(self, state: ScenarioState) -> None:
        for h in self._update_handlers:
            try:
                h(state)
            except Exception:
                # Handlers are user code; one misbehaving listener
                # mustn't break the others or the tick loop.
                import logging
                logging.getLogger(__name__).exception(
                    "Update handler %r failed", h)

    def _fire_end(self) -> None:
        for h in self._end_handlers:
            try:
                h()
            except Exception:
                import logging
                logging.getLogger(__name__).exception(
                    "End handler %r failed", h)

    def _fire_reset(self) -> None:
        for h in self._reset_handlers:
            try:
                h()
            except Exception:
                import logging
                logging.getLogger(__name__).exception(
                    "Reset handler %r failed", h)
