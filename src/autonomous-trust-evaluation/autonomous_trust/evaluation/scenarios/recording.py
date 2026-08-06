# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
# ******************

"""Event recording + key-stat tracking for the demo.

Two concerns, kept small:

    EventRecorder  -- captures a scenario's event stream to JSON so the
                      dashboard can replay an identical run on a laptop
                      without K8s. Complements PlaybackEngine.load_recorded.

    KeyStatTracker -- derives presentation-friendly metrics from the live
                      event stream. Examples:
                        compromise_to_exclusion_sec
                        epa_onboard_sec
                        total_peers_active
                      Feeds the top-bar callout slot.

Both are listeners on the scenario's event stream; they don't mutate
the scenario and have no opinion on time or transport.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


logger = logging.getLogger(__name__)


# ----------------------------------------------------------------------
# EventRecorder
# ----------------------------------------------------------------------

class EventRecorder:
    """Buffers scenario events and writes to a JSON file on flush.

    Example:
        rec = EventRecorder()
        engine.on_event(lambda ev, t: rec.record(ev))
        # ... scenario runs ...
        rec.save('recording.json', scenario=scenario)

    Snapshots (reputation samples, sensor readings, etc.) go into a
    separate sidecar list via ``record_snapshot`` so the event log
    panel doesn't drown in 1 Hz reading records during replay. The
    payload shape is opaque to the recorder; the playback consumer
    decides how to interpret each ``type``.
    """

    def __init__(self):
        self._events: list[dict] = []
        self._snapshots: list[dict] = []

    def record(self, ev) -> None:
        """Accept a ScenarioEvent or any object exposing .to_dict()."""
        try:
            if hasattr(ev, "to_dict"):
                entry = dict(ev.to_dict())
            elif isinstance(ev, dict):
                entry = dict(ev)
            else:
                return
            # Stamp wall-clock time so playback can replay with true cadence.
            entry.setdefault("wall_time", datetime.now(timezone.utc).isoformat())
            self._events.append(entry)
        except Exception:
            logger.exception("EventRecorder.record failed for %r", ev)

    def record_snapshot(self, snapshot: dict) -> None:
        """Buffer a snapshot dict for the sidecar stream.

        Expected keys: ``t`` (float seconds), ``type`` (string label
        the playback consumer dispatches on). Everything else is
        passed through verbatim.
        """
        try:
            if not isinstance(snapshot, dict):
                return
            entry = dict(snapshot)
            entry.setdefault("t", 0.0)
            self._snapshots.append(entry)
        except Exception:
            logger.exception("EventRecorder.record_snapshot failed for %r",
                             snapshot)

    @property
    def events(self) -> list[dict]:
        return list(self._events)

    @property
    def snapshots(self) -> list[dict]:
        return list(self._snapshots)

    def save(self, path: str, scenario=None) -> None:
        payload: dict = {"event_log": list(self._events)}
        if self._snapshots:
            payload["snapshots"] = list(self._snapshots)
        if scenario is not None and hasattr(scenario, "export_scenario_def"):
            payload["scenario"] = scenario.export_scenario_def()
            payload["recorded_at"] = datetime.now(timezone.utc).isoformat()

        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w") as f:
            json.dump(payload, f, indent=2)


# ----------------------------------------------------------------------
# KeyStatTracker
# ----------------------------------------------------------------------

@dataclass
class KeyStats:
    """Presentation-friendly metrics extracted from the event log."""
    peers_joined: int = 0
    peers_active: int = 0
    peers_excluded: int = 0
    compromise_onset_sec: Optional[float] = None
    compromise_detected_sec: Optional[float] = None
    compromise_excluded_sec: Optional[float] = None
    epa_join_sec: Optional[float] = None
    epa_onboard_sec: Optional[float] = None

    # Derived durations -- headline numbers for the top-bar callout.
    @property
    def detection_latency_sec(self) -> Optional[float]:
        if (self.compromise_onset_sec is not None
                and self.compromise_detected_sec is not None):
            return max(0.0, self.compromise_detected_sec
                       - self.compromise_onset_sec)
        return None

    @property
    def exclusion_latency_sec(self) -> Optional[float]:
        if (self.compromise_onset_sec is not None
                and self.compromise_excluded_sec is not None):
            return max(0.0, self.compromise_excluded_sec
                       - self.compromise_onset_sec)
        return None

    @property
    def epa_onboarding_sec(self) -> Optional[float]:
        if (self.epa_join_sec is not None
                and self.epa_onboard_sec is not None):
            return max(0.0, self.epa_onboard_sec - self.epa_join_sec)
        return None

    def callouts(self) -> list[tuple[str, str]]:
        """Return (label, value) pairs suitable for the top-bar chip row."""
        out: list[tuple[str, str]] = []
        d = self.detection_latency_sec
        x = self.exclusion_latency_sec
        on = self.epa_onboarding_sec
        if d is not None:
            out.append(("Detection", _fmt_sec(d)))
        if x is not None:
            out.append(("Compromise → Exclusion", _fmt_sec(x)))
        if on is not None:
            out.append(("EPA onboarding", _fmt_sec(on)))
        out.append(("Peers active",
                    f"{self.peers_active} of {self.peers_joined}"))
        return out


class KeyStatTracker:
    """Listens to the scenario event stream and keeps stats current.

    A lightweight companion to EventRecorder; wire both onto the engine:

        tracker = KeyStatTracker(compromised_peer='noaa-3', epa_peer='epa-1')
        engine.on_event(lambda ev, t: tracker.observe(ev))
    """

    def __init__(self,
                 compromised_peer: str = "noaa-3",
                 epa_peer: str = "epa-1",
                 onboard_threshold: float = 0.5):
        self._compromised = compromised_peer
        self._epa = epa_peer
        self._onboard_threshold = onboard_threshold
        self.stats = KeyStats()

    # --- event handler ----------------------------------------------

    def observe(self, ev) -> None:
        """Event sink. Accepts scenario ScenarioEvent objects."""
        try:
            kind = getattr(ev.event_type, "name", str(ev.event_type))
        except Exception:
            kind = str(getattr(ev, "event_type", ""))

        peer = getattr(ev, "peer_name", None)
        # Scenario events carry a timedelta; downstream float seconds.
        t_td = getattr(ev, "timestamp", None)
        t = t_td.total_seconds() if hasattr(t_td, "total_seconds") else None

        if kind == "PEER_JOIN":
            self.stats.peers_joined += 1
            self.stats.peers_active += 1
            if peer == self._epa and t is not None:
                self.stats.epa_join_sec = t
        elif kind == "PEER_DEPART":
            self.stats.peers_active = max(0, self.stats.peers_active - 1)
        elif kind == "COMPROMISE_START":
            if peer == self._compromised and t is not None:
                self.stats.compromise_onset_sec = t
        elif kind == "COMPROMISE_DETECT":
            if peer == self._compromised and t is not None:
                self.stats.compromise_detected_sec = t
        elif kind == "PEER_EXCLUDE":
            self.stats.peers_active = max(0, self.stats.peers_active - 1)
            self.stats.peers_excluded += 1
            if peer == self._compromised and t is not None:
                self.stats.compromise_excluded_sec = t

    def observe_reputation(self, peer: str, score: float,
                           t_seconds: float) -> None:
        """Optional hook for the reputation feed.

        Marks EPA onboarded when its score first crosses the threshold.
        Kept separate from `observe` so callers can wire only what they have.
        """
        if peer == self._epa and self.stats.epa_onboard_sec is None:
            if score >= self._onboard_threshold:
                self.stats.epa_onboard_sec = t_seconds


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------

def _fmt_sec(sec: float) -> str:
    if sec < 1:
        return "<1s"
    if sec < 60:
        return f"{int(sec)}s"
    m = int(sec) // 60
    s = int(sec) % 60
    return f"{m}m{s:02d}s"
