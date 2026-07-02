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
Event recording and canned playback for AutonomousTrust demo scenarios.

Recording mode: Attach to a running Scenario, capture all events and data
readings into a JSON event stream file.

Playback mode: Load a recorded session, replay events at configurable speed
with play/pause/seek.  No live simulator or AT processes needed — the
dashboard shows a deterministic replay.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any, Callable, Optional

from autonomous_trust.services.data import Reading
from .scenarios.scenario import Scenario, ScenarioEvent

logger = logging.getLogger(__name__)


@dataclass
class PlaybackFrame:
    """A single frame in a recorded session.

    Attributes:
        t:         Scenario-relative time in seconds
        kind:      "event", "reading", "state", or "phase"
        payload:   Serialized event/reading/state dict
    """
    t: float
    kind: str
    payload: dict[str, Any]


class EventRecorder:
    """Records scenario events and data readings to a JSON-lines file.

    Attach to a Scenario before running it:

        recorder = EventRecorder("session.jsonl")
        scenario.on_event(recorder.record_event)
        # also call recorder.record_reading() from generator ticks
        scenario.run()
        recorder.close()
    """

    def __init__(self, output_path: str | Path):
        self._path = Path(output_path)
        self._fp = open(self._path, "w")
        self._frame_count = 0

    def _write(self, frame: PlaybackFrame):
        line = json.dumps({"t": frame.t, "kind": frame.kind,
                           "payload": frame.payload},
                          default=str)
        self._fp.write(line + "\n")
        self._frame_count += 1

    def record_event(self, event: ScenarioEvent):
        """Callback for Scenario.on_event()."""
        self._write(PlaybackFrame(
            t=event.timestamp.total_seconds(),
            kind="event",
            payload=event.to_dict(),
        ))

    def record_reading(self, reading: Reading):
        """Call from generator tick loops."""
        self._write(PlaybackFrame(
            t=reading.timestamp.total_seconds(),
            kind="reading",
            payload=reading.to_dict(),
        ))

    def record_state(self, t: timedelta, state: dict):
        """Record arbitrary state snapshot (e.g. reputation scores)."""
        self._write(PlaybackFrame(
            t=t.total_seconds(),
            kind="state",
            payload=state,
        ))

    def close(self):
        self._fp.close()
        logger.info("Recorded %d frames to %s", self._frame_count, self._path)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class PlaybackEngine:
    """Replays a recorded session from a JSON-lines file.

    Usage:
        engine = PlaybackEngine("session.jsonl")
        engine.on_frame(my_callback)
        engine.play(speed=1.0)    # real-time
        engine.play(speed=10.0)   # 10x
        engine.seek(120.0)        # jump to T+2:00

    The engine fires callbacks for each frame in order, sleeping to match
    the requested playback speed.
    """

    def __init__(self, input_path: str | Path):
        self._path = Path(input_path)
        self._frames: list[PlaybackFrame] = []
        self._listeners: list[Callable[[PlaybackFrame], None]] = []
        self._cursor: int = 0
        self._playing: bool = False
        self._speed: float = 1.0

        self._load()

    def _load(self):
        """Load all frames from the JSONL file."""
        with open(self._path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                obj = json.loads(line)
                self._frames.append(PlaybackFrame(
                    t=obj["t"],
                    kind=obj["kind"],
                    payload=obj["payload"],
                ))
        self._frames.sort(key=lambda f: f.t)
        logger.info("Loaded %d frames from %s (%.1fs duration)",
                    len(self._frames), self._path,
                    self._frames[-1].t if self._frames else 0)

    @property
    def duration(self) -> float:
        """Total duration in seconds."""
        return self._frames[-1].t if self._frames else 0.0

    @property
    def frame_count(self) -> int:
        return len(self._frames)

    @property
    def current_time(self) -> float:
        """Current playback position in seconds."""
        if 0 <= self._cursor < len(self._frames):
            return self._frames[self._cursor].t
        return self.duration

    def on_frame(self, callback: Callable[[PlaybackFrame], None]):
        """Register a listener for playback frames."""
        self._listeners.append(callback)

    def _emit(self, frame: PlaybackFrame):
        for cb in self._listeners:
            try:
                cb(frame)
            except Exception:
                logger.exception("Playback listener error")

    def seek(self, t_seconds: float):
        """Jump to the frame nearest to the given time."""
        self._cursor = 0
        for i, frame in enumerate(self._frames):
            if frame.t >= t_seconds:
                self._cursor = i
                return
        self._cursor = len(self._frames)

    def play(self, speed: float = 1.0, from_cursor: bool = True):
        """Play back frames at the given speed multiplier.

        Args:
            speed:       1.0 = real time, 10.0 = 10x fast-forward
            from_cursor: If False, restart from beginning
        """
        if not from_cursor:
            self._cursor = 0
        self._speed = max(0.1, speed)
        self._playing = True

        prev_t = self._frames[self._cursor].t if self._cursor < len(self._frames) else 0

        while self._playing and self._cursor < len(self._frames):
            frame = self._frames[self._cursor]

            # Sleep to match playback speed
            dt = frame.t - prev_t
            if dt > 0:
                time.sleep(dt / self._speed)

            self._emit(frame)
            prev_t = frame.t
            self._cursor += 1

        self._playing = False

    def pause(self):
        """Pause playback."""
        self._playing = False

    def set_speed(self, speed: float):
        """Change playback speed (takes effect on next frame)."""
        self._speed = max(0.1, speed)
