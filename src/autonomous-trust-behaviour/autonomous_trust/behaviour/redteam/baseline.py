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
"""A static-policy baseline detector for the M&S comparison (SOW Task 3.4 asks
for results *vs a static-policy baseline*).

This is the kind of fixed, hand-tuned threshold rule a non-ML system would use:
flag a peer when, over a sliding window, its refusal rate is too high or its mean
transaction score is too low. It has no learned per-peer envelope, no calibration
to a peer's own normal, and no sustained-anomaly dwell -- so it reacts to any
window that crosses the line, including a benign peer disrupted by DDIL. The
harness measures exactly that contrast.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Dict, Optional

from ..features import AccessEvent


@dataclass
class StaticPolicyDetector:
    """Fixed-threshold, per-peer windowed policy. ``observe`` returns True the
    first tick a peer crosses a threshold (the analogue of a sustained-alarm
    proposal); the peer stays flagged thereafter."""
    window: int = 32
    max_refusal_rate: float = 0.35     # exclude if refusals exceed this share
    min_mean_score: float = 0.4        # exclude if mean txn score drops below
    min_obs: int = 16                  # don't judge before this many events

    _recent: Dict[str, Deque[AccessEvent]] = field(default_factory=dict)
    _flagged: Dict[str, bool] = field(default_factory=dict)

    def observe(self, peer_id: str, event: AccessEvent) -> bool:
        win = self._recent.setdefault(peer_id, deque(maxlen=self.window))
        win.append(event)
        if self._flagged.get(peer_id):
            return False                # already flagged; first-crossing only
        if len(win) < self.min_obs:
            return False
        refusals = sum(1 for e in win if e.refused) / len(win)
        scored = [e.score for e in win if e.score is not None]
        mean_score = sum(scored) / len(scored) if scored else 1.0
        if refusals > self.max_refusal_rate or mean_score < self.min_mean_score:
            self._flagged[peer_id] = True
            return True
        return False

    def flagged(self, peer_id: str) -> bool:
        return bool(self._flagged.get(peer_id))
