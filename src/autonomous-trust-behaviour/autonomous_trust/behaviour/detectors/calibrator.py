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
"""Streaming score calibrator (SOW Task 3.2).

Half-Space Trees and HBOS produce scores on different, drifting scales. To
combine them and to threshold consistently, each raw score stream is mapped to a
calibrated anomaly probability in [0, 1] via a deterministic online Gaussian
model: track the running mean and variance of the raw score (Welford), then map
a new score to its upper-tail probability through a logistic of its z-score.
"High" calibrated values mean "far above this detector's own typical score" --
which is what makes a fixed downstream threshold meaningful regardless of the
detector's raw scale.

Deterministic: Welford's update and the logistic are pure functions of the
ordered input sequence; identical inputs in identical order yield identical
output on every node (the C port pins this via the conformance corpus).
"""
from __future__ import annotations

import math


class StreamingCalibrator:
    """Online mean/variance calibrator mapping a raw score to a [0, 1] tail
    probability.

    Args:
        warmup:  observations before calibration is meaningful (until then
                 returns the clamped raw score).
        k:       logistic steepness over the z-score.
        min_std: a noise floor on the standard deviation. Without it, a detector
                 trained on near-identical normal traffic has ~zero variance, so
                 ANY micro-deviation calibrates to ~1.0 -- a hair-trigger that is
                 precisely the base-rate-fallacy failure mode the SOW/survey warn
                 about. The floor says "deviations smaller than this scale are not
                 trustworthy signal," so only deviations large relative to
                 ``min_std`` (or to the observed spread, whichever is larger)
                 calibrate high. This is the primary base-rate guard.

    Note: this is a stationary Welford estimator. Drift-adaptation (a bounded
    exponentially-weighted variant) is layered on in the ensemble (B3) where the
    per-peer×role lifecycle is known; keeping the primitive a plain, exactly
    reproducible Welford makes the C-port conformance pin trivial (Task 3.5).
    """

    def __init__(self, warmup: int = 50, k: float = 1.0, min_std: float = 0.0):
        self.warmup = int(warmup)
        self.k = float(k)
        self.min_std = float(min_std)
        self._n = 0
        self._mean = 0.0
        self._m2 = 0.0

    @property
    def warm(self) -> bool:
        return self._n >= self.warmup

    @property
    def mean(self) -> float:
        return self._mean

    def std(self) -> float:
        s = 0.0 if self._n < 2 else math.sqrt(self._m2 / (self._n - 1))
        return s if s > self.min_std else self.min_std

    def update(self, raw: float) -> None:
        """Fold a raw score into the running statistics (Welford)."""
        self._n += 1
        delta = raw - self._mean
        self._mean += delta / self._n
        delta2 = raw - self._mean
        self._m2 += delta * delta2

    def calibrate(self, raw: float) -> float:
        """Map a raw score to a [0, 1] anomaly probability (its upper-tail
        position in this detector's own score distribution)."""
        if not self.warm:
            return 0.0 if raw < 0.0 else (1.0 if raw > 1.0 else raw)
        sd = self.std()
        if sd <= 0.0:
            return 1.0 if raw > self._mean else 0.0
        z = (raw - self._mean) / sd
        return 1.0 / (1.0 + math.exp(-self.k * z))

    def calibrate_partial_fit(self, raw: float) -> float:
        """Calibrate ``raw`` against the current distribution, then fold it in
        (evaluate-then-update, so a point cannot calibrate against itself)."""
        out = self.calibrate(raw)
        self.update(raw)
        return out
