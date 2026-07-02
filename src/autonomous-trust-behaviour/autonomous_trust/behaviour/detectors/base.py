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
"""Common interface for the streaming anomaly detectors (SOW Task 3.2).

The Phase-I prototype builds the detectors **via River/PyOD** (the mature,
permissively-licensed reference runtimes named in the SOW and the AI/ML survey):
the multivariate isolation score from ``river.anomaly.HalfSpaceTrees`` and the
per-feature, natively-explainable histogram score from ``pyod.models.hbos.HBOS``.
Both are unsupervised, online (HBOS via a sliding-window refit), and
deterministic under a fixed seed, so their scores are reproducible enough to act
as governed evidence. The deferred formally-verified C core (Task 3.5) is the
"owned" reimplementation; this interface is what it will satisfy.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Dict, Sequence


class AnomalyDetector(ABC):
    """A streaming anomaly detector over a fixed-length, [0, 1]-normalized
    feature vector (the canonical :data:`FEATURE_NAMES` order).

    The streaming contract is **evaluate-then-learn**: callers score a point
    before learning it, so an attacker's own anomalous traffic cannot train the
    model to accept itself.
    """

    @property
    @abstractmethod
    def warm(self) -> bool:
        """True once enough observations have been seen for scores to mean
        something (before this, callers should treat scores as provisional)."""

    @abstractmethod
    def learn_one(self, x: Sequence[float]) -> 'AnomalyDetector':
        """Incorporate one observation into the model."""

    @abstractmethod
    def score_one(self, x: Sequence[float]) -> float:
        """Anomaly score for ``x`` (higher == more anomalous). The scale need
        not be [0, 1]; the ensemble calibrator normalizes it."""

    def attributions(self, x: Sequence[float]) -> Dict[str, float]:
        """Per-feature contribution to the score in [0, 1] (the explanation).
        Detectors without native attribution return an empty mapping."""
        return {}

    def score_partial_fit(self, x: Sequence[float]) -> float:
        """Score ``x`` against the current model, then learn it."""
        score = self.score_one(x)
        self.learn_one(x)
        return score
