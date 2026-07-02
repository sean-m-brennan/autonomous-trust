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
"""Multivariate isolation score via ``river.anomaly.HalfSpaceTrees`` (SOW Task
3.2; the AI/ML survey's primary streaming-anomaly reference runtime).

River's Half-Space Trees is online, unsupervised, bounded-memory and
deterministic given a seed (the tree structure is fixed at construction; only
integer mass counters update). We pass explicit per-feature ``limits`` of
``(0, 1)`` so the trees are built over the known normalized feature range rather
than inferred from the data — making the model independent of which point
arrives first, hence reproducible across nodes.
"""
from __future__ import annotations

from typing import Sequence

from .base import AnomalyDetector


class RiverHalfSpaceTrees(AnomalyDetector):
    """Adapter wrapping ``river.anomaly.HalfSpaceTrees`` to the
    :class:`AnomalyDetector` (list-vector, evaluate-then-learn) interface.

    Args:
        feature_names: ordered feature labels; the vector positions map to these
                       River dict keys (and fix the tree ``limits``).
        n_trees, height, window_size, seed: forwarded to River.
    """

    def __init__(self, feature_names: Sequence[str], n_trees: int = 25,
                 height: int = 12, window_size: int = 250, seed: int = 0):
        from river import anomaly  # lazy: River is a prototype-runtime dep
        self.feature_names = tuple(feature_names)
        self.window_size = int(window_size)
        self._model = anomaly.HalfSpaceTrees(
            n_trees=int(n_trees), height=int(height),
            window_size=self.window_size,
            limits={name: (0.0, 1.0) for name in self.feature_names},
            seed=int(seed))
        self._count = 0

    def _as_dict(self, x: Sequence[float]) -> dict:
        return {name: x[i] for i, name in enumerate(self.feature_names)}

    @property
    def warm(self) -> bool:
        # River's reference window is populated after window_size observations;
        # before that the score has no reference distribution to compare to.
        return self._count >= self.window_size

    def learn_one(self, x: Sequence[float]) -> 'RiverHalfSpaceTrees':
        self._model.learn_one(self._as_dict(x))
        self._count += 1
        return self

    def score_one(self, x: Sequence[float]) -> float:
        """River returns a score in [0, 1] (higher == more anomalous)."""
        return float(self._model.score_one(self._as_dict(x)))
