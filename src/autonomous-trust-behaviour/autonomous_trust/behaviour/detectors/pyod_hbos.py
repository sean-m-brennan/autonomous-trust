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
"""Per-feature, natively-explainable histogram score via ``pyod.models.hbos``
(SOW Task 3.2; the AI/ML survey's explainability + determinism layer).

PyOD's HBOS is a *batch* estimator, so — exactly as the survey notes ("batch but
trivially made incremental with streaming histograms") — we make it streaming
with a bounded sliding window that is periodically refit. Scoring uses PyOD's
``decision_function`` (higher == more anomalous; the ensemble calibrator
normalizes the scale). The per-feature attribution is read straight off the
fitted histograms (``hist_`` / ``bin_edges_``): how rare the bin a value falls
in is, relative to that feature's modal bin — which *is* the HBOS "why" (survey
axis 6). HBOS has no randomness, so a given window refits to the identical model
on every node.
"""
from __future__ import annotations

from collections import deque
from typing import Deque, Dict, List, Sequence


class PyODHBOS:
    """Sliding-window, streaming adapter over ``pyod.models.hbos.HBOS``.

    Args:
        feature_names: ordered feature labels (for attribution).
        n_bins:        histogram resolution per feature.
        window:        sliding-window size the model is refit over.
        refit_every:   observations between refits (amortizes the batch fit).
        warmup:        observations before the first fit / before ``warm``.
    """

    def __init__(self, feature_names: Sequence[str], n_bins: int = 20,
                 window: int = 400, refit_every: int = 50, warmup: int = 200):
        self.feature_names = tuple(feature_names)
        self.n_features = len(self.feature_names)
        self.n_bins = int(n_bins)
        self.window = int(window)
        self.refit_every = int(refit_every)
        self.warmup = int(warmup)
        self._buf: Deque[List[float]] = deque(maxlen=self.window)
        self._model = None
        self._count = 0
        self._since_fit = 0

    @property
    def warm(self) -> bool:
        return self._model is not None and self._count >= self.warmup

    def _maybe_refit(self) -> None:
        enough = len(self._buf) >= max(self.n_bins, self.n_features + 1)
        due = self._model is None or self._since_fit >= self.refit_every
        if self._count >= self.warmup and enough and due:
            import numpy as np
            from pyod.models.hbos import HBOS
            model = HBOS(n_bins=self.n_bins)
            model.fit(np.asarray(self._buf, dtype=float))
            self._model = model
            self._since_fit = 0

    def learn_one(self, x: Sequence[float]) -> 'PyODHBOS':
        self._buf.append([float(v) for v in x])
        self._count += 1
        self._since_fit += 1
        self._maybe_refit()
        return self

    def score_one(self, x: Sequence[float]) -> float:
        """PyOD ``decision_function`` score (higher == more anomalous); 0.0
        until the first fit (not warm yet)."""
        if self._model is None:
            return 0.0
        import numpy as np
        return float(self._model.decision_function(
            np.asarray([[float(v) for v in x]], dtype=float))[0])

    def attributions(self, x: Sequence[float]) -> Dict[str, float]:
        """Per-feature rarity in [0, 1] (the explanation): ``1 - density`` where
        density is the value's bin count relative to that feature's modal bin.
        0 == as common as the modal value, ~1 == an (almost) unseen region.
        Empty until the model is fitted."""
        if self._model is None:
            return {}
        import numpy as np
        hist = self._model.hist_          # shape (n_bins, n_features)
        edges = self._model.bin_edges_    # shape (n_bins + 1, n_features)
        out: Dict[str, float] = {}
        for f, name in enumerate(self.feature_names):
            col = hist[:, f]
            top = col.max()
            val = float(x[f])
            # A value outside the fitted range is, by construction, unseen ->
            # maximal rarity. (Clamping it into an edge bin would understate the
            # anomaly, since the edge bin holds the tail of the normal data.)
            if top <= 0 or val < edges[0, f] or val > edges[-1, f]:
                out[name] = 1.0
                continue
            b = int(np.searchsorted(edges[:, f], val, side='right') - 1)
            b = 0 if b < 0 else (self.n_bins - 1 if b >= self.n_bins else b)
            density = col[b] / top
            contrib = 1.0 - float(density)
            out[name] = 0.0 if contrib < 0.0 else (1.0 if contrib > 1.0 else contrib)
        return out

    def top_features(self, x: Sequence[float], k: int = 3):
        items = sorted(self.attributions(x).items(), key=lambda kv: kv[1],
                       reverse=True)
        return items[:k]

    def score_partial_fit(self, x: Sequence[float]) -> float:
        score = self.score_one(x)
        self.learn_one(x)
        return score
