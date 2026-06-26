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
"""Access-stream feature extraction (SOW Task 3.1).

A behavioral *envelope* is learned per **peer×role** from the access stream. An
:class:`AccessEvent` is one observed interaction (a capability request, its
acceptance/refusal, an optional committed transaction score, the counterparty);
:class:`BehaviorFeatures` folds a stream of them into a fixed-length,
[0, 1]-normalized **descriptor** vector that the detectors consume.

Design stance: the features are *descriptors*, not pre-judged anomaly signals.
We do not decide here that "high rate == bad" — the per-entity detector learns
what is normal for this peer×role and flags deviation in any direction. That
keeps the feature layer faithful and the detectors honest (a bot-like, too-
regular cadence is as much a deviation from a human operator's normal as an
erratic one). The survey's axis-4 feature menu maps to:

  * ``rate``          — exponentially-weighted request rate (vs a configured max)
  * ``burst``         — fast/slow rate ratio (burstiness)
  * ``cap_entropy``   — capability-mix diversity (normalized Shannon entropy)
  * ``seq_predict``   — fraction of recent capability transitions already seen
  * ``refusal``       — recent refusal-rate signature
  * ``cohort``        — counterparty diversity (normalized Shannon entropy)
  * ``timing``        — inter-arrival irregularity (coefficient of variation)
  * ``txn_score``     — recent transaction-score level (trust trend)

Everything is deterministic (no RNG) and bounded-memory (a fixed-capacity recent
window + capped "known-transition" set + scalar EW accumulators), so it ports to
fixed-point C with the detectors (Task 3.5).
"""
from __future__ import annotations

import math
from collections import deque
from dataclasses import dataclass
from typing import Deque, Dict, List, Optional, Tuple


@dataclass(frozen=True)
class AccessEvent:
    """One observed interaction in the access stream.

    Args:
        time:         monotonic timestamp (seconds); supplied by the observer so
                      feature extraction is deterministic and clock-injectable.
        capability:   the capability name requested/invoked.
        refused:      True if the request was refused (tier-gate or policy).
        score:        optional committed transaction score in [0, 1] (trust
                      signal); None for non-transaction events.
        counterparty: optional id of the other party (for cohort diversity).
    """
    time: float
    capability: str
    refused: bool = False
    score: Optional[float] = None
    counterparty: Optional[str] = None


#: Canonical, fixed feature order. The detectors are constructed against this,
#: so the order must never change without re-pinning the conformance corpus.
FEATURE_NAMES: Tuple[str, ...] = (
    'rate', 'burst', 'cap_entropy', 'seq_predict',
    'refusal', 'cohort', 'timing', 'txn_score',
)


def _clamp01(v: float) -> float:
    return 0.0 if v < 0.0 else (1.0 if v > 1.0 else v)


def _norm_entropy(counts) -> float:
    """Shannon entropy of a count distribution, normalized to [0, 1] by the
    maximum entropy for the number of observed categories (so 1 == uniform over
    whatever was seen, 0 == a single category)."""
    total = sum(counts)
    if total <= 0:
        return 0.0
    k = sum(1 for c in counts if c > 0)
    if k <= 1:
        return 0.0
    h = 0.0
    for c in counts:
        if c > 0:
            p = c / total
            h -= p * math.log(p)
    return _clamp01(h / math.log(k))


class BehaviorFeatures:
    """Streaming, bounded-memory feature accumulator for one peer×role.

    Args:
        window:        recent-event window size for the windowed descriptors.
        max_rate:      request rate (events/sec) that maps to ``rate == 1.0``.
        fast_half_life / slow_half_life: EW horizons (seconds) for the
                       burstiness fast/slow rate estimators.
        known_cap_seqs_cap: cap on the remembered capability-transition set
                       (bounds memory; LRU-ish via insertion-order trim).
    """

    def __init__(self, window: int = 64, max_rate: float = 10.0,
                 fast_half_life: float = 5.0, slow_half_life: float = 60.0,
                 known_cap_seqs_cap: int = 256):
        self.window = int(window)
        self.max_rate = float(max_rate)
        self._fast_tau = float(fast_half_life) / math.log(2)
        self._slow_tau = float(slow_half_life) / math.log(2)
        self._known_cap_cap = int(known_cap_seqs_cap)

        self._events: Deque[AccessEvent] = deque(maxlen=self.window)
        self._last_time: Optional[float] = None
        self._last_cap: Optional[str] = None
        self._fast_rate = 0.0
        self._slow_rate = 0.0
        self._known_transitions: Dict[Tuple[str, str], int] = {}
        # Windowed record of whether each recent transition was novel *at the
        # time it arrived* (checked before it was learned), so predictability
        # reflects past learning rather than trivially counting a transition as
        # known the instant it is observed.
        self._novel_window: Deque[bool] = deque(maxlen=self.window)
        self._count = 0

    @property
    def count(self) -> int:
        return self._count

    @staticmethod
    def n_features() -> int:
        return len(FEATURE_NAMES)

    def observe(self, event: AccessEvent) -> 'BehaviorFeatures':
        """Fold one access event into the running state."""
        # EW rate estimators (fast + slow) for the burstiness ratio.
        if self._last_time is not None:
            dt = event.time - self._last_time
            if dt < 0.0:
                dt = 0.0
            inst = 1.0 / dt if dt > 0 else self.max_rate
            af = math.exp(-dt / self._fast_tau) if self._fast_tau > 0 else 0.0
            as_ = math.exp(-dt / self._slow_tau) if self._slow_tau > 0 else 0.0
            self._fast_rate = af * self._fast_rate + (1 - af) * inst
            self._slow_rate = as_ * self._slow_rate + (1 - as_) * inst
        else:
            self._fast_rate = self._slow_rate = 0.0

        # Capability-transition memory (sequence predictability). Evaluate
        # novelty BEFORE learning the transition, so a transition only counts as
        # "known" once it has been seen on a previous event.
        if self._last_cap is not None:
            key = (self._last_cap, event.capability)
            self._novel_window.append(key not in self._known_transitions)
            if key not in self._known_transitions and \
                    len(self._known_transitions) >= self._known_cap_cap:
                # Trim the oldest remembered transition (insertion order).
                oldest = next(iter(self._known_transitions))
                del self._known_transitions[oldest]
            self._known_transitions[key] = self._known_transitions.get(key, 0) + 1

        self._events.append(event)
        self._last_time = event.time
        self._last_cap = event.capability
        self._count += 1
        return self

    # -- feature computation (pure; does not mutate state) ----------------

    def named(self) -> Dict[str, float]:
        """The current [0, 1] feature vector as a name→value mapping."""
        ev = list(self._events)
        n = len(ev)

        # rate: EW slow rate vs configured max.
        rate = _clamp01(self._slow_rate / self.max_rate) if self.max_rate > 0 else 0.0

        # burst: fast/slow ratio, squashed to [0,1] (1:1 -> 0.5).
        if self._slow_rate > 0:
            ratio = self._fast_rate / self._slow_rate
            burst = _clamp01(ratio / (1.0 + ratio))
        else:
            burst = 0.0

        # cap_entropy: diversity of the capability mix in the window.
        cap_counts: Dict[str, int] = {}
        for e in ev:
            cap_counts[e.capability] = cap_counts.get(e.capability, 0) + 1
        cap_entropy = _norm_entropy(list(cap_counts.values()))

        # seq_predict: fraction of recent transitions that were already known
        # when they arrived (1.0 == fully predictable, nothing novel lately).
        if self._novel_window:
            novel = sum(1 for was_novel in self._novel_window if was_novel)
            seq_predict = _clamp01(1.0 - novel / len(self._novel_window))
        else:
            seq_predict = 1.0   # nothing surprising yet

        # refusal: recent refusal rate.
        refusal = _clamp01(sum(1 for e in ev if e.refused) / n) if n else 0.0

        # cohort: counterparty diversity in the window.
        cp_counts: Dict[str, int] = {}
        for e in ev:
            if e.counterparty is not None:
                cp_counts[e.counterparty] = cp_counts.get(e.counterparty, 0) + 1
        cohort = _norm_entropy(list(cp_counts.values()))

        # timing: coefficient of variation of inter-arrival times, squashed.
        times = [e.time for e in ev]
        gaps = [t2 - t1 for t1, t2 in zip(times, times[1:]) if t2 - t1 >= 0]
        if len(gaps) >= 2:
            mean = sum(gaps) / len(gaps)
            if mean > 0:
                var = sum((g - mean) ** 2 for g in gaps) / len(gaps)
                cov = math.sqrt(var) / mean
                timing = _clamp01(cov / (1.0 + cov))
            else:
                timing = 0.0
        else:
            timing = 0.0

        # txn_score: recent transaction-score level (0.5 neutral if none seen).
        scores = [e.score for e in ev if e.score is not None]
        txn_score = _clamp01(sum(scores) / len(scores)) if scores else 0.5

        return {
            'rate': rate, 'burst': burst, 'cap_entropy': cap_entropy,
            'seq_predict': seq_predict, 'refusal': refusal, 'cohort': cohort,
            'timing': timing, 'txn_score': txn_score,
        }

    def vector(self) -> List[float]:
        """The current feature vector in canonical :data:`FEATURE_NAMES` order."""
        named = self.named()
        return [named[name] for name in FEATURE_NAMES]
