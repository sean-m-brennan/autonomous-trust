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
"""Resilience/threat M&S metrics (SOW Task 3.4): detection latency, exclusion
correctness, and -- the load-bearing one -- the **false-exclusion rate against a
realistic attack base rate** (Axelsson's base-rate fallacy).

Axelsson's point: in intrusion detection the prior probability that any given
actor is hostile is tiny, so even a detector with an excellent false-positive
*rate* can have terrible *precision* (most alarms are false). A resilience claim
that quotes only TPR/FPR is misleading; it must project precision at the realistic
base rate. That projection is exactly what justifies the governed two-tier design
(ML proposes, deterministic quorum disposes) rather than letting the detector
exclude on its own.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from statistics import mean, median
from typing import Dict, List, Optional

from .archetypes import ADVERSARY_ARCHETYPES, ARCHETYPES, PeerProfile


@dataclass(frozen=True)
class PeerOutcome:
    """Per-peer ground truth + what a detector did."""
    peer_id: str
    archetype: str
    adversary: bool
    flagged: bool
    onset_time: Optional[float]
    flag_time: Optional[float]

    @property
    def latency(self) -> Optional[float]:
        """Detection latency: flag time minus behaviour-change onset. None when
        not a true detection or there is no onset (steady benign)."""
        if not (self.adversary and self.flagged):
            return None
        if self.onset_time is None or self.flag_time is None:
            return None
        return max(0.0, self.flag_time - self.onset_time)


@dataclass(frozen=True)
class DetectorMetrics:
    """Confusion matrix + rates for one detector over the population."""
    tp: int
    fp: int
    fn: int
    tn: int
    detection_latencies: List[float] = field(default_factory=list)
    per_archetype_detected: Dict[str, int] = field(default_factory=dict)
    per_archetype_total: Dict[str, int] = field(default_factory=dict)

    @property
    def tpr(self) -> float:                 # recall / detection rate
        d = self.tp + self.fn
        return self.tp / d if d else 0.0

    @property
    def fpr(self) -> float:                 # == false-exclusion rate (benign)
        d = self.fp + self.tn
        return self.fp / d if d else 0.0

    #: SOW wording: the fraction of benign peers wrongly excluded.
    false_exclusion_rate = fpr

    @property
    def ppv(self) -> float:                 # precision at the observed base rate
        d = self.tp + self.fp
        return self.tp / d if d else 0.0

    @property
    def fdr(self) -> float:                 # false-discovery rate
        return 1.0 - self.ppv if (self.tp + self.fp) else 0.0

    @property
    def latency_mean(self) -> Optional[float]:
        return mean(self.detection_latencies) if self.detection_latencies else None

    @property
    def latency_median(self) -> Optional[float]:
        return median(self.detection_latencies) if self.detection_latencies else None

    def ppv_at_base_rate(self, base_rate: float) -> float:
        """Projected precision if the true fraction of hostile actors were
        ``base_rate`` (Axelsson). Uses the measured class-conditional rates::

            PPV = p·TPR / (p·TPR + (1-p)·FPR)

        With a tiny ``p`` and any non-zero FPR this collapses toward 0 -- the
        quantitative statement of why the detector must be a *governed* sensor,
        not an autonomous excluder."""
        p, tpr, fpr = base_rate, self.tpr, self.fpr
        denom = p * tpr + (1.0 - p) * fpr
        return (p * tpr) / denom if denom > 0 else 0.0

    def archetype_detection_rate(self, archetype: str) -> Optional[float]:
        total = self.per_archetype_total.get(archetype, 0)
        if not total:
            return None
        return self.per_archetype_detected.get(archetype, 0) / total

    def as_dict(self) -> dict:
        return {
            'tp': self.tp, 'fp': self.fp, 'fn': self.fn, 'tn': self.tn,
            'tpr_detection_rate': round(self.tpr, 4),
            'fpr_false_exclusion_rate': round(self.fpr, 4),
            'ppv_observed': round(self.ppv, 4),
            'fdr': round(self.fdr, 4),
            'latency_mean': (round(self.latency_mean, 3)
                             if self.latency_mean is not None else None),
            'latency_median': (round(self.latency_median, 3)
                               if self.latency_median is not None else None),
            'ppv_at_base_rate': {
                '0.10': round(self.ppv_at_base_rate(0.10), 4),
                '0.05': round(self.ppv_at_base_rate(0.05), 4),
                '0.01': round(self.ppv_at_base_rate(0.01), 4),
            },
            'per_archetype_detection_rate': {
                a: (round(r, 4) if (r := self.archetype_detection_rate(a))
                    is not None else None)
                for a in ARCHETYPES},
        }


def compute_metrics(outcomes: List[PeerOutcome]) -> DetectorMetrics:
    tp = fp = fn = tn = 0
    latencies: List[float] = []
    detected: Dict[str, int] = {a: 0 for a in ARCHETYPES}
    total: Dict[str, int] = {a: 0 for a in ARCHETYPES}
    for o in outcomes:
        total[o.archetype] = total.get(o.archetype, 0) + 1
        if o.flagged:
            detected[o.archetype] = detected.get(o.archetype, 0) + 1
        if o.adversary and o.flagged:
            tp += 1
            if o.latency is not None:
                latencies.append(o.latency)
        elif o.adversary and not o.flagged:
            fn += 1
        elif (not o.adversary) and o.flagged:
            fp += 1
        else:
            tn += 1
    return DetectorMetrics(tp=tp, fp=fp, fn=fn, tn=tn,
                           detection_latencies=latencies,
                           per_archetype_detected=detected,
                           per_archetype_total=total)


def make_outcome(profile: PeerProfile, flagged: bool,
                 onset_time: Optional[float],
                 flag_time: Optional[float]) -> PeerOutcome:
    return PeerOutcome(peer_id=profile.peer_id, archetype=profile.archetype,
                       adversary=profile.adversary, flagged=flagged,
                       onset_time=onset_time, flag_time=flag_time)
