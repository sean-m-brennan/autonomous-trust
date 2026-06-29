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
"""Access-decision latency M&S — AT-local vs ZTA-PDP (SOW Task 2.4, "Latency -50%").

Models the **steady-state per-request access decision** for an enrolled node under
two architectures, over a modeled tactical link, and reports the AT-vs-ZTA latency
reduction. (One-time enrollment / consensus admission is a separate, characterized
cost — SOW Task 2.4 (2) — and is NOT modeled here.)

The structural difference the model captures:

* **ZTA-PDP** — the PEP must reach a (possibly distant) Policy Decision Point and a
  revocation source (OCSP responder or large CRL) to decide a request. That is one
  or two **round-trips over the contested link** plus PDP processing, and the PDP
  is a **shared bottleneck** that queues under cohort load.
* **AT-local** — an enrolled peer already holds the reputation/tier/credential
  state, so the per-request decision is **local**: a local X.509 chain verify plus
  an in-memory tier/reputation lookup. No link round-trip is on the decision path
  (revocation is handled by AT's background re-verification / DDIL deferral, not a
  synchronous OCSP fetch). There is **no shared bottleneck** — every peer decides
  independently, so latency is flat in cohort size.

Everything is MODELED (seeded Monte Carlo, stdlib only) and deterministic under a
fixed seed. Per SOW measured-vs-modeled discipline: the **AT path is the one to be
replaced with subscale *measurement* (Task 4)**; the **ZTA baseline is
modeled/anchored to published DoD-PKI/OCSP/CRL figures (Task 2.2)**. All model
parameters are exposed on :class:`LatencyConfig` for re-anchoring; nothing here is
presented as a measured result.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from statistics import mean, median
from typing import List, Optional


def _pctl(values: List[float], q: float) -> float:
    """The q-quantile (0..1) by nearest-rank on the sorted sample."""
    if not values:
        return 0.0
    s = sorted(values)
    idx = min(len(s) - 1, max(0, int(round(q * (len(s) - 1)))))
    return s[idx]


@dataclass(frozen=True)
class LinkModel:
    """A modeled tactical link (one direction). MODELED — anchor to measured/
    published tactical-link figures before reporting as fact.

    Args:
        oneway_ms:      mean one-way propagation+transmission latency.
        jitter_ms:      per-traversal Gaussian jitter (std), clamped at 0.
        loss_prob:      per-traversal loss probability (triggers a retransmit).
        retransmit_ms:  retransmit timeout added per lost traversal.
    """
    oneway_ms: float = 75.0
    jitter_ms: float = 25.0
    loss_prob: float = 0.05
    retransmit_ms: float = 300.0

    def traverse(self, rng: random.Random) -> float:
        """One one-way traversal time (ms), including a retransmit on loss."""
        t = self.oneway_ms + rng.gauss(0.0, self.jitter_ms)
        if t < 0.0:
            t = 0.0
        if rng.random() < self.loss_prob:
            t += self.retransmit_ms
        return t

    def round_trip(self, rng: random.Random) -> float:
        """A request+response round-trip = two one-way traversals."""
        return self.traverse(rng) + self.traverse(rng)


@dataclass(frozen=True)
class LatencyConfig:
    """Model parameters for one AT-vs-ZTA comparison. All MODELED/illustrative —
    exposed for re-anchoring (SOW Task 2.2/2.3 measured inputs)."""
    link: LinkModel = field(default_factory=LinkModel)

    # ZTA-PDP path -------------------------------------------------------
    pdp_proc_ms: float = 5.0           # policy-decision-point processing (modest)
    separate_revocation_rtt: bool = True   # OCSP responder reached over the link
    #   (False models OCSP-stapling / cached revocation = the *favorable* ZTA case)
    cohort_size: int = 25              # concurrent enrolled nodes hitting the PDP
    pdp_capacity: int = 100            # requests the PDP serves before it queues
    #   queueing multiplier 1/(1-rho) with rho = min(0.95, cohort/capacity)

    # AT-local path ------------------------------------------------------
    at_chain_verify_ms: float = 3.0    # local X.509 chain verify (no network)
    at_lookup_ms: float = 0.2          # in-memory tier/reputation lookup

    # Run ----------------------------------------------------------------
    trials: int = 5000
    seed: int = 1234

    def pdp_effective_ms(self) -> float:
        """PDP processing inflated by cohort contention (shared bottleneck)."""
        rho = min(0.95, self.cohort_size / max(1, self.pdp_capacity))
        return self.pdp_proc_ms / (1.0 - rho)


@dataclass(frozen=True)
class PathStats:
    label: str
    mean_ms: float
    median_ms: float
    p95_ms: float

    @classmethod
    def of(cls, label: str, samples: List[float]) -> 'PathStats':
        return cls(label, mean(samples), median(samples), _pctl(samples, 0.95))

    def as_dict(self) -> dict:
        return {'label': self.label, 'mean_ms': round(self.mean_ms, 2),
                'median_ms': round(self.median_ms, 2),
                'p95_ms': round(self.p95_ms, 2)}


@dataclass(frozen=True)
class LatencyResult:
    config: LatencyConfig
    zta: PathStats
    at: PathStats

    @property
    def reduction_mean(self) -> float:
        return 0.0 if self.zta.mean_ms <= 0 else (
            (self.zta.mean_ms - self.at.mean_ms) / self.zta.mean_ms)

    @property
    def reduction_p95(self) -> float:
        return 0.0 if self.zta.p95_ms <= 0 else (
            (self.zta.p95_ms - self.at.p95_ms) / self.zta.p95_ms)

    @property
    def meets_target(self) -> bool:
        return self.reduction_mean >= 0.50

    def as_report(self) -> dict:
        return {
            'target': 'SOW Task 2.4 — Latency -50% (AT-local vs ZTA-PDP)',
            'modeled': True,
            'note': ('All figures MODELED (seeded Monte Carlo). AT path → to be '
                     'measured on subscale HW (Task 4); ZTA baseline → anchor to '
                     'published DoD-PKI/OCSP/CRL figures (Task 2.2). Steady-state '
                     'per-request decision; one-time enrollment characterized '
                     'separately (Task 2.4(2)).'),
            'seed': self.config.seed,
            'cohort_size': self.config.cohort_size,
            'link_oneway_ms': self.config.link.oneway_ms,
            'zta_favorable_no_ocsp_rtt': not self.config.separate_revocation_rtt,
            'zta_pdp': self.zta.as_dict(),
            'at_local': self.at.as_dict(),
            'reduction_mean': round(self.reduction_mean, 4),
            'reduction_p95': round(self.reduction_p95, 4),
            'meets_50pct_target': self.meets_target,
        }


def _zta_decision_ms(cfg: LatencyConfig, rng: random.Random) -> float:
    """One ZTA-PDP access decision: PEP↔PDP round-trip + PDP processing
    (+ contention) + an optional OCSP/revocation round-trip over the link."""
    t = cfg.link.round_trip(rng)            # PEP -> PDP -> PEP
    t += cfg.pdp_effective_ms()             # decision + queueing under load
    if cfg.separate_revocation_rtt:
        t += cfg.link.round_trip(rng)       # PEP/PDP -> OCSP responder -> back
    return t


def _at_decision_ms(cfg: LatencyConfig, rng: random.Random) -> float:
    """One AT-local access decision: local chain verify + in-memory lookup.
    No link round-trip, no shared bottleneck (cohort-independent)."""
    # Small modeled CPU jitter (±10%) so the distribution isn't a delta.
    jitter = 1.0 + rng.uniform(-0.10, 0.10)
    return (cfg.at_chain_verify_ms + cfg.at_lookup_ms) * jitter


def run(config: Optional[LatencyConfig] = None) -> LatencyResult:
    """Monte-Carlo both decision paths over ``config.trials``; deterministic in
    ``config.seed``."""
    cfg = config or LatencyConfig()
    rng = random.Random(cfg.seed)
    zta = [_zta_decision_ms(cfg, rng) for _ in range(cfg.trials)]
    at = [_at_decision_ms(cfg, rng) for _ in range(cfg.trials)]
    return LatencyResult(config=cfg,
                         zta=PathStats.of('ZTA-PDP', zta),
                         at=PathStats.of('AT-local', at))


#: Coherent named link profiles (oneway, jitter, loss, retransmit) spanning a
#: benign LAN to a severe DDIL tactical link. MODELED — anchor to measured/
#: published figures before reporting as fact.
PROFILES = {
    'benign-LAN':    LinkModel(1.0, 0.5, 0.001, 50.0),
    'garrison-WAN':  LinkModel(15.0, 5.0, 0.005, 150.0),
    'tactical':      LinkModel(75.0, 25.0, 0.05, 300.0),
    'DDIL-severe':   LinkModel(250.0, 80.0, 0.15, 500.0),
}


@dataclass(frozen=True)
class SweepRow:
    profile: str
    oneway_ms: float
    favorable_zta: bool
    zta_mean_ms: float
    at_mean_ms: float
    reduction_mean: float


def sweep(base: Optional[LatencyConfig] = None) -> List[SweepRow]:
    """Run every link profile (and the favorable-ZTA variant) to show the -50%
    result is structural — driven by AT deciding locally while ZTA needs >=1 link
    round-trip — not a single cherry-picked point, and to expose the honest floor
    (benign LAN) vs the contested-tactical case. 'favorable' gives ZTA its best
    case: OCSP-stapling / cached revocation (no extra revocation round-trip)."""
    base = base or LatencyConfig()
    rows: List[SweepRow] = []
    for favorable in (False, True):
        for name, link in PROFILES.items():
            cfg = LatencyConfig(
                link=link, pdp_proc_ms=base.pdp_proc_ms,
                separate_revocation_rtt=not favorable,
                cohort_size=base.cohort_size, pdp_capacity=base.pdp_capacity,
                at_chain_verify_ms=base.at_chain_verify_ms,
                at_lookup_ms=base.at_lookup_ms,
                trials=base.trials, seed=base.seed)
            r = run(cfg)
            rows.append(SweepRow(name, link.oneway_ms, favorable,
                                 r.zta.mean_ms, r.at.mean_ms, r.reduction_mean))
    return rows
