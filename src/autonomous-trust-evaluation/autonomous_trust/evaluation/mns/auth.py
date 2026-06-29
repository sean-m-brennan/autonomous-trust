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
"""Authentication-time M&S — the three Auth (<=5 s) quantities (SOW Task 2.4).

Reports, over a modeled tactical link (seeded Monte-Carlo, reusing
:class:`~autonomous_trust.evaluation.mns.latency.LinkModel`):

1. **Steady-state re-authentication** of an enrolled node, vs cohort size /
   contention — **gated <=5 s**. In AT this is a *local* credential/trust check
   (optionally one lightweight challenge round-trip to an already-known peer);
   there is no central PDP, so it is flat in cohort size. Contrasted with a
   ZTA-baseline re-auth (round-trip to a shared PDP that queues under load).
2. **One-time enrollment** (consensus admission) — **characterized, NOT gated**.
   Modeled as announce + a quorum vouch (q-of-N border guards; the quorum-met
   time is the q-th order statistic of the vouch round-trips) + welcome.
3. **Degraded-edge first-contact admission** under DDIL — **gated <=5 s**. The
   revocation source (OCSP/CRL) is unreachable; a strict ZTA blocks on it and
   busts the gate, while AT admits via its **deferred-verification fallback**
   (reputation-capped admit now; delegated-verification quorum lifts the cap
   later, off the admission path — see `doc/architecture/zta-integration.md`).

**Trust "bases".** The SOW phrases (3) as "bases 1, 3-4 (base-2 attestation
modeled)". Only **base 2 = hardware root-of-trust / attestation** is enumerated in
the available docs (it is unbuilt -> **modeled** here as an added attestation
step, mechanism M12 / Option O.2). The other first-contact bases exercised are the
*implemented* admission mechanisms — cryptographic identity (Ed25519 + X.509 ZTA
chain), quorum vouching (welcoming committee), and DDIL delegated verification.
**The precise 1/3/4 numbering should be reconciled with the Technical Volume**
(not machine-readable here); the mechanisms modeled are the substantive content.

Honesty discipline (as across `mns`): all figures MODELED; per SOW, the AT path is
to be **measured on subscale HW (Task 4)** and the basic ICAM/PIV path built
there, with base-2 attestation modeled. Parameters are exposed for re-anchoring.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from statistics import mean
from typing import List, Optional

from .latency import LinkModel, _pctl

GATE_MS = 5000.0


@dataclass(frozen=True)
class AuthConfig:
    link: LinkModel = field(default_factory=LinkModel)                  # operational
    degraded_link: LinkModel = field(
        default_factory=lambda: LinkModel(250.0, 80.0, 0.15, 600.0))    # DDIL edge

    local_verify_ms: float = 3.0          # Ed25519 + X.509 chain verify (local)
    reauth_challenge: bool = True         # re-auth does one challenge round-trip

    # ZTA-baseline re-auth (shared PDP) — for the contrast in (1)
    pdp_proc_ms: float = 5.0
    pdp_capacity: int = 100

    # Enrollment / degraded admission quorum
    n_border_guards: int = 7
    quorum_q: int = 4                     # q-of-N vouches needed
    base2_attestation_ms: float = 150.0   # MODELED hardware attestation step (M12)

    # A strict ZTA at the degraded edge blocks on the unreachable OCSP/PDP for
    # this long before timing out — busts the 5 s gate.
    strict_zta_dead_pdp_wait_ms: float = 8000.0

    gate_ms: float = GATE_MS
    trials: int = 4000
    seed: int = 1234


@dataclass(frozen=True)
class Dist:
    mean_ms: float
    p95_ms: float

    @classmethod
    def of(cls, xs: List[float]) -> 'Dist':
        return cls(mean(xs), _pctl(xs, 0.95))

    def as_dict(self):
        return {'mean_ms': round(self.mean_ms, 1), 'p95_ms': round(self.p95_ms, 1)}


def _quorum_met_ms(link: LinkModel, n: int, q: int, rng: random.Random) -> float:
    """Time for q-of-n vouch round-trips to complete = the q-th order statistic
    of n independent vouch round-trips over the link."""
    rtts = sorted(link.round_trip(rng) for _ in range(n))
    q = max(1, min(q, n))
    return rtts[q - 1]


def reauth_sweep(cfg: AuthConfig,
                 cohorts=(5, 25, 50, 100, 250)) -> List[dict]:
    """(1) Steady-state re-auth p95 vs cohort size — AT (local) vs ZTA (shared
    PDP). AT is flat; ZTA grows with contention."""
    rng = random.Random(cfg.seed)
    rows = []
    for n in cohorts:
        at, zta = [], []
        rho = min(0.95, n / max(1, cfg.pdp_capacity))
        pdp_eff = cfg.pdp_proc_ms / (1.0 - rho)
        for _ in range(cfg.trials):
            # AT: local verify + optional one challenge RTT to a known peer.
            a = cfg.local_verify_ms * (1.0 + rng.uniform(-0.1, 0.1))
            if cfg.reauth_challenge:
                a += cfg.link.round_trip(rng)
            at.append(a)
            # ZTA baseline: round-trip to the shared PDP + queueing.
            zta.append(cfg.link.round_trip(rng) + pdp_eff)
        rows.append({'cohort': n, 'at': Dist.of(at), 'zta': Dist.of(zta)})
    return rows


def enrollment(cfg: AuthConfig) -> Dist:
    """(2) One-time enrollment (consensus admission): announce + quorum vouch +
    welcome. Characterized, NOT gated."""
    rng = random.Random(cfg.seed + 1)
    xs = []
    for _ in range(cfg.trials):
        t = cfg.link.round_trip(rng)                                   # announce
        t += _quorum_met_ms(cfg.link, cfg.n_border_guards, cfg.quorum_q, rng)
        t += cfg.link.round_trip(rng)                                  # welcome
        t += cfg.local_verify_ms
        xs.append(t)
    return Dist.of(xs)


def degraded_admission(cfg: AuthConfig, with_base2: bool = True) -> Dist:
    """(3) Degraded-edge first-contact admission via AT's deferred-verification
    fallback (does NOT block on the unreachable OCSP/PDP). Gated <=5 s."""
    rng = random.Random(cfg.seed + 2)
    xs = []
    for _ in range(cfg.trials):
        t = cfg.degraded_link.round_trip(rng)                          # announce
        t += _quorum_met_ms(cfg.degraded_link, cfg.n_border_guards,
                            cfg.quorum_q, rng)                          # reachable vouch
        t += cfg.local_verify_ms
        if with_base2:
            t += cfg.base2_attestation_ms                              # MODELED M12
        xs.append(t)
    return Dist.of(xs)


@dataclass(frozen=True)
class AuthResult:
    config: AuthConfig
    reauth: List[dict]
    enroll: Dist
    degraded_with_base2: Dist
    degraded_no_base2: Dist

    @property
    def reauth_worst_p95(self) -> float:
        return max(r['at'].p95_ms for r in self.reauth)

    @property
    def reauth_passes(self) -> bool:
        return self.reauth_worst_p95 < self.config.gate_ms

    @property
    def degraded_passes(self) -> bool:
        return self.degraded_with_base2.p95_ms < self.config.gate_ms

    @property
    def strict_zta_degraded_passes(self) -> bool:
        # A strict ZTA blocks on the unreachable revocation source.
        return self.config.strict_zta_dead_pdp_wait_ms < self.config.gate_ms

    def as_report(self) -> dict:
        return {
            'target': 'SOW Task 2.4 — Auth <=5s (3 quantities)',
            'modeled': True,
            'gate_ms': self.config.gate_ms,
            'note': ('MODELED; AT path to be MEASURED on subscale HW (Task 4), '
                     'base-2 attestation modeled (M12). base-numbering to be '
                     'reconciled with the Technical Volume.'),
            'seed': self.config.seed,
            'reauth_steady_state': {
                'gated': True,
                'at_worst_p95_ms': round(self.reauth_worst_p95, 1),
                'passes_5s': self.reauth_passes,
                'by_cohort': [{'cohort': r['cohort'], 'at': r['at'].as_dict(),
                               'zta_baseline': r['zta'].as_dict()}
                              for r in self.reauth]},
            'enrollment_one_time': {'gated': False, 'characterized': self.enroll.as_dict()},
            'degraded_edge_first_contact': {
                'gated': True,
                'at_with_base2': self.degraded_with_base2.as_dict(),
                'at_no_base2': self.degraded_no_base2.as_dict(),
                'at_passes_5s': self.degraded_passes,
                'strict_zta_passes_5s': self.strict_zta_degraded_passes,
                'strict_zta_dead_pdp_wait_ms': self.config.strict_zta_dead_pdp_wait_ms},
        }


def run(config: Optional[AuthConfig] = None) -> AuthResult:
    cfg = config or AuthConfig()
    return AuthResult(
        config=cfg, reauth=reauth_sweep(cfg), enroll=enrollment(cfg),
        degraded_with_base2=degraded_admission(cfg, with_base2=True),
        degraded_no_base2=degraded_admission(cfg, with_base2=False))


def _s(ms: float) -> str:
    return f'{ms / 1000.0:.2f} s'


def main(argv=None):
    import argparse
    import json
    p = argparse.ArgumentParser(
        prog='autonomous_trust.evaluation.mns.auth', description=__doc__)
    p.add_argument('--seed', type=int, default=1234)
    p.add_argument('--json', metavar='PATH', default=None)
    args = p.parse_args(argv)

    r = run(AuthConfig(seed=args.seed))
    gate = r.config.gate_ms

    print('# Authentication-time M&S — Auth <=5 s (SOW Task 2.4)')
    print()
    print(f'Seed {r.config.seed} (deterministic) · gate {_s(gate)} · modeled '
          'tactical link. MODELED — AT path to be MEASURED on subscale HW (Task 4); '
          'base-2 attestation modeled (M12).')
    print()

    print('## (1) Steady-state re-authentication — gated ≤ 5 s')
    print()
    print('| cohort | AT p95 | ZTA-baseline p95 | AT ≤ 5 s |')
    print('|---|---|---|---|')
    for row in r.reauth:
        ok = 'yes' if row['at'].p95_ms < gate else 'NO'
        print(f"| {row['cohort']} | {_s(row['at'].p95_ms)} | "
              f"{_s(row['zta'].p95_ms)} | {ok} |")
    print()
    print(f"AT re-auth is local (no central PDP) → flat in cohort; worst p95 "
          f"{_s(r.reauth_worst_p95)} → **{'PASS' if r.reauth_passes else 'FAIL'}** "
          f"vs the 5 s gate.")
    print()

    print('## (2) One-time enrollment — characterized (NOT gated)')
    print()
    print(f"Consensus admission (announce + {r.config.quorum_q}-of-"
          f"{r.config.n_border_guards} quorum vouch + welcome): mean "
          f"{_s(r.enroll.mean_ms)}, p95 {_s(r.enroll.p95_ms)}. Reported as a "
          f"characterization per SOW (one-time, not gated).")
    print()

    print('## (3) Degraded-edge first-contact admission — gated ≤ 5 s')
    print()
    print('| posture | mean | p95 | ≤ 5 s |')
    print('|---|---|---|---|')
    print(f"| AT (deferred-verif fallback, base-2 modeled) | "
          f"{_s(r.degraded_with_base2.mean_ms)} | {_s(r.degraded_with_base2.p95_ms)} "
          f"| {'yes' if r.degraded_passes else 'NO'} |")
    print(f"| AT (bases 1/3-4 only, no base-2) | "
          f"{_s(r.degraded_no_base2.mean_ms)} | {_s(r.degraded_no_base2.p95_ms)} "
          f"| {'yes' if r.degraded_no_base2.p95_ms < gate else 'NO'} |")
    print(f"| strict ZTA (blocks on unreachable OCSP/PDP) | "
          f"≥ {_s(r.config.strict_zta_dead_pdp_wait_ms)} | — | "
          f"{'yes' if r.strict_zta_degraded_passes else 'NO'} |")
    print()
    print('_At the DDIL edge a strict ZTA blocks on the unreachable revocation '
          'source and busts the gate (or never admits); AT admits within 5 s via '
          'its deferred-verification fallback, then a delegated-verification quorum '
          'lifts the reputation cap off the admission path. This is the '
          'operationally-decisive case._')

    if args.json:
        with open(args.json, 'w') as fh:
            json.dump(r.as_report(), fh, indent=2)
        print(f'\n[wrote JSON report to {args.json}]')


if __name__ == '__main__':
    main()
