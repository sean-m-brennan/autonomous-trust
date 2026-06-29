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
"""Unauthorized-access reduction M&S — with vs without AT (SOW Task 2.4, "-90%").

Counts successful unauthorized-access events over a **fixed attempt population**
drawn from an ATT&CK-mapped taxonomy, under two postures:

* **without AT** = the ZTA-only baseline (cert PDP + static authz) — SOW Task 2.2;
* **with AT** = the AT overlay added (consensus admission, ZTA verifier, credential
  uniqueness, tier-gating, reputation/behavioural slashing, encrypted transport).

The delta is what AT adds *over* a cert-only ZTA baseline — chiefly catching the
**valid-credentialed abuse** a cert PDP cannot see. Per-attack block rates are
mechanism-grounded (mechanism IDs M1..M8 are the `NIST_DOD_ZT_TRACEABILITY.md`
inventory); the **behavioural rows are anchored to the red-team's MEASURED
detection** (`autonomous_trust.behaviour.redteam`: compromised-credential 1.00,
Byzantine 0.60), the rest are MODELED gates.

Honesty discipline (as in `latency.py`): all rates are **modeled estimates**
except where tagged measured; the taxonomy mix is **TPOC-pre-registration
dependent** (SOW Task 2.2) and exposed on :class:`AttackType` for re-anchoring.
The harness reports the reduction the rates *imply* — it does not hardcode 90%.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass(frozen=True)
class AttackType:
    """One class of unauthorized-access attempt.

    Args:
        key, name:    identifier + label.
        attack_id:    ATT&CK technique id (illustrative mapping).
        tactic:       ATT&CK tactic.
        weight:       share of the attempt population (the pre-registered mix).
        p_baseline:   P(success) against the ZTA-only baseline.
        p_at:         P(success) against full AT.
        mechanism:    AT mechanism that reduces it (M-code, traceability matrix).
        source:       'measured' (anchored to red-team) or 'modeled'.
    """
    key: str
    name: str
    attack_id: str
    tactic: str
    weight: float
    p_baseline: float
    p_at: float
    mechanism: str
    source: str


#: Default ATT&CK-mapped taxonomy + mix (TPOC pre-registration dependent).
#: Behavioural rows (valid_cred_abuse, byzantine_commit) anchor p_at to the
#: behaviour red-team's MEASURED detection; the rest are modeled gates with their
#: residual tied to tracked gaps where applicable.
TAXONOMY: Tuple[AttackType, ...] = (
    AttackType('valid_cred_abuse', 'Compromised-but-credentialed asset',
               'T1078', 'Valid Accounts', 0.30, 0.95, 0.00, 'M8→M6',
               'measured: red-team compromised-credential detection = 1.00'),
    AttackType('cred_replay', 'Harvested-credential replay under new identity',
               'T1550.001', 'Defense Evasion', 0.15, 0.90, 0.20, 'M2b',
               'modeled; residual = ISSUES §1.5 (TOFU race + C-parity pending)'),
    AttackType('sybil_admission', 'Sybil / fabricated identity at admission',
               'T1136', 'Persistence', 0.12, 0.60, 0.15, 'M1',
               'modeled; residual = ISSUES §8.1 (admission-bounding unproven)'),
    AttackType('open_channel', 'Unauthorized interception over open channel',
               'T1040', 'Collection', 0.12, 0.40, 0.02, 'M7', 'modeled gate'),
    AttackType('tier_escalation', 'Privilege / tier escalation',
               'T1068', 'Privilege Escalation', 0.11, 0.50, 0.10, 'M5',
               'modeled gate'),
    AttackType('byzantine_commit', 'Byzantine manipulation of consensus',
               'T1565.001', 'Impact', 0.10, 0.70, 0.15, 'M3',
               'modeled; quorum prevention (red-team Byzantine detection = 0.60)'),
    AttackType('revoked_cred', 'Expired / revoked credential use',
               'T1588.004', 'Resource Development', 0.10, 0.30, 0.05, 'M2',
               'modeled; ZTA baseline also revocation-checks → small delta'),
)

#: Tracked-gap closures (gap-closure plan): full cert↔identity binding (G11 /
#: ISSUES §1.5) and proven Sybil admission-bounding (ISSUES §8.1). Used for the
#: "projected with tracked gaps closed" line — NOT the current state.
GAPS_CLOSED_PAT = {'cred_replay': 0.05, 'sybil_admission': 0.05}


@dataclass(frozen=True)
class UnauthorizedConfig:
    taxonomy: Tuple[AttackType, ...] = TAXONOMY
    n_attempts: int = 20000
    seed: int = 1234


@dataclass(frozen=True)
class TypeOutcome:
    atype: AttackType
    attempts: int
    success_baseline: int
    success_at: int

    @property
    def reduction(self) -> float:
        return 0.0 if self.success_baseline == 0 else (
            (self.success_baseline - self.success_at) / self.success_baseline)


@dataclass(frozen=True)
class UnauthorizedResult:
    config: UnauthorizedConfig
    per_type: List[TypeOutcome]
    total_attempts: int
    total_baseline: int
    total_at: int
    projected_at_gaps_closed: int

    @property
    def reduction(self) -> float:
        return 0.0 if self.total_baseline == 0 else (
            (self.total_baseline - self.total_at) / self.total_baseline)

    @property
    def reduction_gaps_closed(self) -> float:
        return 0.0 if self.total_baseline == 0 else (
            (self.total_baseline - self.projected_at_gaps_closed) / self.total_baseline)

    @property
    def meets_target(self) -> bool:
        return self.reduction >= 0.90

    def as_report(self) -> dict:
        return {
            'target': 'SOW Task 2.4 — Unauthorized access -90% (with vs without AT)',
            'modeled': True,
            'baseline': 'ZTA-only (cert PDP + static authz)',
            'note': ('Per-attack block rates mechanism-grounded; behavioural rows '
                     'anchored to red-team MEASURED detection, rest MODELED. Mix is '
                     'TPOC-pre-registration dependent (Task 2.2). Reduction is '
                     'implied by the rates, not hardcoded.'),
            'seed': self.config.seed,
            'total_attempts': self.total_attempts,
            'successful_unauthorized': {'without_AT': self.total_baseline,
                                        'with_AT': self.total_at},
            'reduction': round(self.reduction, 4),
            'meets_90pct_target': self.meets_target,
            'reduction_projected_gaps_closed': round(self.reduction_gaps_closed, 4),
            'per_attack': [
                {'key': o.atype.key, 'attack_id': o.atype.attack_id,
                 'mechanism': o.atype.mechanism, 'source': o.atype.source,
                 'success_without_AT': o.success_baseline,
                 'success_with_AT': o.success_at,
                 'reduction': round(o.reduction, 4)}
                for o in self.per_type],
        }


def run(config: Optional[UnauthorizedConfig] = None) -> UnauthorizedResult:
    """Monte-Carlo the fixed attempt population through both postures.
    Deterministic in ``config.seed``."""
    cfg = config or UnauthorizedConfig()
    rng = random.Random(cfg.seed)
    types = list(cfg.taxonomy)
    weights = [t.weight for t in types]

    counts: Dict[str, int] = {t.key: 0 for t in types}
    sb: Dict[str, int] = {t.key: 0 for t in types}
    sa: Dict[str, int] = {t.key: 0 for t in types}
    sa_closed = 0

    for _ in range(cfg.n_attempts):
        t = rng.choices(types, weights=weights, k=1)[0]
        counts[t.key] += 1
        # Independent draws so an attempt's baseline/AT outcomes don't correlate.
        if rng.random() < t.p_baseline:
            sb[t.key] += 1
        if rng.random() < t.p_at:
            sa[t.key] += 1
        p_closed = GAPS_CLOSED_PAT.get(t.key, t.p_at)
        if rng.random() < p_closed:
            sa_closed += 1

    per_type = [TypeOutcome(t, counts[t.key], sb[t.key], sa[t.key]) for t in types]
    return UnauthorizedResult(
        config=cfg, per_type=per_type, total_attempts=cfg.n_attempts,
        total_baseline=sum(sb.values()), total_at=sum(sa.values()),
        projected_at_gaps_closed=sa_closed)


def _pct(x: float) -> str:
    return f'{x * 100:.1f}%'


def main(argv=None):
    import argparse
    import json
    p = argparse.ArgumentParser(
        prog='autonomous_trust.evaluation.mns.unauthorized', description=__doc__)
    p.add_argument('--seed', type=int, default=1234)
    p.add_argument('--json', metavar='PATH', default=None)
    args = p.parse_args(argv)

    result = run(UnauthorizedConfig(seed=args.seed))
    r = result.as_report()

    print('# Unauthorized-access reduction M&S — with vs without AT (SOW Task 2.4)')
    print()
    print(f'Seed {result.config.seed} (deterministic) · '
          f'{result.total_attempts} attempts · baseline = ZTA-only (cert PDP).')
    print()
    print('_MODELED. Behavioural rows anchored to red-team MEASURED detection; '
          'rest modeled gates. Mix is TPOC-pre-registration dependent (Task 2.2); '
          'reduction is implied by the rates, not hardcoded._')
    print()
    print('| Attack (ATT&CK) | mechanism | succeed w/o AT | succeed w/ AT | reduction | rate source |')
    print('|---|---|---|---|---|---|')
    for o in result.per_type:
        print(f'| {o.atype.name} ({o.atype.attack_id}) | {o.atype.mechanism} '
              f'| {o.success_baseline} | {o.success_at} | {_pct(o.reduction)} '
              f'| {o.atype.source} |')
    print()
    print('| Metric | Value | Target | Result |')
    print('|---|---|---|---|')
    print(f'| Total successful unauthorized accesses | {result.total_baseline} '
          f'(w/o AT) → {result.total_at} (w/ AT) | — | — |')
    print(f'| Unauthorized-access reduction | {_pct(result.reduction)} | ↑ ≥ 90% '
          f'| {"PASS" if result.meets_target else "NEAR-MISS"} |')
    print(f'| Projected w/ tracked gaps closed (G11 §1.5 + §8.1) '
          f'| {_pct(result.reduction_gaps_closed)} | ↑ ≥ 90% '
          f'| {"PASS" if result.reduction_gaps_closed >= 0.90 else "FAIL"} |')
    print()
    if not result.meets_target:
        print('_Residual concentrated in the two TRACKED gaps — harvested-credential '
              'replay (G11 / ISSUES §1.5: full cert↔identity binding + C parity) and '
              'Sybil admission-bounding (ISSUES §8.1). Closing both lifts the modeled '
              'reduction over the 90% target (line above); this harness shows where '
              'to invest, consistent with the gap-closure plan._')

    if args.json:
        with open(args.json, 'w') as fh:
            json.dump(r, fh, indent=2)
        print(f'\n[wrote JSON report to {args.json}]')


if __name__ == '__main__':
    main()
