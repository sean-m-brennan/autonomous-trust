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
"""Administrative-overhead M&S — operator actions/day, with vs without AT
(SOW Task 2.4, "Admin overhead -25% net").

This is an **analytic** operator-action accounting (NOT Monte-Carlo): for a
modeled operational day it counts operator actions under a conventional ZTA/
manual-policy baseline vs AT, and reports the **net** reduction = actions AT
*eliminates* minus actions AT *adds*.

AT eliminates the recurring per-asset / per-mission **policy-authoring** load
(its core "no human policy authoring at decision time" claim — trust is evaluated
autonomously, and the MissionValor score→tier-floor mapping auto-derives object
policy) and most manual incident response (autonomous slashing). AT **adds** real
operator burdens that must be counted honestly: per-session **PIV+MFA operator
activation** (M10), mandatory **human-on-the-loop review** of safety-critical
slash recommendations, **false-exclusion adjudication**, and ongoing
**trust-model oversight**.

Honesty discipline: this is the **softest** Task 2 metric (SOW risk register:
modeled/analytic, baseline could be seen as self-serving). It is therefore
**tempo-conditional** — the :func:`sweep` shows the saving grows with operational
tempo and can fall below the -25% target (even negative) at low tempo, where AT's
~fixed added burden dominates. The baseline action rates are **TPOC-pre-
registration dependent** (SOW Task 2.2) and exposed on :class:`AdminConfig`.

The MissionValor interface is **stubbed** here (:class:`MissionValorMock`),
standing in for the Sentar Task 1.5 deliverable (Mission Impact Prediction Score
→ required_tier floor / safety-critical flag).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple


@dataclass(frozen=True)
class MissionValorMock:
    """STUB for the Sentar Task 1.5 MissionValor→AT interface: maps a Mission
    Impact Prediction Score in [0,1] to a (required_tier floor, safety_critical)
    pair. Used here only to count the per-object policy-authoring actions AT
    **auto-derives** (and therefore eliminates from the operator's load)."""
    crit_floors: Tuple[Tuple[float, int], ...] = (
        (0.90, 4), (0.75, 3), (0.50, 2), (0.25, 1))  # score >= -> tier floor
    safety_critical_threshold: float = 0.75

    def derive(self, score: float) -> Tuple[int, bool]:
        tier = 0
        for thresh, t in self.crit_floors:
            if score >= thresh:
                tier = t
                break
        return tier, (score >= self.safety_critical_threshold)


@dataclass(frozen=True)
class AdminConfig:
    """Modeled operational-day tempo + per-action-class rates. All MODELED /
    TPOC-pre-registration dependent; exposed for re-anchoring."""
    # Operational-day tempo (the "activity" drivers scale with tempo_multiplier)
    n_assets: int = 40             # data objects/peers needing access policy
    n_retasks: int = 6             # mission re-taskings/day (policy churn)
    n_anomalies: int = 5           # suspicious events/day
    n_onboard: int = 3             # new peers/day
    n_operator_sessions: int = 6   # operator console activations/step-ups/day
    safety_critical_fraction: float = 0.40
    false_exclusion_per_day: float = 0.5   # red-team FPR ~0; conservative > 0
    tempo_multiplier: float = 1.0  # scales retasks/anomalies/onboard (mission tempo)

    # Baseline (manual ZTA policy admin) per-unit action rates
    b_reauthor_per_retask: float = 3.0
    b_asset_daily_review_frac: float = 0.10
    b_invest_per_anomaly: float = 2.0
    b_actions_per_onboard: float = 2.0
    b_cred_mgmt: float = 4.0

    # AT per-unit action rates (reduced classes)
    at_oversight_per_retask: float = 1.0
    at_standing_trust_policy: float = 4.0
    at_review_per_sc_anomaly: float = 1.0
    at_incident_oversight: float = 2.0
    at_actions_per_onboard: float = 0.30
    at_cred_mgmt: float = 1.5
    # AT-added classes
    at_activation_per_session: float = 1.0
    at_false_exclusion_actions: float = 2.0   # per false-exclusion event
    at_model_oversight: float = 2.0


@dataclass(frozen=True)
class ActionClass:
    key: str
    name: str
    baseline: float
    at: float
    added: bool = False     # True: a burden AT introduces (baseline ~0)

    @property
    def delta(self) -> float:
        return self.baseline - self.at      # >0 = AT saves; <0 = AT adds net


@dataclass(frozen=True)
class AdminResult:
    config: AdminConfig
    classes: List[ActionClass]

    @property
    def baseline_total(self) -> float:
        return sum(c.baseline for c in self.classes)

    @property
    def at_total(self) -> float:
        return sum(c.at for c in self.classes)

    @property
    def net_reduction(self) -> float:
        return 0.0 if self.baseline_total <= 0 else (
            (self.baseline_total - self.at_total) / self.baseline_total)

    @property
    def meets_target(self) -> bool:
        return self.net_reduction >= 0.25

    def as_report(self) -> dict:
        return {
            'target': 'SOW Task 2.4 — Admin overhead -25% net (operator actions/day)',
            'modeled': True,
            'analytic': True,
            'note': ('Analytic operator-action accounting (softest Task 2 metric). '
                     'AT-added burdens counted explicitly. Tempo-conditional — see '
                     'sweep. Baseline rates TPOC-pre-registration dependent; '
                     'MissionValor interface STUBBED (Sentar Task 1.5).'),
            'tempo_multiplier': self.config.tempo_multiplier,
            'operator_actions_per_day': {'without_AT': round(self.baseline_total, 1),
                                         'with_AT': round(self.at_total, 1)},
            'net_reduction': round(self.net_reduction, 4),
            'meets_25pct_target': self.meets_target,
            'per_class': [
                {'key': c.key, 'baseline': round(c.baseline, 2),
                 'at': round(c.at, 2), 'added_by_at': c.added,
                 'delta': round(c.delta, 2)} for c in self.classes],
        }


def run(config: Optional[AdminConfig] = None) -> AdminResult:
    """Analytic operator-action accounting for one modeled operational day."""
    c = config or AdminConfig()
    m = c.tempo_multiplier
    retasks = c.n_retasks * m
    anomalies = c.n_anomalies * m
    onboard = c.n_onboard * m

    classes = [
        ActionClass(
            'policy_authoring', 'Access-policy authoring & maintenance',
            baseline=retasks * c.b_reauthor_per_retask
                     + c.n_assets * c.b_asset_daily_review_frac,
            # MissionValor mock auto-derives per-object floors -> oversight only
            at=retasks * c.at_oversight_per_retask + c.at_standing_trust_policy),
        ActionClass(
            'incident_response', 'Incident investigation & response',
            baseline=anomalies * c.b_invest_per_anomaly,
            at=anomalies * c.safety_critical_fraction * c.at_review_per_sc_anomaly
               + c.at_incident_oversight),
        ActionClass(
            'onboarding', 'Peer onboarding / provisioning',
            baseline=onboard * c.b_actions_per_onboard,
            at=onboard * c.at_actions_per_onboard),
        ActionClass(
            'cred_mgmt', 'Credential / revocation management',
            baseline=c.b_cred_mgmt, at=c.at_cred_mgmt),
        # --- burdens AT ADDS (baseline ~0) ---
        ActionClass(
            'operator_activation', 'Operator PIV+MFA activation / step-up',
            baseline=0.0, at=c.n_operator_sessions * c.at_activation_per_session,
            added=True),
        ActionClass(
            'false_exclusion', 'False-exclusion adjudication',
            baseline=0.0, at=c.false_exclusion_per_day * c.at_false_exclusion_actions,
            added=True),
        ActionClass(
            'model_oversight', 'Trust-model oversight / tuning',
            baseline=0.0, at=c.at_model_oversight, added=True),
    ]
    return AdminResult(config=c, classes=classes)


@dataclass(frozen=True)
class SweepRow:
    tempo: float
    baseline_total: float
    at_total: float
    net_reduction: float


def sweep(tempos=(0.3, 0.5, 0.75, 1.0, 1.5, 2.0, 3.0),
          base: Optional[AdminConfig] = None) -> List[SweepRow]:
    """Vary mission tempo to expose the conditionality of the admin saving: AT's
    eliminated policy/response load scales with tempo while its added activation/
    oversight burden is ~fixed, so the net reduction grows with tempo and can fall
    below -25% (even negative) at low tempo."""
    base = base or AdminConfig()
    rows = []
    for t in tempos:
        cfg = AdminConfig(**{**base.__dict__, 'tempo_multiplier': t})
        r = run(cfg)
        rows.append(SweepRow(t, r.baseline_total, r.at_total, r.net_reduction))
    return rows


def _pct(x: float) -> str:
    return f'{x * 100:+.1f}%'


def main(argv=None):
    import argparse
    import json
    p = argparse.ArgumentParser(
        prog='autonomous_trust.evaluation.mns.admin', description=__doc__)
    p.add_argument('--tempo', type=float, default=1.0,
                   help='mission-tempo multiplier (scales retasks/anomalies/onboard)')
    p.add_argument('--json', metavar='PATH', default=None)
    args = p.parse_args(argv)

    result = run(AdminConfig(tempo_multiplier=args.tempo))

    print('# Administrative-overhead M&S — operator actions/day, with vs without '
          'AT (SOW Task 2.4)')
    print()
    print(f'Modeled operational day · tempo ×{result.config.tempo_multiplier:g} · '
          'analytic accounting (not Monte-Carlo).')
    print()
    print('_MODELED / analytic — the SOFTEST Task 2 metric. AT-added burdens '
          'counted explicitly. Baseline rates TPOC-pre-registration dependent; '
          'MissionValor interface STUBBED (Sentar Task 1.5)._')
    print()
    print('| Operator action class | w/o AT | w/ AT | Δ (saved) | note |')
    print('|---|---|---|---|---|')
    for c in result.classes:
        note = 'AT-ADDED' if c.added else 'AT reduces'
        print(f'| {c.name} | {c.baseline:.1f} | {c.at:.1f} | {c.delta:+.1f} | {note} |')
    print(f'| **Total** | **{result.baseline_total:.1f}** '
          f'| **{result.at_total:.1f}** | **{result.baseline_total - result.at_total:+.1f}** | |')
    print()
    print('| Metric | Value | Target | Result |')
    print('|---|---|---|---|')
    print(f'| Net admin-overhead reduction | {_pct(result.net_reduction)} '
          f'| ↑ ≥ 25% | {"PASS" if result.meets_target else "BELOW TARGET"} |')
    print()
    print('## Tempo sensitivity (this is the softest metric — show the condition)')
    print()
    print('_AT eliminates load that scales with mission tempo; its added '
          'activation/oversight burden is ~fixed. So the -25% holds at '
          'representative tempo and above, and degrades (can go negative) at low '
          'tempo. Honest bound, not a single point._')
    print()
    print('| tempo | w/o AT | w/ AT | net reduction | meets -25% |')
    print('|---|---|---|---|---|')
    for row in sweep(base=result.config):
        ok = 'yes' if row.net_reduction >= 0.25 else 'no'
        print(f'| ×{row.tempo:g} | {row.baseline_total:.1f} | {row.at_total:.1f} '
              f'| {_pct(row.net_reduction)} | {ok} |')

    if args.json:
        with open(args.json, 'w') as fh:
            json.dump(result.as_report(), fh, indent=2)
        print(f'\n[wrote JSON report to {args.json}]')


if __name__ == '__main__':
    main()
