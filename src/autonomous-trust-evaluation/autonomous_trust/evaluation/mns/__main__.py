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
"""Latency-(-50%) M&S results artifact (SOW Task 2.4).

    python -m autonomous_trust.evaluation.mns                 # markdown report
    python -m autonomous_trust.evaluation.mns --json out.json --seed 1234
"""
import argparse
import json

from .latency import LatencyConfig, run, sweep


def _pct(x: float) -> str:
    return f'{x * 100:.1f}%'


def main(argv=None):
    p = argparse.ArgumentParser(prog='autonomous_trust.evaluation.mns',
                                description=__doc__)
    p.add_argument('--seed', type=int, default=1234)
    p.add_argument('--cohort', type=int, default=25,
                   help='concurrent enrolled nodes hitting the shared PDP')
    p.add_argument('--json', metavar='PATH', default=None,
                   help='also write the full report as JSON to PATH')
    args = p.parse_args(argv)

    cfg = LatencyConfig(seed=args.seed, cohort_size=args.cohort)
    result = run(cfg)
    r = result.as_report()

    print('# Access-decision latency M&S — AT-local vs ZTA-PDP (SOW Task 2.4)')
    print()
    print(f'Seed {cfg.seed} (deterministic) · cohort {cfg.cohort_size} · modeled '
          f'tactical link {cfg.link.oneway_ms:.0f} ms one-way '
          f'({cfg.link.jitter_ms:.0f} ms jitter, {cfg.link.loss_prob:.0%} loss).')
    print()
    print('_MODELED (seeded Monte Carlo). AT path → to be MEASURED on subscale HW '
          '(Task 4); ZTA baseline → anchor to published DoD-PKI/OCSP/CRL figures '
          '(Task 2.2). Steady-state per-request decision; enrollment characterized '
          'separately._')
    print()
    print('| Path | mean | median | p95 | tag |')
    print('|---|---|---|---|---|')
    print(f"| ZTA-PDP (round-trip + PDP + OCSP) | {r['zta_pdp']['mean_ms']} ms "
          f"| {r['zta_pdp']['median_ms']} ms | {r['zta_pdp']['p95_ms']} ms "
          f"| modeled / anchored |")
    print(f"| AT-local (local verify + lookup) | {r['at_local']['mean_ms']} ms "
          f"| {r['at_local']['median_ms']} ms | {r['at_local']['p95_ms']} ms "
          f"| modeled (→ measure) |")
    print()
    print(f"| Metric | Value | Target | Result |")
    print(f"|---|---|---|---|")
    print(f"| Mean-latency reduction | {_pct(result.reduction_mean)} | ↑ ≥ 50% "
          f"| {'PASS' if result.meets_target else 'FAIL'} |")
    print(f"| p95-latency reduction | {_pct(result.reduction_p95)} | ↑ ≥ 50% "
          f"| {'PASS' if result.reduction_p95 >= 0.50 else 'FAIL'} |")
    print()

    print('## Robustness — sweep over link profiles')
    print()
    print('_Shows the reduction is structural (AT decides locally; ZTA needs '
          '≥1 link round-trip), not a single point. The benign-LAN row is the '
          'honest floor (AT vs a fast co-located PDP); the contested-tactical row '
          'is the operationally-relevant case. "favorable ZTA" = OCSP-stapling / '
          'cached revocation (no extra revocation round-trip)._')
    print()
    print('| link profile | one-way | ZTA mean | AT mean | reduction | ZTA variant |')
    print('|---|---|---|---|---|---|')
    for row in sweep(base=cfg):
        variant = 'favorable (stapled)' if row.favorable_zta else 'baseline (OCSP RTT)'
        print(f'| {row.profile} | {row.oneway_ms:.0f} ms | {row.zta_mean_ms:.1f} ms '
              f'| {row.at_mean_ms:.2f} ms | {_pct(row.reduction_mean)} | {variant} |')

    if args.json:
        with open(args.json, 'w') as fh:
            json.dump(r, fh, indent=2)
        print(f'\n[wrote JSON report to {args.json}]')


if __name__ == '__main__':
    main()
