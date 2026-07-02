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

"""diff_results: cross-language outcome comparison.

Reads two result JSONs (per the schema_version=1 shape both Python and C
runners emit) and reports any case whose status differs between them.
Asymmetric outcomes (one side pass, the other fail) fail the build.

A case present on one side and skipped on the other is *not* a failure —
many cases are deliberately scoped to one implementation (e.g. wire_vector
on the C side is currently skip while the C-side serializers are wired).
The exit code reflects only true asymmetric pass/fail.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass
class CrossDiff:
    asymmetric_pass_fail: list[tuple[str, str, str]]  # (case_id, lhs_status, rhs_status)
    only_lhs: list[str]
    only_rhs: list[str]

    @property
    def is_clean(self) -> bool:
        return not self.asymmetric_pass_fail


def _load(path: Path) -> dict:
    with path.open('r', encoding='utf-8') as fh:
        return json.load(fh)


def _index_by_case_id(report: dict) -> dict[str, str]:
    """Map case_id -> status. Last entry wins on duplicate ids."""
    return {c['case_id']: c['status'] for c in report.get('cases', [])}


def diff(lhs_report: dict, rhs_report: dict) -> CrossDiff:
    lhs = _index_by_case_id(lhs_report)
    rhs = _index_by_case_id(rhs_report)

    asymmetric: list[tuple[str, str, str]] = []
    for case_id in sorted(set(lhs) & set(rhs)):
        l = lhs[case_id]
        r = rhs[case_id]
        if l == r:
            continue
        # Skip vs anything-else is allowed (one side hasn't wired the case).
        if l == 'skip' or r == 'skip':
            continue
        asymmetric.append((case_id, l, r))

    only_lhs = sorted(set(lhs) - set(rhs))
    only_rhs = sorted(set(rhs) - set(lhs))
    return CrossDiff(asymmetric, only_lhs, only_rhs)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog='diff_results')
    parser.add_argument('lhs', help='First report JSON (e.g. python-<ts>.json)')
    parser.add_argument('rhs', help='Second report JSON (e.g. c-<ts>.json)')
    parser.add_argument('--strict-coverage', action='store_true',
                        help='Also fail on cases present on only one side.')
    args = parser.parse_args(argv)

    lhs = _load(Path(args.lhs))
    rhs = _load(Path(args.rhs))
    d = diff(lhs, rhs)

    lhs_impl = lhs.get('implementation', 'lhs')
    rhs_impl = rhs.get('implementation', 'rhs')

    print(f'comparing {lhs_impl} vs {rhs_impl}: '
          f'{len(d.asymmetric_pass_fail)} asymmetric, '
          f'only-{lhs_impl}={len(d.only_lhs)}, '
          f'only-{rhs_impl}={len(d.only_rhs)}')

    for case_id, l, r in d.asymmetric_pass_fail:
        print(f'  ASYMMETRIC {case_id}: {lhs_impl}={l}, {rhs_impl}={r}',
              file=sys.stderr)

    if args.strict_coverage:
        for case_id in d.only_lhs:
            print(f'  ONLY-{lhs_impl.upper()} {case_id}', file=sys.stderr)
        for case_id in d.only_rhs:
            print(f'  ONLY-{rhs_impl.upper()} {case_id}', file=sys.stderr)
        if d.only_lhs or d.only_rhs:
            return 1

    return 0 if d.is_clean else 1


if __name__ == '__main__':
    raise SystemExit(main())
