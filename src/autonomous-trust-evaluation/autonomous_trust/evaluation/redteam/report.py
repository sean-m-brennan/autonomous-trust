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
"""Generate human-readable markdown report from red team JSON results."""


def generate_markdown_report(report: dict) -> str:
    """Convert a red team JSON report to markdown."""
    lines = []
    lines.append('# Red Team Report')
    lines.append('')
    lines.append(f'**Generated:** {report["timestamp"]}')
    lines.append('')

    s = report['summary']
    lines.append('## Summary')
    lines.append('')
    lines.append(f'| Total | Passed | Failed | Errors |')
    lines.append(f'|-------|--------|--------|--------|')
    lines.append(f'| {s["total"]} | {s["passed"]} | {s["failed"]} | {s.get("errors", 0)} |')
    lines.append('')

    lines.append('## Phase 2 Baseline')
    lines.append('')
    for k, v in report.get('baseline', {}).items():
        lines.append(f'- **{k}:** {v}')
    lines.append('')

    lines.append('## Attack Results')
    lines.append('')
    for attack in report.get('attacks', []):
        result_badge = attack['result']
        lines.append(f'### {attack["name"]} [{result_badge}]')
        lines.append('')
        lines.append(f'*{attack["description"]}*')
        lines.append('')

        if attack.get('metrics_during_attack'):
            lines.append('**Metrics during attack:**')
            lines.append('')
            for k, v in attack['metrics_during_attack'].items():
                baseline_val = report.get('baseline', {}).get(k)
                comparison = ''
                if baseline_val is not None and isinstance(v, (int, float)):
                    delta = v - baseline_val
                    comparison = f' (baseline: {baseline_val}, delta: {delta:+.2f})'
                lines.append(f'- {k}: {v}{comparison}')
            lines.append('')

        if attack.get('attack_specific'):
            lines.append('**Attack-specific:**')
            lines.append('')
            for k, v in attack['attack_specific'].items():
                lines.append(f'- {k}: {v}')
            lines.append('')

    return '\n'.join(lines)
