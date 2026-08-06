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
"""Run a network partition attack against the Appalachian scenario.

Usage:
    python -m autonomous_trust.evaluation.redteam.run_partition_attack \
        --baseline ../../baseline-results.json \
        --output /tmp/partition-report.json \
        --quick
"""

import argparse
import json
import sys

from autonomous_trust.evaluation.redteam import PartitionEvent
from autonomous_trust.evaluation.redteam.attack_router import NetworkPartitionAttack
from autonomous_trust.evaluation.redteam.harness import RedTeamHarness


def main():
    parser = argparse.ArgumentParser(description='Run network partition attack')
    parser.add_argument('--baseline', required=True,
                        help='Path to Phase 2 baseline-results.json')
    parser.add_argument('--output', required=True,
                        help='Path for output report JSON')
    parser.add_argument('--quick', action='store_true',
                        help='Use --quick flag (180s duration)')
    args = parser.parse_args()

    # Partition: split hilltop nodes into two groups at t=30s for 60s
    # Group A: first 4 hilltops, Group B: last 4 hilltops
    partition = PartitionEvent(
        start_s=30.0,
        end_s=90.0,
        group_a=["Sutton Knob", "Burnsville", "Flatwoods", "Gassaway"],
        group_b=["Sutton South", "Birch River", "Heaters", "Exchange"],
    )

    attack = NetworkPartitionAttack(partitions=[partition])
    harness = RedTeamHarness(
        baseline_path=args.baseline,
        scenarios=[attack],
    )

    report = harness.run(output_path=args.output, quick=args.quick)

    print(json.dumps(report, indent=2))
    sys.exit(0 if report['summary']['failed'] == 0 else 1)


if __name__ == '__main__':
    main()
