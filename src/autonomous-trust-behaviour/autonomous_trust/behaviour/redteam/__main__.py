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
"""Generate the resilience/threat M&S results artifact (SOW Task 3.4).

    python -m autonomous_trust.behaviour.redteam            # markdown to stdout
    python -m autonomous_trust.behaviour.redteam --json out.json --seed 1234
"""
import argparse
import json

from .harness import RedTeamConfig, run


def main(argv=None):
    parser = argparse.ArgumentParser(prog='autonomous_trust.behaviour.redteam',
                                     description=__doc__)
    parser.add_argument('--seed', type=int, default=1234)
    parser.add_argument('--json', metavar='PATH', default=None,
                        help='also write the full report as JSON to PATH')
    args = parser.parse_args(argv)

    result = run(RedTeamConfig(seed=args.seed))
    print(result.to_markdown())
    if args.json:
        with open(args.json, 'w') as fh:
            json.dump(result.as_report(), fh, indent=2)
        print('\n[wrote JSON report to %s]' % args.json)


if __name__ == '__main__':
    main()
