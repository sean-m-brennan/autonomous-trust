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
"""The harness's standalone path: a scenario's own deployment."""

import json
import os
from types import SimpleNamespace

from autonomous_trust.evaluation.redteam.harness import RedTeamHarness


def test_artifacts_dir_is_mounted_and_returned():
    seen = {}

    def fake_exec(cmd, **kw):
        if cmd[:2] == ['docker', 'compose'] and cmd[-2:] == ['up', '-d']:
            doc = json.load(open(cmd[cmd.index('-f') + 1]))
            volume = doc['services']['side']['volumes'][0]
            host = volume.split(':')[0]
            seen['host'] = host
            assert 'artifacts' not in doc
            assert os.path.isdir(host)
            with open(os.path.join(host, 'frames.jsonl'), 'w') as f:
                f.write('{"a": 1}\n')
        return SimpleNamespace(stdout='log', stderr='')

    h = RedTeamHarness('', [])
    h._exec, h._sleep = fake_exec, lambda s: None
    compose = {'standalone': True, 'artifacts': '{artifacts}',
               'services': {'side': {'volumes': ['{artifacts}:/capture']}}}
    out = h._run_standalone(compose, {'collect_logs': ['side']}, duration_s=1)
    assert out['artifacts'] == {'frames.jsonl': '{"a": 1}\n'}
    assert out['logs'] == {'side': 'log'}
    assert seen['host'] != '{artifacts}'


def test_without_artifacts_nothing_is_mounted():
    h = RedTeamHarness('', [])
    h._exec = lambda cmd, **kw: SimpleNamespace(stdout='', stderr='')
    h._sleep = lambda s: None
    out = h._run_standalone({'standalone': True, 'services': {}},
                            {'collect_logs': []}, duration_s=1)
    assert 'artifacts' not in out
