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
"""The container-side helpers every live red-team attack shares."""

import json
import os

from autonomous_trust.evaluation.redteam import live


def test_held_since_is_when_the_condition_last_became_true():
    series = [(0, False), (5, True), (10, False), (15, True), (20, True)]
    assert live.held_since(series) == 15


def test_held_since_is_none_when_the_condition_fails_at_the_end():
    assert live.held_since([(0, True), (5, False)]) is None
    assert live.held_since([]) is None


def test_held_since_is_relative_to_the_first_sample():
    assert live.held_since([(100, False), (105, True)]) == 5


def test_read_dumps_skips_malformed_json():
    text = '\n'.join([
        'x AT_REPDUMP {"t": 1, "view": []}',
        'x AT_REPDUMP {"t": 2, "view": [',
        'unrelated line',
        'x AT_REPDUMP {"t": 3, "view": []}',
    ])
    assert [d['t'] for d in live.read_dumps(text)] == [1, 3]


def test_swap_process_writes_the_dotted_class_path(tmp_path):
    from autonomous_trust.core._python.processes import ProcessTracker
    path = tmp_path / ProcessTracker.default_filename
    path.write_text(json.dumps({'reputation': 'a.B', 'identity': 'c.D'}))
    live.swap_process(str(tmp_path), 'reputation', live.RedTeamNode)
    doc = json.loads(path.read_text())
    assert doc['reputation'] == '%s.RedTeamNode' % live.__name__
    assert doc['identity'] == 'c.D'


def test_node_service_runs_the_given_module():
    svc = live.node_service('honest-1', '10.30.0.10', 'honest', {'X': '1'},
                            image='img', module='autonomous_trust.evaluation.redteam.live')
    env = svc['environment']
    assert env['AUTONOMOUS_TRUST_EXE'] == '-m autonomous_trust.evaluation.redteam.live'
    assert env['AT_REDTEAM_ROLE'] == 'honest'
    assert env['AT_PEER_NAME'] == 'honest-1'
    assert env['AUTONOMOUS_TRUST_BACKEND'] == 'python'
    assert env['X'] == '1'
    assert svc['container_name'] == svc['hostname'] == 'honest-1'
    assert svc['image'] == 'img'
    assert svc['networks'] == {'redteam': {'ipv4_address': '10.30.0.10'}}


def test_base_config_grants_plaintext_verbs_and_returns_the_identity(
        tmp_path, monkeypatch):
    from autonomous_trust.core import Configuration
    monkeypatch.setenv('AUTONOMOUS_TRUST_ROOT', str(tmp_path))
    cfg = Configuration.get_cfg_dir()
    ident = live.base_config(cfg, 'honest-1')
    assert ident.uuid
    from autonomous_trust.core._python import plaintext_verbs
    assert os.path.exists(os.path.join(cfg, plaintext_verbs.FILENAME))


def test_an_honest_node_declares_the_join_policy_only_when_told(
        tmp_path, monkeypatch):
    from autonomous_trust.core import Configuration
    from autonomous_trust.core._python.identity.join_policy import (
        load_join_policy)
    monkeypatch.setenv('AUTONOMOUS_TRUST_ROOT', str(tmp_path))
    cfg = Configuration.get_cfg_dir()
    assert live.prepare_honest(cfg, 'honest-1', policy=False) is None
    path = live.prepare_honest(cfg, 'honest-1', policy=True)
    assert load_join_policy(path).enabled


def test_an_honest_service_runs_the_live_module():
    svc = live.honest_service('honest-2', '10.30.0.11', image='img',
                              policy=True, dump_sec=5.0)
    env = svc['environment']
    assert env['AUTONOMOUS_TRUST_EXE'] == '-m autonomous_trust.evaluation.redteam.live'
    assert env['AT_REDTEAM_POLICY'] == '1'
    assert env['AT_REP_DUMP_SEC'] == '5.0'


def _dump(t, **tiers):
    return {'t': t, 'view': [{'nick': '%s@tekfive.com' % k.replace('_', '-'),
                              'tier': tier, 'own': own}
                             for k, (tier, own) in tiers.items()]}


def test_honest_pair_failures_name_each_peer_short_of_the_tier():
    names = ['honest-1', 'honest-2', 'honest-3']
    dumps = [_dump(0, honest_2=(3, 4), honest_3=(4, 0))]
    assert live.honest_pair_failures('honest-1', dumps, names) == [
        'honest-1: honest-3 at tier 4 with own 0']
    assert live.honest_pair_failures('honest-1', [_dump(0)], names) == [
        'honest-1: never saw honest-2', 'honest-1: never saw honest-3']


def test_honest_held_since_needs_every_other_honest_node():
    names = ['honest-1', 'honest-2', 'honest-3']
    dumps = [_dump(0, honest_2=(3, 4)),
             _dump(5, honest_2=(3, 4), honest_3=(3, 1)),
             _dump(10, honest_2=(3, 4), honest_3=(3, 2))]
    assert live.honest_held_since(dumps, 'honest-1', names) == 5


def test_mark_no_data_keeps_the_silent_logs_tail():
    metrics = {}
    assert not live.mark_no_data(metrics, {}, [])
    assert metrics == {}
    assert live.mark_no_data(metrics, {'a': 'x' * 3000}, ['a'])
    assert metrics['error'] == 'no_metrics'
    assert len(metrics['attack_specific']['log_tails']['a']) == 2000
