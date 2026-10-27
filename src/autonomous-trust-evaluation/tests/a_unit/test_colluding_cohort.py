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
"""The live colluding-cohort scenario, without containers
(RD_14.4_HOSTILE_JOIN_PLAN.md Phase 6): the deployment it builds, the
colluder's scoring and probe answers, the joiner's preparation, reading the
result, and the harness's standalone path with docker stubbed out."""
import json
import os
from types import SimpleNamespace

import pytest

from autonomous_trust.evaluation.redteam import colluding_cohort as cc
from autonomous_trust.evaluation.redteam.harness import RedTeamHarness


def test_the_deployment_names_every_node_and_its_role():
    doc = cc.compose(3, 'fail', True)
    names = list(doc['services'])
    assert names == ['colluder-1', 'colluder-2', 'colluder-3', 'joiner-1', 'joiner-2']
    env = doc['services']['joiner-1']['environment']
    assert env['AT_REDTEAM_ROLE'] == 'joiner' and env['AT_REDTEAM_POLICY'] == '1'
    assert 'AT_REP_DUMP_SEC' in env
    assert doc['services']['colluder-1']['environment']['STARTUP_DELAY'] == '0'
    with pytest.raises(ValueError):
        cc.compose(3, 'maybe', True)


def test_a_colluder_inflates_its_fellows_and_slanders_the_rest(monkeypatch):
    seen = []
    monkeypatch.setattr(cc.ReputationProcess, '_start_paxos',
                        lambda self, q, score, g=None: seen.append(score.score))
    proc = object.__new__(cc.ColludingReputationProcess)
    peers = {'a': 'colluder-2', 'b': 'joiner-1'}
    proc.protocol = SimpleNamespace(peers=SimpleNamespace(
        find_by_uuid=lambda u: SimpleNamespace(nickname=peers[u])))
    for subject in ('a', 'b'):
        proc._start_paxos({}, SimpleNamespace(score=0.5, subject_uuid=subject))
    assert seen == [cc.INFLATE, cc.SLANDER]


def test_the_fail_adversary_answers_every_probe_wrongly(monkeypatch):
    from autonomous_trust.core._python import bootstrap_capabilities as bc
    monkeypatch.setattr(bc, 'BOOTSTRAP_FUNCTIONS', dict(bc.BOOTSTRAP_FUNCTIONS))
    cc.fail_probes()
    assert bc.verify_handshake(41, bc.BOOTSTRAP_FUNCTIONS['at.handshake'](nonce=41)) < 0.5
    assert bc.BOOTSTRAP_FUNCTIONS['at.echo-challenge'](payload='x') != 'x'


def test_collect_reads_the_joiners_view():
    def dump(t, joiner_tier, colluder_tier, n):
        rec = {'t': t, 'self': 'j1', 'view': [
            {'s': '1', 'nick': 'joiner-2', 'tier': joiner_tier, 'n': 1},
            {'s': '2', 'nick': 'colluder-1', 'tier': colluder_tier, 'n': n}]}
        return 'x AT_REPDUMP %s' % json.dumps(rec)
    log = '\n'.join([dump(100.0, 1, 1, 0), dump(130.0, 3, 1, 2),
                     dump(160.0, 4, 0, 3)])
    got = cc.collect(log, 'fail')
    assert got == {'t_honest': 30.0, 't_colluders': 60.0, 'told_tier_unprobed': 1}
    assert cc.collect(log, 'pass')['t_colluders'] is None


def test_the_harness_runs_a_standalone_scenario(tmp_path):
    harness = RedTeamHarness(str(tmp_path / 'baseline.json'),
                             [cc.ColludingCohortAttack(2, 'fail', True)])
    calls = []

    def fake(cmd, **kw):
        calls.append(cmd)
        if cmd[:2] == ['docker', 'logs']:
            return SimpleNamespace(stdout='AT_REPDUMP {"t": 1, "view": []}', stderr='')
        if cmd[-2:] == ['up', '-d']:
            spec = json.load(open(cmd[cmd.index('-f') + 1]))
            assert 'standalone' not in spec and 'joiner-2' in spec['services']
        return SimpleNamespace(stdout='', stderr='')
    harness._exec = fake
    harness._sleep = lambda s: None
    sim, comp = {}, {}
    harness.scenarios[0].setup(sim, comp)
    metrics = harness._run_standalone(comp, sim, duration_s=1)
    assert set(metrics['logs']) == {'joiner-1', 'joiner-2'}
    assert calls[0][-2:] == ['up', '-d'] and calls[-1][-2:] == ['down', '-v']
    out = harness.scenarios[0].collect(dict(metrics))
    assert set(out['attack_specific']['joiners']) == {'joiner-1', 'joiner-2'}


def test_a_joiner_records_the_other_as_a_verified_contact(tmp_path, monkeypatch):
    pytest.importorskip('autonomous_trust.first_contact')
    from autonomous_trust.core import Configuration
    from autonomous_trust.core._python.identity.identity import public_identity_to_canonical
    shared = tmp_path / 'shared'
    shared.mkdir()
    # joiner-2 prepares first, in its own root, and publishes its identity.
    monkeypatch.setenv('AUTONOMOUS_TRUST_ROOT', str(tmp_path / 'j2'))
    with open(shared / 'joiner-1.json', 'w') as f:
        json.dump({}, f)          # a placeholder, so joiner-2 does not wait
    os.remove(shared / 'joiner-1.json')
    monkeypatch.setenv('AUTONOMOUS_TRUST_ROOT', str(tmp_path / 'j1'))
    cfg = Configuration.get_cfg_dir()
    # Seed joiner-2's published identity from a generated one.
    from autonomous_trust.core.config.generate import generate_identity
    other_cfg = str(tmp_path / 'other-cfg')
    os.makedirs(other_cfg)
    generate_identity(other_cfg, randomize=True, seed='joiner-2')
    from autonomous_trust.core import CfgIds
    other = Configuration.from_file(os.path.join(other_cfg, CfgIds.identity + Configuration.file_ext))
    with open(shared / 'joiner-2.json', 'w') as f:
        json.dump(public_identity_to_canonical(other.publish()), f)
    path = cc.prepare(cfg, 'joiner-1', 'joiner', 'fail', True,
                      shared_dir=str(shared), wait_sec=1.0)
    assert json.load(open(path))['enabled'] is True
    assert (shared / 'joiner-1.json').exists()
    from autonomous_trust.first_contact import Contacts
    contact = Contacts.load().get(str(other.uuid))
    assert contact is not None and contact.verified


def test_a_colluder_swaps_its_reputation_process(tmp_path, monkeypatch):
    from autonomous_trust.core import Configuration, CfgIds
    from autonomous_trust.core._python.processes import ProcessTracker
    monkeypatch.setenv('AUTONOMOUS_TRUST_ROOT', str(tmp_path))
    cfg = Configuration.get_cfg_dir()
    assert cc.prepare(cfg, 'colluder-1', 'colluder', 'pass', True) is None
    subsystems = json.load(open(os.path.join(cfg, ProcessTracker.default_filename)))
    assert subsystems[CfgIds.reputation].endswith('ColludingReputationProcess')
