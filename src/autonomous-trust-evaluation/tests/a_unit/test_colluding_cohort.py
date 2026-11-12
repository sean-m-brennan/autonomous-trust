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


def test_the_log_level_reaches_every_node():
    doc = cc.compose(2, 'fail', True)
    assert all(svc['environment']['AT_REDTEAM_LOG_LEVEL'] == 'INFO'
               for svc in doc['services'].values())
    doc = cc.compose(2, 'fail', True, log_level='DEBUG')
    assert all(svc['environment']['AT_REDTEAM_LOG_LEVEL'] == 'DEBUG'
               for svc in doc['services'].values())
    attack = cc.ColludingCohortAttack(2, 'fail', True, log_level='DEBUG')
    compose_config = {}
    attack.setup({}, compose_config)
    assert compose_config['services']['joiner-1']['environment'][
        'AT_REDTEAM_LOG_LEVEL'] == 'DEBUG'


def test_a_node_sends_its_capabilities_to_every_process():
    # Its identity process answers peers' caps queries with what it is sent;
    # sent nothing, a node advertises no probes and no one can probe it.
    import queue
    from autonomous_trust.core import Configuration
    node = cc.RedTeamNode(multiproc=False, silent=True,
                          logfile=Configuration.log_stdout)
    q1, own = queue.Queue(), queue.Queue()
    node.autonomous_ability({'identity': q1, node.proc_name: own})
    assert 'at.handshake' in q1.get_nowait().to_list()
    assert own.empty()


def test_a_colluder_inflates_its_fellows_and_slanders_the_rest(monkeypatch):
    seen = []
    monkeypatch.setattr(cc.ReputationProcess, '_start_paxos',
                        lambda self, q, score, g=None: seen.append(score.score_milli))
    proc = object.__new__(cc.ColludingReputationProcess)
    peers = {'a': 'colluder-2', 'b': 'joiner-1'}
    proc.protocol = SimpleNamespace(peers=SimpleNamespace(
        find_by_uuid=lambda u: SimpleNamespace(nickname=peers[u])))
    for subject in ('a', 'b'):
        proc._start_paxos({}, SimpleNamespace(score_milli=500, subject_uuid=subject))
    assert seen == [cc.score_to_milli(cc.INFLATE), cc.score_to_milli(cc.SLANDER)]


def test_the_fail_adversary_answers_every_probe_wrongly(monkeypatch):
    from autonomous_trust.core._python import bootstrap_capabilities as bc
    monkeypatch.setattr(bc, 'BOOTSTRAP_FUNCTIONS', dict(bc.BOOTSTRAP_FUNCTIONS))
    cc.fail_probes()
    assert bc.verify_handshake(41, bc.BOOTSTRAP_FUNCTIONS['at.handshake'](nonce=41)) < 0.5
    assert bc.BOOTSTRAP_FUNCTIONS['at.echo-challenge'](payload='x') != 'x'


def test_the_wrong_probe_answers_survive_pickling(monkeypatch):
    # The node hands its processes to a multiprocessing pool, which pickles
    # them; a colluder whose probe answers cannot be pickled dies at start.
    import pickle
    from autonomous_trust.core._python import bootstrap_capabilities as bc
    monkeypatch.setattr(bc, 'BOOTSTRAP_FUNCTIONS', dict(bc.BOOTSTRAP_FUNCTIONS))
    cc.fail_probes()
    pickle.dumps(bc.BOOTSTRAP_FUNCTIONS)


def _dump(t, joiner_tier, joiner_own, colluder_tier, colluder_own):
    rec = {'t': t, 'self': 'j1', 'view': [
        {'s': '1', 'nick': 'joiner-2', 'tier': joiner_tier, 'n': 1,
         'own': joiner_own},
        {'s': '2', 'nick': 'colluder-1', 'tier': colluder_tier, 'n': 0,
         'own': colluder_own}]}
    return 'x AT_REPDUMP %s' % json.dumps(rec)


def test_collect_counts_only_earned_tiers():
    """Hostile-join run, 2026-11-04: t_colluders read 5 s, the first dump,
    where every peer starts below tier 1 with no evidence at all. A tier
    counts only once this joiner holds bilateral evidence of that peer."""
    log = '\n'.join([_dump(100.0, 1, 0, 1, 0),
                     _dump(130.0, 3, 0, 0, 0),     # unearned both ways
                     _dump(160.0, 4, 2, 1, 1),     # the joiner earned
                     _dump(190.0, 4, 3, 0, 2)])    # the colluder earned
    got = cc.collect(log, 'fail')
    assert got == {'t_honest': 60.0, 't_colluders': 90.0,
                   't_honest_first': 60.0, 't_colluders_first': 90.0,
                   'told_tier_unprobed': 1, 'dumps': 4}
    assert cc.collect(log, 'pass')['t_colluders'] is None


def test_a_time_counts_only_once_it_holds_to_the_end():
    """Hostile-join runs without the policy, 2026-11-04: each joiner held the
    other at tier 3 at 63 s, and the cohort's slander pulled it to tier 0 or 1
    by 180 s for the rest of the run. Read at the first crossing, that was a
    63 s pass. A time is now when the condition last became true and stayed
    so; the first crossing is kept beside it."""
    log = '\n'.join([_dump(100.0, 1, 2, 1, 2),
                     _dump(160.0, 3, 2, 0, 2),     # both reached
                     _dump(220.0, 1, 2, 1, 2),     # both lost
                     _dump(280.0, 3, 2, 0, 2),     # reached again
                     _dump(340.0, 4, 2, 0, 2)])    # and held to the end
    got = cc.collect(log, 'fail')
    assert (got['t_honest'], got['t_honest_first']) == (180.0, 60.0)
    assert (got['t_colluders'], got['t_colluders_first']) == (180.0, 60.0)
    lost = '\n'.join(log.splitlines()[:3])
    got = cc.collect(lost, 'fail')
    assert got['t_honest'] is None and got['t_colluders'] is None
    assert (got['t_honest_first'], got['t_colluders_first']) == (60.0, 60.0)


def test_a_dump_without_own_is_no_evidence():
    rec = {'t': 5.0, 'self': 'j1', 'view': [
        {'s': '1', 'nick': 'joiner-2', 'tier': 4, 'n': 9},
        {'s': '2', 'nick': 'colluder-1', 'tier': 0, 'n': 9}]}
    got = cc.collect('x AT_REPDUMP %s' % json.dumps(rec), 'fail')
    assert got['t_honest'] is None and got['t_colluders'] is None
    assert got['told_tier_unprobed'] == 0


def test_collect_matches_nicknames_that_carry_a_domain():
    # A live node's nickname is its full address, joiner-2@tekfive.com.
    rec = {'t': 5.0, 'self': 'j1', 'view': [
        {'s': '1', 'nick': 'joiner-2@tekfive.com', 'tier': 3, 'n': 1, 'own': 1},
        {'s': '2', 'nick': 'colluder-1@tekfive.com', 'tier': 0, 'n': 2,
         'own': 1}]}
    log = 'x AT_REPDUMP %s' % json.dumps(rec)
    got = cc.collect(log, 'fail')
    assert got['t_honest'] == 0.0 and got['t_colluders'] == 0.0


def test_a_missing_time_fails_the_attack():
    """A run that never earns the honest tier, or never sinks every colluder
    on evidence, is a FAIL, not a PASS with empty times."""
    attack = cc.ColludingCohortAttack(4, 'fail', True)
    never = _dump(5.0, 4, 0, 1, 0)
    out = attack.collect({'logs': {j: never for j in cc.JOINERS}})
    checks = out['attack_specific']['failed_checks']
    assert sorted(checks) == sorted(
        ['%s: %s' % (j, what) for j in cc.JOINERS
         for what in ('t_honest', 't_colluders')])
    assert RedTeamHarness._assess_result(None, {}, out) == 'FAIL'
    earned = '\n'.join([_dump(5.0, 4, 3, 0, 3)])
    out = attack.collect({'logs': {j: earned for j in cc.JOINERS}})
    assert out['attack_specific']['failed_checks'] == []
    assert RedTeamHarness._assess_result(None, {}, out) == 'PASS'


def test_without_the_fail_adversary_t_colluders_is_not_required():
    attack = cc.ColludingCohortAttack(4, 'pass', True)
    earned = _dump(5.0, 4, 3, 1, 3)
    out = attack.collect({'logs': {j: earned for j in cc.JOINERS}})
    assert out['attack_specific']['failed_checks'] == []


def test_a_joiner_that_never_dumped_is_no_data():
    attack = cc.ColludingCohortAttack(4, 'fail', False)
    log = "ModuleNotFoundError: No module named 'autonomous_trust.evaluation'"
    out = attack.collect({'logs': {j: log for j in cc.JOINERS}})
    assert out['error'] == 'no_metrics'
    assert out['attack_specific']['joiners']['joiner-1']['dumps'] == 0
    assert 'ModuleNotFoundError' in out['attack_specific']['log_tails']['joiner-2']


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


def test_every_node_grants_its_extensions_plaintext_verbs(tmp_path, monkeypatch):
    pytest.importorskip('autonomous_trust.first_contact')
    from autonomous_trust.core import Configuration
    from autonomous_trust.core._python.extensions import configure_plaintext_verbs
    monkeypatch.setenv('AUTONOMOUS_TRUST_ROOT', str(tmp_path))
    monkeypatch.setenv('AT_FIRST_CONTACT', '1')
    cfg = Configuration.get_cfg_dir()
    cc.prepare(cfg, 'colluder-1', 'colluder', 'pass', False)
    # What node startup checks: without the file it refuses to start.
    assert 'first_contact_hello' in configure_plaintext_verbs(cfg)
