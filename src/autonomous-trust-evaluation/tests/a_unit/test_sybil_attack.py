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
"""The Sybil attack, live: cheap identities that inflate each other and
slander everyone else, gated on influence rather than admission."""

import json
import os

from autonomous_trust.evaluation.redteam import sybil_attack as sy


def test_sybils_start_after_the_honest_cohort():
    doc = sy.compose(sybils=3, honest=2, sybil_delay=120)
    svcs = doc['services']
    assert sorted(svcs) == ['honest-1', 'honest-2', 'sybil-1', 'sybil-2',
                            'sybil-3']
    assert svcs['honest-1']['environment']['STARTUP_DELAY'] == '0'
    assert svcs['sybil-2']['environment']['STARTUP_DELAY'] == '120'
    assert svcs['sybil-2']['environment']['AT_REDTEAM_ROLE'] == 'sybil'
    assert 'AT_REP_DUMP_SEC' in svcs['honest-2']['environment']


def test_a_sybil_inflates_sybils_and_slanders_honest_nodes(monkeypatch):
    from types import SimpleNamespace
    from autonomous_trust.core._python.reputation.repprocess import (
        ReputationProcess)
    seen = []
    monkeypatch.setattr(ReputationProcess, '_start_paxos',
                        lambda self, q, score, group_uuid=None:
                        seen.append(score.score_milli))
    proc = object.__new__(sy.SybilReputationProcess)
    nicks = {'a': 'sybil-2@tekfive.com', 'b': 'honest-1@tekfive.com'}
    proc.protocol = SimpleNamespace(peers=SimpleNamespace(
        find_by_uuid=lambda u: SimpleNamespace(nickname=nicks[u])))
    for subject in ('a', 'b'):
        proc._start_paxos({}, SimpleNamespace(subject_uuid=subject,
                                              score_milli=500))
    assert seen == [950, 100]


def test_a_sybil_answers_probes_correctly(tmp_path, monkeypatch):
    from autonomous_trust.core import Configuration, CfgIds
    from autonomous_trust.core._python import bootstrap_capabilities as bc
    from autonomous_trust.core._python.processes import ProcessTracker
    before = dict(bc.BOOTSTRAP_FUNCTIONS)
    monkeypatch.setenv('AUTONOMOUS_TRUST_ROOT', str(tmp_path))
    cfg = Configuration.get_cfg_dir()
    sy.prepare(cfg, 'sybil-1')
    assert bc.BOOTSTRAP_FUNCTIONS == before
    doc = json.load(open(os.path.join(cfg, ProcessTracker.default_filename)))
    assert doc[CfgIds.reputation].endswith('SybilReputationProcess')


def _dump(t, honest_tier=3, honest_own=5, sybil_tier=0, sybil_own=0,
          honest=('honest-2',), sybils=('sybil-1',)):
    view = [{'nick': '%s@tekfive.com' % h, 'tier': honest_tier,
             'own': honest_own} for h in honest]
    view += [{'nick': '%s@tekfive.com' % s, 'tier': sybil_tier,
              'own': sybil_own} for s in sybils]
    return 'x AT_REPDUMP %s' % json.dumps({'t': t, 'view': view})


def _node(*dumps, rotations=()):
    lines = list(dumps)
    lines += ['INFO IdentityProcess: Rotated group key to epoch %d '
              '(%d member(s)), key ab…' % (i + 2, m)
              for i, m in enumerate(rotations)]
    return '\n'.join(lines)


def test_collect_node_reads_honest_time_sybil_tiers_and_admissions():
    text = _node(_dump(100, honest_tier=0, honest_own=0),
                 _dump(160, sybil_tier=1, sybil_own=0),
                 _dump(200, sybil_tier=3, sybil_own=4),
                 rotations=(1, 3, 2))
    r = sy.collect_node(text, 'honest-1', ['honest-1', 'honest-2'])
    assert r['t_honest'] == 60
    assert r['sybil_tier_unearned'] == 1
    assert r['sybil_tier_max'] == 3
    assert r['sybils_seen'] == 1
    assert r['admitted'] == 3


def _attack(honest=2, **kw):
    return sy.SybilAttack(sybils=1, honest=honest, **kw)


def _logs(h1, h2):
    return {'logs': {'honest-1': h1,
                     'honest-2': h1 if h2 is None else h2}}


def test_collect_fails_when_slander_breaks_an_honest_pair():
    good = _node(_dump(0), _dump(5))
    broken = _node(_dump(0), _dump(5, honest_tier=2))
    out = _attack().collect(_logs(good, broken.replace('honest-2', 'honest-1')))
    failed = out['attack_specific']['failed_checks']
    assert any(c.startswith('honest-2:') for c in failed)


def test_collect_fails_on_an_unearned_sybil_tier_above_the_ceiling():
    attack = _attack()
    assert attack.ceiling == 1
    told = _node(_dump(0), _dump(5, sybil_tier=2, sybil_own=0))
    out = attack.collect(_logs(told, told.replace('honest-2', 'honest-1')))
    failed = out['attack_specific']['failed_checks']
    assert any('unearned' in c for c in failed)
    earned = _node(_dump(0), _dump(5, sybil_tier=4, sybil_own=6))
    out = attack.collect(_logs(earned, earned.replace('honest-2', 'honest-1')))
    assert out['attack_specific']['failed_checks'] == []


def test_admitted_counts_members_sent_the_group_key():
    text = _node(_dump(0), rotations=(2,)) + (
        '\nINFO IdentityProcess: Sending group update with key 6dc7… epoch 5 '
        '(carries_key=1) to 9 member(s)')
    assert sy.collect_node(text, 'honest-1', ['honest-1', 'honest-2'])[
        'admitted'] == 9


def test_admitted_is_reported_not_gated():
    text = _node(_dump(0), _dump(5), rotations=(7,))
    out = _attack().collect(_logs(text, text.replace('honest-2', 'honest-1')))
    assert out['attack_specific']['admitted_max'] == 7
    assert out['attack_specific']['failed_checks'] == []
    assert 'identity_count_bounded' not in out['attack_specific']


def test_an_honest_node_that_never_dumped_is_no_data():
    text = _node(_dump(0), _dump(5))
    out = _attack().collect(_logs(text, 'Traceback: no module'))
    assert out['error'] == 'no_metrics'
    assert 'honest-2' in out['attack_specific']['log_tails']


def test_setup_hands_the_harness_a_standalone_deployment():
    sim, comp = {}, {}
    _attack(honest=3).setup(sim, comp)
    assert comp['standalone'] is True
    assert sim['collect_logs'] == ['honest-1', 'honest-2', 'honest-3']


def test_no_sybil_in_any_honest_view_is_no_data():
    # Sybils that never ran leave every honest pair at tier 3: not a PASS.
    text = _node(_dump(0, sybils=()), _dump(5, sybils=()))
    out = _attack().collect(_logs(text, text.replace('honest-2', 'honest-1')))
    assert out['error'] == 'no_metrics'
