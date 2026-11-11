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
"""Reputation gaming, live: a node earns trust with right answers, then
defects."""

import json
import pickle

import pytest

from autonomous_trust.evaluation.redteam import reputation_gaming as rg


@pytest.fixture
def probes(monkeypatch):
    from autonomous_trust.core._python import bootstrap_capabilities as bc
    for name, fn in list(bc.BOOTSTRAP_FUNCTIONS.items()):
        monkeypatch.setitem(bc.BOOTSTRAP_FUNCTIONS, name, fn)
    return bc


def test_the_switch_answers_right_then_wrong(probes, monkeypatch):
    bc = probes
    clock = [1000.0]
    monkeypatch.setattr(rg.time, 'time', lambda: clock[0])
    monkeypatch.setenv('AT_REDTEAM_DEFECT_AT', '1500')
    rg.install_switch()
    hs = bc.BOOTSTRAP_FUNCTIONS['at.handshake']
    echo = bc.BOOTSTRAP_FUNCTIONS['at.echo-challenge']
    tm = bc.BOOTSTRAP_FUNCTIONS['at.time-attest']
    right_hs = bc.verify_handshake(bc.at_handshake(7), 7)
    right_echo = bc.verify_echo(bc.at_echo_challenge('abc'), 'abc')
    assert bc.verify_handshake(hs(nonce=7), 7) == right_hs
    assert bc.verify_echo(echo(payload='abc'), 'abc') == right_echo
    assert tm() == 1000.0
    clock[0] = 1500.0
    assert bc.verify_handshake(hs(nonce=7), 7) < right_hs
    assert bc.verify_echo(echo(payload='abc'), 'abc') < right_echo
    assert tm() == 0.0


def test_the_switched_answers_survive_pickling(probes):
    bc = probes
    rg.install_switch()
    for name in ('at.handshake', 'at.time-attest', 'at.echo-challenge'):
        fn = bc.BOOTSTRAP_FUNCTIONS[name]
        assert pickle.loads(pickle.dumps(fn)) is fn


def test_defect_after_sets_the_switch_time(probes, monkeypatch):
    monkeypatch.delenv('AT_REDTEAM_DEFECT_AT', raising=False)
    monkeypatch.setattr(rg.time, 'time', lambda: 2000.0)
    assert rg.defect_after(480) == 2480.0
    import os
    assert float(os.environ['AT_REDTEAM_DEFECT_AT']) == 2480.0


def _dump(t, gamer_tier, gamer_own, honest_tier=3,
          honest=('honest-2', 'honest-3')):
    view = [{'nick': nm, 'tier': honest_tier, 'own': 5} for nm in honest]
    view.append({'nick': 'gamer-1@tekfive.com', 'tier': gamer_tier,
                 'own': gamer_own})
    return 'x AT_REPDUMP %s' % json.dumps({'t': t, 'view': view})


def _log(points):
    return '\n'.join(_dump(*p) for p in points)


def test_collect_reads_rise_peak_and_fall():
    text = _log([(1000, 0, 0), (1060, 3, 4), (1100, 4, 6),
                 (1500, 4, 8), (1520, 2, 9), (1560, 0, 10), (1600, 0, 11)])
    r = rg.collect_node(text, defect_at=1500)
    assert r['t_rise'] == 60
    assert r['peak_tier_before'] == 4
    assert r['t_fall'] == 60
    assert r['final_tier'] == 0
    assert r['dumps'] == 7


def test_a_gamer_that_keeps_its_tier_fails():
    good = _log([(1000, 0, 0), (1060, 3, 4), (1500, 3, 6), (1600, 0, 9)])
    kept = _log([(1000, 0, 0), (1060, 3, 4), (1500, 3, 6), (1600, 2, 9)])
    attack = rg.ReputationGamingAttack(gamers=1, honest=3)
    gamer_log = 'AT_REDTEAM_DEFECT_AT 1500.0'
    out = attack.collect({'logs': {
        'honest-1': good,
        'honest-2': good.replace('honest-2', 'honest-1'),
        'honest-3': kept.replace('honest-3', 'honest-1'),
        'gamer-1': gamer_log}})
    failed = out['attack_specific']['failed_checks']
    assert failed == ['honest-3: gamer-1 kept trust after defecting']


def test_an_honest_pair_below_tier_3_fails():
    low = _log([(1000, 0, 0), (1500, 3, 6), (1600, 0, 9)], )
    attack = rg.ReputationGamingAttack(gamers=1, honest=2)
    out = attack.collect({'logs': {
        'honest-1': low.replace('"honest-3"', '"x"'),
        'honest-2': _log([(1000, 0, 0), (1500, 3, 6), (1600, 0, 9, 2)],
                         ).replace('honest-2', 'honest-1'),
        'gamer-1': 'AT_REDTEAM_DEFECT_AT 1500.0'}})
    assert any('tier 2' in c for c in out['attack_specific']['failed_checks'])


def test_no_defection_time_is_no_data():
    attack = rg.ReputationGamingAttack(gamers=1, honest=2)
    log = _log([(1000, 0, 0), (1600, 0, 9)])
    out = attack.collect({'logs': {'honest-1': log, 'honest-2': log,
                                   'gamer-1': 'Traceback ...'}})
    assert out['error'] == 'no_metrics'


def test_tenure_reaches_only_honest_nodes():
    doc = rg.compose(gamers=1, honest=2, tenure_s=300)
    svcs = doc['services']
    assert svcs['honest-1']['environment']['AT_REP_MIN_TENURE_SEC'] == '300'
    assert 'AT_REP_MIN_TENURE_SEC' not in svcs['gamer-1']['environment']
    assert svcs['gamer-1']['environment']['AT_REDTEAM_DEFECT_S'] == '480'
    doc = rg.compose(gamers=1, honest=2, tenure_s=0)
    assert 'AT_REP_MIN_TENURE_SEC' not in doc['services']['honest-1']['environment']


def test_setup_collects_the_gamers_logs_too():
    attack = rg.ReputationGamingAttack(gamers=1, honest=2)
    sim, comp = {}, {}
    attack.setup(sim, comp)
    assert comp['standalone'] is True
    assert sim['collect_logs'] == ['honest-1', 'honest-2', 'gamer-1']


def test_a_gamer_that_never_rose_is_no_data():
    never = _log([(1000, 0, 0), (1060, 1, 4), (1500, 1, 6), (1600, 0, 9)])
    attack = rg.ReputationGamingAttack(gamers=1, honest=2)
    out = attack.collect({'logs': {
        'honest-1': never, 'honest-2': never.replace('honest-2', 'honest-1'),
        'gamer-1': 'AT_REDTEAM_DEFECT_AT 1500.0'}})
    assert out['error'] == 'no_metrics'


def test_a_gamer_no_honest_node_saw_is_no_data():
    unseen = _log([(1000, 0, 0), (1600, 0, 9)]).replace('gamer-1', 'nobody')
    attack = rg.ReputationGamingAttack(gamers=1, honest=2)
    out = attack.collect({'logs': {
        'honest-1': unseen, 'honest-2': unseen.replace('honest-2', 'honest-1'),
        'gamer-1': 'AT_REDTEAM_DEFECT_AT 1500.0'}})
    assert out['error'] == 'no_metrics'
