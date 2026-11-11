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
"""The Byzantine equivocator, live: one node tells each member a different
score for the same half."""

import hashlib
import json
import queue
from unittest.mock import MagicMock
from uuid import UUID, uuid4

from autonomous_trust.evaluation.redteam import byzantine_node as bz


def _identity(tag):
    from autonomous_trust.core._python.identity.identity import Identity
    from autonomous_trust.core._python.identity.sign import Signature
    from autonomous_trust.core._python.identity.encrypt import Encryptor
    seed = hashlib.sha256(tag.encode()).hexdigest().encode('ascii')
    enc = hashlib.sha256(('enc-' + tag).encode()).hexdigest().encode('ascii')
    return Identity(UUID(bytes=hashlib.md5(tag.encode()).digest()),
                    '10.0.0.%d' % (len(tag) % 200 + 1), '%s.test' % tag,
                    Signature(seed, public_only=False),
                    Encryptor(enc, public_only=False), _public_only=False)


def _equivocator(members):
    from autonomous_trust.core import CfgIds
    from autonomous_trust.core._python.processes import ProcessTracker
    procs = []
    for nm in (CfgIds.network, CfgIds.identity, CfgIds.negotiation,
               CfgIds.reputation):
        p = MagicMock()
        p.name = nm
        procs.append(p)
    configs = {'processes': procs, CfgIds.identity: _identity('byz'),
               CfgIds.peers: MagicMock(), CfgIds.group: MagicMock()}
    rp = bz.EquivocatingReputationProcess(configs, ProcessTracker(),
                                          queue.Queue(), suppress_log=True)
    rp.protocol.group.uuid = uuid4()
    rp.protocol.group.addresses = [m.address for m in members]
    rp.protocol.peers.all = list(members)
    return rp


def test_the_equivocator_sends_one_transaction_per_recipient_with_alternating_scores():
    from autonomous_trust.core import CfgIds
    from autonomous_trust.core._python.reputation.reputation import (
        TransactionScore)
    from autonomous_trust.core._python.reputation.protocol import (
        ReputationProtocol)
    members = [_identity('m-%d' % i) for i in range(3)]
    rp = _equivocator(members)
    net = queue.Queue()
    score = TransactionScore(uuid4(), score_milli=600)
    rp._propose_half({CfgIds.network: net}, (1, 2, rp.identity.uuid), score,
                     str(rp.protocol.group.uuid))
    sent = [net.get_nowait() for _ in range(net.qsize())]
    assert len(sent) == 3
    assert all(m.function == ReputationProtocol.transaction for m in sent)
    order = sorted(members, key=lambda p: str(p.uuid))
    assert [str(m.to_whom[0].uuid) for m in sent] == [str(p.uuid) for p in order]
    scores = [json.loads(m.obj)['score_milli'] for m in sent]
    assert scores == [900, 300, 900]
    # Everything but the score is the honest half.
    bodies = [json.loads(m.obj) for m in sent]
    assert all(b['certify'] is True and b['id1'] == 1 for b in bodies)


def test_the_skew_is_clamped_to_the_score_range():
    assert bz.skewed(900, 0) == 1000
    assert bz.skewed(100, 1) == 0
    assert bz.skewed(500, 2) == 800


def _dump(t, chain_len, head, tiers):
    return 'x AT_REPDUMP %s' % json.dumps({
        't': t, 'chain': {'len': chain_len, 'head': head},
        'view': [{'nick': '%s@tekfive.com' % nick, 'tier': tier, 'own': own,
                  'n': n} for nick, tier, own, n in tiers]})


def _honest_log(chain_len, head, byz_n=0, tier=3, equivocations=0,
                names=('honest-1', 'honest-2', 'honest-3')):
    lines = [_dump(0, 1, 'aa', [(nm, 0, 0, 0) for nm in names]),
             _dump(5, chain_len, head,
                   [(nm, tier, 5, 5) for nm in names] +
                   [('byzantine-1', 1, 3, byz_n)])]
    lines += ['ERROR equivocation recorded on chain abc at index 7'] * equivocations
    return '\n'.join(lines)


def test_collect_node_reads_chain_commits_and_equivocations():
    r = bz.collect_node(_honest_log(40, 'beef', byz_n=2, equivocations=3))
    assert r['chain'] == {'len': 40, 'head': 'beef'}
    assert r['byz_commits'] == 2
    assert r['equivocations_logged'] == 3
    assert r['dumps'] == 2


def _attack_metrics(logs):
    attack = bz.ByzantineNodeAttack(byzantines=1, honest=3)
    return attack, {'logs': logs}


def _three(heads, lens=(40, 40, 40), tier=3):
    names = ('honest-1', 'honest-2', 'honest-3')
    return {nm: _honest_log(ln, hd, tier=tier,
                            names=[o for o in names if o != nm])
            for nm, hd, ln in zip(names, heads, lens)}


def test_collect_fails_on_honest_chains_that_fork():
    attack, metrics = _attack_metrics(_three(('aa', 'bb', 'aa')))
    out = attack.collect(metrics)
    assert any('fork' in c for c in out['attack_specific']['failed_checks'])


def test_collect_tolerates_chains_two_entries_apart():
    attack, metrics = _attack_metrics(_three(('aa', 'bb', 'cc'),
                                             lens=(40, 41, 42)))
    out = attack.collect(metrics)
    assert out['attack_specific']['failed_checks'] == []
    attack, metrics = _attack_metrics(_three(('aa', 'bb', 'cc'),
                                             lens=(40, 41, 43)))
    out = attack.collect(metrics)
    assert out['attack_specific']['failed_checks']


def test_collect_fails_when_an_honest_pair_ends_below_tier_3():
    attack, metrics = _attack_metrics(_three(('aa', 'aa', 'aa'), tier=2))
    out = attack.collect(metrics)
    assert any('tier' in c for c in out['attack_specific']['failed_checks'])


def test_equivocations_are_counted_not_gated():
    logs = _three(('aa', 'aa', 'aa'))
    logs['honest-1'] += '\nERROR equivocation recorded on chain x at index 3'
    attack, metrics = _attack_metrics(logs)
    out = attack.collect(metrics)
    assert out['attack_specific']['failed_checks'] == []
    assert out['attack_specific']['equivocations_logged'] == 1
    assert 'error' not in out


def test_an_honest_node_that_never_dumped_is_no_data():
    logs = _three(('aa', 'aa', 'aa'))
    logs['honest-2'] = 'ModuleNotFoundError: no module named x'
    attack, metrics = _attack_metrics(logs)
    out = attack.collect(metrics)
    assert out['error'] == 'no_metrics'
    assert 'honest-2' in out['attack_specific']['log_tails']


def test_the_byzantine_node_swaps_its_reputation_process(tmp_path, monkeypatch):
    import os
    from autonomous_trust.core import Configuration, CfgIds
    from autonomous_trust.core._python.processes import ProcessTracker
    monkeypatch.setenv('AUTONOMOUS_TRUST_ROOT', str(tmp_path))
    cfg = Configuration.get_cfg_dir()
    bz.prepare(cfg, 'byzantine-1', 'byzantine')
    doc = json.load(open(os.path.join(cfg, ProcessTracker.default_filename)))
    assert doc[CfgIds.reputation].endswith('EquivocatingReputationProcess')


def test_the_deployment_starts_honest_nodes_and_the_equivocators():
    doc = bz.compose(byzantines=2, honest=3)
    svcs = doc['services']
    assert sorted(svcs) == ['byzantine-1', 'byzantine-2', 'honest-1',
                            'honest-2', 'honest-3']
    assert svcs['byzantine-1']['environment']['AT_REDTEAM_ROLE'] == 'byzantine'
    assert all('AT_REP_DUMP_SEC' in svcs[n]['environment']
               for n in svcs if n.startswith('honest-'))
    attack = bz.ByzantineNodeAttack(byzantines=1, honest=3)
    sim, comp = {}, {}
    attack.setup(sim, comp)
    assert comp['standalone'] is True
    assert sim['collect_logs'] == ['honest-1', 'honest-2', 'honest-3']


def test_an_equivocator_no_honest_node_saw_is_no_data():
    logs = {n: t.replace('byzantine-1', 'someone-else')
            for n, t in _three(('aa', 'aa', 'aa')).items()}
    attack, metrics = _attack_metrics(logs)
    out = attack.collect(metrics)
    assert out['error'] == 'no_metrics'


def test_dumps_without_chain_are_no_data():
    logs = {n: '\n'.join(l.replace('"chain"', '"nochain"') for l in t.splitlines())
            for n, t in _three(('aa', 'aa', 'aa')).items()}
    attack, metrics = _attack_metrics(logs)
    out = attack.collect(metrics)
    assert out['error'] == 'no_metrics'


def test_a_fork_seen_at_any_common_length_fails():
    # Final lengths differ by one, so the last dumps never share a length;
    # earlier dumps at length 30 disagree on the head.
    logs = _three(('aa', 'aa', 'aa'), lens=(40, 41, 40))
    logs['honest-2'] = _dump(-1, 30, 'f0', []) + '\n' + logs['honest-2']
    logs['honest-3'] = _dump(-1, 30, 'f1', []) + '\n' + logs['honest-3']
    attack, metrics = _attack_metrics(logs)
    out = attack.collect(metrics)
    assert any('fork at length 30' in c
               for c in out['attack_specific']['failed_checks'])
