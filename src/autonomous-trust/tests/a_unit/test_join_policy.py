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
"""The join-policy declaration and the anchor hook
(RD_14.4_HOSTILE_JOIN_PLAN.md Phase 2).

Opt-in (D9): absent is inert, malformed refuses the start. The declaration
chooses which anchor classes count (D6), and the core intersects what the
extensions report with that list. The C twin is join_policy_test.c, and both
read config/cfg/join_policy.example.json.
"""
import json
import os
from types import SimpleNamespace

import pytest

from autonomous_trust.core._python.extensions import IdentityHooks
from autonomous_trust.core._python.identity import idprocess
from autonomous_trust.core._python.identity.idprocess import IdentityProcess
from autonomous_trust.core._python.identity.join_policy import (
    INERT, JOIN_POLICY_ENV, JoinPolicy, JoinPolicyError, check_join_policy,
    load_join_policy, load_join_policy_env, parse_join_policy)

_HERE = os.path.dirname(os.path.abspath(__file__))
EXAMPLE = os.path.join(_HERE, '..', '..', '..', '..', 'config', 'cfg',
                       'join_policy.example.json')


def _write(tmp_path, doc):
    path = tmp_path / 'join_policy.json'
    path.write_text(doc if isinstance(doc, str) else json.dumps(doc))
    return str(path)


def test_absent_is_inert(monkeypatch):
    monkeypatch.delenv(JOIN_POLICY_ENV, raising=False)
    assert load_join_policy_env() is INERT
    assert not INERT.enabled and not INERT.anchors


def test_the_example_lists_the_recommended_three():
    policy = load_join_policy(EXAMPLE)
    assert policy.enabled
    assert policy.anchors == {'verified_contact', 'zta', 'operator'}
    assert (policy.told_tier, policy.own_evidence_min) == (1, 3)


def test_the_phase_four_bounds():
    """Tier 1 and three own entries unless declared (RD_14.4 Phase 4)."""
    assert (INERT.told_tier, INERT.own_evidence_min) == (1, 3)
    policy = parse_join_policy({'version': 1, 'told_tier': 0,
                                'own_evidence_min': 7})
    assert (policy.told_tier, policy.own_evidence_min) == (0, 7)


def test_the_phase_five_burst():
    """burst_k follows own_evidence_min unless declared; 5 s and 4 by
    default (RD_14.4 Phase 5)."""
    assert (INERT.burst_k, INERT.burst_interval_sec,
            INERT.burst_budget_factor) == (3, 5.0, 4)
    assert parse_join_policy({'version': 1,
                              'own_evidence_min': 7}).burst_k == 7
    policy = parse_join_policy({'version': 1, 'own_evidence_min': 7,
                                'burst_k': 2, 'burst_interval_sec': 0.5,
                                'burst_budget_factor': 1})
    assert (policy.burst_k, policy.burst_interval_sec,
            policy.burst_budget_factor) == (2, 0.5, 1)
    assert load_join_policy(EXAMPLE).burst_k == 3


def test_the_phase_six_cohort_min():
    assert INERT.anchored_cohort_min == 1
    assert parse_join_policy({'version': 1,
                              'anchored_cohort_min': 2}).anchored_cohort_min == 2
    assert load_join_policy(EXAMPLE).anchored_cohort_min == 1


@pytest.mark.parametrize('doc, why', [
    ([], 'not an object'),
    ({'enabled': True}, 'version'),
    ({'version': 2}, 'version'),
    ({'version': True}, 'version'),
    ({'version': 1.0}, 'version'),
    ({'version': 1, 'enabled': 'yes'}, 'boolean'),
    ({'version': 1, 'anchors': 'zta'}, 'not a list'),
    ({'version': 1, 'anchors': ['friend']}, 'unknown class'),
    ({'version': 1, 'anchors': ['zta', 'zta']}, 'twice'),
    ({'version': 1, 'anchor': ['zta']}, 'unknown key'),
    ({'version': 1, 'told_tier': 5}, 'told_tier'),
    ({'version': 1, 'told_tier': -1}, 'told_tier'),
    ({'version': 1, 'told_tier': 1.5}, 'told_tier'),
    ({'version': 1, 'told_tier': True}, 'told_tier'),
    ({'version': 1, 'own_evidence_min': 0}, 'own_evidence_min'),
    ({'version': 1, 'own_evidence_min': '3'}, 'own_evidence_min'),
    ({'version': 1, 'burst_k': 0}, 'burst_k'),
    ({'version': 1, 'burst_k': 2.0}, 'burst_k'),
    ({'version': 1, 'burst_interval_sec': 0}, 'burst_interval_sec'),
    ({'version': 1, 'burst_interval_sec': -1.0}, 'burst_interval_sec'),
    ({'version': 1, 'burst_interval_sec': '5'}, 'burst_interval_sec'),
    ({'version': 1, 'burst_interval_sec': True}, 'burst_interval_sec'),
    ({'version': 1, 'burst_budget_factor': 0}, 'burst_budget_factor'),
    ({'version': 1, 'anchored_cohort_min': 0}, 'anchored_cohort_min'),
    ({'version': 1, 'anchored_cohort_min': True}, 'anchored_cohort_min'),
])
def test_malformed_is_refused(doc, why):
    with pytest.raises(JoinPolicyError, match=why):
        parse_join_policy(doc)


def test_note_is_allowed():
    policy = parse_join_policy({'version': 1, 'note': 'why', 'enabled': False})
    assert policy == JoinPolicy()


def test_a_malformed_file_refuses_the_start(tmp_path, monkeypatch):
    monkeypatch.setenv(JOIN_POLICY_ENV, _write(tmp_path, '{"version": 1,'))
    with pytest.raises(RuntimeError, match='not JSON'):
        check_join_policy(['zta', 'first_contact'])


def test_a_missing_file_refuses_the_start(tmp_path, monkeypatch):
    monkeypatch.setenv(JOIN_POLICY_ENV, str(tmp_path / 'absent.json'))
    with pytest.raises(RuntimeError, match=JOIN_POLICY_ENV):
        check_join_policy(['zta', 'first_contact'])


def test_a_class_no_extension_answers_refuses_the_start(tmp_path, monkeypatch):
    monkeypatch.setenv(JOIN_POLICY_ENV, _write(
        tmp_path, {'version': 1, 'enabled': True, 'anchors': ['verified_contact', 'zta']}))
    with pytest.raises(RuntimeError, match='verified_contact.*first_contact'):
        check_join_policy(['zta'])
    assert check_join_policy(['zta', 'first_contact']).enabled


def test_operator_is_answered_by_either_extension(tmp_path, monkeypatch):
    monkeypatch.setenv(JOIN_POLICY_ENV, _write(
        tmp_path, {'version': 1, 'enabled': True, 'anchors': ['operator']}))
    assert check_join_policy(['first_contact']).anchors == {'operator'}
    assert check_join_policy(['zta']).anchors == {'operator'}


def test_a_disabled_policy_needs_no_extension(tmp_path, monkeypatch):
    monkeypatch.setenv(JOIN_POLICY_ENV, _write(
        tmp_path, {'version': 1, 'enabled': False, 'anchors': ['zta']}))
    assert not check_join_policy([]).enabled


def _proc(policy, answers):
    proc = SimpleNamespace(join_policy=policy, _extensions=())
    hooks = tuple(IdentityHooks(anchor_classes=lambda _p, _i, a=a: a) for a in answers)
    return proc, hooks


@pytest.mark.parametrize('policy, answers, expected', [
    (INERT, [{'zta'}], set()),
    (JoinPolicy(enabled=False, anchors=frozenset({'zta'})), [{'zta'}], set()),
    (JoinPolicy(enabled=True, anchors=frozenset({'zta'})), [{'zta', 'operator'}], {'zta'}),
    (JoinPolicy(enabled=True, anchors=frozenset({'verified_contact', 'zta'})),
     [{'unverified_contact'}, {'zta'}], {'zta'}),
    (JoinPolicy(enabled=True, anchors=frozenset({'unverified_contact'})),
     [{'unverified_contact'}], {'unverified_contact'}),
    (JoinPolicy(enabled=True, anchors=frozenset({'zta'})), [None], set()),
])
def test_the_core_counts_only_declared_classes(monkeypatch, policy, answers, expected):
    proc, hooks = _proc(policy, answers)
    monkeypatch.setattr(idprocess, 'identity_hooks', lambda _p: hooks)
    peer = SimpleNamespace(uuid='u')
    assert IdentityProcess.anchor_classes(proc, peer) == expected
    proc.anchor_classes = lambda ident: IdentityProcess.anchor_classes(proc, ident)
    assert IdentityProcess.is_anchored(proc, peer) is bool(expected)
