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
"""The oracle registry (core/_python/oracles.py, FEATURE_SPLIT_PLAN Phase 3),
the Python twin of test/neg_oracle_test.c.

Pins: arms run in ascending order and the first verdict ends scoring, observe
arms only record, an empty registry scores as the probe + completion arms
alone, the providers fall back to neutral, the refusals, the start-time check
and the reset. The layers' own registrations are pinned where they live, in
autonomous-trust-oracle's tests/a_unit/test_oracle_registration.py.
"""
import logging
import types

import pytest

from autonomous_trust.core import automate, oracles
from autonomous_trust.core.negotiation import TaskResult
from autonomous_trust.core.reputation import TX_CHANNEL_TASK_OUTCOME


@pytest.fixture
def empty(monkeypatch):
    """A registry with nothing in it, restored afterwards."""
    monkeypatch.setattr(oracles, '_oracles', {})
    monkeypatch.setattr(oracles, '_arms', [])
    monkeypatch.setattr(oracles, '_quantity_fn', None)
    monkeypatch.setattr(oracles, '_competence_fn', None)
    for env, _ in oracles.DECLARATIONS:
        monkeypatch.delenv(env, raising=False)


@pytest.fixture(autouse=True)
def _zkp_absent(monkeypatch):
    # The fall-through asserted below is the completion arm, which is the
    # scorer's last arm only with the ZKP extension absent.
    monkeypatch.setattr(
        'autonomous_trust.core._python.automate.ZKP_AVAILABLE', False)


def _inp(cap='c'):
    task = types.SimpleNamespace(result=1, uuid='t')
    return oracles.ScoreInput(task=task, cap=cap, subject='peer', now=0.0)


def _result(cap='decide', value='x'):
    tr = TaskResult(None, value, requestor=None,
                    requested_capability_name=cap, requested_kwargs={})
    tr.executor_uuid = 'peer'
    return tr


class TestArms:
    def test_empty_registry_is_neutral(self, empty):
        assert oracles.score(_inp()) is None
        assert oracles.reported_quantity('c') is None
        assert oracles.competence('c', 'peer') == oracles.NEUTRAL_COMPETENCE
        assert automate.score_task_result(_result()) == (
            0.8, TX_CHANNEL_TASK_OUTCOME)

    def test_arms_run_in_order_and_first_verdict_ends(self, empty):
        ran = []

        def arm(tag, verdict=None):
            def fn(inp):
                ran.append(tag)
                return verdict
            return fn

        # Registered out of order; ties keep registration order.
        assert oracles.register_arm(oracles.Arm('late', 300,
                                                score=arm('late', (0.1, 'x'))))
        assert oracles.register_arm(oracles.Arm('silent', 100,
                                                score=arm('silent')))
        assert oracles.register_arm(oracles.Arm('obs', 200,
                                                observe=arm('obs')))
        assert oracles.register_arm(oracles.Arm('decides', 200,
                                                score=arm('decides',
                                                          (0.9, 'probe'))))
        assert [a.name for a in oracles.arms()] == [
            'silent', 'obs', 'decides', 'late']
        assert oracles.score(_inp()) == (0.9, 'probe')
        assert ran == ['silent', 'obs', 'decides']   # 'late' never ran

    def test_an_observe_arm_cannot_decide(self, empty):
        oracles.register_arm(oracles.Arm('obs', 1, observe=lambda inp: (0.1, 'x')))
        assert oracles.score(_inp()) is None

    def test_the_scorer_reads_the_registry(self, empty):
        oracles.register_arm(oracles.Arm(
            'refutes', 100, score=lambda inp: (0.1, 'physical')
            if inp.cap == 'decide' and inp.subject == 'peer' else None))
        assert automate.score_task_result(_result()) == (0.1, 'physical')
        assert automate.score_task_result(_result('other')) == (
            0.8, TX_CHANNEL_TASK_OUTCOME)

    def test_refusals(self, empty, caplog):
        with caplog.at_level(logging.ERROR, logger=oracles.__name__):
            assert not oracles.register_arm(oracles.Arm('', 1, score=len))
            assert not oracles.register_arm(oracles.Arm('none', 1))
            assert not oracles.register_arm(
                oracles.Arm('both', 1, score=len, observe=len))
            assert oracles.register_arm(oracles.Arm('a', 1, score=len))
            assert not oracles.register_arm(oracles.Arm('a', 2, score=len))
            assert not oracles.declare('')
            assert oracles.declare('physics')
            assert not oracles.declare('physics')
        assert len(caplog.records) == 6
        assert [a.name for a in oracles.arms()] == ['a']


class TestProviders:
    def test_one_provider_each(self, empty):
        assert oracles.provide_quantity(lambda cap: 'q.' + cap)
        assert not oracles.provide_quantity(lambda cap: None)
        assert not oracles.provide_quantity(None)
        assert oracles.reported_quantity('c') == 'q.c'
        assert oracles.reported_quantity('') is None
        assert oracles.reported_quantity(None) is None

        assert oracles.provide_competence(lambda cap, subject: 1.25)
        assert not oracles.provide_competence(lambda cap, subject: 2.0)
        assert oracles.competence('thermo', 'peer') == 1.25
        assert automate.competence_weight('thermo', 'peer') == 1.25

    def test_reported_quantities_shape(self, empty):
        # The calibration and prequential layers read the lookup through the
        # physics-model shape they take.
        rq = oracles.ReportedQuantities()
        assert rq.for_capability('c') is None
        oracles.provide_quantity({'c': 'temp'}.get)
        assert rq.for_capability('c').name == 'temp'
        assert rq.for_capability('d') is None


class TestCheckEnv:
    def test_a_declared_layer_missing_is_refused(self, empty, monkeypatch):
        oracles.check_env()                       # nothing declared: fine
        monkeypatch.setenv('AT_PHYSICS', '/nonexistent/physics.json')
        with pytest.raises(oracles.OracleMissingError, match='physics'):
            oracles.check_env()

    def test_refusal_names_every_missing_layer(self, empty, monkeypatch,
                                               caplog):
        monkeypatch.setenv('AT_CALIBRATION', '/nonexistent/calibration.json')
        monkeypatch.setenv('AT_CERTIFICATES', '/nonexistent/certs.json')
        with caplog.at_level(logging.ERROR, logger=oracles.__name__):
            with pytest.raises(oracles.OracleMissingError,
                               match='calibration, certificates'):
                oracles.check_env()
        assert len(caplog.records) == 2
        assert '$AT_CALIBRATION is set' in caplog.records[0].getMessage()

    def test_empty_is_undeclared(self, empty, monkeypatch):
        monkeypatch.setenv('AT_PHYSICS', '')
        oracles.check_env()

    def test_a_present_layer_passes(self, empty, monkeypatch):
        monkeypatch.setenv('AT_PHYSICS', '/nonexistent/physics.json')
        oracles.declare('physics')
        oracles.check_env()

    def test_reset_reaches_every_declared_layer(self, empty):
        resets = []
        oracles.declare('physics', lambda: resets.append('physics'))
        oracles.declare('replication')          # no reset: skipped
        oracles.declare('calibration', lambda: resets.append('calibration'))
        oracles.reset()
        assert resets == ['physics', 'calibration']


class TestNodeStart:
    def test_a_node_declaring_a_missing_layer_refuses_to_start(
            self, setup_teardown, monkeypatch):
        from autonomous_trust.core.automate import AutonomousTrust
        from autonomous_trust.core.config import Configuration
        # A node without the physics layer, told to check physics. Filtered
        # rather than assumed absent: the oracle distribution may be on the
        # path too.
        monkeypatch.setattr(oracles, '_oracles', {
            k: v for k, v in oracles._oracles.items() if k != 'physics'})
        monkeypatch.setenv('AT_PHYSICS', '/nonexistent/physics.json')
        with pytest.raises(oracles.OracleMissingError, match='physics'):
            AutonomousTrust(multiproc=False, silent=True,
                            logfile=Configuration.log_stdout)
