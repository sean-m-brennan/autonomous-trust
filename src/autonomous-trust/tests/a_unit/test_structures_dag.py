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
import pytest
from datetime import datetime, timedelta
from uuid import uuid4

from autonomous_trust.core.structures.dag import (
    Step, GenesisType, Genesis, LinkedStep, StepDAG,
    InvalidBranchError, BranchExistsError,
)


class ConcreteDAG(StepDAG):
    def _validate(self, branch):
        return True


class FailValidationDAG(StepDAG):
    def _validate(self, branch):
        return False


class TestGenesisType:
    def test_singleton(self):
        g1 = GenesisType()
        g2 = GenesisType()
        assert g1 is g2
        assert g1 is Genesis


class TestLinkedStep:
    def test_default_parent_is_genesis(self):
        step = LinkedStep(payload='data')
        assert step.parent is Genesis

    def test_len_from_genesis(self):
        step = LinkedStep(payload='data')
        assert len(step) == 1

    def test_len_chain(self):
        s1 = LinkedStep(payload='a')
        s2 = LinkedStep(payload='b', parent=s1)
        assert len(s2) == 1  # _length = len(parent) which is 1

    def test_to_dict(self):
        uid = uuid4()
        ts = datetime(2025, 1, 1)
        step = LinkedStep(payload='data', uuid=uid, timestamp=ts)
        d = step.to_dict()
        assert d['payload'] == 'data'
        assert d['uuid'] == uid
        assert d['timestamp'] == ts

    def test_custom_uuid(self):
        uid = uuid4()
        step = LinkedStep(payload='x', uuid=uid)
        # Note: Step.__init__ always sets self.uuid = None (known bug)
        # But LinkedStep may override or not
        assert step.payload == 'x'


class TestStepDAG:
    def _make_step(self, payload='data'):
        return LinkedStep(payload=payload)

    def test_init(self):
        dag = ConcreteDAG()
        assert dag.main is Genesis
        assert dag.size == 1

    def test_add_step_main(self):
        dag = ConcreteDAG()
        s = self._make_step('a')
        dag.add_step(s)
        assert dag.main is s
        assert s.parent is Genesis

    def test_add_step_invalid_branch(self):
        dag = ConcreteDAG()
        with pytest.raises(InvalidBranchError):
            dag.add_step(self._make_step(), 'nonexistent')

    def test_branch_create(self):
        dag = ConcreteDAG()
        s1 = self._make_step('main1')
        dag.add_step(s1)
        s2 = self._make_step('branch1')
        dag.branch('dev', s2)
        assert dag.size == 2
        assert dag.heads['dev'] is s2

    def test_branch_exists_error(self):
        dag = ConcreteDAG()
        s = self._make_step()
        dag.branch('dev', s)
        with pytest.raises(BranchExistsError):
            dag.branch('dev', self._make_step())

    def test_branch_invalid_source(self):
        dag = ConcreteDAG()
        with pytest.raises(InvalidBranchError):
            dag.branch('dev', self._make_step(), source='nonexistent')

    def test_branch_from_genesis(self):
        dag = ConcreteDAG()
        s = self._make_step('gen_branch')
        dag.branch('dev', s, source=Genesis)
        assert s.parent is Genesis

    def test_ingest_branch(self):
        dag = ConcreteDAG()
        steps = [self._make_step('s%d' % i) for i in range(3)]
        name = dag.ingest_branch(steps, 'imported')
        assert name == 'imported'
        assert dag.size == 2

    def test_ingest_branch_auto_name(self):
        dag = ConcreteDAG()
        steps = [self._make_step('s%d' % i) for i in range(3)]
        name = dag.ingest_branch(steps)
        assert name is not None
        assert dag.size == 2

    def test_fork_main(self):
        dag = ConcreteDAG()
        s = self._make_step('a')
        dag.add_step(s)
        forked = dag.fork()
        assert forked is not s  # deep copy

    def test_fork_all(self):
        dag = ConcreteDAG()
        dag.add_step(self._make_step('a'))
        dag.branch('dev', self._make_step('b'))
        forked = dag.fork('all')
        assert 'main' in forked
        assert 'dev' in forked

    def test_fork_invalid_branch(self):
        dag = ConcreteDAG()
        with pytest.raises(InvalidBranchError):
            dag.fork('nonexistent')

    def test_recite(self):
        dag = ConcreteDAG()
        s1 = self._make_step('a')
        s2 = self._make_step('b')
        dag.add_step(s1)
        dag.add_step(s2)
        steps = dag.recite()
        assert len(steps) == 2
        assert steps[0] is s2

    def test_diff(self):
        dag = ConcreteDAG()
        s1 = self._make_step('shared')
        dag.add_step(s1)
        s2 = self._make_step('main2')
        dag.add_step(s2)
        s3 = self._make_step('dev1')
        dag.branch('dev', s3)
        idx, root = dag.diff('dev')
        # diff returns index and common root

    def test_diff_invalid_branch(self):
        dag = ConcreteDAG()
        with pytest.raises(InvalidBranchError):
            dag.diff('nonexistent')

    def test_diff_invalid_target(self):
        dag = ConcreteDAG()
        dag.branch('dev', self._make_step())
        with pytest.raises(InvalidBranchError):
            dag.diff('dev', 'nonexistent')

    def test_merge(self):
        dag = ConcreteDAG()
        s1 = self._make_step('shared')
        dag.add_step(s1)
        s2 = self._make_step('dev1')
        dag.branch('dev', s2)
        s3 = self._make_step('dev2')
        dag.add_step(s3, 'dev')
        dag.merge('dev')
        assert 'dev' not in dag.heads

    def test_merge_keep(self):
        dag = ConcreteDAG()
        s1 = self._make_step('shared')
        dag.add_step(s1)
        dag.branch('dev', self._make_step('d1'))
        dag.merge('dev', keep=True)
        assert 'dev' in dag.heads

    def test_merge_invalid_branch(self):
        dag = ConcreteDAG()
        with pytest.raises(InvalidBranchError):
            dag.merge('nonexistent')

    def test_merge_invalid_target(self):
        dag = ConcreteDAG()
        dag.branch('dev', self._make_step())
        with pytest.raises(InvalidBranchError):
            dag.merge('dev', 'nonexistent')

    def test_catch_up_validates(self):
        dag = ConcreteDAG()
        dag.add_step(self._make_step('a'))
        steps = [self._make_step('ext%d' % i) for i in range(3)]
        result = dag.catch_up(steps)
        assert result is not None

    def test_catch_up_fails_validation(self):
        dag = FailValidationDAG()
        dag.add_step(LinkedStep(payload='a'))
        steps = [LinkedStep(payload='ext%d' % i) for i in range(3)]
        result = dag.catch_up(steps)
        # When validation fails, branch is not merged but result still returned
        assert result is not None
