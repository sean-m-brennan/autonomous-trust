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

import json
import pytest
from unittest.mock import patch

from autonomous_trust.core.negotiation import Task, TaskParameters, TaskResult
from autonomous_trust.core._zkp import ZKP_AVAILABLE


class TestZkpModule:
    def test_zkp_available(self):
        assert isinstance(ZKP_AVAILABLE, bool)

    @pytest.mark.skipif(not ZKP_AVAILABLE, reason="ZKP module not installed")
    def test_prove_verify_roundtrip(self):
        from autonomous_trust.core._zkp import prove, verify
        data = b"test task data"
        proof = prove(data)
        assert isinstance(proof, bytes)
        assert len(proof) > 0
        assert verify(proof) is True

    @pytest.mark.skipif(not ZKP_AVAILABLE, reason="ZKP module not installed")
    def test_tampered_proof_rejected(self):
        from autonomous_trust.core._zkp import prove, verify
        proof = bytearray(prove(b"some data"))
        proof[len(proof) // 2] ^= 0xFF
        result = verify(bytes(proof))
        assert result is False


class TestTaskResultZkp:
    def _make_task_result(self, result=42):
        tp = TaskParameters('cap1')
        task = Task(tp, 'requestor1')
        return TaskResult(task=task, result=result)

    def test_no_proof_by_default(self):
        tr = self._make_task_result()
        assert tr.proof is None

    def test_verify_returns_none_without_proof(self):
        tr = self._make_task_result()
        assert tr.verify_proof() is None

    @pytest.mark.skipif(not ZKP_AVAILABLE, reason="ZKP module not installed")
    def test_generate_proof(self):
        tr = self._make_task_result()
        assert tr.generate_proof() is True
        assert tr.proof is not None
        assert isinstance(tr.proof, bytes)

    @pytest.mark.skipif(not ZKP_AVAILABLE, reason="ZKP module not installed")
    def test_verify_valid_proof(self):
        tr = self._make_task_result()
        tr.generate_proof()
        assert tr.verify_proof() is True

    @pytest.mark.skipif(not ZKP_AVAILABLE, reason="ZKP module not installed")
    def test_verify_tampered_proof(self):
        tr = self._make_task_result()
        tr.generate_proof()
        proof = bytearray(tr.proof)
        proof[len(proof) // 2] ^= 0xFF
        tr.proof = bytes(proof)
        assert tr.verify_proof() is False

    @pytest.mark.skipif(not ZKP_AVAILABLE, reason="ZKP module not installed")
    def test_proof_data_deterministic(self):
        tr = self._make_task_result()
        d1 = tr._proof_data()
        d2 = tr._proof_data()
        assert d1 == d2

    @pytest.mark.skipif(not ZKP_AVAILABLE, reason="ZKP module not installed")
    def test_proof_survives_json_roundtrip(self):
        tr = self._make_task_result()
        tr.generate_proof()
        original_proof = tr.proof
        from autonomous_trust.core.config.configuration import ConfigJSONEncoder, config_json_decoder
        serialized = json.dumps(tr, cls=ConfigJSONEncoder)
        restored = json.loads(serialized, object_hook=config_json_decoder)
        # config_json_decoder reconstructs a TaskResult object
        assert restored.proof == original_proof

    def test_generate_proof_unavailable(self):
        """When ZKP module is not available, generate_proof returns False."""
        tr = self._make_task_result()
        import autonomous_trust.core._zkp as zkp_mod
        with patch.object(zkp_mod, 'ZKP_AVAILABLE', False):
            result = tr.generate_proof()
        assert result is False
        assert tr.proof is None

    def test_verify_proof_unavailable(self):
        """When ZKP module is not available, verify_proof returns None even with proof bytes."""
        tr = self._make_task_result()
        tr.proof = b"fake proof data"
        import autonomous_trust.core._zkp as zkp_mod
        with patch.object(zkp_mod, 'ZKP_AVAILABLE', False):
            result = tr.verify_proof()
        assert result is None
