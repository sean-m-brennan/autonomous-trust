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

"""Test that both backends can be imported simultaneously and that the
switching mechanism works correctly."""

import pytest

from .conftest import requires_native


@requires_native
class TestBackendSwitching:
    """Verify both implementations are independently importable."""

    def test_python_backend_importable(self):
        """Pure Python backend can be imported directly."""
        from autonomous_trust.core._python.automate import AutonomousTrust as PyAT
        from autonomous_trust.core._python.processes import ProcessTracker as PyPT
        from autonomous_trust.core._python.config import Configuration as PyCfg

        assert PyAT is not None
        assert PyPT is not None
        assert PyCfg is not None

    def test_native_backend_importable(self):
        """Native backend can be imported directly."""
        from autonomous_trust.core._native._ffi import ffi, lib

        assert ffi is not None
        assert lib is not None

    def test_native_identity_distinct_from_python(self):
        """Native and Python Identity classes are distinct."""
        from autonomous_trust.core._python.identity.identity import Identity as PyIdentity
        from autonomous_trust.core._native.identity.identity import NativeIdentity

        assert PyIdentity is not NativeIdentity

    def test_native_reputation_types(self):
        """Native reputation types are C-backed."""
        from autonomous_trust.core._native.reputation.reputation import (
            TransactionHistory, Reputations, reputation_compute,
        )

        assert TransactionHistory is not None
        assert Reputations is not None
        assert reputation_compute is not None

    def test_core_exports_match_python(self):
        """The core __init__ exports the expected names regardless of backend."""
        import autonomous_trust.core as core

        expected = [
            'AutonomousTrust', 'ProcessTracker', 'Process', 'ProcMeta',
            'LogLevel', 'Configuration', 'InitializableConfig', 'EmptyObject',
            'to_json_string', 'from_json_string',
            'to_yaml_string', 'from_yaml_string',
            'CfgIds', 'QueueType',
        ]
        for name in expected:
            assert hasattr(core, name), f"core missing export: {name}"

    def test_submodule_fallback(self):
        """Modules not in _native fall back to _python transparently."""
        # These modules exist only in _python
        from autonomous_trust.core.system import CfgIds
        from autonomous_trust.core.structures.merkle import MerkleTree

        assert CfgIds is not None
        assert MerkleTree is not None
