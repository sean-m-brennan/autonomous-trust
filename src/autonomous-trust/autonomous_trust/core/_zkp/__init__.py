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

"""ZK-STARK proof generation and verification for task data integrity.

This module wraps the Rust-based Plonky3 STARK prover/verifier, providing
``prove()`` and ``verify()`` functions usable from both the Python and native
backends.  Since the underlying implementation is Rust via PyO3 (not C via
CFFI), both backends share the same library.
"""

try:
    from autonomous_trust_zkp import prove, verify
    ZKP_AVAILABLE = True
except ImportError:
    ZKP_AVAILABLE = False

    def prove(data: bytes) -> bytes:
        raise RuntimeError(
            "ZKP support not available. Install the autonomous-trust-zkp package "
            "(built with maturin from src/autonomous-trust/rust/)."
        )

    def verify(proof_data: bytes) -> bool:
        raise RuntimeError(
            "ZKP support not available. Install the autonomous-trust-zkp package "
            "(built with maturin from src/autonomous-trust/rust/)."
        )


__all__ = ["prove", "verify", "ZKP_AVAILABLE"]
