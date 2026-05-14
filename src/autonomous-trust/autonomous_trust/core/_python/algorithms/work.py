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

from abc import ABC
from nacl.encoding import HexEncoder
from .agreement import AgreementProtocol, AgreementVoter, AgreementProof
from ..system import encoding


def _raw_hash(blob, nonce: bytes = None) -> bytes:
    """Compute the raw 32-byte blake2b digest of `designation + nonce`.

    `blob.get_hash` returns ASCII-hex bytes (MerkleTree.hash_func defaults
    to nacl.hash.blake2b with HexEncoder); POW canonicalizes on raw bytes
    so the digest is byte-identical to C's crypto_generichash_blake2b
    output for the same input. Hex-decoding the existing output is
    cheaper than re-implementing the hash from scratch and avoids
    forking MerkleTree's encoder default.
    """
    return HexEncoder.decode(blob.get_hash(nonce))


class AgreementByWork(AgreementProtocol, ABC):
    """
    Agreement by computation capability
    Still abstract
    """
    DIFFICULTY = 2  # number of leading zero BYTES required of the raw digest

    def __init__(self, myself: AgreementVoter, peers: list[AgreementVoter]):
        super().__init__(myself, peers)
        self._approved = []

    def prove(self, blob):
        # WARNING: this is *designed* to take some time
        nonce_used = None
        computed_hash = _raw_hash(blob)
        prefix = b'\x00' * self.DIFFICULTY
        try:
            if not computed_hash.startswith(prefix):
                nonce = 0
                while True:
                    nonce += 1
                    nonce_bytes = str(nonce).encode(encoding)
                    computed_hash = _raw_hash(blob, nonce_bytes)
                    if computed_hash.startswith(prefix):
                        nonce_used = nonce_bytes
                        break
        except MemoryError:
            pass
        # Store the nonce in the proof so verify() can recompute the same
        # hash. Without this, any mined proof that needed >0 iterations
        # would re-hash against the no-nonce form in verify and be
        # rejected — see BUGS.md P5 (FIXED 2026-05-11). When the no-nonce
        # hash already met the difficulty, nonce_used stays None and
        # verify naturally re-hashes with no nonce, matching.
        return AgreementProof(self.myself.uuid, computed_hash, True,
                              nonce=nonce_used)

    def verify(self, blob, proof, sig):
        self._pre_verify(blob, proof, sig)
        prefix = b'\x00' * self.DIFFICULTY
        if proof.digest.startswith(prefix) and proof.digest == _raw_hash(blob, proof.nonce):
            self._approved.append(blob)
        return True

    def finalize(self, blob):
        if blob in self._approved:
            self._approved.remove(blob)
            return True
        return False
