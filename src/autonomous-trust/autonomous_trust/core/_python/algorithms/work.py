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
from .agreement import AgreementProtocol, AgreementVoter, AgreementProof
from ..system import encoding


class AgreementByWork(AgreementProtocol, ABC):
    """
    Agreement by computation capability
    Still abstract
    """
    DIFFICULTY = 2

    def __init__(self, myself: AgreementVoter, peers: list[AgreementVoter]):
        super().__init__(myself, peers)
        self._approved = []

    def prove(self, blob):
        # WARNING: this is *designed* to take some time
        nonce_used = None
        computed_hash = blob.get_hash()
        try:
            if not computed_hash.startswith(b'0' * self.DIFFICULTY):
                nonce = 0
                while True:
                    nonce += 1
                    nonce_bytes = str(nonce).encode(encoding)
                    computed_hash = blob.get_hash(nonce_bytes)
                    if computed_hash.startswith(b'0' * self.DIFFICULTY):
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
        if proof.digest.startswith(b'0' * self.DIFFICULTY) and proof.digest == blob.get_hash(proof.nonce):
            self._approved.append(blob)
        return True

    def finalize(self, blob):
        if blob in self._approved:
            self._approved.remove(blob)
            return True
        return False
