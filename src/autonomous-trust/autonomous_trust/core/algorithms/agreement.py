# ******************
#  Copyright 2024 TekFive, Inc. and contributors
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

from abc import ABC, abstractmethod
from uuid import UUID

from ..config import Configuration
from ..structures.merkle import SimplestBlob
from ..system import encoding


class AgreementProof(Configuration):
    """
    Minimum structure of a provable, transmissible vote
    """
    def __init__(self, uuid: UUID, digest: bytes, approval: bool, nonce: bytes = None):
        self.uuid = uuid  # voter
        self.digest = digest  # hash of proposal
        self.approval = approval  # yea/nay
        self.nonce = nonce

    def __bytes__(self):
        return str(self.uuid).encode(encoding) + self.digest + bytes(self.approval) + self.nonce


class AgreementVoter(ABC):
    """
    Minimum abstract class for peers participating in agreements
    """
    def __init__(self, _uuid, _rank):
        self._uuid = _uuid
        self._rank = _rank

    @property
    def uuid(self):
        return self._uuid

    @property
    def rank(self):
        return self._rank

    @abstractmethod
    def verify(self, proof: AgreementProof, sig: bytes) -> bool:
        """
        Was the proof signed by this voter?
        :param proof: AgreementProof
        :param sig: bytes
        :return: bool
        """
        return False


class VoterTracker(ABC):
    def __init__(self, myself: AgreementVoter):
        self.myself = myself


class AgreementProtocol(VoterTracker):
    """
    Interface for agreement
    """
    def __init__(self, myself: AgreementVoter, others: list[AgreementVoter]):
        VoterTracker.__init__(self, myself)
        self.voters = others + [myself]
        self._votes = {}

    def prove(self, blob: SimplestBlob) -> AgreementProof:
        """
        Ensure the consistency of the data in the blob, then return its hash
        :param blob: SimplestBlob
        :return: AgreementProof
        """
        return AgreementProof(self.myself.uuid, blob.get_hash(), True)

    @abstractmethod
    def _pre_verify(self, blob: SimplestBlob, proof: AgreementProof, sig: bytes):
        return False

    def verify(self, blob: SimplestBlob, proof: AgreementProof, sig: bytes):
        """
        Confirm validity of this blob and collect votes for it;
        non-voting implementations should override
        :param blob: SimplestBlob
        :param proof: AgreementProof
        :param sig: bytes
        :return: bool
        """
        if not self._pre_verify(blob, proof, sig):
            return False
        if blob.uuid not in self._votes:
            self._votes[blob.uuid] = []
        self._votes[blob.uuid].append((blob, proof, sig))
        return True

    def _prep_vote(self):
        return

    @abstractmethod
    def _count_vote(self, blob: SimplestBlob, proof: AgreementProof, voter: AgreementVoter):
        return False

    @abstractmethod
    def _accumulate_votes(self, votes) -> bool:
        return False

    def finalize(self, blob: SimplestBlob) -> bool:
        """
        Determine whether to accept this blob or not
        :param blob: SimplestBlob
        :return: bool
        """
        if self.myself.uuid == blob.originator:
            return True

        self._prep_vote()
        voters = {peer.uuid: peer for peer in self.voters}
        approvals = []
        if blob.uuid not in self._votes:
            return False
        for id_obj, proof, sig in self._votes[blob.uuid]:
            if proof.uuid not in voters:
                continue
            voter = voters[proof.uuid]
            #if voter.verify(proof, sig):  # properly signed proof  # FIXME The signature must be exactly 64 bytes long
            approvals.append(self._count_vote(id_obj, proof, voter))
        del self._votes[blob.uuid]
        return self._accumulate_votes(approvals)
