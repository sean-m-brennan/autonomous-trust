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

from abc import ABC, abstractmethod
from uuid import UUID

from ..config import Configuration
from ..structures.merkle import SimplestBlob
from ..system import encoding
from autonomous_trust.core.protobuf.algorithms import agreement_pb2


class AgreementProof(Configuration):
    """
    Minimum structure of a provable, transmissible vote
    """
    _msg_class = agreement_pb2.AgreementProof

    def __init__(self, uuid: UUID, digest: bytes, approval: bool, nonce: bytes = None):
        Configuration.__init__(self, agreement_pb2.AgreementProof)
        self.uuid = uuid  # voter
        self.digest = digest  # hash of proposal
        self.approval = approval  # yea/nay
        self.nonce = nonce

    def __bytes__(self):
        # nonce defaults to None; sync_from_message also stores None for
        # an empty wire field. Treat None as the empty byte string so
        # callers don't blow up with "can't concat NoneType to bytes".
        # bytes(approval) gives b'\x00' for True, b'' for False — kept as
        # is for wire-format stability.
        return (str(self.uuid).encode(encoding)
                + (self.digest or b'')
                + bytes(self.approval)
                + (self.nonce or b''))

    def sync_to_message(self):
        self.message.uuid = str(self.uuid).encode('utf-8')
        self.message.digest = self.digest if self.digest else b''
        self.message.approval = self.approval
        self.message.nonce = self.nonce if self.nonce is not None else b''

    def sync_from_message(self):
        self.uuid = UUID(self.message.uuid.decode('utf-8'))
        self.digest = self.message.digest
        self.approval = self.message.approval
        self.nonce = self.message.nonce if self.message.nonce else None


class AgreementVoter(ABC):
    """
    Minimum abstract class for peers participating in agreements
    """
    def __init__(self, _uuid, _rank, _tier=0):
        self._uuid = _uuid
        self._rank = _rank
        # Trust tier (0..4) — reputation-derived access level, distinct
        # from topological rank. Read by AgreementByTrust; PoA voters
        # leave it at 0. See doc/architecture/trust-tiers.md §1.
        self._tier = _tier

    @property
    def uuid(self):
        return self._uuid

    @property
    def rank(self):
        return self._rank

    @property
    def tier(self):
        return self._tier

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
            # Vote sig is a (signed_message_hex, signature_hex) tuple
            # produced by Identity.sign — see history.verify_object for
            # the same reconstruction.
            if isinstance(sig, tuple) and len(sig) == 2:
                sig_msg, sig_signature = sig
                smessage = sig_signature + sig_msg
            else:
                smessage = sig
            try:
                voter.verify(smessage)
            except Exception:
                continue  # skip votes with invalid signatures
            approvals.append(self._count_vote(id_obj, proof, voter))
        del self._votes[blob.uuid]
        return self._accumulate_votes(approvals)
