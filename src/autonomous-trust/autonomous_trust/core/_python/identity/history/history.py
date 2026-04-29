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

from uuid import UUID

from nacl.exceptions import BadSignatureError

from ...algorithms.agreement import VoterTracker
from ...structures.merkle import MerkleTree, SimplestBlob
from ...structures.dag import StepDAG, LinkedStep
from ...config import Configuration, from_yaml_string, to_yaml_string
from ...processes import ProcessLogger
from ...system import encoding
from ..identity import Identity
from autonomous_trust.core.protobuf.identity import identity_pb2, history_pb2


# Design note: the DAG tracks the *history* of Merkle-root changes over time.
# Each DAG step payload is a Merkle root hash. The Merkle tree itself stores
# IdentityObj blobs (peer identities). Branches in the DAG represent divergent
# history views from different peers, which are merged once a lowest common
# ancestor is established. This mirrors how git tracks file-diff transactions
# (blobs) in commits (merkle roots) across branches (DAG heads).


class IdentityObj(SimplestBlob, Configuration):
    """
    Identity encapsulation for transmission
    """
    _msg_class = history_pb2.IdBlob

    def __init__(self, identity, originator: UUID):
        Configuration.__init__(self, history_pb2.IdBlob)
        SimplestBlob.__init__(self, originator, identity.uuid)
        self.identity = identity

    @property
    def designation(self):
        return (str(self.originator) + str(self.identity.uuid) + self.identity.fullname).encode(encoding) + \
            self.identity.signature.publish()

    def validate(self):
        """Validate that the wrapped identity has the required fields."""
        if self.identity is None:
            return False
        if not isinstance(self.identity, Identity):
            return False
        if self.identity.uuid is None:
            return False
        if not self.identity.fullname:
            return False
        if self.identity.signature is None:
            return False
        if self.identity.encryptor is None:
            return False
        return True

    def to_dict(self):
        return dict(identity=self.identity, originator=self.originator)

    def sync_to_message(self):
        self.message.originator = str(self.originator).encode('utf-8')
        self.identity.message = self.message.identity
        self.identity.sync_to_message()

    def sync_from_message(self):
        self.originator = UUID(self.message.originator.decode('utf-8'))
        self.identity = Identity.__new__(Identity)
        self.identity.message = identity_pb2.Identity()
        self.identity.message.CopyFrom(self.message.identity)
        self.identity.sync_from_message()
        self.uuid = self.identity.uuid


class IdentityHistory(StepDAG, VoterTracker):
    """
    Tracks community identity history with provable membership.

    A StepDAG of MerkleTree root_hash history where Merkle leaf-blobs
    are Identities or Groups. Functions as an efficient, long-memory
    identity recognizer.
    """
    def __init__(self, myself, peers, log_queue, timeout=0, blacklist=None):
        StepDAG.__init__(self)
        VoterTracker.__init__(self, myself)
        self._peers = peers
        self.logger = ProcessLogger(self.__class__.__name__, log_queue)
        self._timeout = timeout
        self.blacklist = blacklist
        if blacklist is None:
            self.blacklist = []
        self._merkle = MerkleTree()  # object tree
        self._merkle.insert(IdentityObj(self.myself, self._merkle.root_digest))
        self.add_step(LinkedStep(self._merkle.root_digest))  # history tracking

    def to_dict(self):
        return {'step_dag': self.recite(), 'blacklist': self.blacklist}

    def populate(self, dictionary):
        self.blacklist = dictionary['blacklist']
        self.merge(self.ingest_branch(dictionary['step_dag']))

    @property
    def timeout(self):
        return self._timeout

    def insert_peer(self, who, level=None):
        if who.uuid is None or not who.fullname or who.signature is None:
            self.logger.warning(f'Rejecting peer with incomplete identity')
            return
        existing = self._find_identity(who)
        if existing is not None:
            self.logger.warning(f'Peer {who.nickname} already in history')
            return
        if who not in self._peers.all:
            self._merkle.insert(IdentityObj(who, self._merkle.root_digest))
            self.add_step(LinkedStep(self._merkle.root_digest))
        self._peers.add(who, level)

    def _find_identity(self, identity):
        """Search the Merkle tree for a blob matching the given identity by UUID."""
        for blob in self._merkle.blobs:
            if isinstance(blob, IdentityObj) and blob.identity.uuid == identity.uuid:
                return blob
        return None

    def __contains__(self, item):
        if self._find_identity(item) is not None:
            return True
        return False

    def prove_existence(self, item):
        identity_blob = self._find_identity(item)
        if identity_blob is not None:
            return self._merkle.inclusion_proof(identity_blob)

    def verify_existence(self, item, proof):
        identity_blob = self._find_identity(item)
        if identity_blob is not None:
            return self._merkle.audit(identity_blob, proof)

    def _validate(self, branch):
        """Validate a branch of the DAG for structural integrity."""
        if branch not in self._StepDAG__branch_lists:
            self.logger.error(f'Branch {branch} not found')
            return False
        steps = self._StepDAG__branch_lists[branch]
        if not steps:
            return True
        for i in range(1, len(steps)):
            if steps[i].timestamp is not None and steps[i - 1].timestamp is not None:
                if steps[i - 1].timestamp >= steps[i].timestamp:
                    self.logger.error(f'Backdating at step {i}.')
                    return False
        return True

    def verify_object(self, blob, proof, sig):
        """Verify that a blob is a valid IdentityObj with a correct signature."""
        if not isinstance(blob, IdentityObj) or not isinstance(blob.identity, Identity):
            self.logger.debug('Not Identity')
            return False
        if not blob.validate():
            self.logger.debug('Identity validation failed')
            return False
        if sig is not None and proof is not None:
            # The signature was made by the *voter* (proof.uuid), not by
            # the subject (blob.identity). Look up the voter — either
            # ourselves or a known peer. Cf. the parallel lookup at
            # IdentityHistory._pre_verify above.
            voter = None
            myself = getattr(self, 'myself', None)
            if myself is not None and myself.uuid == proof.uuid:
                voter = myself
            elif self._peers is not None:
                voter = self._peers.find_by_uuid(proof.uuid)
            if voter is None:
                self.logger.warning(
                    f'Unknown voter {proof.uuid} for proof on '
                    f'{blob.identity.nickname}')
                return False
            # _process_id stores the vote signature as a (msg, sig)
            # tuple, where both are HexEncoder-encoded by Identity.sign
            # (msg = hex of proof.to_string().encode(); sig = hex of the
            # 64-byte raw signature). PyNaCl's VerifyKey.verify expects
            # either a single SignedMessage (signature+message
            # concatenated) or msg+raw-signature — but with HexEncoder
            # it only decodes the smessage, not a separately-passed
            # signature. Reconstructing signature+message gives the
            # SignedMessage form that round-trips correctly.
            if isinstance(sig, tuple) and len(sig) == 2:
                sig_msg, sig_signature = sig
                smessage = sig_signature + sig_msg
            else:
                smessage = sig
            try:
                voter.verify(smessage)
            except (BadSignatureError, Exception) as e:
                self.logger.warning(f'Signature verification failed: {e}')
                return False
        return True

    def share(self):
        """
        Serialize and sign the main branch for transmission.
        :return: tuple of (serialized_bytes, signature)
        """
        steps = self.recite()
        steps_msg = to_yaml_string(steps)
        if isinstance(steps_msg, str):
            steps_msg = steps_msg.encode(encoding)
        sig = self.myself.sign(steps_msg)
        return steps_msg, sig

    def hear(self, steps_msg, sig=None):
        """
        Receive and verify a main branch from another peer.
        :return: list of steps, or None if verification fails
        """
        if isinstance(steps_msg, str):
            steps_msg_bytes = steps_msg.encode(encoding)
        else:
            steps_msg_bytes = steps_msg
        if sig is not None:
            try:
                result = self.myself.verify(steps_msg_bytes, sig)
                if result is False:
                    self.logger.warning('History signature verification failed')
                    return None
            except (BadSignatureError, Exception):
                self.logger.warning('History signature verification failed')
                return None
        else:
            if len(self._peers.all) > 0:
                self.logger.warning('Rejecting unsigned history — not in bootstrap')
                return None
            self.logger.warning('Accepting unsigned history during bootstrap')
        if isinstance(steps_msg, bytes):
            steps_msg = steps_msg.decode(encoding)
        steps = from_yaml_string(steps_msg)
        return steps

    ####################
    # Agreement protocol

    def _pre_verify(self, blob: IdentityObj, proof, sig: bytes):
        ident = self._peers.find_by_uuid(blob.originator)
        if ident is not None:
            self.logger.error(f'Duplicate of existing peer.')
            return False
        peer = self._peers.find_by_uuid(proof.uuid)
        if peer is not None and proof != peer.verify(sig):
            self.logger.error(f'Invalid proof signature.')
            return False
        # TODO: Handle divergence in branches — check other branch heads
        # to detect conflicting history views from different peers. This
        # requires comparing the blob's previous hash against all known
        # branch heads, not just the main branch.
        return True
