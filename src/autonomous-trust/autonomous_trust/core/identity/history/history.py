from uuid import UUID

from ...algorithms.agreement import VoterTracker
from ...structures.merkle import MerkleTree, SimplestBlob
from ...structures.dag import StepDAG, LinkedStep
from ...config import Configuration, from_yaml_string
from ...processes import ProcessLogger
from ...system import encoding
from ..identity import Identity


# FIXME how does a DAG relate to the merkle tree?
# git: file diffs are transactions, commit is a block, branches diverge
# here: blobs are transactions, merkle root is a block, DAG tracks heads and branches

# This should be a StepDAG of MerkleTree root_hash history, the Merkle leaf-blobs are Identities or Groups
# Essentially an efficient, long-memory identity recognizer
# With super-tree hierarchy (-ies?), can find anyone given (what? name, uuid?)

# need to be able to exchange Identities plus position in memory (DAG placement [index?]), all else rebuilt
# perhaps DAG branches are incomplete memories from others, mergeable once there is a lowest common ancestor
# that implies undirected acyclic graph to stitch together histories
# also answering queries: how to search among multiple branches
# do non-main branches have no data backing?

# At two or more peers, form Group with shared keys

# attribution


class IdentityObj(SimplestBlob, Configuration):
    """
    Identity encapsulation for transmission
    """
    def __init__(self, identity, originator: UUID):
        super().__init__(originator, identity.uuid)
        self.identity = identity

    @property
    def designation(self):
        return (str(self.originator) + str(self.identity.uuid) + self.identity.fullname).encode(encoding) + \
            self.identity.signature.publish()

    def validate(self):
        pass  # FIXME

    def to_dict(self):
        return dict(identity=self.identity, originator=self.originator)


class IdentityHistory(StepDAG, VoterTracker):
    """
    Tracks community identity history with provable membership
    A StepDAG of MerkleTree root_hash history, the Merkle leaf-blobs are Identities or Groups
    Essentially an efficient, long-memory identity recognizer
    """
    def __init__(self, myself, peers, log_queue, timeout=0, blacklist=None):
        StepDAG.__init__(self)
        VoterTracker.__init__(self, myself)
        Configuration.__init__(self)
        self._peers = peers
        self.logger = ProcessLogger(self.__class__.__name__, log_queue)
        self._timeout = timeout
        self.blacklist = blacklist
        if blacklist is None:
            self.blacklist = []
        self._merkle = MerkleTree()  # object tree
        self._merkle.insert(IdentityObj(self.myself, self._merkle.root_digest))
        self.add_step(LinkedStep(self._merkle.root_digest))  # history tracking

    @property
    def timeout(self):
        return self._timeout

    def upgrade_peer(self, who):
        # FIXME confirm eligibility i.e. uuid, fullname, signature all unique
        if who not in self._peers.all:
            self._merkle.insert(IdentityObj(who, self._merkle.root.digest))
            self.add_step(LinkedStep(self._merkle.root.digest))
        self._peers.promote(who)

    def downgrade_peer(self, who):
        self._peers.demote(who)
        if who not in self._peers:
            self._merkle.delete(who)
            self.add_step(LinkedStep(self._merkle.root.digest))

    def _find_identity(self, identity):
        # FIXME minimum info
        return None

    def __contains__(self, item):
        if self._find_identity(item) is not None:
            return True
        return False

    def prove_existence(self, item):
        identity_blob = self._find_identity(item)
        if identity_blob is not None:
            return self._merkle.inclusion_proof(item)  # to yaml?

    def verify_existence(self, item, proof):
        identity_blob = self._find_identity(item)
        if identity_blob is not None:
            return self._merkle.audit(item, proof)

    def _validate(self, branch):
        return True
        # FIXME better validation
        flag = True
        blobs = self.__branch_lists[branch]  # root to head
        for i in range(1, len(blobs)):
            if not blobs[i].validate():
                flag = False
                self.logger.error(f'Wrong data type(s) at block {i}.')
            if blobs[i-1].get_hash() != blobs[i].previous:
                flag = False
                self.logger.error(f'Wrong previous hash at block {i}.')
            if blobs[i].hash != blobs[i].compute_hash():
                flag = False
                self.logger.error(f'Wrong hash at block {i}.')
            if blobs[i-1].timestamp >= blobs[i].timestamp:
                flag = False
                self.logger.error(f'Backdating at block {i}.')
        return flag

    def verify_object(self, blob, proof, sig):
        if not isinstance(blob, IdentityObj) or not isinstance(blob.identity, Identity):
            self.logger.debug('Not Identity')
            return False
        # FIXME verify sig
        ident = blob
        if isinstance(blob, IdentityObj):
            ident = blob.identity
        self.logger.debug("Verify existence")  # FIXME!! dump altogether
        return True  # self.verify_existence(ident, proof)

    def share(self):
        """
        Transmit main branch to another
        :return: tuple of steps list, signature
        """
        steps = self.recite()
        # FIXME to yaml
        steps_msg = b''
        sig = self.myself.sign(steps_msg)  # noqa
        return steps_msg, sig

    def hear(self, steps_msg, sig=None):
        """
        Receive main branch from another
        :return: list of steps
        """
        if sig is None:  # FIXME remove this, need sig
            steps = from_yaml_string(steps_msg)
        if self.myself.verify(steps_msg, sig):
            steps = from_yaml_string(steps_msg)
            return steps
        return None

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
        # previous_hash = self.main.root.digest
        # FIXME handle divergence in branches (i.e. check other branch heads)
        # steps have previous
        # if previous_hash != blob.previous:
        #    self.logger.error('Invalid previous hash')
        #    self.logger.debug('%s vs %s' % (previous_hash, blob.previous))
        #    return False
        return True
