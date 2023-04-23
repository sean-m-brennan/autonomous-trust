from datetime import datetime
from copy import deepcopy
import logging

from aenum import Enum
from nacl.hashlib import blake2b

from ..config.configuration import Configuration, EmptyObject


class ChainImpl(Enum):
    POW = 'work'
    POS = 'stake'
    POA = 'authority'


class IdentityBlock(Configuration):
    def __init__(self, index, identity, timestamp, previous_hash, sig_hash, nonce=0):
        self.index = index
        self.identity = identity
        self.timestamp = timestamp
        self.previous_hash = previous_hash
        self.sig_hash = sig_hash
        self.nonce = nonce
        self.hash = self.compute_hash()

    def __eq__(self, other):
        return self.identity == other.identity

    def compute_hash(self, nonce=None):
        if nonce is None:
            nonce = ''
        msg_str = self.to_yaml_string() + nonce
        return blake2b(msg_str.encode('utf-8')).hexdigest()

    def validate(self):  # check data types of all info in a block
        instances = [self.index, self.timestamp, self.previous_hash, self.hash]
        types = [int, datetime, str, str]
        if sum(map(lambda inst_, type_: isinstance(inst_, type_), instances, types)) == len(instances):
            return True
        else:
            return False


class IdentityChain(object):
    GENESIS_BLOCK = IdentityBlock(0, EmptyObject(), datetime.utcnow(), None, '0')
    request_chain = 'request_identity_chain'
    provide_chain = 'provide_identity_chain'
    propose = 'propose_block'
    vote = 'vote_block'

    def __init__(self, me, peers, timeout=0, blacklist=None):
        self.blocks = [self.GENESIS_BLOCK]
        self._me = me
        self._peers = peers
        self._timeout = timeout
        self.blacklist = blacklist
        if blacklist is None:
            self.blacklist = []
        self.logger = logging.getLogger(__name__)

    @property
    def last_block(self):
        return self.blocks[-1]

    @property
    def now(self):
        return datetime.utcnow()

    def add_block(self, block, proof, sig):
        previous_hash = self.last_block.hash
        if previous_hash != block.previous_hash:  # FIXME change for DAG
            return False
        if not self.verify(block, proof, sig):  # FIXME allow for delayed approval (voting)
            return False
        # FIXME finalize(block)
        block.hash = proof
        block.sig_hash = sig
        self.blocks.append(block)
        return True

    def catch_up(self, other_chain):
        if len(self.blocks) < 3:
            self.blocks = other_chain

    ####################
    # DAG functions

    def fork(self, head='latest'):
        if head in ['latest', 'whole', 'all']:
            return deepcopy(self)
        elif isinstance(head, int):
            c = deepcopy(self)
            c.blocks = c.blocks[0:head+1]
            return c
        else:
            raise RuntimeError("Given bad head when forking: %s" % str(head))

    def get_root(self, other):
        for i in range(1, min(len(self.blocks), len(other.blocks))):
            if self.blocks[i] != other.blocks[i]:
                return self.fork(i-1)  # noqa
        return self.fork(min_chain_size)  # noqa

    ####################
    # Proving

    def confirm(self, block):
        raise NotImplementedError

    ####################
    # Verifying proof

    def validate_chain(self, verbose=True):
        flag = True
        for i in range(1, len(self.blocks)):
            if not self.blocks[i].validate():
                flag = False
                self.logger.error(f'Wrong data type(s) at block {i}.')
            if self.blocks[i].index != i:
                flag = False
                self.logger.error(f'Wrong block index at block {i}.')
            if self.blocks[i-1].hash != self.blocks[i].previous_hash:
                flag = False
                self.logger.error(f'Wrong previous hash at block {i}.')
            if self.blocks[i].hash != self.blocks[i].compute_hash():
                flag = False
                self.logger.error(f'Wrong hash at block {i}.')
            if self.blocks[i-1].timestamp >= self.blocks[i].timestamp:
                flag = False
                self.logger.error(f'Backdating at block {i}.')
        return flag

    def validate(self, new_block, proof, sig, verbose=True):
        if new_block in self.blocks:
            self.logger.error(f'Duplicate of existing block.')
            return False
        peer = None
        for p in self._peers:
            if p.uuid == proof.uuid:
                peer = p
                break
        if sig != peer.verify(proof):
            self.logger.error(f'Invalid proof signature.')
            return False
        return True

    def verify(self, block, proof, sig):
        raise NotImplementedError


class IdentityProof(Configuration):
    """
    Structure of transmitted proof of identity
    """
    def __init__(self, uuid, digest, approval):
        self.uuid = uuid
        self.digest = digest
        self.approval = approval


class BlockMessage(Configuration):
    def __init__(self, block, proof, sig):
        self.block = block
        self.proof = proof
        self.sig = sig


class BlockChainMessage(Configuration):
    def __init__(self, impl, chain):
        self.impl = impl
        self.chain = chain
        # FIXME signed?
