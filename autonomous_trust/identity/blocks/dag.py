from datetime import datetime
from copy import deepcopy

from ...config import Configuration, EmptyObject
from ...processes import ProcessLogger
from .blocks import IdentityBlock


class IdentityChain(Configuration):
    GENESIS_BLOCK = IdentityBlock(0, EmptyObject(), datetime.utcnow(), None, '0')
    request_chain = 'request_identity_chain'
    provide_chain = 'provide_identity_chain'
    propose = 'propose_block'
    vote = 'vote_block'

    def __init__(self, me, peers, log_queue, timeout=0, blacklist=None):
        self.blocks = [self.GENESIS_BLOCK]
        self._me = me
        self._peers = peers
        self.logger = ProcessLogger(self.__class__.__name__, log_queue)
        self._timeout = timeout
        self.blacklist = blacklist
        if blacklist is None:
            self.blacklist = []
        self.block_queue = dict({})  # keyed by identity

    def __len__(self):
        return len(self.blocks)

    @property
    def timeout(self):
        return self._timeout

    @property
    def last_block(self):
        return self.blocks[-1]

    @property
    def now(self):
        return datetime.utcnow()

    def add_block(self, block, proof, sig):
        #block.hash = proof  # FIXME wrong
        block.sig_hash = sig
        self.blocks.append(block)

    def catch_up(self, other_chain):
        if len(self.blocks) < 3:
            self.blocks = other_chain
        for ident in [b.identity for b in self.blocks]:
            self._peers.promote(ident)


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

    def validate(self, new_block, proof, signed_proof):
        if new_block in self.blocks:
            self.logger.error(f'Duplicate of existing block.')
            return False
        # FIXME must happen early to decode message
        peer = None
        for p in self._peers.all:
            if p.uuid == proof.uuid:
                peer = p
                break
        if peer is not None and proof != peer.verify(signed_proof):  # FIXME verify takes (signed msg, sig) -> msg
            self.logger.error(f'Invalid proof signature.')
            return False
        return True

    def verify(self, block, proof, sig):
        previous_hash = self.last_block.hash
        if previous_hash != block.previous_hash:  # FIXME change for DAG
            self.logger.error('Invalid previous hash')
            self.logger.debug('%s vs %s' % (previous_hash, block.previous_hash))
            return False
        return True

    def finalize(self, block):
        raise NotImplementedError


# FIXME transmit as tuple
class BlockChainMessage(Configuration):
    def __init__(self, impl, chain, signed_chain=None):
        self.impl = impl
        self.chain = chain
        self.signed_chain = signed_chain

    def signed(self):
        #self.signed_chain = 0  # FIXME
        return self
