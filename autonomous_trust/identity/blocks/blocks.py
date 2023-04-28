from datetime import datetime, timedelta

from aenum import Enum
from nacl.hashlib import blake2b

from ...config import Configuration


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
        self.queue = []

    def __eq__(self, other):
        return self.identity == other.identity

    def to_dict(self):
        d = dict(self.__dict__)
        keys = d.keys()
        for key in ['hash', 'queue']:
            if key in keys:
                del d[key]
        return d

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
        return False

    def checker(self, chain, proof, sig):  # threaded
        start = datetime.utcnow()
        while datetime.utcnow() < start + timedelta(seconds=chain.timeout):
            if len(self.queue) < 1:
                continue
            entry = self.queue.pop(0)  # externally submitted
            if entry is not None:
                block, proof, sig = entry
                if not chain.verify(block, proof, sig):
                    return False  # bad block, short-circuit
        if chain.finalize(self):
            chain.add_block(self, proof, sig)
            return True
        return False


class BlockMessage(Configuration):
    def __init__(self, block, proof, signed_proof=None):
        self.block = block
        self.proof = proof
        self.signed_proof = signed_proof


class BlockSignedMessage(Configuration):
    def __init__(self, _message, _signature):
        self._message = _message
        self._signature = _signature

    @property
    def message(self):
        return self._message

    @property
    def signature(self):
        return self._signature
