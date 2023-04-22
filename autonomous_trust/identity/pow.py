from .blocks import IdentityChain


class IdentityProofOfWork(IdentityChain):
    DIFFICULTY = 2

    def __init__(self, me, peers, timeout, blacklist=None):
        super().__init__(me, peers, timeout, blacklist)
        self._approved = []

    def confirm(self, block):
        nonce = 0
        computed_hash = block.compute_hash()
        # WARNING: this is *designed* to take some time, it will delay joining the network - on purpose
        try:
            while not computed_hash.startswith('0' * self.DIFFICULTY):
                nonce += 1
                computed_hash = block.compute_hash(str(nonce))
        except MemoryError:
            pass
        return computed_hash

    def verify(self, block, proof, sig):
        if not self.validate(block, proof, sig):
            return False
        if proof.digest.startswith('0' * self.DIFFICULTY) and proof.digest == block.compute_hash():
            self._approved.append(block)
        return True

    def finalize(self, block):
        if block in self._approved:
            self._approved.remove(block)
            return True
        return False

