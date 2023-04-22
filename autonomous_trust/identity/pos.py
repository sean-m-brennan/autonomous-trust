from .blocks import IdentityChain


class IdentityProofOfStake(IdentityChain):
    """
    The identities vote with reputation weights for approval/disapproval
    Given me: my Identity; timeout: seconds to final decision, blacklist: exclusion list of Identities
    """
    def __init__(self, me, peers, timeout, blacklist=None):
        super().__init__(me, peers, timeout, blacklist)
        self._votes = {}

    def confirm(self, block):
        if block.identity.uuid in map(lambda x: x.uuid, self.blacklist):
            return None
        if block.identity.address in map(lambda x: x.address, self.blacklist):
            return None
        return block.compute_hash()

    def verify(self, block, proof, sig):
        if not self.validate(block, proof, sig):
            return False
        if block not in self._votes.keys():
            self._votes[block] = []
        self._votes[block].append((proof, sig))
        return True

    def finalize(self, block):
        yea = 0
        nay = 0
        identities = {block.identity.uuid: (block.index, block.identity) for block in self.blocks[1:]}
        for vote in self._votes[block]:
            proof, sig = vote
            idx, voter = identities[proof.uuid]
            rep = self.find_reputation(voter)  # FIXME need latest rep
            if voter.verify(proof, sig):
                if vote.approval:
                    yea += rep
                else:
                    nay += rep
        del self._votes[block]
        return yea > nay
