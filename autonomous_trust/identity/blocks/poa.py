from .dag import IdentityChain


class IdentityProofOfAuthority(IdentityChain):
    """
    The eldest identity has final say in approval/disapproval
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
        if not super().verify(block, proof, sig):
            return False
        if not self.validate(block, proof, sig):
            return False
        if block.identity.uuid not in self._votes.keys():
            self._votes[block.identity.uuid] = []
        self._votes[block.identity.uuid].append((block, proof, sig))
        return True

    def finalize(self, block):
        pub_ident = self._me.publish()
        if block.identity == pub_ident:
            return True
        approve = False
        eldest = self.now
        identities = {block.identity.uuid: (block.index, block.identity) for block in self.blocks[1:]}
        for vote in self._votes[block.identity.uuid]:
            block, proof, sig = vote
            if proof.uuid not in identities.keys():
                continue
            idx, voter = identities[proof.uuid]
            if voter.verify(proof, sig):
                if self.blocks[idx].timestamp < eldest:
                    approve = proof.approval
        del self._votes[block.identity.uuid]
        self.logger.debug("Block approval: %s" % approve)
        return approve
