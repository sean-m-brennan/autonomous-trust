from ...algorithms import AgreementByStake, AgreementProof
from .history import IdentityHistory


class IdentityByStake(AgreementByStake, IdentityHistory):
    """
    The identities vote with reputation weights for approval/disapproval
    """
    def __init__(self, me, peers, log_queue, timeout, blacklist=None):
        AgreementByStake.__init__(self, me, peers.all)
        IdentityHistory.__init__(self, me, peers, log_queue, timeout, blacklist)

    def prove(self, block):
        if block.identity.uuid in map(lambda x: x.uuid, self.blacklist):
            return None
        if block.identity.address in map(lambda x: x.address, self.blacklist):
            return None
        return block.compute_hash()

    def _pre_verify(self, block, proof, sig):
        if not IdentityHistory.verify(self, block, proof, sig):
            return False
        if not self.validate(block, proof, sig):
            return False
        return True

    def _get_stake(self, who):
        # FIXME get reputation
        return 0

    def finalize(self, block):
        approve = super().finalize(block)
        self.logger.debug("Block approval: %s" % approve)
        return approve
