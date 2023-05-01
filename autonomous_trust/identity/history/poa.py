from ...algorithms import AgreementByAuthority, AgreementProof
from .history import IdentityHistory


class IdentityByAuthority(AgreementByAuthority, IdentityHistory):
    """
    The eldest identity has final say in approval/disapproval
    """
    def __init__(self, me, peers, log_queue, timeout, threshold_rank=3, blacklist=None):
        IdentityHistory.__init__(self, me, peers, log_queue, timeout, blacklist)
        AgreementByAuthority.__init__(self, me, peers.all, threshold_rank)

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

    def finalize(self, block):
        approve = super().finalize(block)
        self.logger.debug("Block approval: %s" % approve)
        return approve
