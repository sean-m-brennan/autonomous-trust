from ...algorithms import AgreementByStake, AgreementProof
from .history import IdentityHistory


class IdentityByStake(AgreementByStake, IdentityHistory):
    """
    The identities vote with reputation weights for approval/disapproval
    """
    def __init__(self, me, peers, log_queue, timeout, blacklist=None):
        AgreementByStake.__init__(self, me, peers.all)
        IdentityHistory.__init__(self, me, peers, log_queue, timeout, blacklist)

    def prove(self, blob):
        if blob.identity.uuid in map(lambda x: x.uuid, self.blacklist):
            return None
        if blob.identity.address in map(lambda x: x.address, self.blacklist):
            return None
        return super().prove(blob)

    def _pre_verify(self, blob, proof, sig):
        if not self.verify_object(blob, proof, sig):
            return False
        return True

    def _get_stake(self, who):
        # FIXME get reputation
        return 0

    def finalize(self, blob):
        approve = super().finalize(blob)
        self.logger.debug("blob approval: %s" % approve)
        return approve
