from ...algorithms import AgreementByAuthority, AgreementProof
from .history import IdentityHistory, IdentityObj


class IdentityByAuthority(AgreementByAuthority, IdentityHistory):
    """
    The eldest identity has final say in approval/disapproval
    """
    def __init__(self, me, peers, log_queue, timeout, threshold_rank=3, blacklist=None):
        IdentityHistory.__init__(self, me, peers, log_queue, timeout, blacklist)
        AgreementByAuthority.__init__(self, me, peers.all, threshold_rank)

    def prove(self, blob: IdentityObj):
        if blob.identity.uuid in map(lambda x: x.uuid, self.blacklist):
            return None
        if blob.identity.address in map(lambda x: x.address, self.blacklist):
            return None
        return super().prove(blob)

    def _pre_verify(self, blob: IdentityObj, proof: AgreementProof, sig):
        if not self.verify_object(blob, proof, sig):  # FIXME blob.validate(proof, sig)
            return False
        return True

    def finalize(self, blob: IdentityObj):
        approve = super().finalize(blob)
        self.logger.debug("Approval: %s" % approve)
        return approve
