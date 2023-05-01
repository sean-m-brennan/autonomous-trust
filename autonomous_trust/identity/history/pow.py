from ...algorithms import AgreementByWork
from .history import IdentityHistory


class IdentityByWork(AgreementByWork, IdentityHistory):
    def __init__(self, me, peers, log_queue, timeout, blacklist=None):
        AgreementByWork.__init__(self, me, peers.all)
        IdentityHistory.__init__(self, me, peers, log_queue, timeout, blacklist)
