from abc import ABC
from .agreement import AgreementProtocol, AgreementVoter


class AgreementByAuthority(AgreementProtocol, ABC):
    """
    Agreement reached by vote, but only those above a certain rank count
    Still abstract
    """
    def __init__(self, myself: AgreementVoter, peers: list[AgreementVoter], threshold_rank):
        AgreementProtocol.__init__(self, myself, peers)
        self.threshold_rank = threshold_rank

    def _count_vote(self, blob, proof, voter):
        if voter.rank < self.threshold_rank:  # FIXME
            return voter.rank, proof.approval
        return voter.rank, False

    def _accumulate_votes(self, votes):
        self.logger.debug([voter.rank for voter in self.voters])
        leader = max([voter.rank for voter in self.voters])
        return dict(votes)[leader]
