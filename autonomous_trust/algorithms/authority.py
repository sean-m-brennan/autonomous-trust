from abc import ABC
from .agreement import AgreementProtocol, AgreementVoter


class AgreementByAuthority(AgreementProtocol, ABC):
    """
    Agreement reached by vote, but only those above a certain rank count
    Still abstract
    """
    def __init__(self, myself: AgreementVoter, peers: list[AgreementVoter], threshold_rank):
        super().__init__(myself, peers)
        self.threshold_rank = threshold_rank

    def _count_vote(self, blob, proof, voter):
        if voter.rank < self.threshold_rank:  # FIXME
            return voter.rank, proof.approval
        return voter.rank, False

    def _accumulate_votes(self, votes):
        max([voter.rank for voter in self.others])
        return dict(votes)[max([voter.rank for voter in self.others])]
