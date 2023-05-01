from abc import ABC, abstractmethod
from .agreement import AgreementProtocol, AgreementVoter


class AgreementByStake(AgreementProtocol, ABC):
    """
    Agreement reached by vote, votes weighted by staked value
    Still abstract
    """
    def _prep_vote(self):
        self.yea = 0
        self.nay = 0

    @abstractmethod
    def _get_stake(self, voter: AgreementVoter) -> int | float:
        return 0

    def _count_vote(self, blob, proof, voter):
        stake = self._get_stake(voter)
        if proof.approval:
            self.yea += stake
        else:
            self.nay += stake

    def _accumulate_votes(self, votes):
        return self.yea > self.nay
