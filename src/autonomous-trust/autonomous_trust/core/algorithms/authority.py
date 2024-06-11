# ******************
#  Copyright 2024 TekFive, Inc. and contributors
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
# ******************

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
        if voter.rank < self.threshold_rank:  # FIXME derive threshold
            return voter.rank, proof.approval
        return voter.rank, False

    def _accumulate_votes(self, votes):
        leader = max([voter.rank for voter in self.voters])
        return dict(votes)[leader]
