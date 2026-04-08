# ******************
#  Copyright 2025 Sean M. Brennan and contributors
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
    def __init__(self, myself: AgreementVoter, peers: list[AgreementVoter], threshold_rank=None):
        AgreementProtocol.__init__(self, myself, peers)
        self._explicit_threshold = threshold_rank

    @property
    def threshold_rank(self):
        """Derive threshold from voter ranks: top 1/3 of peers by rank qualify."""
        if self._explicit_threshold is not None:
            return self._explicit_threshold
        if not self.voters:
            return 0
        ranks = sorted([v.rank for v in self.voters], reverse=True)
        cutoff_idx = max(1, len(ranks) // 3) - 1
        return ranks[cutoff_idx]

    def _count_vote(self, blob, proof, voter):
        if voter.rank >= self.threshold_rank:
            return voter.rank, proof.approval
        return voter.rank, False

    def _accumulate_votes(self, votes):
        leader = max([voter.rank for voter in self.voters])
        return dict(votes)[leader]
