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

from abc import ABC, abstractmethod
from typing import Union
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
    def _get_stake(self, voter: AgreementVoter) -> Union[int, float]:
        return 0

    def _count_vote(self, blob, proof, voter):
        stake = self._get_stake(voter)
        if proof.approval:
            self.yea += stake
        else:
            self.nay += stake

    def _accumulate_votes(self, votes):
        return self.yea > self.nay
