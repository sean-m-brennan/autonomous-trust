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

from typing import Callable, Optional, Union
from uuid import UUID

from ...algorithms.stake import AgreementByStake
from .history import IdentityHistory


class IdentityByStake(AgreementByStake, IdentityHistory):
    """
    The identities vote with reputation weights for approval/disapproval.
    Requires a reputation_fn callable that maps peer UUID -> score.
    """
    def __init__(self, me, peers, log_queue, timeout, blacklist=None,
                 reputation_fn: Optional[Callable[[UUID], Union[int, float]]] = None):
        AgreementByStake.__init__(self, me, peers.all)
        IdentityHistory.__init__(self, me, peers, log_queue, timeout, blacklist)
        self._reputation_fn = reputation_fn

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
        """Look up the voter's reputation score as their stake weight."""
        if self._reputation_fn is not None:
            try:
                score = self._reputation_fn(who.uuid)
                if score is not None:
                    return score
            except (KeyError, Exception):
                pass
        return 1.0  # default: equal weight for peers without reputation data

    def finalize(self, blob):
        approve = super().finalize(blob)
        self.logger.debug("blob approval: %s" % approve)
        return approve
