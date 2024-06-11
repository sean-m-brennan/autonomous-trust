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

from ...algorithms.stake import AgreementByStake
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
