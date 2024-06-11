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

from ...algorithms.agreement import AgreementProof
from ...algorithms.authority import AgreementByAuthority
from .history import IdentityHistory, IdentityObj


class IdentityByAuthority(AgreementByAuthority, IdentityHistory):
    """
    The eldest identity has final say in approval/disapproval
    """
    def __init__(self, me, peers, log_queue, timeout, threshold_rank=3, blacklist=None):
        IdentityHistory.__init__(self, me, peers, log_queue, timeout, blacklist)
        AgreementByAuthority.__init__(self, me, peers.all, threshold_rank)  # noqa

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
        self.logger.debug("Approval for %s: %s" % (blob.identity.nickname, approve))
        return approve
