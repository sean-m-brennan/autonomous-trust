# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
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


class AgreementByTrust(AgreementProtocol, ABC):
    """
    Proof of Trust (PoT): a strict majority of the eligible voters.

    A voter is eligible when its ``voter.tier`` (reputation-derived, see
    doc/architecture/trust-tiers.md §10) is at or above ``threshold_tier``.
    Use PoT when an agreement's correctness depends on behavioral track
    record rather than node capability, e.g. authorising a data-sharing
    operation that any well-behaved peer should be able to vote on, gateway
    or not.

    The blob is approved when more than half of the eligible voters cast an
    approval. An eligible voter that does not vote counts against, a tie
    rejects, and no eligible voters means no approval. Votes from voters
    below the threshold are dropped, not counted as nays.

    Tolerance: an outcome on which the honest eligible voters agree cannot be
    flipped while fewer than half of the eligible voters are Byzantine. No
    single voter decides, however high its tier. This is a local decision
    over this node's view of tiers; tiers are not on the wire, so two nodes
    can disagree on the eligible set (RD_13.1 §6).

    Unlike AgreementByAuthority, PoT has no leader. Until RD_13.1 the two
    were copies of each other on different axes.
    """
    # Derived default threshold: tier 1, reputation >= 0.50 in
    # ReputationProcess.TIER_FLOORS. Mirror of TRUST_DEFAULT_THRESHOLD_TIER
    # in agreement.h.
    DEFAULT_THRESHOLD_TIER = 1

    def __init__(self, myself: AgreementVoter, peers: list[AgreementVoter], threshold_tier=None):
        AgreementProtocol.__init__(self, myself, peers)
        self._explicit_threshold = threshold_tier

    @property
    def threshold_tier(self):
        """Minimum tier that may vote: the explicit ctor arg when given,
        otherwise ``DEFAULT_THRESHOLD_TIER``."""
        if self._explicit_threshold is not None:
            return self._explicit_threshold
        return self.DEFAULT_THRESHOLD_TIER

    def _count_vote(self, blob, proof, voter):
        # Report every vote; _accumulate_votes drops the ineligible ones,
        # since it needs the threshold anyway to size the eligible set.
        return voter.tier, proof.approval

    def _accumulate_votes(self, votes):
        threshold = self.threshold_tier
        eligible = sum(1 for voter in self.voters if voter.tier >= threshold)
        yea = sum(1 for tier, approval in votes if tier >= threshold and approval)
        return eligible > 0 and yea * 2 > eligible
