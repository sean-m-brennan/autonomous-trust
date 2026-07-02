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
    Proof of Trust (PoT) — parallel to AgreementByAuthority (PoA), but
    reads ``voter.tier`` (reputation-derived) instead of ``voter.rank``
    (network topology). Use when an agreement's correctness depends on
    behavioral track record rather than inherent node capability —
    e.g., authorising a data-sharing operation where any well-behaved
    peer should be eligible to vote, regardless of whether it's a
    gateway. See doc/architecture/trust-tiers.md §10.
    """
    def __init__(self, myself: AgreementVoter, peers: list[AgreementVoter], threshold_tier=None):
        AgreementProtocol.__init__(self, myself, peers)
        self._explicit_threshold = threshold_tier

    @property
    def threshold_tier(self):
        """Derive threshold from voter tiers: top 1/3 of peers by tier qualify.

        Mirrors AgreementByAuthority.threshold_rank exactly, just on the
        ``tier`` axis. With an explicit threshold_tier ctor arg, that
        value wins.
        """
        if self._explicit_threshold is not None:
            return self._explicit_threshold
        if not self.voters:
            return 0
        tiers = sorted([v.tier for v in self.voters], reverse=True)
        cutoff_idx = max(1, len(tiers) // 3) - 1
        return tiers[cutoff_idx]

    def _count_vote(self, blob, proof, voter):
        if voter.tier >= self.threshold_tier:
            return voter.tier, proof.approval
        return voter.tier, False

    def _accumulate_votes(self, votes):
        # PoT semantics mirror PoA's leader-decides: the highest-tier
        # voter's verdict is the outcome. If the leader didn't actually
        # cast a vote, treat the agreement as not reached (False) —
        # same edge-case handling as authority._accumulate_votes.
        if not self.voters:
            return False
        leader = max(voter.tier for voter in self.voters)
        return dict(votes).get(leader, False)
