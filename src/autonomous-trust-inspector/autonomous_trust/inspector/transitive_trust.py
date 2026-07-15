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

"""Shared peer-of-peer (transitive) reputation querying.

Both the stock ``Inspector`` and the ``InspectorBridge`` want the same thing:
ask each observer peer for its view of every *other* subject peer, routed over
the network so the remote peer's ReputationProcess is the one that computes the
score. The responses arrive as ``rep_resp`` on the AT main loop and are captured
into ``self.latest_reputation_pairs[(observer_uuid, subject_uuid)]`` by
``automate.py``. This mixin factors that query round out of the frontends so the
logic lives in exactly one place.
"""

from autonomous_trust.core import CfgIds
from autonomous_trust.core.config import to_json_string
from autonomous_trust.core.network import Message
from autonomous_trust.core.reputation.protocol import ReputationProtocol
from autonomous_trust.core.system import queue_cadence


# Cadence for a full peer-pair reputation-query round.
PEER_PAIR_QUERY_SEC = 60.0


class TransitiveTrustMixin:
    """Mixin for AutonomousTrust frontends that collect transitive trust.

    Requires the host class to provide ``peers`` (a Peers listing with
    ``.all``), ``identity``, and ``proc_name`` — all standard on
    ``AutonomousTrust`` subclasses.
    """

    def query_peer_pairs(self, queues, *, logger=None):
        """Send one peer-pair reputation-query round.

        For every ordered (observer, subject) pair of distinct peers, send a
        ``consensus_rep_req`` addressed to the *observer* (so it is routed over
        the network and the observer computes its own view of the subject).
        ``from_whom`` MUST be our identity so the observer's
        ``forward_reputation`` can route the ``rep_resp`` back to us.

        We use ``consensus_rep_req`` (the deterministic, chain-derived
        third-party view) rather than ``rep_req`` (contrite-tit-for-tat).
        CTFT is *bilateral*: an observer with no direct shared-task history
        with a subject reports ``PREREP_NEUTRAL`` (0.0), which the
        trust-network graph treats as "no relationship" (``EDGE_TRUST_EPS``)
        and draws no edge — so in a cohort whose committed transactions
        concentrate on a few hubs, almost every pair reads 0.0 and the graph
        stays edgeless even while per-peer consensus is healthy. The
        consensus view has data for any peer the cohort has transacted with,
        so it is the correct "who does the cohort trust whom" signal for the
        graph (and matches the per-peer Trust-Dynamics timeline, which is
        already consensus-sourced). For a leaf observer ``_subtree_roster``
        returns exactly ``Reputation(subject, consensus)``, so the per-pair
        query shape and ``rep_resp`` capture into
        ``latest_reputation_pairs`` are unchanged.

        Returns the number of queries actually enqueued.
        """
        peers = list(self.peers.all)
        sent = 0
        for observer in peers:
            for subject in peers:
                if str(observer.uuid) == str(subject.uuid):
                    continue
                try:
                    query = Message(
                        CfgIds.reputation,
                        ReputationProtocol.consensus_rep_req,
                        to_json_string((subject, self.proc_name)),
                        observer,               # routed over the network
                        from_whom=self.identity,
                    )
                    queues[CfgIds.network].put(
                        query, block=True, timeout=queue_cadence)
                    sent += 1
                except Exception:
                    if logger is not None:
                        logger.exception(
                            "peer-pair consensus_rep_req %r->%r failed",
                            observer, subject)
        return sent
