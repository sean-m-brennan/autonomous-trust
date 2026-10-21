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

        Asks every observer peer for its view of every *other* peer, as one
        batched ``consensus_rep_batch_req`` per observer addressed to that
        observer (so it is routed over the network and the observer computes the
        scores itself). ``from_whom`` MUST be our identity so the observer's
        ``forward_reputation`` can route the ``rep_resp`` back to us.

        **One request per observer, not one per pair.** The per-subject verb
        made a round cost N(N-1) messages -- 6320 requests plus 6320 responses at
        N=80, each triggering its own chain walk and its own signed reply -- while
        the answers were always a roster the response side already knew how to
        read. The batched verb names every subject in one body, so a round is N
        requests and N responses. Coverage, the scores themselves, and the
        ``latest_reputation_pairs[(observer, subject)]`` capture in ``automate.py``
        are all unchanged; only the number of messages differs.

        The body names subjects by **uuid**, not as full Identity objects: the
        responder only ever reads ``peer.uuid`` off it, and sending N identities
        to N observers would trade N-squared messages for N-squared bytes. That
        also makes the body identical for every observer in a round, which is why
        the first message is signed and the rest are readdressed copies of it
        (see ``Message.for_recipient``) -- one Ed25519 operation per round rather
        than one per recipient. Each observer skips its own uuid responder-side,
        so no self-pairs appear.

        We use the consensus view (deterministic, chain-derived, third-party)
        rather than ``rep_req``'s contrite-tit-for-tat. CTFT is *bilateral*: an
        observer with no direct shared-task history with a subject reports
        ``PREREP_NEUTRAL`` (0.0), which the trust-network graph treats as "no
        relationship" (``EDGE_TRUST_EPS``) and draws no edge -- so in a cohort
        whose committed transactions concentrate on a few hubs, almost every pair
        reads 0.0 and the graph stays edgeless even while per-peer consensus is
        healthy. The consensus view has data for any peer the cohort has
        transacted with, so it is the correct "who does the cohort trust whom"
        signal for the graph (and matches the per-peer Trust-Dynamics timeline,
        which is already consensus-sourced).

        Returns the number of REQUESTS enqueued -- one per observer, so at most
        ``len(peers)``. This counted pair-queries before the batch verb; a caller
        comparing it against N(N-1) is reading the old contract.
        """
        peers = list(self.peers.all)
        if len(peers) < 2:
            # A single peer has no other subject to be asked about, and a lone
            # observer asked about only itself would answer with an empty roster.
            return 0
        try:
            body = to_json_string({
                'peer_uuids': [str(peer.uuid) for peer in peers],
                'requesting_process': self.proc_name,
            })
        except Exception:
            # Nothing partial to salvage: the body is shared by every request in
            # the round, so a failure here is the whole round.
            if logger is not None:
                logger.exception('peer-pair query body could not be built')
            return 0
        signed = None
        sent = 0
        for observer in peers:
            try:
                if signed is None:
                    # First message carries the signing cost; the rest reuse it.
                    query = Message(
                        CfgIds.reputation,
                        ReputationProtocol.consensus_rep_batch_req,
                        body,
                        observer,               # routed over the network
                        from_whom=self.identity,
                    )
                    signed = query
                else:
                    query = signed.for_recipient(observer)
                queues[CfgIds.network].put(
                    query, block=True, timeout=queue_cadence)
                sent += 1
            except Exception:
                if logger is not None:
                    logger.exception(
                        "peer-pair consensus_rep_batch_req to %r failed", observer)
        return sent
