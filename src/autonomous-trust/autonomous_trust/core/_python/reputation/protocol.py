# ******************
#  Copyright 2023 TekFive, Inc., Sean M. Brennan, and contributors
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

from ..protocol import Protocol

# see https://understandingpaxos.wordpress.com


class ReputationProtocol(Protocol):
    """
    Protocol for establishing Reputation
    ------------------------------------

    Permissioned consensus: assumes IdentityProtocol has previously succeeded

    Leaderless Byzantine Multi-Paxos protocol:
    1. request the floor: unique proposal id (timestamp + index + my uuid)
    2. granted (or not) - from majority of peers: proposal id + last id + chain hash
    2a. if timestamp < max approved -> nack: proposal id -> requestor must retry (exponential backoff?)
    2b. if requestor index < my index -> update nack
    2c. if my index < requestor index -> catch up
    3. proposal: proposal id + value
    4. accepted: proposal id -> confirmed iff #accepted >= #peers/2+1
    5. To guarantee up-to-date do only steps 1,2
    5a. request update from 3 peers: depth of chain

    Overall process
    1. transaction from main -> record, broadcast out
    2. peer transaction score (uses task uuid)
    3. coupled, saved to history (to disk?)
    4. reputation request
    4a. compute
    5. reputation response
    """
    request = 'ask permission'
    grant = 'permission granted'
    nack = 'try again'
    backdate = 'out of date'
    transaction = 'transaction'
    accepted = 'tx accepted'
    # Phase 3 — proposer announces commit to the group once majority
    # acceptance is reached.  Acceptors handle this by writing
    # (task_id, proposer_id, score) to their own history, which is
    # how bilateral Transactions form: when peer A and peer B each
    # submit a TransactionScore for the same task_id, each commit
    # broadcast lets the other side fill the missing slot.  Without
    # this, every peer's local history is single-sided (only its own
    # submissions) and CTFT can never find a bilateral entry.
    committed = 'tx committed'
    outdated = 'update needed'
    update = 'latest update'
    rep_req = 'request reputation'
    rep_resp = 'reputation response'
    # History-only reputation score for observer/dashboard use:
    # deterministic EMA over committed bilateral txs (see
    # ReputationProcess._consensus_reputation). Distinct request op
    # so peer-side callers keep their identity-dependent CTFT scoring
    # via rep_req; the reply reuses rep_resp so automate.py's
    # latest_reputation dispatch consumes it unchanged.
    consensus_rep_req = 'request consensus reputation'
    # Batched form of consensus_rep_req: ONE request naming many subjects,
    # answered with one roster. The per-subject form makes an observer-by-subject
    # sweep cost N**2 messages per round (the inspector's transitive-trust round
    # is exactly that sweep); this makes it N. Semantics are otherwise identical
    # -- same deterministic history-only score per subject, reply reused as
    # rep_resp, and automate.py already captures a multi-element roster one
    # entry per peer, so nothing on the response side changes.
    #
    # A responder answers for every named subject EXCEPT itself: a self-pair is
    # not part of the observer-by-subject sweep, and excluding it responder-side
    # is what lets one request body serve every observer in a round (identical
    # bytes, so identical signature). See doc/architecture/reputation.md.
    consensus_rep_batch_req = 'request consensus reputation batch'
    # AT -> app pull (doc/architecture/app-peer-carrier.md). Spelled EXACTLY as C's
    # AT_APP_ROSTER_REQUEST ("app_roster_request", message.h) because the
    # protocol strings are the wire form shared with the C twin -- a shortened
    # or prettified spelling here breaks Python<->C interop.
    #
    # This is the only path on which `rated=false` can cross: every
    # change-driven emission is by construction rated, so a consumer that has
    # never pulled cannot tell "AT holds no rating" from "no message yet".
    app_roster_request = 'app_roster_request'
    # Slashing — fast-penalty path (default-off; absent in legacy
    # scenarios so byte-pinned corpora are unaffected). A detector
    # broadcasts `slash_propose` (a SlashAttestation); members co-sign
    # with `slash_sign`; on quorum the slasher broadcasts `slash_final`
    # (a SignedSlash) and every node floors the target's reputation at the top of
    # _consensus_reputation/_compute_reputation, bypassing the slow EMA. Mirrors the
    # transaction/accepted/committed three-phase shape. See reputation.py
    # SlashAttestation and doc/architecture/reputation.md.
    slash_propose = 'slash propose'
    slash_sign = 'slash sign'
    slash_final = 'slash final'
    # Phase 2 — quorum-signed Merkle checkpoints (default-off; absent in
    # legacy scenarios so byte-pinned corpora are unaffected). A proposer
    # broadcasts `checkpoint_propose` (a Checkpoint over its window_root);
    # each member co-signs with `checkpoint_sign` ONLY if its own
    # window_root matches; on quorum the proposer broadcasts
    # `checkpoint_final` (a SignedCheckpoint) and every node stores it as the
    # latest finalized commitment to the agreed committed window. Mirrors the
    # slash three-phase shape. See reputation.py Checkpoint/SignedCheckpoint
    # and reputation-vs-blockchain-analysis.md §2.1.
    checkpoint_propose = 'checkpoint propose'
    checkpoint_sign = 'checkpoint sign'
    checkpoint_final = 'checkpoint final'
    # Deep resolution (doc/architecture/gateway-reputation-tree.md): one peer, on
    # demand, at any depth.
    #
    # The gateway tree scores a peer against the chain its transactions
    # actually landed in, and a node holds chains only for the groups it is a
    # member of. A peer two or more levels down is therefore unscoreable
    # locally, and enumerating the whole subtree to fix that costs the size of
    # the TREE on every query while the need is one PEER. So: `rep_resolve`
    # asks for a single peer and is relayed hop by hop toward whoever holds
    # its chain; `rep_resolved` carries the answer back along the reverse
    # path. Cost is O(depth) messages for a case assumed rare, and no node
    # outside a boundary ever exchanges a message with a node inside it.
    #
    # Both directions are relayed rather than answered directly so the
    # topology stays opaque: a requestor learns a score, never the shape of
    # the subtree that produced it, and a deep holder never learns who asked.
    # The relay costs each gateway a TTL'd pending table (query id -> the
    # neighbour to answer), which is the only state this adds anywhere. No
    # handler ever blocks awaiting a child — the query and the answer are
    # independent messages, preserving the non-blocking model that the
    # 2026-07-23 requestor-side-BFS decision established for the identity
    # roster.
    #
    # The answer is EVIDENCE-BACKED (user's call, 2026-08-13): it carries the
    # quorum-signed checkpoint and the peer's committed entries with their
    # RFC 6962 inclusion proofs, so the requestor verifies the score itself
    # and neither the holder nor any relay on the path can fabricate a number.
    # See reputation.py ResolvedReputation.
    rep_resolve = 'resolve reputation'
    rep_resolved = 'resolved reputation'
