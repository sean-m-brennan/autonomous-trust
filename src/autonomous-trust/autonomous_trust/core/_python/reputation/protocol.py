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
    # Slashing — fast-penalty path (default-off; absent in legacy
    # scenarios so byte-pinned corpora are unaffected). A detector
    # broadcasts `slash_propose` (a SlashAttestation); members co-sign
    # with `slash_sign`; on quorum the slasher broadcasts `slash_final`
    # (a SignedSlash) and every node floors the target's reputation at
    # the top of _consensus_reputation/_compute_reputation, bypassing the
    # slow EMA. Mirrors the transaction/accepted/committed three-phase
    # shape. See reputation.py SlashAttestation and
    # doc/architecture/reputation.md.
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
