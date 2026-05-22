/********************
 *  Copyright 2025 Sean M. Brennan and contributors
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *******************/

#ifndef REPUTATION_H
#define REPUTATION_H

/** @addtogroup internal_reputation
 *  @{
 */

#include <stdbool.h>
#include <stdint.h>
#include <uuid/uuid.h>
#include <jansson.h>

#include "structures/map.h"
#include "structures/array.h"
#include "identity/identity.h"
#include "utilities/exception.h"
#include "processes/capabilities.h"   /* CAP_NAMELEN */
#include "autonomous_trust/algorithms/paxos.h"

/****************************
 * Protocol constants — must match the Python ReputationProtocol enum
 * (src/autonomous-trust/.../reputation/protocol.py) verbatim so a
 * Python node and a C node can interoperate. The conformance corpus
 * uses these strings as the `function` field on every reputation
 * scenario step. Changing any of these is a wire-protocol break.
 *
 * Declared as writable char arrays (not `#define` string literals) so
 * `net_msg.function = REP_PROTO_X` is type-correct under
 * `-Wwrite-strings` without the `(char *)` cast that used to obscure
 * the const violation. Definitions live in `rep_proc.c`.
 *
 * Note on string literals: `REP_PROTO_REP_REQ` etc. matches Python's
 * `ReputationProtocol.rep_req` verbatim; do NOT tidy
 * `"request reputation"` back to "reputation request" — breaks
 * Python↔C interop. See BUGS.md §P9.
 ****************************/

extern char REP_PROTO_REQUEST[];
extern char REP_PROTO_GRANT[];
extern char REP_PROTO_NACK[];
extern char REP_PROTO_BACKDATE[];
extern char REP_PROTO_TX[];
extern char REP_PROTO_ACCEPTED[];
/* Phase 3 — proposer broadcasts the committed (task_id, peer_id,
 * score) tuple to the group after handle_accepted reaches majority.
 * Acceptors handle this by writing the entry to their own history,
 * which is how bilateral Transactions form across all peers' views.
 * Matches Python's ReputationProtocol.committed verbatim. */
extern char REP_PROTO_COMMITTED[];
extern char REP_PROTO_OUTDATED[];
extern char REP_PROTO_UPDATE[];
extern char REP_PROTO_REP_REQ[];
extern char REP_PROTO_REP_RESP[];
/* History-only reputation score for observer/dashboard use. Distinct
 * request op so peer-side callers keep their identity-dependent CTFT
 * scoring via rep_req; reply reuses REP_PROTO_REP_RESP so the existing
 * response dispatch consumes it unchanged. Mirrors Python's
 * ReputationProtocol.consensus_rep_req — string must match verbatim. */
extern char REP_PROTO_CONSENSUS_REP_REQ[];
extern char REP_PROTO_LOCAL_QUERY[];
extern char REP_PROTO_LOCAL_RESP[];

/****************************
 * Reputation tuning constants — mirror Python class attributes in
 * src/autonomous-trust/.../reputation/repprocess.py:ReputationProcess.
 ****************************/

/* Hysteresis band for the CTFT ↔ pure-reputation mode switch in
 * reputation_compute / handle_rep_request. A single 0.5 threshold
 * made peers hovering near 0.5 flip scoring functions every tick;
 * widening the switch band so a peer must clear COOP_ENTER to graduate
 * and fall below COOP_EXIT to fall back removes the chatter without
 * altering either scoring function. */
#define COOP_ENTER 0.55
#define COOP_EXIT  0.45

/* EMA half-life (in committed bilateral txs) for reputation_consensus.
 * Smaller → faster crash on a peer that begins producing bad scores,
 * slower rebuild for the rest. 20 gives α ≈ 0.034. */
#define CONSENSUS_EMA_HALF_LIFE 20

/* FIFO cap on rep_state.committed_paxos_rounds (rep_proc.c). Paired
 * with MAX_CHAIN_LEN so neither dedup structure grows without bound.
 * Mirrors Python's ReputationProcess.COMMITTED_ROUNDS_CAP. Sized for
 * ~2 min of in-flight protection at ~16 paxos commits/sec — small
 * caps let late ACCEPTEDs bypass the dedup and trigger redundant
 * commit re-broadcasts that fan out to every peer (cheap on the
 * receivers thanks to the tx_history tombstone, but still real
 * network/dispatch cost). 2000 eliminates the spurious traffic
 * entirely. */
#define COMMITTED_ROUNDS_CAP 2000

/****************************
 * Transaction score (pending Paxos request)
 ****************************/

typedef struct {
    smrt_ptr_t;
    uuid_t task_uuid;
    double score;
    /* Optional: name of the Capability that produced this TS. Used by
     * _pure_reputation to look up transaction_weight (Slice 3). Empty
     * string == "unknown / legacy" — weight defaults to 1. Mirrors
     * Python TransactionScore.capability_name. See
     * doc/architecture/trust-tiers.md §4.4. */
    char capability_name[CAP_NAMELEN+1];
} tx_score_t;

/****************************
 * Transaction record (chain entry)
 ****************************/

typedef struct {
    uuid_t task_uuid;
    uuid_t p1_uuid;
    double p1_score;
    bool   p1_set;
    uuid_t p2_uuid;
    double p2_score;
    bool   p2_set;
    int    index;
} transaction_t;

/****************************
 * Transaction history (block chain)
 ****************************/

/* Cap on the resident chain. When full, tx_history_update evicts
 * chain[0] (FIFO) and shifts the remainder down by one slot,
 * renumbering map entries to match. Mirrors Python's
 * TransactionHistory.DEFAULT_MAX_CHAIN_LEN — keep in lockstep with
 * src/autonomous-trust/.../reputation/reputation.py.
 *
 * Slot-index semantics: tx->index and map values are slot positions
 * in chain[], not the monotonic absolute index Python uses. Wire
 * interop via tx_history_era_to_json/from_json remains because
 * era_from_json bulk-loads (treating sender's chain as authoritative)
 * rather than incrementally catching up. */
#define MAX_CHAIN_LEN 200

typedef struct {
    transaction_t chain[MAX_CHAIN_LEN];
    int           chain_len;
    map_t         task_map;   /* uuid_str -> int (chain index) */
    map_t         peer_map;   /* uuid_str -> array_t* (list of indices) */
    /* Tombstone of evicted task_uuids — FIFO ring sized to
     * MAX_CHAIN_LEN so we remember the most-recent MAX_CHAIN_LEN
     * evictions. tx_history_update refuses to re-create entries
     * for tombstoned tasks; without this, a late `committed`
     * broadcast for an evicted task would build a half-completed
     * Transaction in task_map that the counterparty's late
     * `committed` would complete and re-insert at the head of
     * the chain (silently evicting a legitimate recent entry).
     * Mirrors Python's TransactionHistory._evicted_task_ids. */
    char          evicted_ring[MAX_CHAIN_LEN][UUID_STRING_LEN + 1];
    int           evicted_ring_head;  /* next slot to overwrite */
    int           evicted_ring_len;   /* up to MAX_CHAIN_LEN */
    map_t         evicted_set;        /* uuid_str -> integer_data(1) */
} tx_history_t;

/*@
  requires \valid(hist);
  allocates *hist;
  behavior success:
    ensures \result == 0;
    ensures *hist != \null;
  behavior failure:
    ensures \result != 0;
  disjoint behaviors;
*/
int  tx_history_create(tx_history_t **hist);

/*@
  requires \valid(hist);
  assigns *hist;
  ensures \result == 0 || \result != 0;
  ensures \result == 0 ==> hist->chain_len == 0;
*/
int  tx_history_init(tx_history_t *hist);

/*@
  requires hist == \null || \valid(hist);
  frees hist;
*/
void tx_history_destroy(tx_history_t *hist);

/*@
  requires \valid(hist);
  requires score >= 0.0 && score <= 1.0;
  assigns hist->chain[0 .. MAX_CHAIN_LEN - 1],
          hist->chain_len, hist->task_map, hist->peer_map;
  ensures \result == 0;
*/
int  tx_history_update(tx_history_t *hist, const uuid_t task_uuid,
                       const uuid_t peer_uuid, double score);

/*@
  requires \valid(hist);
  requires \valid(out);
  assigns *out;
  behavior found:
    ensures \result == 0;
  behavior not_found:
    ensures \result != 0;
  disjoint behaviors;
*/
int  tx_history_by_task(const tx_history_t *hist, const uuid_t task_uuid,
                        transaction_t *out);

/*@
  requires \valid(hist);
  requires \valid(out + (0 .. max_out - 1));
  requires max_out > 0;
  requires \valid(out_count);
  assigns out[0 .. max_out - 1], *out_count;
  ensures *out_count >= 0 && *out_count <= max_out;
  ensures \result == 0;
*/
int  tx_history_by_peer(const tx_history_t *hist, const uuid_t peer_uuid,
                        transaction_t *out, int *out_count, int max_out);

/*@
  requires \valid(hist);
  requires \valid(out_count);
  assigns *out_count;
  ensures *out_count >= 0;
  ensures \result == 0;
*/
int  tx_history_era(const tx_history_t *hist, int start_idx, int end_idx,
                    transaction_t *out, int *out_count);

/*@
  requires \valid(hist);
  assigns \nothing;
  ensures \result == hist->chain_len;
  ensures \result >= 0;
*/
int  tx_history_len(const tx_history_t *hist);

/*@
  requires \valid(hist);
  assigns hist->task_map, hist->peer_map, hist->chain_len;
  ensures hist->chain_len == 0;
*/
void tx_history_free(tx_history_t *hist);

int  tx_history_era_to_json(const tx_history_t *hist, int start_idx, int end_idx,
                            json_t **out);
int  tx_history_era_from_json(tx_history_t *hist, const json_t *arr);

/****************************
 * Reputations map
 ****************************/

typedef struct {
    map_t scores;   /* uuid_str -> data_t* (float score) */
} reputations_t;

/*@
  requires \valid(reps);
  allocates *reps;
  behavior success:
    ensures \result == 0;
    ensures *reps != \null;
  behavior failure:
    ensures \result != 0;
  disjoint behaviors;
*/
int  reputations_create(reputations_t **reps);

/*@
  requires \valid(reps);
  assigns reps->scores;
  ensures \result == 0 || \result != 0;
*/
int  reputations_init(reputations_t *reps);

/*@
  requires reps == \null || \valid(reps);
  frees reps;
*/
void reputations_destroy(reputations_t *reps);

/*@
  requires \valid(reps);
  requires score >= 0.0 && score <= 1.0;
  assigns reps->scores;
  ensures \result == 0 || \result != 0;
*/
int  reputations_update(reputations_t *reps, const uuid_t peer_uuid, double score);

/*@
  requires \valid(reps);
  requires \valid(score);
  assigns *score;
  behavior found:
    ensures \result == 0;
    ensures *score >= 0.0 && *score <= 1.0;
  behavior not_found:
    ensures \result != 0;
  disjoint behaviors;
*/
int  reputations_get(const reputations_t *reps, const uuid_t peer_uuid, double *score);

/*@
  requires \valid(reps);
  assigns \nothing;
  ensures \result == \true || \result == \false;
*/
bool reputations_contains(const reputations_t *reps, const uuid_t peer_uuid);

/*@
  requires \valid(reps);
  requires reps->scores.length <= reps->scores.capacity;
  assigns reps->scores;
*/
void reputations_free(reputations_t *reps);

/****************************
 * Reputation algorithms
 ****************************/

typedef struct {
    smrt_ptr_t;
    double score;
    int    grant_count;
} paxos_tx_count_t;

/*@
  requires \valid(hist);
  requires \valid(reps);
  assigns \nothing;
  ensures \result >= 0.0 && \result <= 1.0;
*/
/** Pure socially-weighted average. @p task_weights is a uuid_str -> int
 *  map of per-task transaction_weight values (populated by the
 *  reputation process at proposer + receiver time); pass NULL to
 *  treat every transaction as weight 1. The weighted form lines up
 *  with Python's _pure_reputation (trust-tiers.md §5). */
double reputation_pure(const tx_history_t *hist, const reputations_t *reps,
                       const uuid_t peer_uuid,
                       const map_t *task_weights);

/*@
  requires \valid(hist);
  requires \valid(reps);
  assigns \nothing;
  ensures \result >= 0.0 && \result <= 1.0;
*/
double reputation_contrite_tft(const tx_history_t *hist, const reputations_t *reps,
                               const uuid_t self_uuid, const uuid_t peer_uuid);

/*@
  requires \valid(hist);
  requires \valid(reps);
  assigns \nothing;
  ensures \result >= 0.0 && \result <= 1.0;
*/
/** @p task_weights forwarded to reputation_pure on the pure branch; NULL
 *  → unweighted aggregator. CTFT branch ignores it. */
double reputation_compute(const tx_history_t *hist, const reputations_t *reps,
                          const uuid_t self_uuid, const uuid_t peer_uuid,
                          const map_t *task_weights);

/*@
  requires \valid(hist);
  assigns \nothing;
  ensures \result >= 0.0 && \result <= 1.0;
*/
/** Deterministic, history-only reputation score over the consensus tx
 *  chain. Walks committed bilateral transactions involving @p peer_uuid
 *  in chain order and folds each counterparty-side score into an
 *  exponentially-weighted moving average with half-life
 *  CONSENSUS_EMA_HALF_LIFE. @p task_weights weights each EMA update by
 *  running it @c w times (a tier-w transaction moves the EMA exactly
 *  as far as @c w tier-1 transactions would, preserving the [0,1]
 *  range). NULL → unweighted. Mirrors Python's
 *  ReputationProcess._consensus_reputation. */
double reputation_consensus(const tx_history_t *hist, const uuid_t peer_uuid,
                            const map_t *task_weights);

/* paxos_id_index is provided by algorithms/paxos.h */

/****************************
 * Error codes
 ****************************/

#define EREP_NOTX 250
DECLARE_ERROR(EREP_NOTX, "Transaction not found");

#define EREP_NOPEER 251
DECLARE_ERROR(EREP_NOPEER, "Peer not found in reputation map");

#define EREP_CHAIN_FULL 252
DECLARE_ERROR(EREP_CHAIN_FULL, "Transaction chain is full");


/** @} */ /* end of internal_reputation */

#endif  /* REPUTATION_H */
