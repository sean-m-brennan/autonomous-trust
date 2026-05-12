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
#include "autonomous_trust/algorithms/paxos.h"

/****************************
 * Protocol constants — must match the Python ReputationProtocol enum
 * (src/autonomous-trust/.../reputation/protocol.py) verbatim so a
 * Python node and a C node can interoperate. The conformance corpus
 * uses these strings as the `function` field on every reputation
 * scenario step. Changing any of these is a wire-protocol break.
 ****************************/

#define REP_PROTO_REQUEST  "ask permission"
#define REP_PROTO_GRANT    "permission granted"
#define REP_PROTO_NACK     "try again"
#define REP_PROTO_BACKDATE "out of date"
#define REP_PROTO_TX       "transaction"
#define REP_PROTO_ACCEPTED "tx accepted"
#define REP_PROTO_OUTDATED "update needed"
#define REP_PROTO_UPDATE   "latest update"
#define REP_PROTO_REP_REQ  "request reputation"  /* matches Python's
                                                   * ReputationProtocol.rep_req
                                                   * verbatim; do NOT tidy back to
                                                   * "reputation request" — breaks
                                                   * Python<->C interop. See
                                                   * BUGS.md §P9. */
#define REP_PROTO_REP_RESP "reputation response"
#define REP_PROTO_LOCAL_QUERY  "local_rep_query"    /* Local IPC: query a peer's score */
#define REP_PROTO_LOCAL_RESP   "local_rep_response"  /* Local IPC: reply with score */

/****************************
 * Transaction score (pending Paxos request)
 ****************************/

typedef struct {
    smrt_ptr_t;
    uuid_t task_uuid;
    double score;
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

#define MAX_CHAIN_LEN 4096

typedef struct {
    transaction_t chain[MAX_CHAIN_LEN];
    int           chain_len;
    map_t         task_map;   /* uuid_str -> int (chain index) */
    map_t         peer_map;   /* uuid_str -> array_t* (list of indices) */
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
  behavior full:
    assumes hist->chain_len >= MAX_CHAIN_LEN;
    ensures \result != 0;
  behavior success:
    assumes hist->chain_len < MAX_CHAIN_LEN;
    ensures \result == 0;
  disjoint behaviors;
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
double reputation_pure(const tx_history_t *hist, const reputations_t *reps,
                       const uuid_t peer_uuid);

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
double reputation_compute(const tx_history_t *hist, const reputations_t *reps,
                          const uuid_t self_uuid, const uuid_t peer_uuid);

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
