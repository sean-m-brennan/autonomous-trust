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

#include <stdbool.h>
#include <uuid/uuid.h>
#include <jansson.h>

#include "structures/map_priv.h"
#include "structures/data_priv.h"
#include "identity/identity.h"
#include "utilities/exception.h"

/****************************
 * Protocol constants (must match Python ReputationProtocol)
 ****************************/

#define REP_PROTO_REQUEST   "ask permission"
#define REP_PROTO_GRANT     "permission granted"
#define REP_PROTO_NACK      "try again"
#define REP_PROTO_BACKDATE  "out of date"
#define REP_PROTO_TX        "transaction"
#define REP_PROTO_ACCEPTED  "tx accepted"
#define REP_PROTO_OUTDATED  "update needed"
#define REP_PROTO_UPDATE    "latest update"
#define REP_PROTO_REP_REQ   "reputation request"
#define REP_PROTO_REP_RESP  "reputation response"

/****************************
 * Transaction score
 ****************************/

typedef struct {
    uuid_t task_uuid;
    double score;
} tx_score_t;

/****************************
 * Transaction (two-party score exchange)
 ****************************/

typedef struct {
    uuid_t task_uuid;
    uuid_t p1_uuid;
    double p1_score;
    bool p1_set;
    uuid_t p2_uuid;
    double p2_score;
    bool p2_set;
    int index;
} transaction_t;

/****************************
 * Transaction history (chain)
 ****************************/

#define MAX_CHAIN_LEN 4096

typedef struct {
    transaction_t chain[MAX_CHAIN_LEN];
    int chain_len;
    map_t task_map;   /* uuid_str -> int (chain index) */
    map_t peer_map;   /* uuid_str -> array_t* of int (chain indices) */
} tx_history_t;

int tx_history_init(tx_history_t *hist);
int tx_history_update(tx_history_t *hist, const uuid_t task_uuid,
                      const uuid_t peer_uuid, double score);
int tx_history_by_task(const tx_history_t *hist, const uuid_t task_uuid, transaction_t *out);
int tx_history_by_peer(const tx_history_t *hist, const uuid_t peer_uuid,
                       transaction_t *out, int *out_count, int max_out);
int tx_history_era(const tx_history_t *hist, int start_idx, int end_idx,
                   transaction_t *out, int *out_count);
int tx_history_len(const tx_history_t *hist);
void tx_history_free(tx_history_t *hist);

/* JSON serialization for chain sync */
int tx_history_era_to_json(const tx_history_t *hist, int start_idx, int end_idx, json_t **out);
int tx_history_era_from_json(tx_history_t *hist, const json_t *arr);

/****************************
 * Reputations map (peer -> score)
 ****************************/

typedef struct {
    map_t scores;   /* uuid_str -> double */
} reputations_t;

int reputations_init(reputations_t *reps);
int reputations_update(reputations_t *reps, const uuid_t peer_uuid, double score);
int reputations_get(const reputations_t *reps, const uuid_t peer_uuid, double *score);
bool reputations_contains(const reputations_t *reps, const uuid_t peer_uuid);
void reputations_free(reputations_t *reps);

/****************************
 * Reputation algorithms
 ****************************/

/**
 * Pure socially-weighted average:
 *   sum(counterparty_score * reputation[counterparty]) / count
 */
double reputation_pure(const tx_history_t *hist, const reputations_t *reps,
                       const uuid_t peer_uuid);

/**
 * Game-theoretic contrite tit-for-tat:
 * - If no history, return 0.49
 * - Check last peer score and own standing to decide cooperate/defect
 */
double reputation_contrite_tft(const tx_history_t *hist, const reputations_t *reps,
                               const uuid_t self_uuid, const uuid_t peer_uuid);

/**
 * Gate on previous score > 0.5 to select algorithm:
 * - If score > 0.5: use reputation_pure
 * - Else: use reputation_contrite_tft
 */
double reputation_compute(const tx_history_t *hist, const reputations_t *reps,
                          const uuid_t self_uuid, const uuid_t peer_uuid);

/****************************
 * Paxos ID helpers
 ****************************/

/**
 * Compute Paxos ID index: id1 + id2/10^digits(id2)
 * Direct port from Python.
 */
double paxos_id_index(double id1, double id2);

/****************************
 * Error codes
 ****************************/

#define EREP_NOTX 250
DECLARE_ERROR(EREP_NOTX, "Transaction not found");

#define EREP_NOPEER 251
DECLARE_ERROR(EREP_NOPEER, "Peer not found in reputation map");

#define EREP_CHAIN_FULL 252
DECLARE_ERROR(EREP_CHAIN_FULL, "Transaction chain is full");

#endif  /* REPUTATION_H */
