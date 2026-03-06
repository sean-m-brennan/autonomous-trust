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

#ifndef HISTORY_H
#define HISTORY_H

#include <stdbool.h>
#include <stddef.h>

#include "identity.h"
#include "peers.h"
#include "structures/dag.h"
#include "structures/merkle.h"
#include "algorithms/agreement.h"
#include "utilities/logger.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    merkle_blob_t base;             /* must be first for casting */
    public_identity_t *identity;
    char originator_uuid[MERKLE_UUID_LEN];
} identity_obj_t;

int identity_obj_create(public_identity_t *identity, const char *originator_uuid,
                        identity_obj_t **obj);

int identity_obj_designation(const identity_obj_t *obj, uint8_t **out, size_t *out_len);

void identity_obj_free(identity_obj_t *obj);

typedef struct {
    step_dag_t dag;
    merkle_tree_t *merkle;
    agreement_protocol_t *agreement;
    peers_t *peers;
    logger_t *logger;
    int timeout;
    array_t *blacklist;
} identity_history_t;

int identity_history_create(agreement_voter_t *myself,
                            peers_t *peers,
                            logger_t *logger,
                            int timeout,
                            identity_history_t **history);

int identity_history_insert_peer(identity_history_t *history,
                                 public_identity_t *who);

int identity_history_prove_existence(identity_history_t *history,
                                     merkle_blob_t *item,
                                     merkle_proof_step_t **proof_out,
                                     int *proof_len);

bool identity_history_verify_existence(identity_history_t *history,
                                       merkle_blob_t *item,
                                       merkle_proof_step_t *proof,
                                       int proof_len);

int identity_history_share(identity_history_t *history,
                           array_t **steps_out);

int identity_history_hear(identity_history_t *history,
                          linked_step_t **steps, size_t count);

void identity_history_free(identity_history_t *history);

int identity_history_by_authority_create(public_identity_t *myself,
                                         peers_t *peers,
                                         logger_t *logger,
                                         int timeout,
                                         int threshold_rank,
                                         identity_history_t **history);

int identity_history_by_stake_create(public_identity_t *myself,
                                     peers_t *peers,
                                     logger_t *logger,
                                     int timeout,
                                     double (*get_stake)(agreement_voter_t *),
                                     identity_history_t **history);

int identity_history_by_work_create(public_identity_t *myself,
                                    peers_t *peers,
                                    logger_t *logger,
                                    int timeout,
                                    int difficulty,
                                    identity_history_t **history);

#ifdef __cplusplus
} // extern "C"
#endif

#endif  // HISTORY_H
