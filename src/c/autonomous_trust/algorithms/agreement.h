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

#ifndef AGREEMENT_H
#define AGREEMENT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "structures/array.h"
#include "structures/map.h"
#include "structures/merkle.h"
#include "utilities/exception.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AGREEMENT_UUID_LEN 37

typedef struct {
    char uuid[AGREEMENT_UUID_LEN];
    uint8_t *digest;
    size_t digest_len;
    bool approval;
    uint8_t *nonce;
    size_t nonce_len;
} agreement_proof_t;

typedef struct {
    char uuid[AGREEMENT_UUID_LEN];
    int rank;
} agreement_voter_t;

typedef enum {
    AGREEMENT_AUTHORITY,
    AGREEMENT_STAKE,
    AGREEMENT_WORK
} agreement_type_t;

typedef struct agreement_protocol_s agreement_protocol_t;

/* vtable function pointer types */
typedef bool (*pre_verify_fn)(agreement_protocol_t *proto, merkle_blob_t *blob,
                              agreement_proof_t *proof, const uint8_t *sig, size_t sig_len);
typedef void (*prep_vote_fn)(agreement_protocol_t *proto);
typedef void (*count_vote_fn)(agreement_protocol_t *proto, merkle_blob_t *blob,
                              agreement_proof_t *proof, agreement_voter_t *voter,
                              int *rank_out, bool *approval_out);
typedef bool (*accumulate_votes_fn)(agreement_protocol_t *proto, int *ranks, bool *approvals, int count);

struct agreement_protocol_s {
    agreement_voter_t myself;
    agreement_voter_t *voters;
    int voter_count;
    map_t *votes;       /* uuid -> array of (blob, proof, sig) */
    agreement_type_t type;

    /* vtable */
    pre_verify_fn pre_verify;
    prep_vote_fn prep_vote;
    count_vote_fn count_vote;
    accumulate_votes_fn accumulate_votes;

    /* type-specific state */
    union {
        struct {
            int threshold_rank;
        } authority;
        struct {
            double yea;
            double nay;
            double (*get_stake)(agreement_voter_t *voter);
        } stake;
        struct {
            int difficulty;
            array_t *approved;
        } work;
    } state;
};

int agreement_proof_create(const char *uuid, const uint8_t *digest, size_t digest_len,
                           bool approval, const uint8_t *nonce, size_t nonce_len,
                           agreement_proof_t **proof);

void agreement_proof_free(agreement_proof_t *proof);

int agreement_proof_sync_out(agreement_proof_t *proof, void *proto_msg);
int agreement_proof_sync_in(void *proto_msg, agreement_proof_t *proof);

int agreement_protocol_create(agreement_voter_t *myself,
                              agreement_voter_t *others, int other_count,
                              agreement_type_t type,
                              agreement_protocol_t **proto);

int agreement_by_authority_create(agreement_voter_t *myself,
                                  agreement_voter_t *others, int other_count,
                                  int threshold_rank,
                                  agreement_protocol_t **proto);

int agreement_by_stake_create(agreement_voter_t *myself,
                              agreement_voter_t *others, int other_count,
                              double (*get_stake)(agreement_voter_t *voter),
                              agreement_protocol_t **proto);

int agreement_by_work_create(agreement_voter_t *myself,
                             agreement_voter_t *others, int other_count,
                             int difficulty,
                             agreement_protocol_t **proto);

int agreement_prove(agreement_protocol_t *proto, merkle_blob_t *blob,
                    agreement_proof_t **proof_out);

bool agreement_verify(agreement_protocol_t *proto, merkle_blob_t *blob,
                      agreement_proof_t *proof, const uint8_t *sig, size_t sig_len);

bool agreement_finalize(agreement_protocol_t *proto, merkle_blob_t *blob);

void agreement_protocol_free(agreement_protocol_t *proto);

#ifdef __cplusplus
} // extern "C"
#endif

#endif  // AGREEMENT_H
