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

#include <uuid/uuid.h>
#include <sodium.h>

#include "utilities/exception.h"
#include "utilities/allocation.h"
#include "structures/merkle.h"
#include "algorithms/algorithms.h"

#define AGREEMENT_MAX_VOTERS 128
#define AGREEMENT_ENCODING "utf-8"

/**
 * @brief Transmissible vote structure.
 */
typedef struct {
    uuid_t uuid;             /**< Voter identity */
    uint8_t digest[MERKLE_HASH_LEN]; /**< Hash of proposal */
    bool approval;           /**< Yea/nay */
    uint8_t *nonce;          /**< Optional nonce */
    size_t nonce_len;
} agreement_proof_t;

/**
 * @brief Initialize an agreement proof.
 */
void agreement_proof_init(agreement_proof_t *proof);

/**
 * @brief Free dynamic members of a proof.
 */
void agreement_proof_free(agreement_proof_t *proof);

/**
 * @brief Abstract voter: uuid + rank + verify capability.
 */
typedef struct {
    uuid_t uuid;
    double rank;
    /** Verify that a proof was signed by this voter. NULL if not applicable. */
    bool (*verify)(const void *voter, const agreement_proof_t *proof, const uint8_t *sig, size_t sig_len);
    void *user_data;
} agreement_voter_t;

/**
 * @brief Collected vote: (blob, proof, signature).
 */
typedef struct {
    merkle_blob_t *blob;
    agreement_proof_t proof;
    uint8_t *sig;
    size_t sig_len;
} collected_vote_t;

/**
 * @brief Vote collection for a single blob (keyed by blob UUID).
 */
typedef struct {
    uuid_t blob_uuid;
    collected_vote_t *votes;
    size_t vote_count;
    size_t vote_capacity;
} vote_collection_t;

/**
 * @brief Agreement protocol: manages voters and vote collection.
 */
typedef struct {
    agreement_voter_t *myself;
    agreement_voter_t **voters;
    size_t voter_count;
    vote_collection_t *collections;
    size_t collection_count;
    size_t collection_capacity;
    block_impl_t algorithm;
    /* POW state */
    int pow_difficulty;
    /* POS state (used during finalize) */
    double yea;
    double nay;
    /* POA state */
    double poa_threshold;
} agreement_protocol_t;

/**
 * @brief Initialize an agreement protocol.
 */
int agreement_protocol_init(agreement_protocol_t *proto,
                            agreement_voter_t *myself,
                            agreement_voter_t **voters, size_t voter_count,
                            block_impl_t algorithm);

/**
 * @brief Generate a proof for a blob (method depends on algorithm).
 */
int agreement_prove(agreement_protocol_t *proto, merkle_blob_t *blob,
                    agreement_proof_t *proof_out);

/**
 * @brief Verify a proof and collect the vote.
 */
int agreement_verify(agreement_protocol_t *proto, merkle_blob_t *blob,
                     const agreement_proof_t *proof,
                     const uint8_t *sig, size_t sig_len);

/**
 * @brief Finalize: count votes and determine acceptance.
 * @return true if accepted, false if rejected
 */
bool agreement_finalize(agreement_protocol_t *proto, merkle_blob_t *blob);

/**
 * @brief Free all internal state.
 */
void agreement_protocol_free(agreement_protocol_t *proto);

/**
 * @brief Set POW difficulty (default: 2).
 */
void agreement_set_pow_difficulty(agreement_protocol_t *proto, int difficulty);

/**
 * @brief Set POA threshold rank.
 */
void agreement_set_poa_threshold(agreement_protocol_t *proto, double threshold);

#define EAGR_NOVOTE 226
DECLARE_ERROR(EAGR_NOVOTE, "No votes collected for blob");

#endif // AGREEMENT_H
