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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "algorithms/agreement.h"

DEFINE_ERROR(EAGR_NOVOTE, "No votes collected for blob");

/****************************
 * AgreementProof
 ****************************/

void agreement_proof_init(agreement_proof_t *proof)
{
    memset(proof, 0, sizeof(agreement_proof_t));
}

void agreement_proof_free(agreement_proof_t *proof)
{
    if (proof == NULL)
        return;
    free(proof->nonce);
    proof->nonce = NULL;
    proof->nonce_len = 0;
}

/****************************
 * Vote collection
 ****************************/

static vote_collection_t *find_collection(agreement_protocol_t *proto, const uuid_t blob_uuid)
{
    for (size_t i = 0; i < proto->collection_count; i++)
    {
        if (uuid_compare(proto->collections[i].blob_uuid, blob_uuid) == 0)
            return &proto->collections[i];
    }
    return NULL;
}

static vote_collection_t *get_or_create_collection(agreement_protocol_t *proto, const uuid_t blob_uuid)
{
    vote_collection_t *coll = find_collection(proto, blob_uuid);
    if (coll != NULL)
        return coll;

    if (proto->collection_count >= proto->collection_capacity)
    {
        size_t new_cap = (proto->collection_capacity == 0) ? 8 : proto->collection_capacity * 2;
        vote_collection_t *nc = realloc(proto->collections, new_cap * sizeof(vote_collection_t));
        if (nc == NULL)
            return NULL;
        proto->collections = nc;
        proto->collection_capacity = new_cap;
    }

    coll = &proto->collections[proto->collection_count++];
    memset(coll, 0, sizeof(vote_collection_t));
    uuid_copy(coll->blob_uuid, blob_uuid);
    return coll;
}

static int collection_add_vote(vote_collection_t *coll, merkle_blob_t *blob,
                               const agreement_proof_t *proof,
                               const uint8_t *sig, size_t sig_len)
{
    if (coll->vote_count >= coll->vote_capacity)
    {
        size_t new_cap = (coll->vote_capacity == 0) ? 8 : coll->vote_capacity * 2;
        collected_vote_t *nv = realloc(coll->votes, new_cap * sizeof(collected_vote_t));
        if (nv == NULL)
            return SYS_EXCEPTION();
        coll->votes = nv;
        coll->vote_capacity = new_cap;
    }

    collected_vote_t *v = &coll->votes[coll->vote_count++];
    v->blob = blob;
    memcpy(&v->proof, proof, sizeof(agreement_proof_t));
    /* Copy nonce if present */
    v->proof.nonce = NULL;
    if (proof->nonce != NULL && proof->nonce_len > 0)
    {
        v->proof.nonce = malloc(proof->nonce_len);
        if (v->proof.nonce != NULL)
        {
            memcpy(v->proof.nonce, proof->nonce, proof->nonce_len);
            v->proof.nonce_len = proof->nonce_len;
        }
    }
    /* Copy signature */
    v->sig = NULL;
    v->sig_len = 0;
    if (sig != NULL && sig_len > 0)
    {
        v->sig = malloc(sig_len);
        if (v->sig != NULL)
        {
            memcpy(v->sig, sig, sig_len);
            v->sig_len = sig_len;
        }
    }
    return 0;
}

static void collection_free(vote_collection_t *coll)
{
    for (size_t i = 0; i < coll->vote_count; i++)
    {
        free(coll->votes[i].proof.nonce);
        free(coll->votes[i].sig);
    }
    free(coll->votes);
    coll->votes = NULL;
    coll->vote_count = 0;
}

/****************************
 * Protocol init/free
 ****************************/

int agreement_protocol_init(agreement_protocol_t *proto,
                            agreement_voter_t *myself,
                            agreement_voter_t **voters, size_t voter_count,
                            block_impl_t algorithm)
{
    if (proto == NULL || myself == NULL)
        return EXCEPTION(EINVAL);

    memset(proto, 0, sizeof(agreement_protocol_t));
    proto->myself = myself;
    proto->voters = voters;
    proto->voter_count = voter_count;
    proto->algorithm = algorithm;
    proto->pow_difficulty = 2;
    proto->poa_threshold = 0.0;
    return 0;
}

void agreement_set_pow_difficulty(agreement_protocol_t *proto, int difficulty)
{
    proto->pow_difficulty = difficulty;
}

void agreement_set_poa_threshold(agreement_protocol_t *proto, double threshold)
{
    proto->poa_threshold = threshold;
}

void agreement_protocol_free(agreement_protocol_t *proto)
{
    if (proto == NULL)
        return;
    for (size_t i = 0; i < proto->collection_count; i++)
        collection_free(&proto->collections[i]);
    free(proto->collections);
    proto->collections = NULL;
    proto->collection_count = 0;
}

/****************************
 * Prove: generate proof
 ****************************/

static int prove_basic(agreement_protocol_t *proto, merkle_blob_t *blob,
                       agreement_proof_t *proof)
{
    agreement_proof_init(proof);
    uuid_copy(proof->uuid, proto->myself->uuid);
    merkle_blob_hash(blob, NULL, 0, proof->digest);
    proof->approval = true;
    return 0;
}

/**
 * Proof-of-Work: find nonce such that hash starts with N zero bytes.
 */
static int prove_pow(agreement_protocol_t *proto, merkle_blob_t *blob,
                     agreement_proof_t *proof)
{
    agreement_proof_init(proof);
    uuid_copy(proof->uuid, proto->myself->uuid);
    proof->approval = true;

    int difficulty = proto->pow_difficulty;
    uint8_t hash[MERKLE_HASH_LEN];
    char nonce_str[32];
    unsigned long nonce = 0;

    while (1)
    {
        snprintf(nonce_str, sizeof(nonce_str), "%lu", nonce);
        size_t nlen = strlen(nonce_str);
        merkle_blob_hash(blob, (uint8_t *)nonce_str, nlen, hash);

        /* Check leading zero bytes */
        bool found = true;
        for (int i = 0; i < difficulty && i < MERKLE_HASH_LEN; i++)
        {
            if (hash[i] != 0)
            {
                found = false;
                break;
            }
        }
        if (found)
            break;
        nonce++;
    }

    memcpy(proof->digest, hash, MERKLE_HASH_LEN);
    proof->nonce_len = strlen(nonce_str);
    proof->nonce = malloc(proof->nonce_len);
    if (proof->nonce != NULL)
        memcpy(proof->nonce, nonce_str, proof->nonce_len);

    return 0;
}

int agreement_prove(agreement_protocol_t *proto, merkle_blob_t *blob,
                    agreement_proof_t *proof_out)
{
    if (proto == NULL || blob == NULL || proof_out == NULL)
        return EXCEPTION(EINVAL);

    switch (proto->algorithm)
    {
    case POW:
        return prove_pow(proto, blob, proof_out);
    case POS:
    case POA:
    default:
        return prove_basic(proto, blob, proof_out);
    }
}

/****************************
 * Verify: check and collect
 ****************************/

static bool verify_pow(agreement_protocol_t *proto, merkle_blob_t *blob,
                       const agreement_proof_t *proof)
{
    int difficulty = proto->pow_difficulty;

    /* Check leading zeros */
    for (int i = 0; i < difficulty && i < MERKLE_HASH_LEN; i++)
    {
        if (proof->digest[i] != 0)
            return false;
    }

    /* Re-derive hash from blob + nonce */
    uint8_t check[MERKLE_HASH_LEN];
    merkle_blob_hash(blob, proof->nonce, proof->nonce_len, check);
    return memcmp(check, proof->digest, MERKLE_HASH_LEN) == 0;
}

int agreement_verify(agreement_protocol_t *proto, merkle_blob_t *blob,
                     const agreement_proof_t *proof,
                     const uint8_t *sig, size_t sig_len)
{
    if (proto == NULL || blob == NULL || proof == NULL)
        return EXCEPTION(EINVAL);

    if (proto->algorithm == POW)
    {
        if (!verify_pow(proto, blob, proof))
            return -1;
    }

    vote_collection_t *coll = get_or_create_collection(proto, blob->uuid);
    if (coll == NULL)
        return SYS_EXCEPTION();

    return collection_add_vote(coll, blob, proof, sig, sig_len);
}

/****************************
 * Finalize: count votes
 ****************************/

static agreement_voter_t *find_voter(agreement_protocol_t *proto, const uuid_t uuid)
{
    for (size_t i = 0; i < proto->voter_count; i++)
    {
        if (uuid_compare(proto->voters[i]->uuid, uuid) == 0)
            return proto->voters[i];
    }
    return NULL;
}

static bool finalize_pow(agreement_protocol_t *proto, merkle_blob_t *blob)
{
    vote_collection_t *coll = find_collection(proto, blob->uuid);
    if (coll == NULL)
        return false;

    /* POW: any valid proof suffices */
    for (size_t i = 0; i < coll->vote_count; i++)
    {
        if (verify_pow(proto, blob, &coll->votes[i].proof))
        {
            collection_free(coll);
            return true;
        }
    }
    collection_free(coll);
    return false;
}

static bool finalize_pos(agreement_protocol_t *proto, merkle_blob_t *blob)
{
    vote_collection_t *coll = find_collection(proto, blob->uuid);
    if (coll == NULL)
        return false;

    proto->yea = 0.0;
    proto->nay = 0.0;

    for (size_t i = 0; i < coll->vote_count; i++)
    {
        agreement_voter_t *voter = find_voter(proto, coll->votes[i].proof.uuid);
        if (voter == NULL)
            continue;

        double stake = voter->rank; /* rank == stake in POS */
        if (coll->votes[i].proof.approval)
            proto->yea += stake;
        else
            proto->nay += stake;
    }

    bool result = proto->yea > proto->nay;
    collection_free(coll);
    return result;
}

static bool finalize_poa(agreement_protocol_t *proto, merkle_blob_t *blob)
{
    vote_collection_t *coll = find_collection(proto, blob->uuid);
    if (coll == NULL)
        return false;

    /* Find leader (highest rank) */
    double leader_rank = -1.0;
    for (size_t i = 0; i < proto->voter_count; i++)
    {
        if (proto->voters[i]->rank > leader_rank)
            leader_rank = proto->voters[i]->rank;
    }

    /* Leader's vote decides */
    bool result = false;
    for (size_t i = 0; i < coll->vote_count; i++)
    {
        agreement_voter_t *voter = find_voter(proto, coll->votes[i].proof.uuid);
        if (voter == NULL)
            continue;
        double rank_diff = voter->rank - leader_rank;
        if (rank_diff < 0) rank_diff = -rank_diff;
        if (voter->rank >= proto->poa_threshold && rank_diff < 0.0001)
        {
            result = coll->votes[i].proof.approval;
            break;
        }
    }

    collection_free(coll);
    return result;
}

bool agreement_finalize(agreement_protocol_t *proto, merkle_blob_t *blob)
{
    if (proto == NULL || blob == NULL)
        return false;

    /* Originator always self-approves */
    if (uuid_compare(proto->myself->uuid, blob->originator) == 0)
        return true;

    switch (proto->algorithm)
    {
    case POW:
        return finalize_pow(proto, blob);
    case POS:
        return finalize_pos(proto, blob);
    case POA:
        return finalize_poa(proto, blob);
    default:
        return false;
    }
}
