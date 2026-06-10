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

/** @addtogroup internal_algorithms
 *  @{
 */

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
    /* Reputation-derived trust tier (0..4). Distinct from rank
     * (network topology); read by AgreementByTrust (PoT). PoA/PoS/PoW
     * leave this 0 — they all key off rank or stake instead. See
     * doc/architecture/trust-tiers.md §1. */
    int tier;
} agreement_voter_t;

typedef enum {
    AGREEMENT_AUTHORITY,
    AGREEMENT_STAKE,
    AGREEMENT_WORK,
    /* Proof of Trust — parallel to AUTHORITY but reads voter.tier
     * instead of voter.rank. See doc/architecture/trust-tiers.md §10. */
    AGREEMENT_TRUST
} agreement_type_t;

/* PoW canonical difficulty — leading zero BYTES required on the digest
 * prefix. Mirrors Python's `AgreementByWork.DIFFICULTY = 2` class
 * constant (work.py:41). Callers of agreement_by_work_create may still
 * pass a different value for tests, but production runs and any
 * cross-impl interop MUST use this constant so a C-mined proof
 * validates against a Python verifier and vice versa. Change here
 * MUST land in Python at the same time. */
#define POW_DEFAULT_DIFFICULTY 2

/* Pass to agreement_by_authority_create's @c threshold_rank arg to
 * select dynamic top-1/3 derivation from the current voter set, the
 * same rule Python AgreementByAuthority.threshold_rank applies when
 * the explicit override is None (authority.py:30-39). Any negative
 * value works; this name reads cleaner at call sites. */
#define AUTHORITY_THRESHOLD_DERIVE (-1)

/* Pass to agreement_by_trust_create's @c threshold_tier arg to select
 * dynamic top-1/3 derivation from the current voter set (mirrors PoA;
 * see trust.py:32-40). Any negative value works. */
#define TRUST_THRESHOLD_DERIVE (-1)

typedef struct agreement_protocol_s agreement_protocol_t;

/* vtable function pointer types */
typedef bool (*pre_verify_fn)(agreement_protocol_t *proto, merkle_blob_t *blob,
                              agreement_proof_t *proof, const uint8_t *sig, size_t sig_len);
typedef void (*prep_vote_fn)(agreement_protocol_t *proto);
typedef void (*count_vote_fn)(agreement_protocol_t *proto, merkle_blob_t *blob,
                              agreement_proof_t *proof, agreement_voter_t *voter,
                              int *rank_out, bool *approval_out);
typedef bool (*accumulate_votes_fn)(agreement_protocol_t *proto, int *ranks, bool *approvals, int count);

/**
 * @brief Polymorphic agreement protocol — authority, stake, or work.
 *
 * The @c type field selects which union arm of @c state is live AND which
 * vtable entries semantically apply. Construct with the matching
 * `agreement_by_*_create()` helper; do not hand-initialize.
 */
struct agreement_protocol_s {
    agreement_voter_t myself;          /**< This participant's voter record. */
    agreement_voter_t *voters;         /**< Array of all voters including self. */
    int voter_count;                   /**< Length of @c voters. */
    map_t *votes;                      /**< uuid → array of (blob, proof, sig). */
    agreement_type_t type;             /**< Discriminates the @c state union. */

    /* vtable — populated by agreement_by_*_create(); must not be replaced. */
    pre_verify_fn       pre_verify;       /**< Per-vote signature/proof check. */
    prep_vote_fn        prep_vote;        /**< Reset transient tallies before a round. */
    count_vote_fn       count_vote;       /**< Fold one incoming vote into tallies. */
    accumulate_votes_fn accumulate_votes; /**< Decide final outcome from tallies. */

    /** @brief Type-specific state; only the arm matching @c type is live. */
    union {
        /** @brief Valid when @c type == @ref AGREEMENT_AUTHORITY. */
        struct {
            int threshold_rank;                            /**< Minimum rank that counts as authority. */
        } authority;
        /** @brief Valid when @c type == @ref AGREEMENT_STAKE. */
        struct {
            double yea;                                    /**< Accumulated stake-weighted approvals. */
            double nay;                                    /**< Accumulated stake-weighted rejections. */
            double (*get_stake)(agreement_voter_t *voter); /**< Callback returning stake weight. */
        } stake;
        /** @brief Valid when @c type == @ref AGREEMENT_WORK. */
        struct {
            int difficulty;                                /**< PoW target (leading-zero bits). */
            array_t *approved;                             /**< UUIDs whose proof has cleared @c difficulty. */
        } work;
        /** @brief Valid when @c type == @ref AGREEMENT_TRUST. */
        struct {
            int threshold_tier;                            /**< Minimum tier that counts. -1 = derive top-1/3. */
        } trust;
    } state;
};

/*@
  requires \valid(proof);
  allocates *proof;
  behavior success:
    ensures \result == 0;
    ensures *proof != \null;
    ensures (*proof)->approval == approval;
  behavior null_out:
    assumes proof == \null;
    ensures \result == EINVAL;
  behavior oom:
    ensures \result == ENOMEM;
  disjoint behaviors null_out, success;
*/
int agreement_proof_create(const char *uuid, const uint8_t *digest, size_t digest_len,
                           bool approval, const uint8_t *nonce, size_t nonce_len,
                           agreement_proof_t **proof);

/*@
  requires proof == \null || \valid(proof);
  frees proof;
*/
void agreement_proof_free(agreement_proof_t *proof);

int agreement_proof_sync_out(agreement_proof_t *proof, void *proto_msg);
int agreement_proof_sync_in(void *proto_msg, agreement_proof_t *proof);

/*@
  requires myself == \null || \valid(myself);
  requires \valid(proto);
  requires other_count >= 0;
  allocates *proto;
  behavior null_self:
    assumes myself == \null;
    ensures \result == EINVAL;
  behavior success:
    assumes myself != \null;
    ensures \result == 0 ==> *proto != \null;
    ensures \result == 0 ==> (*proto)->voter_count == other_count + 1;
  disjoint behaviors;
*/
int agreement_protocol_create(agreement_voter_t *myself,
                              agreement_voter_t *others, int other_count,
                              agreement_type_t type,
                              agreement_protocol_t **proto);

/*@
  requires myself != \null && \valid(myself);
  requires \valid(proto);
  allocates *proto;
  behavior success:
    ensures \result == 0;
    ensures *proto != \null;
    ensures (*proto)->type == AGREEMENT_AUTHORITY;
  behavior failure:
    ensures \result != 0;
  disjoint behaviors;
*/
/**
 * Construct an AGREEMENT_AUTHORITY protocol.
 *
 * Pass a non-negative @p threshold_rank to pin the cutoff explicitly,
 * or pass a negative value (e.g. -1) to let the protocol derive the
 * threshold dynamically from the current voter set as the top-1/3 cutoff
 * — the same rule Python's `AgreementByAuthority.threshold_rank`
 * applies (authority.py:30-39). The derived form lets reputation-tied
 * elevation raise the authority bar as peers earn rank, while still
 * staying safe during bootstrap (all-zero ranks → threshold 0, every
 * vote counts).
 */
int agreement_by_authority_create(agreement_voter_t *myself,
                                  agreement_voter_t *others, int other_count,
                                  int threshold_rank,
                                  agreement_protocol_t **proto);

/*@
  requires myself != \null && \valid(myself);
  requires \valid(proto);
  allocates *proto;
  behavior success:
    ensures \result == 0;
    ensures *proto != \null;
    ensures (*proto)->type == AGREEMENT_TRUST;
  behavior failure:
    ensures \result != 0;
  disjoint behaviors;
*/
/**
 * Construct an AGREEMENT_TRUST (PoT) protocol.
 *
 * Parallel to agreement_by_authority_create but reads voter.tier
 * instead of voter.rank. Pass a non-negative @p threshold_tier to pin
 * the cutoff explicitly, or @ref TRUST_THRESHOLD_DERIVE (-1) to let
 * the protocol derive the threshold dynamically from the current
 * voter set as the top-1/3 cutoff. Mirrors Python
 * AgreementByTrust (trust.py); see doc/architecture/trust-tiers.md §10.
 */
int agreement_by_trust_create(agreement_voter_t *myself,
                              agreement_voter_t *others, int other_count,
                              int threshold_tier,
                              agreement_protocol_t **proto);

/*@
  requires myself != \null && \valid(myself);
  requires \valid(proto);
  allocates *proto;
  behavior success:
    ensures \result == 0;
    ensures *proto != \null;
    ensures (*proto)->type == AGREEMENT_STAKE;
  behavior failure:
    ensures \result != 0;
  disjoint behaviors;
*/
int agreement_by_stake_create(agreement_voter_t *myself,
                              agreement_voter_t *others, int other_count,
                              double (*get_stake)(agreement_voter_t *voter),
                              agreement_protocol_t **proto);

/*@
  requires myself != \null && \valid(myself);
  requires \valid(proto);
  allocates *proto;
  behavior success:
    ensures \result == 0;
    ensures *proto != \null;
    ensures (*proto)->type == AGREEMENT_WORK;
  behavior failure:
    ensures \result != 0;
  disjoint behaviors;
*/
/**
 * Construct an AGREEMENT_WORK protocol.
 *
 * Production callers SHOULD pass @ref POW_DEFAULT_DIFFICULTY for
 * @p difficulty so a C-mined proof validates against a Python verifier
 * (and vice versa). Tests may pass any non-negative value. The value
 * is in leading-zero BYTES of the digest, not bits — matching Python
 * AgreementByWork.DIFFICULTY (work.py:41).
 */
int agreement_by_work_create(agreement_voter_t *myself,
                             agreement_voter_t *others, int other_count,
                             int difficulty,
                             agreement_protocol_t **proto);

/*@
  requires proto == \null || \valid(proto);
  requires blob == \null || \valid(blob);
  requires \valid(proof_out);
  allocates *proof_out;
  behavior null_args:
    assumes proto == \null || blob == \null || proof_out == \null;
    ensures \result == EINVAL;
  behavior success:
    assumes proto != \null && blob != \null && proof_out != \null;
    ensures \result == 0 ==> *proof_out != \null;
  disjoint behaviors;
*/
int agreement_prove(agreement_protocol_t *proto, merkle_blob_t *blob,
                    agreement_proof_t **proof_out);

/*@
  requires proto == \null || \valid(proto);
  requires blob == \null || \valid(blob);
  requires proof == \null || \valid(proof);
  assigns \nothing;
  behavior null_args:
    assumes proto == \null || blob == \null || proof == \null;
    ensures \result == \false;
  behavior valid_args:
    assumes proto != \null && blob != \null && proof != \null;
    ensures \result == \true || \result == \false;
  disjoint behaviors;
  complete behaviors;
*/
bool agreement_verify(agreement_protocol_t *proto, merkle_blob_t *blob,
                      agreement_proof_t *proof, const uint8_t *sig, size_t sig_len);

/*@
  requires proto == \null || \valid(proto);
  requires blob == \null || \valid(blob);
  behavior null_args:
    assumes proto == \null || blob == \null;
    ensures \result == \false;
  behavior valid_args:
    assumes proto != \null && blob != \null;
    ensures \result == \true || \result == \false;
  disjoint behaviors;
  complete behaviors;
*/
bool agreement_finalize(agreement_protocol_t *proto, merkle_blob_t *blob);

/*@
  behavior null:
    assumes proto == \null;
    assigns \nothing;
  behavior valid:
    assumes proto != \null;
    requires \valid(proto);
    requires proto->votes == \null || \valid(proto->votes);
    requires proto->votes == \null || proto->votes->items != \null;
    requires proto->votes == \null || proto->votes->length <= proto->votes->capacity;
    requires (proto->type == AGREEMENT_WORK && proto->state.work.approved != \null)
          ==> (\valid(proto->state.work.approved)
               && proto->state.work.approved->array != \null);
  disjoint behaviors;
*/
void agreement_protocol_free(agreement_protocol_t *proto);

#ifdef __cplusplus
} // extern "C"
#endif


/** @} */ /* end of internal_algorithms */

#endif  // AGREEMENT_H
