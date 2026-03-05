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

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <string.h>
#include <stdlib.h>
#include <sodium.h>

#include "algorithms/agreement.h"
#include "structures/merkle.h"
#include "utilities/exception.h"
#include "utilities/logger.h"

static const uint8_t *test_designation(void *user_data, size_t *len)
{
    const char *s = (const char *)user_data;
    *len = strlen(s);
    return (const uint8_t *)s;
}

DEFINE_TEST(test_agreement_proof_init)
{
    agreement_proof_t proof;
    agreement_proof_init(&proof);
    ck_assert_int_eq(proof.approval, false);
    ck_assert_ptr_null(proof.nonce);
    ck_assert_int_eq(proof.nonce_len, 0);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_agreement_pos)
{
    if (sodium_init() < 0 && sodium_init() != 1)
        ck_abort_msg("sodium_init failed");

    /* Setup voters */
    agreement_voter_t myself;
    memset(&myself, 0, sizeof(myself));
    uuid_generate(myself.uuid);
    myself.rank = 10.0;

    agreement_voter_t voter2;
    memset(&voter2, 0, sizeof(voter2));
    uuid_generate(voter2.uuid);
    voter2.rank = 5.0;

    agreement_voter_t voter3;
    memset(&voter3, 0, sizeof(voter3));
    uuid_generate(voter3.uuid);
    voter3.rank = 3.0;

    agreement_voter_t *voters[3] = {&myself, &voter2, &voter3};

    /* Setup protocol */
    agreement_protocol_t proto;
    ck_assert_ret_ok(agreement_protocol_init(&proto, &myself, voters, 3, POS));

    /* Create blob */
    uuid_t blob_uuid;
    uuid_generate(blob_uuid);
    merkle_blob_t blob;
    memset(&blob, 0, sizeof(blob));
    uuid_copy(blob.uuid, blob_uuid);
    uuid_copy(blob.originator, voter2.uuid); /* Not self */
    blob.user_data = (void *)"test_proposal";
    blob.designation = test_designation;

    /* Generate proof for ourselves */
    agreement_proof_t my_proof;
    ck_assert_ret_ok(agreement_prove(&proto, &blob, &my_proof));
    ck_assert(my_proof.approval);

    /* Verify our vote */
    ck_assert_ret_ok(agreement_verify(&proto, &blob, &my_proof, NULL, 0));

    /* Simulate voter2 approving */
    agreement_proof_t v2_proof;
    agreement_proof_init(&v2_proof);
    uuid_copy(v2_proof.uuid, voter2.uuid);
    merkle_blob_hash(&blob, NULL, 0, v2_proof.digest);
    v2_proof.approval = true;
    ck_assert_ret_ok(agreement_verify(&proto, &blob, &v2_proof, NULL, 0));

    /* Simulate voter3 rejecting */
    agreement_proof_t v3_proof;
    agreement_proof_init(&v3_proof);
    uuid_copy(v3_proof.uuid, voter3.uuid);
    merkle_blob_hash(&blob, NULL, 0, v3_proof.digest);
    v3_proof.approval = false;
    ck_assert_ret_ok(agreement_verify(&proto, &blob, &v3_proof, NULL, 0));

    /* Finalize: yea=15 (10+5), nay=3 → should pass */
    bool result = agreement_finalize(&proto, &blob);
    ck_assert(result);

    agreement_proof_free(&my_proof);
    agreement_protocol_free(&proto);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_agreement_poa)
{
    if (sodium_init() < 0 && sodium_init() != 1)
        ck_abort_msg("sodium_init failed");

    agreement_voter_t myself;
    memset(&myself, 0, sizeof(myself));
    uuid_generate(myself.uuid);
    myself.rank = 5.0;

    agreement_voter_t leader;
    memset(&leader, 0, sizeof(leader));
    uuid_generate(leader.uuid);
    leader.rank = 10.0; /* Highest rank = leader */

    agreement_voter_t *voters[2] = {&myself, &leader};

    agreement_protocol_t proto;
    ck_assert_ret_ok(agreement_protocol_init(&proto, &myself, voters, 2, POA));
    agreement_set_poa_threshold(&proto, 1.0);

    uuid_t blob_uuid;
    uuid_generate(blob_uuid);
    merkle_blob_t blob;
    memset(&blob, 0, sizeof(blob));
    uuid_copy(blob.uuid, blob_uuid);
    uuid_copy(blob.originator, leader.uuid);
    blob.user_data = (void *)"authority_test";
    blob.designation = test_designation;

    /* Leader vote approves */
    agreement_proof_t leader_proof;
    agreement_proof_init(&leader_proof);
    uuid_copy(leader_proof.uuid, leader.uuid);
    merkle_blob_hash(&blob, NULL, 0, leader_proof.digest);
    leader_proof.approval = true;
    ck_assert_ret_ok(agreement_verify(&proto, &blob, &leader_proof, NULL, 0));

    /* Our vote rejects (should be overridden by leader) */
    agreement_proof_t my_proof;
    agreement_proof_init(&my_proof);
    uuid_copy(my_proof.uuid, myself.uuid);
    merkle_blob_hash(&blob, NULL, 0, my_proof.digest);
    my_proof.approval = false;
    ck_assert_ret_ok(agreement_verify(&proto, &blob, &my_proof, NULL, 0));

    /* Originator self-approves */
    bool result = agreement_finalize(&proto, &blob);
    ck_assert(result);

    agreement_protocol_free(&proto);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_agreement_originator_self_approve)
{
    if (sodium_init() < 0 && sodium_init() != 1)
        ck_abort_msg("sodium_init failed");

    agreement_voter_t myself;
    memset(&myself, 0, sizeof(myself));
    uuid_generate(myself.uuid);
    myself.rank = 1.0;

    agreement_voter_t *voters[1] = {&myself};

    agreement_protocol_t proto;
    ck_assert_ret_ok(agreement_protocol_init(&proto, &myself, voters, 1, POS));

    uuid_t blob_uuid;
    uuid_generate(blob_uuid);
    merkle_blob_t blob;
    memset(&blob, 0, sizeof(blob));
    uuid_copy(blob.uuid, blob_uuid);
    uuid_copy(blob.originator, myself.uuid); /* Self is originator */
    blob.user_data = (void *)"self_approval";
    blob.designation = test_designation;

    /* Originator always self-approves, no voting needed */
    bool result = agreement_finalize(&proto, &blob);
    ck_assert(result);

    agreement_protocol_free(&proto);
}

RUN_TESTS(Agreement, test_agreement_proof_init, test_agreement_pos,
          test_agreement_poa, test_agreement_originator_self_approve)
