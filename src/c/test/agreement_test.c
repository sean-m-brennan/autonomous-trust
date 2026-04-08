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

#include <string.h>
#include <sodium.h>

#include "autonomous_trust/algorithms/agreement.h"
#include "autonomous_trust/utilities/protobuf_shutdown.h"

#define DEBUG_TESTS 1
#include "test_setup.h"

static int _test_blob_hash(const merkle_blob_t *blob, const uint8_t *nonce,
                           size_t nonce_len, uint8_t *hash_out)
{
    size_t uuid_len = strlen(blob->uuid);
    size_t total = uuid_len + nonce_len;
    uint8_t *buf = malloc(total);
    if (buf == NULL)
        return -1;
    memcpy(buf, blob->uuid, uuid_len);
    if (nonce != NULL && nonce_len > 0)
        memcpy(buf + uuid_len, nonce, nonce_len);
    int ret = merkle_hash(buf, total, hash_out);
    free(buf);
    return ret;
}

static merkle_blob_t *_make_blob(const char *uuid, const char *originator)
{
    merkle_blob_t *blob = malloc(sizeof(merkle_blob_t));
    memset(blob, 0, sizeof(merkle_blob_t));
    strncpy(blob->uuid, uuid, MERKLE_UUID_LEN - 1);
    strncpy(blob->originator, originator, MERKLE_UUID_LEN - 1);
    blob->get_hash = _test_blob_hash;
    return blob;
}

DEFINE_TEST(test_proof_create)
{
    if (sodium_init() < 0 && sodium_init() != 1)
        ck_assert(0);

    uint8_t digest[] = {1, 2, 3, 4};
    agreement_proof_t *proof = NULL;
    ck_assert_ret_ok(agreement_proof_create("voter-uuid", digest, 4, true, NULL, 0, &proof));
    ck_assert_ptr_nonnull(proof);
    ck_assert_str_eq(proof->uuid, "voter-uuid");
    ck_assert(proof->approval);
    ck_assert_int_eq(proof->digest_len, 4);
    ck_assert_mem_eq(proof->digest, digest, 4);
    ck_assert_ptr_null(proof->nonce);

    agreement_proof_free(proof);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_authority_voting)
{
    agreement_voter_t leader = {.rank = 5};
    strncpy(leader.uuid, "leader-uuid", AGREEMENT_UUID_LEN - 1);

    agreement_voter_t peer1 = {.rank = 3};
    strncpy(peer1.uuid, "peer1-uuid", AGREEMENT_UUID_LEN - 1);

    agreement_voter_t peer2 = {.rank = 1};
    strncpy(peer2.uuid, "peer2-uuid", AGREEMENT_UUID_LEN - 1);

    agreement_voter_t others[] = {peer1, peer2};

    agreement_protocol_t *proto = NULL;
    ck_assert_ret_ok(agreement_by_authority_create(&leader, others, 2, 4, &proto));
    ck_assert_ptr_nonnull(proto);

    merkle_blob_t *blob = _make_blob("test-blob", "someone");

    /* leader proves and votes yes */
    agreement_proof_t *leader_proof = NULL;
    ck_assert_ret_ok(agreement_prove(proto, blob, &leader_proof));
    ck_assert(agreement_verify(proto, blob, leader_proof, NULL, 0));

    /* peer1 votes no (below threshold, rank 3 < 4) */
    agreement_proof_t *p1_proof = NULL;
    ck_assert_ret_ok(agreement_proof_create("peer1-uuid", leader_proof->digest,
                                            leader_proof->digest_len, false, NULL, 0, &p1_proof));
    ck_assert(agreement_verify(proto, blob, p1_proof, NULL, 0));

    /* finalize: leader's vote should win */
    ck_assert(agreement_finalize(proto, blob));

    agreement_proof_free(leader_proof);
    agreement_proof_free(p1_proof);
    agreement_protocol_free(proto);
    free(blob);
}
END_TEST_DEFINITION()

static double _test_get_stake(agreement_voter_t *voter)
{
    return (double)voter->rank;
}

DEFINE_TEST(test_stake_voting)
{
    agreement_voter_t me = {.rank = 5};
    strncpy(me.uuid, "me-uuid", AGREEMENT_UUID_LEN - 1);

    agreement_voter_t p1 = {.rank = 3};
    strncpy(p1.uuid, "p1-uuid", AGREEMENT_UUID_LEN - 1);

    agreement_voter_t p2 = {.rank = 2};
    strncpy(p2.uuid, "p2-uuid", AGREEMENT_UUID_LEN - 1);

    agreement_voter_t others[] = {p1, p2};

    agreement_protocol_t *proto = NULL;
    ck_assert_ret_ok(agreement_by_stake_create(&me, others, 2, _test_get_stake, &proto));

    merkle_blob_t *blob = _make_blob("stake-blob", "someone");

    /* me votes yes (stake 5) */
    agreement_proof_t *my_proof = NULL;
    ck_assert_ret_ok(agreement_prove(proto, blob, &my_proof));
    ck_assert(agreement_verify(proto, blob, my_proof, NULL, 0));

    /* p1 votes no (stake 3) */
    agreement_proof_t *p1_proof = NULL;
    ck_assert_ret_ok(agreement_proof_create("p1-uuid", my_proof->digest,
                                            my_proof->digest_len, false, NULL, 0, &p1_proof));
    ck_assert(agreement_verify(proto, blob, p1_proof, NULL, 0));

    /* p2 votes no (stake 2) */
    agreement_proof_t *p2_proof = NULL;
    ck_assert_ret_ok(agreement_proof_create("p2-uuid", my_proof->digest,
                                            my_proof->digest_len, false, NULL, 0, &p2_proof));
    ck_assert(agreement_verify(proto, blob, p2_proof, NULL, 0));

    /* yea=5, nay=5 → not approved (need strict >) */
    ck_assert(!agreement_finalize(proto, blob));

    agreement_proof_free(my_proof);
    agreement_proof_free(p1_proof);
    agreement_proof_free(p2_proof);
    agreement_protocol_free(proto);
    free(blob);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_work_voting)
{
    agreement_voter_t me = {.rank = 1};
    strncpy(me.uuid, "worker-uuid", AGREEMENT_UUID_LEN - 1);

    agreement_protocol_t *proto = NULL;
    /* difficulty=1 means first byte of hash must be 0 */
    ck_assert_ret_ok(agreement_by_work_create(&me, NULL, 0, 1, &proto));

    merkle_blob_t *blob = _make_blob("work-blob", "someone");

    /* prove does PoW */
    agreement_proof_t *proof = NULL;
    ck_assert_ret_ok(agreement_prove(proto, blob, &proof));
    ck_assert_ptr_nonnull(proof);
    ck_assert(proof->approval);

    /* first byte should be ASCII '0' (0x30) matching Python PoW convention */
    ck_assert_int_eq(proof->digest[0], '0');

    /* verify checks PoW */
    ck_assert(agreement_verify(proto, blob, proof, NULL, 0));

    /* finalize should succeed since blob was approved in verify */
    ck_assert(agreement_finalize(proto, blob));

    agreement_proof_free(proof);
    agreement_protocol_free(proto);
    free(blob);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_originator_auto_approve)
{
    agreement_voter_t me = {.rank = 1};
    strncpy(me.uuid, "orig-uuid", AGREEMENT_UUID_LEN - 1);

    agreement_protocol_t *proto = NULL;
    ck_assert_ret_ok(agreement_by_authority_create(&me, NULL, 0, 1, &proto));

    /* blob originated by ourselves */
    merkle_blob_t *blob = _make_blob("my-blob", "orig-uuid");

    /* originator always approves */
    ck_assert(agreement_finalize(proto, blob));

    agreement_protocol_free(proto);
    free(blob);
}
END_TEST_DEFINITION()

RUN_TESTS(agreement, test_proof_create, test_authority_voting,
          test_stake_voting, test_work_voting, test_originator_auto_approve)
