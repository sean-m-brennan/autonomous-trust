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

#include <sodium.h>
#include <uuid/uuid.h>
#include <string.h>

#include "autonomous_trust/fleet/update_proposal.h"

static void fill_test_proposal(update_proposal_t *prop)
{
    memset(prop, 0, sizeof(*prop));
    strncpy(prop->version, "1.2.3", UPDATE_VERSION_LEN);
    randombytes_buf(prop->artifact_hash, UPDATE_HASH_LEN);
    uuid_generate(prop->signer_uuid);
    strncpy(prop->target_arch, "x86_64", UPDATE_ARCH_LEN);
    prop->min_proposer_reputation = 0.75;
    uuid_generate(prop->proposal_uuid);
    memset(prop->signature, 0, UPDATE_SIG_LEN);
}

DEFINE_TEST(test_proposal_json_roundtrip)
{
    ck_assert_int_eq(sodium_init() < 0 ? -1 : 0, 0);

    update_proposal_t orig;
    fill_test_proposal(&orig);

    json_t *json = update_proposal_to_json(&orig);
    ck_assert_ptr_nonnull(json);

    update_proposal_t restored;
    ck_assert_ret_ok(update_proposal_from_json(json, &restored));

    ck_assert_str_eq(orig.version, restored.version);
    ck_assert_mem_eq(orig.artifact_hash, restored.artifact_hash, UPDATE_HASH_LEN);
    ck_assert_str_eq(orig.target_arch, restored.target_arch);
    ck_assert_double_eq_tol(orig.min_proposer_reputation, restored.min_proposer_reputation, 1e-9);

    char orig_signer[37], restored_signer[37];
    uuid_unparse_lower(orig.signer_uuid, orig_signer);
    uuid_unparse_lower(restored.signer_uuid, restored_signer);
    ck_assert_str_eq(orig_signer, restored_signer);

    char orig_proposal[37], restored_proposal[37];
    uuid_unparse_lower(orig.proposal_uuid, orig_proposal);
    uuid_unparse_lower(restored.proposal_uuid, restored_proposal);
    ck_assert_str_eq(orig_proposal, restored_proposal);

    ck_assert_mem_eq(orig.signature, restored.signature, UPDATE_SIG_LEN);

    json_decref(json);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_proposal_sign_verify)
{
    ck_assert_int_eq(sodium_init() < 0 ? -1 : 0, 0);

    uint8_t pk[crypto_sign_PUBLICKEYBYTES];
    uint8_t sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(pk, sk);

    update_proposal_t prop;
    fill_test_proposal(&prop);

    ck_assert_ret_ok(update_proposal_sign(&prop, sk));
    ck_assert_ret_ok(update_proposal_verify(&prop, pk));
}
END_TEST_DEFINITION()

DEFINE_TEST(test_proposal_verify_rejects_tampered)
{
    ck_assert_int_eq(sodium_init() < 0 ? -1 : 0, 0);

    uint8_t pk[crypto_sign_PUBLICKEYBYTES];
    uint8_t sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(pk, sk);

    update_proposal_t prop;
    fill_test_proposal(&prop);

    ck_assert_ret_ok(update_proposal_sign(&prop, sk));

    /* Tamper with the version field */
    strncpy(prop.version, "9.9.9", UPDATE_VERSION_LEN);

    ck_assert_ret_nonzero(update_proposal_verify(&prop, pk));
}
END_TEST_DEFINITION()

DEFINE_TEST(test_proposal_verify_rejects_wrong_key)
{
    ck_assert_int_eq(sodium_init() < 0 ? -1 : 0, 0);

    uint8_t pk1[crypto_sign_PUBLICKEYBYTES];
    uint8_t sk1[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(pk1, sk1);

    uint8_t pk2[crypto_sign_PUBLICKEYBYTES];
    uint8_t sk2[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(pk2, sk2);

    update_proposal_t prop;
    fill_test_proposal(&prop);

    ck_assert_ret_ok(update_proposal_sign(&prop, sk1));

    /* Verify with wrong key should fail */
    ck_assert_ret_nonzero(update_proposal_verify(&prop, pk2));
}
END_TEST_DEFINITION()

RUN_TESTS(UpdateProposal,
    test_proposal_json_roundtrip,
    test_proposal_sign_verify,
    test_proposal_verify_rejects_tampered,
    test_proposal_verify_rejects_wrong_key
)
