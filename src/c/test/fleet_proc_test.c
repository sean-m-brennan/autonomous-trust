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
#include "autonomous_trust/fleet/fleet_proc.h"

static void fill_test_proposal(update_proposal_t *prop)
{
    memset(prop, 0, sizeof(*prop));
    strncpy(prop->version, "2.0.0", UPDATE_VERSION_LEN);
    randombytes_buf(prop->artifact_hash, UPDATE_HASH_LEN);
    uuid_generate(prop->signer_uuid);
    strncpy(prop->target_arch, "aarch64", UPDATE_ARCH_LEN);
    prop->min_proposer_reputation = 0.7;
    uuid_generate(prop->proposal_uuid);
    memset(prop->signature, 0, UPDATE_SIG_LEN);
}

/* ---------------------------------------------------------------
 * test_validate_proposal_valid
 * Sign a proposal then validate — should return true.
 * --------------------------------------------------------------- */
DEFINE_TEST(test_validate_proposal_valid)
{
    ck_assert_int_eq(sodium_init() < 0 ? -1 : 0, 0);

    uint8_t pk[crypto_sign_PUBLICKEYBYTES];
    uint8_t sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(pk, sk);

    update_proposal_t prop;
    fill_test_proposal(&prop);

    ck_assert_ret_ok(update_proposal_sign(&prop, sk));
    ck_assert(fleet_validate_proposal(&prop, pk));
}
END_TEST_DEFINITION()

/* ---------------------------------------------------------------
 * test_validate_proposal_tampered
 * Tamper with a field after signing — validate should return false.
 * --------------------------------------------------------------- */
DEFINE_TEST(test_validate_proposal_tampered)
{
    ck_assert_int_eq(sodium_init() < 0 ? -1 : 0, 0);

    uint8_t pk[crypto_sign_PUBLICKEYBYTES];
    uint8_t sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(pk, sk);

    update_proposal_t prop;
    fill_test_proposal(&prop);

    ck_assert_ret_ok(update_proposal_sign(&prop, sk));

    /* Tamper: change the version after signing */
    strncpy(prop.version, "9.9.9", UPDATE_VERSION_LEN);

    ck_assert(!fleet_validate_proposal(&prop, pk));
}
END_TEST_DEFINITION()

/* ---------------------------------------------------------------
 * test_validate_proposal_wrong_key
 * Verify with a different public key — should return false.
 * --------------------------------------------------------------- */
DEFINE_TEST(test_validate_proposal_wrong_key)
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

    /* Verify with the wrong key */
    ck_assert(!fleet_validate_proposal(&prop, pk2));
}
END_TEST_DEFINITION()

/* ---------------------------------------------------------------
 * test_reputation_threshold_pass
 * 0.8 >= 0.7 should return true.
 * --------------------------------------------------------------- */
DEFINE_TEST(test_reputation_threshold_pass)
{
    ck_assert(fleet_check_reputation_threshold(0.8, 0.7));
}
END_TEST_DEFINITION()

/* ---------------------------------------------------------------
 * test_reputation_threshold_fail
 * 0.5 < 0.7 should return false.
 * --------------------------------------------------------------- */
DEFINE_TEST(test_reputation_threshold_fail)
{
    ck_assert(!fleet_check_reputation_threshold(0.5, 0.7));
}
END_TEST_DEFINITION()

/* ---------------------------------------------------------------
 * test_reputation_threshold_exact
 * 0.7 >= 0.7 (boundary case) should return true.
 * --------------------------------------------------------------- */
DEFINE_TEST(test_reputation_threshold_exact)
{
    ck_assert(fleet_check_reputation_threshold(0.7, 0.7));
}
END_TEST_DEFINITION()

/* ---------------------------------------------------------------
 * test_should_accept_valid
 * Valid signature + good reputation — should return true.
 * --------------------------------------------------------------- */
DEFINE_TEST(test_should_accept_valid)
{
    ck_assert_int_eq(sodium_init() < 0 ? -1 : 0, 0);

    uint8_t pk[crypto_sign_PUBLICKEYBYTES];
    uint8_t sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(pk, sk);

    update_proposal_t prop;
    fill_test_proposal(&prop);
    prop.min_proposer_reputation = 0.7;

    ck_assert_ret_ok(update_proposal_sign(&prop, sk));
    ck_assert(fleet_should_accept_proposal(&prop, pk, 0.9));
}
END_TEST_DEFINITION()

/* ---------------------------------------------------------------
 * test_should_accept_bad_sig
 * Invalid signature — should return false regardless of reputation.
 * --------------------------------------------------------------- */
DEFINE_TEST(test_should_accept_bad_sig)
{
    ck_assert_int_eq(sodium_init() < 0 ? -1 : 0, 0);

    uint8_t pk[crypto_sign_PUBLICKEYBYTES];
    uint8_t sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(pk, sk);

    /* Generate a second keypair to sign with */
    uint8_t pk2[crypto_sign_PUBLICKEYBYTES];
    uint8_t sk2[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(pk2, sk2);

    update_proposal_t prop;
    fill_test_proposal(&prop);
    prop.min_proposer_reputation = 0.7;

    /* Sign with sk2 but verify against pk (mismatch) */
    ck_assert_ret_ok(update_proposal_sign(&prop, sk2));
    ck_assert(!fleet_should_accept_proposal(&prop, pk, 0.9));
}
END_TEST_DEFINITION()

/* ---------------------------------------------------------------
 * test_should_accept_low_rep
 * Valid signature but reputation below threshold — should return false.
 * --------------------------------------------------------------- */
DEFINE_TEST(test_should_accept_low_rep)
{
    ck_assert_int_eq(sodium_init() < 0 ? -1 : 0, 0);

    uint8_t pk[crypto_sign_PUBLICKEYBYTES];
    uint8_t sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(pk, sk);

    update_proposal_t prop;
    fill_test_proposal(&prop);
    prop.min_proposer_reputation = 0.7;

    ck_assert_ret_ok(update_proposal_sign(&prop, sk));
    ck_assert(!fleet_should_accept_proposal(&prop, pk, 0.5));
}
END_TEST_DEFINITION()

RUN_TESTS(FleetProc,
    test_validate_proposal_valid,
    test_validate_proposal_tampered,
    test_validate_proposal_wrong_key,
    test_reputation_threshold_pass,
    test_reputation_threshold_fail,
    test_reputation_threshold_exact,
    test_should_accept_valid,
    test_should_accept_bad_sig,
    test_should_accept_low_rep
)
