/********************
 *  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
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

#include "zta/zta_verifier.h"
#include "zta/x509_verifier.h"
#include "zta/oidc_verifier.h"

/*
 * Tests for the ZTA verifier interface:
 * - Null verifier always returns VERIFIED
 * - X.509 verifier rejects empty credentials
 * - OIDC stub returns UNAVAILABLE
 * - credential_hash is deterministic
 * - zta_status_str returns correct strings
 */

DEFINE_TEST(test_null_verifier_verify)
{
    zta_verifier_t *v = NULL;
    ck_assert_ret_ok(zta_null_verifier_create(&v));
    ck_assert_ptr_nonnull(v);

    zta_result_t result;
    ck_assert_ret_ok(v->verify_credential(v, NULL, 0, &result));
    ck_assert_int_eq(result.status, ZTA_VERIFIED);

    v->destroy(v);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_null_verifier_revocation)
{
    zta_verifier_t *v = NULL;
    ck_assert_ret_ok(zta_null_verifier_create(&v));

    uint8_t fake_hash[ZTA_HASH_LEN] = {0};
    zta_result_t result;
    ck_assert_ret_ok(v->check_revocation(v, fake_hash, &result));
    ck_assert_int_eq(result.status, ZTA_VERIFIED);

    ck_assert(v->is_available(v) == true);

    v->destroy(v);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_null_verifier_hash)
{
    zta_verifier_t *v = NULL;
    ck_assert_ret_ok(zta_null_verifier_create(&v));

    uint8_t hash[ZTA_HASH_LEN];
    ck_assert_ret_ok(v->credential_hash(v, NULL, 0, hash));

    /* Null verifier returns all zeros */
    uint8_t expected[ZTA_HASH_LEN] = {0};
    ck_assert_mem_eq(hash, expected, ZTA_HASH_LEN);

    v->destroy(v);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_x509_verifier_no_credential)
{
    x509_verifier_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    /* Use system default CA (empty path triggers default) */
    cfg.connect_timeout_ms = 1000;

    zta_verifier_t *v = NULL;
    ck_assert_ret_ok(x509_verifier_create(&cfg, &v));
    ck_assert_ptr_nonnull(v);

    /* Verify with no credential data -> REJECTED */
    zta_result_t result;
    ck_assert_ret_ok(v->verify_credential(v, NULL, 0, &result));
    ck_assert_int_eq(result.status, ZTA_REJECTED);

    v->destroy(v);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_x509_verifier_garbage_data)
{
    x509_verifier_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.connect_timeout_ms = 1000;

    zta_verifier_t *v = NULL;
    ck_assert_ret_ok(x509_verifier_create(&cfg, &v));

    /* Verify with garbage data -> REJECTED (can't parse) */
    uint8_t garbage[] = {0xDE, 0xAD, 0xBE, 0xEF};
    zta_result_t result;
    ck_assert_ret_ok(v->verify_credential(v, garbage, sizeof(garbage), &result));
    ck_assert_int_eq(result.status, ZTA_REJECTED);

    v->destroy(v);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_oidc_stub_unavailable)
{
    zta_verifier_t *v = NULL;
    ck_assert_ret_ok(oidc_verifier_create(&v));
    ck_assert_ptr_nonnull(v);

    zta_result_t result;
    ck_assert_ret_ok(v->verify_credential(v, NULL, 0, &result));
    ck_assert_int_eq(result.status, ZTA_UNAVAILABLE);

    ck_assert_ret_ok(v->check_revocation(v, NULL, &result));
    ck_assert_int_eq(result.status, ZTA_UNAVAILABLE);

    ck_assert(v->is_available(v) == false);

    v->destroy(v);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_zta_status_str)
{
    ck_assert_str_eq(zta_status_str(ZTA_VERIFIED), "VERIFIED");
    ck_assert_str_eq(zta_status_str(ZTA_REJECTED), "REJECTED");
    ck_assert_str_eq(zta_status_str(ZTA_DEFERRED), "DEFERRED");
    ck_assert_str_eq(zta_status_str(ZTA_EXPIRED), "EXPIRED");
    ck_assert_str_eq(zta_status_str(ZTA_REVOKED), "REVOKED");
    ck_assert_str_eq(zta_status_str(ZTA_UNAVAILABLE), "UNAVAILABLE");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_zta_result_set)
{
    zta_result_t result;
    zta_result_set(&result, ZTA_VERIFIED, "test reason");
    ck_assert_int_eq(result.status, ZTA_VERIFIED);
    ck_assert_str_eq(result.reason, "test reason");
    ck_assert(result.timestamp.tv_sec > 0);
}
END_TEST_DEFINITION()

RUN_TESTS(ZTA_Verifier,
    test_null_verifier_verify,
    test_null_verifier_revocation,
    test_null_verifier_hash,
    test_x509_verifier_no_credential,
    test_x509_verifier_garbage_data,
    test_oidc_stub_unavailable,
    test_zta_status_str,
    test_zta_result_set)
