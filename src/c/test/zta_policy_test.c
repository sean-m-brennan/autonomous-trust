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
#include <jansson.h>

#include "zta/zta_policy.h"
#include "zta/zta_verifier.h"

/*
 * Tests for ZTA policy configuration:
 * - Default values
 * - JSON serialization roundtrip
 * - Verifier factory creates correct type
 * - Disabled policy creates null verifier
 */

DEFINE_TEST(test_policy_defaults)
{
    zta_policy_t policy;
    zta_policy_defaults(&policy);

    ck_assert(policy.enabled == false);
    ck_assert(policy.require_at_admission == true);
    ck_assert_int_eq(policy.reverify_interval_sec, 3600);
    ck_assert_double_eq_tol(policy.revocation_reputation_penalty, 0.8, 0.001);
    ck_assert(policy.allow_ddil_fallback == true);
    ck_assert_double_eq_tol(policy.ddil_fallback_reputation_cap, 0.5, 0.001);
    ck_assert(policy.audit_deferred_verifications == true);
    ck_assert_double_eq_tol(policy.delegated_verification_min_reputation, 0.7, 0.001);
    ck_assert_int_eq(policy.delegated_verification_quorum, 1);
    ck_assert_str_eq(policy.verifier_type, "x509");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_policy_json_roundtrip)
{
    zta_policy_t original;
    zta_policy_defaults(&original);
    original.enabled = true;
    original.reverify_interval_sec = 1800;
    original.revocation_reputation_penalty = 0.6;
    original.delegated_verification_min_reputation = 0.8;
    original.delegated_verification_quorum = 3;
    snprintf(original.ca_bundle_path, sizeof(original.ca_bundle_path),
             "/test/ca-bundle.pem");
    snprintf(original.ocsp_url, sizeof(original.ocsp_url),
             "http://ocsp.test.local:8080");

    /* Serialize to JSON */
    json_t *obj = NULL;
    ck_assert_ret_ok(zta_policy_to_json(&original, &obj));
    ck_assert_ptr_nonnull(obj);

    /* Deserialize back */
    zta_policy_t restored;
    ck_assert_ret_ok(zta_policy_from_json(obj, &restored));
    json_decref(obj);

    /* Verify roundtrip */
    ck_assert(restored.enabled == true);
    ck_assert(restored.require_at_admission == true);
    ck_assert_int_eq(restored.reverify_interval_sec, 1800);
    ck_assert_double_eq_tol(restored.revocation_reputation_penalty, 0.6, 0.001);
    ck_assert_double_eq_tol(restored.delegated_verification_min_reputation, 0.8, 0.001);
    ck_assert_int_eq(restored.delegated_verification_quorum, 3);
    ck_assert(restored.allow_ddil_fallback == true);
    ck_assert_str_eq(restored.verifier_type, "x509");
    ck_assert_str_eq(restored.ca_bundle_path, "/test/ca-bundle.pem");
    ck_assert_str_eq(restored.ocsp_url, "http://ocsp.test.local:8080");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_policy_disabled_creates_null_verifier)
{
    zta_policy_t policy;
    zta_policy_defaults(&policy);
    policy.enabled = false;

    zta_verifier_t *v = NULL;
    ck_assert_ret_ok(zta_policy_create_verifier(&policy, &v));
    ck_assert_ptr_nonnull(v);

    /* Null verifier: always returns VERIFIED */
    zta_result_t result;
    ck_assert_ret_ok(v->verify_credential(v, NULL, 0, &result));
    ck_assert_int_eq(result.status, ZTA_VERIFIED);

    v->destroy(v);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_policy_x509_creates_x509_verifier)
{
    zta_policy_t policy;
    zta_policy_defaults(&policy);
    policy.enabled = true;
    /* Empty ca_bundle_path means use system defaults */

    zta_verifier_t *v = NULL;
    ck_assert_ret_ok(zta_policy_create_verifier(&policy, &v));
    ck_assert_ptr_nonnull(v);

    /* X.509 verifier rejects empty creds (unlike null verifier) */
    zta_result_t result;
    ck_assert_ret_ok(v->verify_credential(v, NULL, 0, &result));
    ck_assert_int_eq(result.status, ZTA_REJECTED);

    v->destroy(v);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_policy_oidc_creates_oidc_stub)
{
    zta_policy_t policy;
    zta_policy_defaults(&policy);
    policy.enabled = true;
    snprintf(policy.verifier_type, sizeof(policy.verifier_type), "oidc");

    zta_verifier_t *v = NULL;
    ck_assert_ret_ok(zta_policy_create_verifier(&policy, &v));
    ck_assert_ptr_nonnull(v);

    /* OIDC stub: always returns UNAVAILABLE */
    zta_result_t result;
    ck_assert_ret_ok(v->verify_credential(v, NULL, 0, &result));
    ck_assert_int_eq(result.status, ZTA_UNAVAILABLE);

    v->destroy(v);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_policy_unknown_type_falls_back_to_null)
{
    zta_policy_t policy;
    zta_policy_defaults(&policy);
    policy.enabled = true;
    snprintf(policy.verifier_type, sizeof(policy.verifier_type), "unknown_type");

    zta_verifier_t *v = NULL;
    ck_assert_ret_ok(zta_policy_create_verifier(&policy, &v));
    ck_assert_ptr_nonnull(v);

    /* Falls back to null verifier */
    zta_result_t result;
    ck_assert_ret_ok(v->verify_credential(v, NULL, 0, &result));
    ck_assert_int_eq(result.status, ZTA_VERIFIED);

    v->destroy(v);
}
END_TEST_DEFINITION()

RUN_TESTS(ZTA_Policy,
    test_policy_defaults,
    test_policy_json_roundtrip,
    test_policy_disabled_creates_null_verifier,
    test_policy_x509_creates_x509_verifier,
    test_policy_oidc_creates_oidc_stub,
    test_policy_unknown_type_falls_back_to_null)
