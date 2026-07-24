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

/** @file Unit tests for the C operator-attended signal (ethne guardian edge,
 *  D8/Q9) — the mirror of Python tests/a_unit/test_operator_attestation.py
 *  (P-L1 data model + canonical carriage).
 *
 *  Covers the cross-runtime canonical carrier (public_identity_to_json /
 *  public_identity_from_json): the two new fields (operator_bound,
 *  operator_attested_at) plus the base64 ZTA binding round-trip, and the
 *  omit-when-default rule that keeps a plain (non-operator) peer's canonical
 *  form byte-identical to before. The operator-class VERIFICATION (distinct
 *  operator anchor) is exercised under the full toolchain via the conformance
 *  corpus (needs a real operator-CA test cert), not here.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <string.h>
#include <stdlib.h>

#include <jansson.h>
#include <sodium.h>
#include <uuid/uuid.h>

#include "identity/identity.h"
#include "identity/identity_priv.h"

static public_identity_t *_mk_pub(const char *name, const char *addr)
{
    uuid_t uuid;
    uuid_generate(uuid);
    identity_t *ident = NULL;
    ck_assert_ret_ok(identity_create(&uuid, addr, name, name, &ident));
    ck_assert_ptr_nonnull(ident);
    public_identity_t *pub = NULL;
    ck_assert_ret_ok(identity_publish(ident, &pub));
    ck_assert_ptr_nonnull(pub);
    return pub;
}

/* operator_bound + operator_attested_at survive the canonical JSON round-trip. */
DEFINE_TEST(test_json_roundtrip_operator_fields)
{
    public_identity_t *pub = _mk_pub("node-op", "10.0.0.5");
    pub->operator_bound = true;
    pub->operator_attested_at = 1721800000.0;

    json_t *obj = NULL;
    ck_assert_ret_ok(public_identity_to_json(pub, &obj));
    ck_assert_ptr_nonnull(obj);
    ck_assert(json_is_true(json_object_get(obj, "operator_bound")));
    ck_assert(json_is_number(json_object_get(obj, "operator_attested_at")));

    public_identity_t back;
    memset(&back, 0, sizeof(back));
    ck_assert_ret_ok(public_identity_from_json(obj, &back));
    ck_assert(back.operator_bound);
    ck_assert_double_eq_tol(back.operator_attested_at, 1721800000.0, 1e-6);

    json_decref(obj);
    smrt_deref(pub);
}
END_TEST_DEFINITION()

/* A plain (non-operator) peer emits NEITHER key -> byte-identical to the
 * pre-feature canonical form (backward compat / cross-runtime parity). */
DEFINE_TEST(test_json_plain_peer_omits_operator_keys)
{
    public_identity_t *pub = _mk_pub("node-plain", "10.0.0.6");

    json_t *obj = NULL;
    ck_assert_ret_ok(public_identity_to_json(pub, &obj));
    ck_assert_ptr_null(json_object_get(obj, "operator_bound"));
    ck_assert_ptr_null(json_object_get(obj, "operator_attested_at"));
    /* the six base keys and nothing else */
    ck_assert_int_eq((int)json_object_size(obj), 6);

    public_identity_t back;
    memset(&back, 0, sizeof(back));
    ck_assert_ret_ok(public_identity_from_json(obj, &back));
    ck_assert(!back.operator_bound);
    ck_assert_double_eq_tol(back.operator_attested_at, 0.0, 1e-9);

    json_decref(obj);
    smrt_deref(pub);
}
END_TEST_DEFINITION()

#ifdef AT_ZTA_ENABLED
/* The ZTA binding that backs the signal round-trips as base64 (matching Python
 * base64.b64encode / VARIANT_ORIGINAL). */
DEFINE_TEST(test_json_roundtrip_zta_binding_base64)
{
    public_identity_t *pub = _mk_pub("node-op", "10.0.0.7");
    const unsigned char cred[] = "FAKE-OPERATOR-DER-CERT";
    size_t cred_len = sizeof(cred) - 1;
    pub->zta_credential = malloc(cred_len);
    ck_assert_ptr_nonnull(pub->zta_credential);
    memcpy(pub->zta_credential, cred, cred_len);
    pub->zta_credential_len = cred_len;
    crypto_hash_sha256(pub->zta_credential_hash, cred, cred_len);
    snprintf(pub->zta_issuer, sizeof(pub->zta_issuer), "PIV:CN=Jane Operator");
    pub->operator_bound = true;

    json_t *obj = NULL;
    ck_assert_ret_ok(public_identity_to_json(pub, &obj));
    ck_assert(json_is_string(json_object_get(obj, "zta_credential")));
    ck_assert(json_is_string(json_object_get(obj, "zta_credential_hash")));
    ck_assert_str_eq(json_string_value(json_object_get(obj, "zta_issuer")),
                     "PIV:CN=Jane Operator");

    public_identity_t back;
    memset(&back, 0, sizeof(back));
    ck_assert_ret_ok(public_identity_from_json(obj, &back));
    ck_assert_int_eq((int)back.zta_credential_len, (int)cred_len);
    ck_assert_ptr_nonnull(back.zta_credential);
    ck_assert(memcmp(back.zta_credential, cred, cred_len) == 0);
    ck_assert(memcmp(back.zta_credential_hash, pub->zta_credential_hash, 32) == 0);
    ck_assert(back.operator_bound);

    free(back.zta_credential);
    json_decref(obj);
    smrt_deref(pub);
}
END_TEST_DEFINITION()
#endif

#ifdef AT_ZTA_ENABLED
RUN_TESTS(OperatorAttestation,
          test_json_roundtrip_operator_fields,
          test_json_plain_peer_omits_operator_keys,
          test_json_roundtrip_zta_binding_base64)
#else
RUN_TESTS(OperatorAttestation,
          test_json_roundtrip_operator_fields,
          test_json_plain_peer_omits_operator_keys)
#endif
