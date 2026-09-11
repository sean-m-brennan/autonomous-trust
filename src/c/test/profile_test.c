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

/**
 * @file profile_test.c
 * @brief agora.profile canonical serialization, signing, and field validation
 *        (Increment 3). The canonical-bytes + signature vectors below are PINNED
 *        and MUST match the Python twin (tests/a_unit/test_profile_exchange.py):
 *        both suites assert the same literals, which is the cross-language
 *        lockstep guard the signed exchange depends on.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <string.h>
#include <sodium.h>
#include <jansson.h>

#include "identity/profile.h"

/* Fixed reference input shared with the Python twin:
 *   seed = bytes 1..32, uuid = bytes 0..15,
 *   profile = {display_name:"José 🚀", handle:"jose_b", bio:"hi there",
 *              avatar_ref:"https://x/a.png",
 *              links:["https://a.example","https://b.example"]} */
static const char *const REF_JSON =
    "{\"display_name\":\"Jos\\u00e9 \\ud83d\\ude80\",\"handle\":\"jose_b\","
    "\"bio\":\"hi there\",\"avatar_ref\":\"https://x/a.png\","
    "\"links\":[\"https://a.example\",\"https://b.example\"]}";
static const char *const REF_CANON_HEX =
    "000102030405060708090a0b0c0d0e0f0a0000004a6f73c3a920f09f9a80060000006a6f"
    "73655f620800000068692074686572650f00000068747470733a2f2f782f612e706e6702"
    "0000001100000068747470733a2f2f612e6578616d706c65110000006874747073"
    "3a2f2f622e6578616d706c65";
static const char *const REF_SIG_HEX =
    "2f89d11b9c247ff49a657895f7765dc79464fa5e2acc1a10fa08f29e750ea41872330da4"
    "4324e948d072efb83aa7329f2cbde4d3b3c077eaaef621c0f57afc01";

static void ref_uuid(uuid_t u)   { for (int i = 0; i < 16; i++) u[i] = (uint8_t)i; }
static void ref_seed(unsigned char s[crypto_sign_SEEDBYTES])
{ for (size_t i = 0; i < crypto_sign_SEEDBYTES; i++) s[i] = (unsigned char)(i + 1); }

static void ref_profile(at_profile_t *p)
{
    json_error_t je;
    json_t *o = json_loads(REF_JSON, 0, &je);
    ck_assert_ptr_nonnull(o);
    ck_assert_int_eq(at_profile_from_json(o, true, p), 0);
    json_decref(o);
}

DEFINE_TEST(test_canonical_matches_pinned_vector)
{
    at_profile_t p; ref_profile(&p);
    uuid_t u; ref_uuid(u);
    uint8_t canon[4096];
    size_t clen = at_profile_canonical(u, &p, canon, sizeof(canon));
    ck_assert(clen != (size_t)-1);
    char hex[2 * sizeof(canon) + 1];
    sodium_bin2hex(hex, sizeof(hex), canon, clen);
    ck_assert_str_eq(hex, REF_CANON_HEX);
}

DEFINE_TEST(test_sign_matches_pinned_and_verifies)
{
    at_profile_t p; ref_profile(&p);
    uuid_t u; ref_uuid(u);
    unsigned char seed[crypto_sign_SEEDBYTES]; ref_seed(seed);
    unsigned char pk[crypto_sign_PUBLICKEYBYTES], sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_seed_keypair(pk, sk, seed);

    char sig[AT_PROFILE_SIG_HEX_LEN + 1];
    ck_assert_int_eq(at_profile_sign(sk, u, &p, sig), 0);
    /* Ed25519 is deterministic: the signature is byte-stable and cross-runtime. */
    ck_assert_str_eq(sig, REF_SIG_HEX);
    ck_assert(at_profile_verify(pk, u, &p, sig));
}

DEFINE_TEST(test_verify_rejects_tamper_and_wrong_key)
{
    at_profile_t p; ref_profile(&p);
    uuid_t u; ref_uuid(u);
    unsigned char seed[crypto_sign_SEEDBYTES]; ref_seed(seed);
    unsigned char pk[crypto_sign_PUBLICKEYBYTES], sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_seed_keypair(pk, sk, seed);
    char sig[AT_PROFILE_SIG_HEX_LEN + 1];
    ck_assert_int_eq(at_profile_sign(sk, u, &p, sig), 0);

    /* Tampered field: signature no longer matches. */
    at_profile_t p2 = p;
    strcpy(p2.handle, "someone_else");
    ck_assert(!at_profile_verify(pk, u, &p2, sig));

    /* Wrong signer uuid (re-attribution): rejected because uuid is in canonical. */
    uuid_t u2; ref_uuid(u2); u2[0] ^= 0xFF;
    ck_assert(!at_profile_verify(pk, u2, &p, sig));

    /* Different key. */
    unsigned char seed2[crypto_sign_SEEDBYTES]; ref_seed(seed2); seed2[0] = 0xAA;
    unsigned char pk2[crypto_sign_PUBLICKEYBYTES], sk2[crypto_sign_SECRETKEYBYTES];
    crypto_sign_seed_keypair(pk2, sk2, seed2);
    ck_assert(!at_profile_verify(pk2, u, &p, sig));

    /* Malformed sig hex. */
    ck_assert(!at_profile_verify(pk, u, &p, "not-hex"));
}

/* Parse one JSON object string with validate=true; return the rc. */
static int parse_validate(const char *json)
{
    json_error_t je;
    json_t *o = json_loads(json, 0, &je);
    if (o == NULL) return -99;
    at_profile_t p;
    int rc = at_profile_from_json(o, true, &p);
    json_decref(o);
    return rc;
}

DEFINE_TEST(test_validate_accepts_and_rejects)
{
    ck_assert_int_eq(parse_validate("{\"display_name\":\"Ok\"}"), 0);
    ck_assert_int_eq(parse_validate("{}"), 0);   /* empty is valid (opted out) */
    /* over-bound handle (33 bytes > 32) */
    ck_assert((parse_validate(
        "{\"handle\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}")) != 0);
    /* bad handle charset */
    ck_assert((parse_validate("{\"handle\":\"has space\"}")) != 0);
    /* control char in a field */
    ck_assert((parse_validate("{\"bio\":\"a\\u0001b\"}")) != 0);
    /* too many links (5 > 4) */
    ck_assert((parse_validate(
        "{\"links\":[\"a\",\"b\",\"c\",\"d\",\"e\"]}")) != 0);
}

DEFINE_TEST(test_sanitize_truncates_trusted_input)
{
    /* validate=false truncates rather than rejecting; a bad-charset handle is
     * dropped but the rest is kept. */
    json_error_t je;
    json_t *o = json_loads(
        "{\"display_name\":\"Keep\",\"handle\":\"bad space\"}", 0, &je);
    ck_assert_ptr_nonnull(o);
    at_profile_t p;
    ck_assert_int_eq(at_profile_from_json(o, false, &p), 0);
    json_decref(o);
    ck_assert_str_eq(p.display_name, "Keep");
    ck_assert_str_eq(p.handle, "");          /* dropped */
    ck_assert(!at_profile_is_empty(&p));
}

DEFINE_TEST(test_compact_str_roundtrip)
{
    at_profile_t p; ref_profile(&p);
    char buf[AT_PROFILE_JSON_MAX + 1];
    ck_assert((at_profile_to_compact_str(&p, buf, sizeof(buf))) > 0);
    /* Re-parse the compact form; the fields must survive intact. */
    json_error_t je;
    json_t *o = json_loads(buf, 0, &je);
    ck_assert_ptr_nonnull(o);
    at_profile_t p2;
    ck_assert_int_eq(at_profile_from_json(o, true, &p2), 0);
    json_decref(o);
    ck_assert_str_eq(p2.handle, "jose_b");
    ck_assert_str_eq(p2.avatar_ref, "https://x/a.png");
    ck_assert_int_eq(p2.num_links, 2);
}

RUN_TESTS(Profile,
          test_canonical_matches_pinned_vector,
          test_sign_matches_pinned_and_verifies,
          test_verify_rejects_tamper_and_wrong_key,
          test_validate_accepts_and_rejects,
          test_sanitize_truncates_trusted_input,
          test_compact_str_roundtrip)
