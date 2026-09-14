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
 * @file post_test.c
 * @brief Feed-post canonical serialization, blake2b content-id, and Ed25519
 *        signing/verify (Increment 7).
 *
 * The canonical-bytes vector below is PINNED and MUST match the Python twin
 * (post_canonical() in capabilities.py): both suites assert the same literal,
 * the cross-language lockstep guard the signed post depends on. The content-id
 * and signature literals are NOT hand-pinned here (blake2b/Ed25519 over the
 * canonical are the cross-runtime contract, exercised end-to-end by the feed-*
 * conformance scenarios on both runtimes); this suite pins the canonical bytes
 * and proves the sign→verify path binds author+seq+ts+tier+body, the content-id
 * is deterministic and body/seq/tier-sensitive, and the wire JSON round-trips.
 * The plaintext-refusal of the peer_post verb is pinned in
 * unencrypted_verbs_test.c (peer_post in the REFUSED list).
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <string.h>
#include <sodium.h>

#include "identity/post.h"

/* Fixed reference input shared with the Python twin:
 *   author uuid = bytes 0..15, seq = 7, ts = 0.0 (all-zero IEEE-754 bytes),
 *   required_tier = 2, body = "hi". */
static const char *const REF_CANON_HEX =
    "000102030405060708090a0b0c0d0e0f"  /* author uuid */
    "0700000000000000"                  /* seq = 7 (u64 le) */
    "0000000000000000"                  /* ts = 0.0 (f64 le) */
    "02"                                /* required_tier = 2 */
    "02000000"                          /* body_len = 2 (u32 le) */
    "6869";                             /* "hi" */
/* blake2b-256(canonical) and the Ed25519 detached signature (seed = bytes 1..32)
 * over the same canonical. PINNED and byte-identical to the Python twin
 * (tests/a_unit/test_post_exchange.py) — the cross-language contract. */
static const char *const REF_ID_HEX =
    "cea547b388f5ad97fa994ce0cbfff1bf62b679ff5a0c4eb6202b51c4c7513e7c";
static const char *const REF_SIG_HEX =
    "0c2364a3291286e9c30414be71aba15e819becb140b5039859efa02b56a2e099"
    "3c2802ed0bf1098150912752cd479fa4bd762e352ba7f20434eea77ae44b6206";

static void ref_author(uuid_t u) { for (int i = 0; i < 16; i++) u[i] = (uint8_t)i; }
static void ref_seed(unsigned char s[crypto_sign_SEEDBYTES])
{ for (size_t i = 0; i < crypto_sign_SEEDBYTES; i++) s[i] = (unsigned char)(i + 1); }

DEFINE_TEST(test_canonical_matches_pinned_vector)
{
    uuid_t a; ref_author(a);
    uint8_t canon[AT_POST_CANON_MAX];
    size_t clen = at_post_canonical(a, 7, 0.0, 2, "hi", canon, sizeof(canon));
    ck_assert(clen != (size_t)-1);
    char hex[2 * AT_POST_CANON_MAX + 1];
    sodium_bin2hex(hex, sizeof(hex), canon, clen);
    ck_assert_str_eq(hex, REF_CANON_HEX);
}

DEFINE_TEST(test_content_id_is_hex_and_deterministic)
{
    uuid_t a; ref_author(a);
    char id1[AT_POST_ID_HEX_LEN + 1];
    char id2[AT_POST_ID_HEX_LEN + 1];
    ck_assert_int_eq(at_post_content_id(a, 7, 0.0, 2, "hi", id1), 0);
    ck_assert_int_eq(at_post_content_id(a, 7, 0.0, 2, "hi", id2), 0);
    ck_assert_int_eq((int)strlen(id1), AT_POST_ID_HEX_LEN);
    ck_assert_str_eq(id1, id2);   /* deterministic */
    ck_assert_str_eq(id1, REF_ID_HEX);   /* pinned cross-language vector */
    for (size_t i = 0; i < AT_POST_ID_HEX_LEN; i++)
        ck_assert((id1[i] >= '0' && id1[i] <= '9') ||
                  (id1[i] >= 'a' && id1[i] <= 'f'));

    /* Any field change flips the content id. */
    char idb[AT_POST_ID_HEX_LEN + 1];
    ck_assert_int_eq(at_post_content_id(a, 7, 0.0, 2, "ho", idb), 0);
    ck_assert(strcmp(id1, idb) != 0);
    ck_assert_int_eq(at_post_content_id(a, 8, 0.0, 2, "hi", idb), 0);
    ck_assert(strcmp(id1, idb) != 0);
    ck_assert_int_eq(at_post_content_id(a, 7, 0.0, 3, "hi", idb), 0);
    ck_assert(strcmp(id1, idb) != 0);
}

DEFINE_TEST(test_sign_verifies_and_binds_fields)
{
    uuid_t a; ref_author(a);
    unsigned char seed[crypto_sign_SEEDBYTES]; ref_seed(seed);
    unsigned char pk[crypto_sign_PUBLICKEYBYTES], sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_seed_keypair(pk, sk, seed);

    char sig[AT_POST_SIG_HEX_LEN + 1];
    ck_assert_int_eq(at_post_sign(sk, a, 7, 0.0, 2, "hi", sig), 0);
    ck_assert_int_eq((int)strlen(sig), AT_POST_SIG_HEX_LEN);
    /* Ed25519 is deterministic: the signature is byte-stable and cross-runtime. */
    ck_assert_str_eq(sig, REF_SIG_HEX);
    ck_assert(at_post_verify(pk, a, 7, 0.0, 2, "hi", sig));

    /* Every field is bound: flipping any one fails verification. */
    ck_assert(!at_post_verify(pk, a, 8, 0.0, 2, "hi", sig));    /* seq */
    ck_assert(!at_post_verify(pk, a, 7, 1.0, 2, "hi", sig));    /* ts */
    ck_assert(!at_post_verify(pk, a, 7, 0.0, 3, "hi", sig));    /* tier */
    ck_assert(!at_post_verify(pk, a, 7, 0.0, 2, "ho", sig));    /* body */
    uuid_t a2; ref_author(a2); a2[0] ^= 0xFF;
    ck_assert(!at_post_verify(pk, a2, 7, 0.0, 2, "hi", sig));   /* author */
}

DEFINE_TEST(test_bad_signature_rejected)
{
    uuid_t a; ref_author(a);
    unsigned char seed[crypto_sign_SEEDBYTES]; ref_seed(seed);
    unsigned char pk[crypto_sign_PUBLICKEYBYTES], sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_seed_keypair(pk, sk, seed);
    char sig[AT_POST_SIG_HEX_LEN + 1];
    ck_assert_int_eq(at_post_sign(sk, a, 7, 0.0, 2, "hi", sig), 0);

    /* All-zero signature (the conformance bad-signature override). */
    char zeros[AT_POST_SIG_HEX_LEN + 1];
    memset(zeros, '0', AT_POST_SIG_HEX_LEN);
    zeros[AT_POST_SIG_HEX_LEN] = '\0';
    ck_assert(!at_post_verify(pk, a, 7, 0.0, 2, "hi", zeros));

    /* Wrong signing key. */
    unsigned char seed2[crypto_sign_SEEDBYTES]; ref_seed(seed2); seed2[0] = 0xAA;
    unsigned char pk2[crypto_sign_PUBLICKEYBYTES], sk2[crypto_sign_SECRETKEYBYTES];
    crypto_sign_seed_keypair(pk2, sk2, seed2);
    ck_assert(!at_post_verify(pk2, a, 7, 0.0, 2, "hi", sig));

    /* Malformed hex. */
    ck_assert(!at_post_verify(pk, a, 7, 0.0, 2, "hi", "not-hex"));
}

DEFINE_TEST(test_body_bound_truncation)
{
    char out[AT_POST_BODY_MAX + 1];
    ck_assert_int_eq((int)at_post_bound_body("hi", out, sizeof(out)), 2);
    ck_assert_str_eq(out, "hi");

    char big[AT_POST_BODY_MAX + 64];
    memset(big, 'x', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';
    ck_assert_int_eq((int)at_post_bound_body(big, out, sizeof(out)), AT_POST_BODY_MAX);
    ck_assert_int_eq((int)strlen(out), AT_POST_BODY_MAX);

    ck_assert_int_eq((int)at_post_bound_body(NULL, out, sizeof(out)), 0);
    ck_assert_str_eq(out, "");
}

DEFINE_TEST(test_wire_json_round_trips)
{
    uuid_t a; ref_author(a);
    char pk_hex[crypto_sign_PUBLICKEYBYTES * 2 + 1];
    unsigned char pk[crypto_sign_PUBLICKEYBYTES], sk[crypto_sign_SECRETKEYBYTES];
    unsigned char seed[crypto_sign_SEEDBYTES]; ref_seed(seed);
    crypto_sign_seed_keypair(pk, sk, seed);
    sodium_bin2hex(pk_hex, sizeof(pk_hex), pk, sizeof(pk));
    char sig[AT_POST_SIG_HEX_LEN + 1];
    ck_assert_int_eq(at_post_sign(sk, a, 7, 0.0, 2, "hi", sig), 0);

    json_t *env = at_post_to_json(a, pk_hex, 7, 0.0, 2, "hi", sig, 0);
    ck_assert_ptr_nonnull(env);

    uuid_t a_out;
    char pk_out[AT_POST_SIG_HEX_LEN + 1];
    char sig_out[AT_POST_SIG_HEX_LEN + 1];
    char body_out[AT_POST_BODY_MAX + 1];
    int64_t seq = 0; double ts = 0.0; uint8_t tier = 0; int hops = -1;
    ck_assert_int_eq(at_post_from_json(env, a_out, pk_out, &seq, &ts, &tier,
                                       body_out, sizeof(body_out), sig_out, &hops), 0);
    ck_assert_int_eq(uuid_compare(a, a_out), 0);
    ck_assert_str_eq(pk_out, pk_hex);
    ck_assert_str_eq(sig_out, sig);
    ck_assert_str_eq(body_out, "hi");
    ck_assert_int_eq((int)seq, 7);
    ck_assert_int_eq((int)tier, 2);
    ck_assert_int_eq(hops, 0);
    /* The round-tripped fields verify against the round-tripped signature. */
    unsigned char vpk[crypto_sign_PUBLICKEYBYTES]; size_t bl = 0;
    ck_assert_int_eq(sodium_hex2bin(vpk, sizeof(vpk), pk_out, strlen(pk_out),
                                    NULL, &bl, NULL), 0);
    ck_assert(at_post_verify(vpk, a_out, seq, ts, tier, body_out, sig_out));
    json_decref(env);
}

DEFINE_TEST(test_malformed_payload_refused)
{
    uuid_t a_out; char pk_out[AT_POST_SIG_HEX_LEN + 1];
    char sig_out[AT_POST_SIG_HEX_LEN + 1]; char body_out[AT_POST_BODY_MAX + 1];
    int64_t seq = 0; double ts = 0.0; uint8_t tier = 0; int hops = 0;

    /* Missing sig is refused. */
    json_t *o = json_object();
    json_object_set_new(o, "author", json_string("00010203-0405-0607-0809-0a0b0c0d0e0f"));
    json_object_set_new(o, "author_pk", json_string("00"));
    json_object_set_new(o, "seq", json_integer(1));
    json_object_set_new(o, "ts", json_real(0.0));
    json_object_set_new(o, "tier", json_integer(0));
    json_object_set_new(o, "body", json_string("hi"));
    json_object_set_new(o, "hops", json_integer(0));
    ck_assert_ret_nonzero(at_post_from_json(o, a_out, pk_out, &seq, &ts, &tier,
                                            body_out, sizeof(body_out), sig_out, &hops));
    json_decref(o);

    /* Out-of-range tier is refused. */
    char pk_hex[crypto_sign_PUBLICKEYBYTES * 2 + 1];
    memset(pk_hex, 'a', sizeof(pk_hex) - 1); pk_hex[sizeof(pk_hex) - 1] = '\0';
    char sig_hex[AT_POST_SIG_HEX_LEN + 1];
    memset(sig_hex, 'b', AT_POST_SIG_HEX_LEN); sig_hex[AT_POST_SIG_HEX_LEN] = '\0';
    json_t *bt = json_object();
    json_object_set_new(bt, "author", json_string("00010203-0405-0607-0809-0a0b0c0d0e0f"));
    json_object_set_new(bt, "author_pk", json_string(pk_hex));
    json_object_set_new(bt, "seq", json_integer(1));
    json_object_set_new(bt, "ts", json_real(0.0));
    json_object_set_new(bt, "tier", json_integer(9));   /* > AT_POST_TIER_MAX */
    json_object_set_new(bt, "body", json_string("hi"));
    json_object_set_new(bt, "sig", json_string(sig_hex));
    json_object_set_new(bt, "hops", json_integer(0));
    ck_assert_ret_nonzero(at_post_from_json(bt, a_out, pk_out, &seq, &ts, &tier,
                                            body_out, sizeof(body_out), sig_out, &hops));
    json_decref(bt);

    /* NULL is refused. */
    ck_assert_ret_nonzero(at_post_from_json(NULL, a_out, pk_out, &seq, &ts, &tier,
                                            body_out, sizeof(body_out), sig_out, &hops));
}

RUN_TESTS(Post,
          test_canonical_matches_pinned_vector,
          test_content_id_is_hex_and_deterministic,
          test_sign_verifies_and_binds_fields,
          test_bad_signature_rejected,
          test_body_bound_truncation,
          test_wire_json_round_trips,
          test_malformed_payload_refused)
