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
 * @file post_multicast_test.c
 * @brief The encrypted group-multicast SEND/RECV crypto round-trip a feed post
 *        rides on (Increment 7).
 *
 * net_proc's new RECIPIENT_GROUP send path frames a message as
 * nonce || group_encrypt(wire) on NET_CHAN_GROUP, and handle_inbound_group
 * reverses it with group_decrypt. group_encrypt/group_decrypt were dead code
 * before this increment, so this pins the pair the multicast path now depends on:
 * a post payload group_encrypt'd under a cohort key round-trips through
 * group_decrypt with the same key, is UNREADABLE under a different cohort key,
 * and the recovered plaintext still verifies as a signed post. The full
 * handler-level send→recv→verify→tier-gate→dedup→forward path is exercised
 * end-to-end by the feed-*.yaml conformance scenarios (both runtimes).
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <string.h>
#include <stdlib.h>
#include <sodium.h>

#include "identity/group.h"
#include "identity/identity.h"   /* msg_str_t */
#include "identity/post.h"

/* Frame a plaintext exactly as net_encrypt_and_send's RECIPIENT_GROUP branch:
 * nonce || crypto_box(plaintext) via group_encrypt. Returns malloc'd frame. */
static uint8_t *group_frame(const group_t *grp, const uint8_t *plain,
                            size_t plain_len, size_t *frame_len_out)
{
    unsigned char nonce[crypto_box_NONCEBYTES];
    randombytes_buf(nonce, sizeof(nonce));
    size_t cipher_len = plain_len + crypto_box_MACBYTES;
    unsigned char *cipher = malloc(cipher_len);
    if (cipher == NULL) return NULL;
    msg_str_t in = {.msg = (unsigned char *)plain, .len = plain_len};
    if (group_encrypt(grp, &in, grp, nonce, cipher) != 0) { free(cipher); return NULL; }
    size_t frame_len = sizeof(nonce) + cipher_len;
    uint8_t *frame = malloc(frame_len);
    if (frame == NULL) { free(cipher); return NULL; }
    memcpy(frame, nonce, sizeof(nonce));
    memcpy(frame + sizeof(nonce), cipher, cipher_len);
    free(cipher);
    *frame_len_out = frame_len;
    return frame;
}

/* Reverse it exactly as handle_inbound_group: nonce | cipher -> group_decrypt.
 * Returns malloc'd plaintext, or NULL on failure; sets *plain_len_out. */
static uint8_t *group_unframe(const group_t *grp, const uint8_t *frame,
                              size_t frame_len, size_t *plain_len_out)
{
    if (frame_len <= crypto_box_NONCEBYTES + crypto_box_MACBYTES) return NULL;
    const unsigned char *nonce = frame;
    const unsigned char *cipher = frame + crypto_box_NONCEBYTES;
    size_t cipher_len = frame_len - crypto_box_NONCEBYTES;
    size_t plain_len = cipher_len - crypto_box_MACBYTES;
    unsigned char *plain = malloc(plain_len);
    if (plain == NULL) return NULL;
    msg_str_t cmsg = {.msg = (unsigned char *)cipher, .len = cipher_len};
    if (group_decrypt(grp, &cmsg, grp, nonce, plain) != 0) { free(plain); return NULL; }
    *plain_len_out = plain_len;
    return plain;
}

DEFINE_TEST(test_group_roundtrip_delivers_post)
{
    ck_assert(sodium_init() >= 0);
    group_t g; memset(&g, 0, sizeof(g));
    ck_assert_int_eq(group_init(NULL, (char *)"10.0.0.1", &g), 0);

    const char *msg = "{\"author\":\"x\",\"body\":\"hello feed\"}";
    size_t frame_len = 0;
    uint8_t *frame = group_frame(&g, (const uint8_t *)msg, strlen(msg), &frame_len);
    ck_assert_ptr_nonnull(frame);
    /* The wire frame is not the plaintext (it is encrypted). */
    ck_assert(frame_len > strlen(msg));

    size_t plain_len = 0;
    uint8_t *plain = group_unframe(&g, frame, frame_len, &plain_len);
    ck_assert_ptr_nonnull(plain);
    ck_assert_int_eq((int)plain_len, (int)strlen(msg));
    ck_assert_int_eq(memcmp(plain, msg, plain_len), 0);

    free(frame);
    free(plain);
    if (g.address_map.items != NULL) map_free(&g.address_map);
}

DEFINE_TEST(test_wrong_group_key_cannot_decrypt)
{
    ck_assert(sodium_init() >= 0);
    group_t a; memset(&a, 0, sizeof(a));
    group_t b; memset(&b, 0, sizeof(b));
    ck_assert_int_eq(group_init(NULL, (char *)"10.0.0.1", &a), 0);
    ck_assert_int_eq(group_init(NULL, (char *)"10.0.0.2", &b), 0);

    const char *msg = "confidential feed post";
    size_t frame_len = 0;
    uint8_t *frame = group_frame(&a, (const uint8_t *)msg, strlen(msg), &frame_len);
    ck_assert_ptr_nonnull(frame);

    /* A node holding a DIFFERENT cohort key cannot read the multicast. */
    size_t plain_len = 0;
    uint8_t *plain = group_unframe(&b, frame, frame_len, &plain_len);
    ck_assert_ptr_null(plain);

    free(frame);
    if (a.address_map.items != NULL) map_free(&a.address_map);
    if (b.address_map.items != NULL) map_free(&b.address_map);
}

DEFINE_TEST(test_signed_post_survives_group_transit)
{
    ck_assert(sodium_init() >= 0);
    group_t g; memset(&g, 0, sizeof(g));
    ck_assert_int_eq(group_init(NULL, (char *)"10.0.0.1", &g), 0);

    uuid_t author; for (int i = 0; i < 16; i++) author[i] = (uint8_t)(i + 3);
    unsigned char seed[crypto_sign_SEEDBYTES];
    for (size_t i = 0; i < sizeof(seed); i++) seed[i] = (unsigned char)(i + 5);
    unsigned char pk[crypto_sign_PUBLICKEYBYTES], sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_seed_keypair(pk, sk, seed);
    char pk_hex[crypto_sign_PUBLICKEYBYTES * 2 + 1];
    sodium_bin2hex(pk_hex, sizeof(pk_hex), pk, sizeof(pk));
    char sig[AT_POST_SIG_HEX_LEN + 1];
    ck_assert_int_eq(at_post_sign(sk, author, 42, 0.0, 1, "over the wire", sig), 0);

    json_t *env = at_post_to_json(author, pk_hex, 42, 0.0, 1, "over the wire", sig, 0);
    ck_assert_ptr_nonnull(env);
    char *wire = json_dumps(env, JSON_COMPACT);
    json_decref(env);
    ck_assert_ptr_nonnull(wire);

    size_t frame_len = 0;
    uint8_t *frame = group_frame(&g, (const uint8_t *)wire, strlen(wire), &frame_len);
    ck_assert_ptr_nonnull(frame);
    size_t plain_len = 0;
    uint8_t *plain = group_unframe(&g, frame, frame_len, &plain_len);
    ck_assert_ptr_nonnull(plain);

    json_error_t jerr;
    json_t *back = json_loadb((const char *)plain, plain_len, 0, &jerr);
    ck_assert_ptr_nonnull(back);
    uuid_t a_out; char pk_out[AT_POST_SIG_HEX_LEN + 1];
    char sig_out[AT_POST_SIG_HEX_LEN + 1]; char body_out[AT_POST_BODY_MAX + 1];
    int64_t seq = 0; double ts = 0.0; uint8_t tier = 0; int hops = -1;
    ck_assert_int_eq(at_post_from_json(back, a_out, pk_out, &seq, &ts, &tier,
                                       body_out, sizeof(body_out), sig_out, &hops), 0);
    json_decref(back);

    unsigned char vpk[crypto_sign_PUBLICKEYBYTES]; size_t bl = 0;
    ck_assert_int_eq(sodium_hex2bin(vpk, sizeof(vpk), pk_out, strlen(pk_out),
                                    NULL, &bl, NULL), 0);
    ck_assert(at_post_verify(vpk, a_out, seq, ts, tier, body_out, sig_out));
    ck_assert_str_eq(body_out, "over the wire");

    free(wire);
    free(frame);
    free(plain);
    if (g.address_map.items != NULL) map_free(&g.address_map);
}

RUN_TESTS(PostMulticast,
          test_group_roundtrip_delivers_post,
          test_wrong_group_key_cannot_decrypt,
          test_signed_post_survives_group_transit)
