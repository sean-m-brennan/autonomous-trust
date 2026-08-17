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
#include <sodium.h>
#include <uuid/uuid.h>
#include <jansson.h>

#include "identity/group.h"
#include "identity/identity_priv.h"

DEFINE_TEST(test_group_json_roundtrip)
{
    ck_assert(sodium_init() >= 0);

    uuid_t uuid;
    uuid_generate(uuid);
    char addr[] = "10.0.0.42";

    group_t *grp = NULL;
    ck_assert_ret_ok(group_create(&uuid, addr, &grp));

    /* Serialize to JSON */
    json_t *obj = NULL;
    ck_assert_ret_ok(group_to_json(grp, &obj));
    ck_assert_ptr_nonnull(obj);

    /* Check typename */
    const char *tn = json_string_value(json_object_get(obj, "typename"));
    ck_assert_ptr_nonnull(tn);
    ck_assert_str_eq(tn, "group");

    /* Check UUID in JSON */
    const char *j_uuid = json_string_value(json_object_get(obj, "uuid"));
    ck_assert_ptr_nonnull(j_uuid);

    char uuid_str[UUID_STRING_LEN + 1];
    uuid_unparse(uuid, uuid_str);
    ck_assert_str_eq(j_uuid, uuid_str);

    /* Check address in JSON */
    const char *j_addr = json_string_value(json_object_get(obj, "address"));
    ck_assert_ptr_nonnull(j_addr);
    ck_assert_str_eq(j_addr, "10.0.0.42");

    /* Check encryptor hex_seed exists */
    json_t *encr = json_object_get(obj, "encryptor");
    ck_assert_ptr_nonnull(encr);
    const char *hex = json_string_value(json_object_get(encr, "hex_seed"));
    ck_assert_ptr_nonnull(hex);
    ck_assert(strlen(hex) > 0);

    json_decref(obj);
    group_free(grp);
}
END_TEST_DEFINITION()

/* Group-key sync (SG3): group_to_json must serialize the RAW private key
 * (when owned) so group_from_json reconstructs the SAME keypair — a peer
 * receiving full_history can then decrypt group traffic. The prior code
 * wrote the PUBLIC key but read it back as a seed, so the keypair never
 * round-tripped. Also pins the cross-runtime canonical: hex_seed is the
 * raw private key + public_only=false. */
DEFINE_TEST(test_group_json_roundtrip_preserves_keypair)
{
    ck_assert(sodium_init() >= 0);

    uuid_t uuid;
    uuid_generate(uuid);
    char addr[] = "10.0.0.7";

    group_t *grp = NULL;
    ck_assert_ret_ok(group_create(&uuid, addr, &grp));
    /* group_create generates a keypair, so we own the private key */
    ck_assert_int_eq(sodium_is_zero(grp->encryptor.private,
                                    crypto_box_SECRETKEYBYTES), 0);

    json_t *obj = NULL;
    ck_assert_ret_ok(group_to_json(grp, &obj));

    /* Canonical: hex_seed is 64 chars (raw 32-byte private key) + public_only=false */
    json_t *encr = json_object_get(obj, "encryptor");
    const char *hex = json_string_value(json_object_get(encr, "hex_seed"));
    ck_assert_ptr_nonnull(hex);
    ck_assert_uint_eq(strlen(hex), (size_t)(crypto_box_SECRETKEYBYTES * 2));
    json_t *po = json_object_get(encr, "public_only");
    ck_assert_ptr_nonnull(po);
    ck_assert(!json_boolean_value(po));

    /* Round-trip: the reconstructed keypair must match byte-for-byte */
    group_t grp2;
    memset(&grp2, 0, sizeof(grp2));
    ck_assert_ret_ok(group_from_json(obj, &grp2));
    ck_assert_int_eq(memcmp(grp->encryptor.private, grp2.encryptor.private,
                            crypto_box_SECRETKEYBYTES), 0);
    ck_assert_int_eq(memcmp(grp->encryptor.public, grp2.encryptor.public,
                            crypto_box_PUBLICKEYBYTES), 0);

    json_decref(obj);
    group_free(grp);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_group_free_null)
{
    /* group_free(NULL) should not crash */
    group_free(NULL);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_group_publish_null)
{
    /* identity_publish(NULL, ...) should return EINVAL */
    public_identity_t *pub = NULL;
    int ret = identity_publish(NULL, &pub);
    ck_assert(ret != 0);
    ck_assert_ptr_null(pub);
}
END_TEST_DEFINITION()

/* Regression for group.c:38 (and the sibling site at :148) — group_init
 * used strncpy(group->address, address, ADDR_LEN) with no explicit NUL
 * terminator. group_create() happens to zero the struct first, but direct
 * callers of group_init with an uninitialised stack-allocated group_t and
 * an address whose first ADDR_LEN bytes are non-NUL see garbage past the
 * copy.  Fix explicitly NUL-terminates at byte ADDR_LEN. */
DEFINE_TEST(test_group_init_nul_terminates_long_address)
{
    ck_assert(sodium_init() >= 0);

    group_t group;
    /* Pre-fill with non-NUL so we can detect a missing explicit NUL.  This
     * models a stack-allocated struct passed directly to group_init. */
    memset(&group, 0xAB, sizeof(group));

    char addr[ADDR_LEN + 1];
    memset(addr, 'X', ADDR_LEN);
    addr[ADDR_LEN] = '\0';

    (void)group_init(NULL, addr, &group);

    ck_assert_int_eq((unsigned char)group.address[ADDR_LEN], 0);
    ck_assert_uint_eq(strlen(group.address), (size_t)ADDR_LEN);
}
END_TEST_DEFINITION()


/* --- Group key rotation (ISSUES.md §10.2) --------------------------------
 * Admission used to hand a joiner a PERMANENT shared key, so a new member
 * could decrypt cohort traffic it had recorded before it joined. Admission now
 * rotates; these pin the three things that makes safe. */

DEFINE_TEST(test_group_rotate_key_mints_new_key_and_bumps_epoch)
{
    ck_assert(sodium_init() >= 0);

    uuid_t uuid;
    uuid_generate(uuid);
    char addr[] = "10.0.0.1";
    group_t *grp = NULL;
    ck_assert_ret_ok(group_create(&uuid, addr, &grp));
    ck_assert(grp->key_epoch == 0);   /* never rotated */

    unsigned char before[crypto_box_SECRETKEYBYTES];
    memcpy(before, grp->encryptor.private, sizeof(before));

    ck_assert(group_rotate_key(grp) == 1);
    ck_assert(grp->key_epoch == 1);
    /* The point of the rotation: the live key is a DIFFERENT key. */
    ck_assert(memcmp(before, grp->encryptor.private, sizeof(before)) != 0);
    /* ...and the superseded one is retained for the grace window only. */
    ck_assert(grp->num_previous_keys == 1);
    ck_assert_mem_eq(grp->previous_keys[0].private, before, sizeof(before));

    /* Retained keys are bounded: a third rotation evicts the oldest rather
     * than growing the window without limit. */
    ck_assert(group_rotate_key(grp) == 2);
    ck_assert(group_rotate_key(grp) == 3);
    ck_assert(grp->num_previous_keys == GROUP_PREVIOUS_KEY_MAX);

    group_free(grp);
}

/* A public-only view of somebody else's group has no standing to rotate it:
 * minting a key we cannot already decrypt with would fork the cohort into two
 * halves that cannot hear each other. */
DEFINE_TEST(test_group_rotate_key_refused_without_private)
{
    ck_assert(sodium_init() >= 0);

    uuid_t uuid;
    uuid_generate(uuid);
    char addr[] = "10.0.0.2";
    group_t *grp = NULL;
    ck_assert_ret_ok(group_create(&uuid, addr, &grp));
    sodium_memzero(grp->encryptor.private, crypto_box_SECRETKEYBYTES);

    ck_assert(group_rotate_key(grp) == -1);
    ck_assert(grp->key_epoch == 0);
    ck_assert(grp->num_previous_keys == 0);

    group_free(grp);
}

/* accept_rotation's three conditions, each of which is load-bearing. The
 * epoch one is the security-relevant half: without it a captured OLD key could
 * be replayed back over a newer one, which is exactly what rotation exists to
 * foreclose. */
DEFINE_TEST(test_group_accept_rotation_requires_higher_epoch_and_key)
{
    ck_assert(sodium_init() >= 0);

    uuid_t uuid;
    uuid_generate(uuid);
    char addr[] = "10.0.0.3";
    group_t *mine = NULL, *theirs = NULL;
    ck_assert_ret_ok(group_create(&uuid, addr, &mine));
    ck_assert_ret_ok(group_create(&uuid, addr, &theirs));
    memcpy(theirs->uuid, mine->uuid, sizeof(uuid_t));

    /* Equal epoch: not newer, so not adopted (this is the replay case). */
    ck_assert(!group_accept_rotation(mine, theirs));

    /* Strictly higher epoch + a real private key: adopted. */
    theirs->key_epoch = 1;
    ck_assert(group_accept_rotation(mine, theirs));
    ck_assert(mine->key_epoch == 1);
    ck_assert_mem_eq(mine->encryptor.private, theirs->encryptor.private,
                     crypto_box_SECRETKEYBYTES);
    /* Our superseded key stays available for the grace window. */
    ck_assert(mine->num_previous_keys == 1);

    /* A LOWER epoch afterwards is refused — the replay, arriving late. */
    unsigned char current[crypto_box_SECRETKEYBYTES];
    memcpy(current, mine->encryptor.private, sizeof(current));
    group_t *stale = NULL;
    ck_assert_ret_ok(group_create(&uuid, addr, &stale));
    memcpy(stale->uuid, mine->uuid, sizeof(uuid_t));
    stale->key_epoch = 0;
    ck_assert(!group_accept_rotation(mine, stale));
    ck_assert_mem_eq(mine->encryptor.private, current, sizeof(current));

    /* A public-only offer carries nothing to adopt: taking it would leave us
     * unable to decrypt our own cohort. */
    stale->key_epoch = 9;
    sodium_memzero(stale->encryptor.private, crypto_box_SECRETKEYBYTES);
    ck_assert(!group_accept_rotation(mine, stale));
    ck_assert(mine->key_epoch == 1);

    /* A key for a DIFFERENT cohort is not a rotation of this one. */
    uuid_t other_uuid;
    uuid_generate(other_uuid);
    group_t *foreign = NULL;
    ck_assert_ret_ok(group_create(&other_uuid, addr, &foreign));
    foreign->key_epoch = 99;
    ck_assert(!group_accept_rotation(mine, foreign));
    ck_assert(mine->key_epoch == 1);

    group_free(foreign);
    group_free(stale);
    group_free(theirs);
    group_free(mine);
}

/* A rotation is not synchronous across a cohort: a member that has not yet
 * processed the key update is still sending under the old key. Those frames
 * must still decrypt, or rotation would cost more than it buys. */
DEFINE_TEST(test_group_decrypt_falls_back_to_retired_key)
{
    ck_assert(sodium_init() >= 0);

    uuid_t uuid;
    uuid_generate(uuid);
    char addr[] = "10.0.0.4";
    group_t *sender = NULL, *receiver = NULL;
    ck_assert_ret_ok(group_create(&uuid, addr, &sender));
    ck_assert_ret_ok(group_create(&uuid, addr, &receiver));
    /* Both hold the SAME shared key, as cohort members do. */
    memcpy(&receiver->encryptor, &sender->encryptor, sizeof(encryptor_t));

    unsigned char plain[] = "cohort traffic in flight";
    msg_str_t in = { plain, sizeof(plain) };
    unsigned char nonce[crypto_box_NONCEBYTES];
    randombytes_buf(nonce, sizeof(nonce));
    unsigned char cipher[sizeof(plain) + crypto_box_MACBYTES];
    ck_assert_ret_ok(group_encrypt(sender, &in, sender, nonce, cipher));

    /* The receiver rotates (it just admitted somebody); the sender has not yet
     * seen the update. */
    ck_assert(group_rotate_key(receiver) == 1);

    msg_str_t ct = { cipher, sizeof(cipher) };
    unsigned char out[sizeof(plain)] = {0};
    ck_assert_ret_ok(group_decrypt(receiver, &ct, sender, nonce, out));
    ck_assert_mem_eq(out, plain, sizeof(plain));

    /* But the window is bounded: age the retired key past the grace period and
     * the same frame no longer opens. An unbounded fallback would make
     * rotation decorative. */
    receiver->previous_retired_at[0] -= (GROUP_PREVIOUS_KEY_GRACE + 1.0);
    ck_assert_ret_nonzero(group_decrypt(receiver, &ct, sender, nonce, out));

    group_free(receiver);
    group_free(sender);
}

RUN_TESTS(Group2, test_group_json_roundtrip,
          test_group_json_roundtrip_preserves_keypair, test_group_free_null,
          test_group_publish_null,
          test_group_init_nul_terminates_long_address,
          test_group_rotate_key_mints_new_key_and_bumps_epoch,
          test_group_rotate_key_refused_without_private,
          test_group_accept_rotation_requires_higher_epoch_and_key,
          test_group_decrypt_falls_back_to_retired_key)
