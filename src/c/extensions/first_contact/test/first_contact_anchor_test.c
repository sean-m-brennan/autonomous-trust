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

/* First contact's answer to the join policy's "is this identity anchored"
 * (RD_14.4 plan, Phase 2): a recorded contact as verified_contact or
 * unverified_contact by its state, a device its operator vouched for as the
 * contact does, and a sibling as operator. Every match is on uuid AND keys.
 * Mirrors Python tests/a_unit/test_first_contact_anchor.py. */

#define _GNU_SOURCE
#define DEBUG_TESTS 1
#include "test_setup.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sodium.h>

#include "config/configuration.h"
#include "first_contact/contacts.h"
#include "first_contact/device.h"
#include "first_contact/first_contact.h"
#include "first_contact/siblings.h"
#include "identity/id_ext.h"
#include "identity/identity_priv.h"
#include "identity/join_policy.h"

#define PUB(id) ((const public_identity_t *)(id))

static char g_root[64];
static char g_data[CFG_PATH_LEN + 1];

static void _isolate(void)
{
    snprintf(g_root, sizeof(g_root), "/tmp/at-fc-anchorXXXXXX");
    ck_assert_ptr_nonnull(mkdtemp(g_root));
    setenv("AUTONOMOUS_TRUST_ROOT", g_root, 1);
    setenv(AT_FIRST_CONTACT_ENV, "1", 1);
    ck_assert(get_data_dir(g_data, sizeof(g_data)) > 0);
    char cmd[CFG_PATH_LEN + 16];
    snprintf(cmd, sizeof(cmd), "mkdir -p %s", g_data);
    ck_assert_int_eq(system(cmd), 0);
}

static void _cleanup(void)
{
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", g_root);
    ck_assert_int_eq(system(cmd), 0);
    unsetenv(AT_FIRST_CONTACT_ENV);
}

static identity_t *_mk(const char *name, const uuid_t *with)
{
    uuid_t u;
    if (with != NULL)
        uuid_copy(u, *with);
    else
        uuid_generate(u);
    identity_t *id = NULL;
    ck_assert_ret_ok(identity_create(&u, "127.0.0.1", name, name, &id));
    return id;
}

static void _operator(unsigned char seed_byte, unsigned char sk[crypto_sign_SECRETKEYBYTES])
{
    unsigned char seed[32], pk[crypto_sign_PUBLICKEYBYTES];
    memset(seed, seed_byte, sizeof(seed));
    crypto_sign_seed_keypair(pk, sk, seed);
}

static void _record(contacts_t *store, const identity_t *who, bool verified)
{
    contact_t c;
    memset(&c, 0, sizeof(c));
    c.identity = *PUB(who);
    c.identity.operator_key_binding = NULL;
    if (verified)
        contact_mark_verified(&c, 0.3);
    ck_assert_ret_ok(contacts_add(store, &c));
}

static uint32_t _anchors(const identity_t *who)
{
    return identity_ext_anchor_classes(NULL, PUB(who));
}

DEFINE_TEST(test_contacts_anchor_by_their_state_and_keys)
{
    _isolate();
    identity_t *bob = _mk("bob", NULL), *carol = _mk("carol", NULL);
    identity_t *stranger = _mk("stranger", NULL);
    identity_t *impostor = _mk("impostor", &bob->uuid);
    contacts_t store;
    contacts_init(&store);
    _record(&store, bob, true);
    _record(&store, carol, false);
    ck_assert_ret_ok(contacts_save(&store, g_data));
    contacts_free(&store);

    ck_assert_uint_eq(_anchors(bob), AT_ANCHOR_VERIFIED_CONTACT);
    ck_assert_uint_eq(_anchors(carol), AT_ANCHOR_UNVERIFIED_CONTACT);
    ck_assert_uint_eq(_anchors(stranger), 0);
    /* Bob's uuid with other keys: a cohort can list a contact's uuid. */
    ck_assert(uuid_compare(impostor->uuid, bob->uuid) == 0);
    ck_assert_uint_eq(_anchors(impostor), 0);
    /* Off without first contact. */
    unsetenv(AT_FIRST_CONTACT_ENV);
    ck_assert_uint_eq(_anchors(bob), 0);

    identity_free(bob);
    identity_free(carol);
    identity_free(stranger);
    identity_free(impostor);
    _cleanup();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_device_the_contacts_operator_vouched_for_anchors_as_the_contact)
{
    _isolate();
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    _operator(0x33, sk);
    identity_t *phone = _mk("bob-phone", NULL), *laptop = _mk("bob-laptop", NULL);
    contacts_t store;
    contacts_init(&store);
    contact_t c;
    memset(&c, 0, sizeof(c));
    c.identity = *PUB(phone);
    c.identity.operator_key_binding = NULL;
    contact_mark_verified(&c, 0.3);
    at_dir_signed_t cert;
    ck_assert_int_eq(at_device_cert_create(sk, PUB(phone), 1000, &cert), AT_DEVICE_OK);
    ck_assert_int_eq(at_adopt_operator(&c, &cert, &store), AT_DEVICE_OK);
    at_dir_free(&cert);
    ck_assert_ret_ok(contacts_add(&store, &c));
    ck_assert_int_eq(at_device_cert_create(sk, PUB(laptop), 1000, &cert), AT_DEVICE_OK);
    ck_assert_int_eq(at_link_device(&store, PUB(laptop), &cert, NULL), AT_DEVICE_OK);
    at_dir_free(&cert);
    ck_assert_ret_ok(contacts_save(&store, g_data));
    contacts_free(&store);

    ck_assert_uint_eq(_anchors(laptop), AT_ANCHOR_VERIFIED_CONTACT);
    identity_t *impostor = _mk("impostor", &laptop->uuid);
    ck_assert_uint_eq(_anchors(impostor), 0);

    identity_free(phone);
    identity_free(laptop);
    identity_free(impostor);
    _cleanup();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_sibling_anchors_as_operator)
{
    _isolate();
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    _operator(0x44, sk);
    identity_t *me = _mk("my-phone", NULL), *laptop = _mk("my-laptop", NULL);
    at_dir_signed_t own, theirs;
    ck_assert_int_eq(at_device_cert_create(sk, PUB(me), 1000, &own), AT_DEVICE_OK);
    ck_assert_int_eq(at_device_cert_create(sk, PUB(laptop), 1000, &theirs), AT_DEVICE_OK);
    at_siblings_t sib;
    at_siblings_init(&sib);
    ck_assert_int_eq(at_siblings_add(&sib, PUB(laptop), &theirs, &own), 0);
    ck_assert_ret_ok(at_siblings_save(&sib, g_data));
    at_siblings_free(&sib);
    at_dir_free(&own);
    at_dir_free(&theirs);

    ck_assert_uint_eq(_anchors(laptop), AT_ANCHOR_OPERATOR);
    identity_t *impostor = _mk("impostor", &laptop->uuid);
    ck_assert_uint_eq(_anchors(impostor), 0);

    identity_free(me);
    identity_free(laptop);
    identity_free(impostor);
    _cleanup();
}
END_TEST_DEFINITION()

RUN_TESTS(FirstContactAnchor,
          test_contacts_anchor_by_their_state_and_keys,
          test_a_device_the_contacts_operator_vouched_for_anchors_as_the_contact,
          test_a_sibling_anchors_as_operator)
