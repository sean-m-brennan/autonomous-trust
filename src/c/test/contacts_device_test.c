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

/* One human, several devices (contacts/device), FIRST_CONTACT_PLAN Phase 4.
 * Mirrors Python tests/a_unit/test_first_contact_devices.py. */

#define _GNU_SOURCE
#define DEBUG_TESTS 1
#include "test_setup.h"

#include <stdlib.h>
#include <string.h>

#include <sodium.h>

#include "contacts/contacts.h"
#include "contacts/device.h"
#include "identity/identity_priv.h"

/* Python: create_device_cert(SigningKey(0x33*32), node uuid ...d1 with
 * signing key(0x55*32), issued_at=1790000000). */
#define PY_CERT "{\"body\":\"{\\\"v\\\":1,\\\"typename\\\":\\\"at-device-cert\\\",\\\"operator\\\":\\\"17cb79fb2b4120f2b1ec65e4198d6e08b28e813feb01e4a400839b85e18080ce\\\",\\\"uuid\\\":\\\"00000000-0000-4000-8000-0000000000d1\\\",\\\"key\\\":\\\"c6822637c7d310ec57627be00ba259d253749f4aaf644470cffbe53a35f73242\\\",\\\"issued_at\\\":1790000000}\",\"sig\":\"d73d752108e1662bde818b18dd807829f5a80cdb940cf3cd32a685ae2f6839e095136fd8b57b65e56d7b2b5fc55eca7020748ddd64e9f2c9160efcb0ce114c0f\"}"
#define PY_OPERATOR "17cb79fb2b4120f2b1ec65e4198d6e08b28e813feb01e4a400839b85e18080ce"
#define PY_NODE "{\"typename\":\"identity\",\"uuid\":\"00000000-0000-4000-8000-0000000000d1\",\"address\":\"\",\"nickname\":\"alice\",\"signature\":{\"hex_seed\":\"c6822637c7d310ec57627be00ba259d253749f4aaf644470cffbe53a35f73242\"},\"encryptor\":{\"hex_seed\":\"7777777777777777777777777777777777777777777777777777777777777777\"}}"

static void _operator(unsigned char seed_byte, unsigned char sk[crypto_sign_SECRETKEYBYTES])
{
    unsigned char seed[32], pk[crypto_sign_PUBLICKEYBYTES];
    memset(seed, seed_byte, sizeof(seed));
    crypto_sign_seed_keypair(pk, sk, seed);
}

static identity_t *_mk(const char *name)
{
    uuid_t u;
    uuid_generate(u);
    identity_t *id = NULL;
    ck_assert_ret_ok(identity_create(&u, "127.0.0.1", name, name, &id));
    return id;
}

#define PUB(id) ((const public_identity_t *)(id))

static void _cert(const unsigned char *sk, const identity_t *id, at_dir_signed_t *out)
{
    ck_assert_int_eq(at_device_cert_create(sk, PUB(id), 1000, out), AT_DEVICE_OK);
}

/* Bob's record of Alice's first device @p phone, verified, operator learned,
 * filed in @p store. */
static void _verified_alice(contacts_t *store, const unsigned char *sk, const identity_t *phone)
{
    contact_t c;
    memset(&c, 0, sizeof(c));
    c.identity = *PUB(phone);
    c.identity.operator_key_binding = NULL;
    contact_mark_verified(&c, 0.3);
    at_dir_signed_t cert;
    _cert(sk, phone, &cert);
    ck_assert_int_eq(at_adopt_operator(&c, &cert, store), AT_DEVICE_OK);
    at_dir_free(&cert);
    ck_assert_ret_ok(contacts_add(store, &c));
}

DEFINE_TEST(test_a_python_cert_verifies_and_c_mints_the_same_bytes)
{
    at_dir_signed_t cert;
    ck_assert_int_eq(at_dir_from_text(PY_CERT, &cert), AT_DIR_OK);
    ck_assert_int_eq(at_device_cert_verify(&cert), AT_DEVICE_OK);
    ck_assert_str_eq(at_device_cert_operator(&cert), PY_OPERATOR);
    json_t *nj = json_loads(PY_NODE, 0, NULL);
    public_identity_t node;
    memset(&node, 0, sizeof(node));
    ck_assert_ret_ok(public_identity_from_json(nj, &node));
    ck_assert(at_device_cert_names(&cert, &node));

    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    _operator(0x33, sk);
    at_dir_signed_t mine;
    ck_assert_int_eq(at_device_cert_create(sk, &node, 1790000000, &mine), AT_DEVICE_OK);
    ck_assert_str_eq(mine.body_str, cert.body_str);
    ck_assert_str_eq(mine.sig_hex, cert.sig_hex);
    at_dir_free(&mine);
    at_dir_free(&cert);
    free(node.operator_key_binding);
    json_decref(nj);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_tampered_or_malformed_cert_is_refused)
{
    at_dir_signed_t cert;
    ck_assert_int_eq(at_dir_from_text(PY_CERT, &cert), AT_DIR_OK);
    /* Same signature, another uuid in the body. */
    char *swapped = strdup(cert.body_str);
    char *at = strstr(swapped, "0000000000d1");
    at[11] = '2';
    json_t *w = json_pack("{s:s, s:s}", "body", swapped, "sig", cert.sig_hex);
    at_dir_signed_t forged;
    ck_assert_int_eq(at_dir_from_wire(w, &forged), AT_DIR_OK);
    ck_assert_int_eq(at_device_cert_verify(&forged), AT_DEVICE_BAD_SIGNATURE);
    ck_assert_str_eq(at_device_reason(AT_DEVICE_BAD_SIGNATURE), "bad_signature");
    at_dir_free(&forged);
    json_decref(w);
    free(swapped);
    /* A body of the wrong shape. */
    w = json_pack("{s:s, s:s}", "body", "{\"v\":1,\"typename\":\"at-device-cert\"}",
                  "sig", cert.sig_hex);
    ck_assert_int_eq(at_dir_from_wire(w, &forged), AT_DIR_OK);
    ck_assert_int_eq(at_device_cert_verify(&forged), AT_DEVICE_MALFORMED);
    at_dir_free(&forged);
    json_decref(w);
    at_dir_free(&cert);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_adopt_operator_needs_the_contacts_own_cert_and_never_changes)
{
    unsigned char sk[crypto_sign_SECRETKEYBYTES], other[crypto_sign_SECRETKEYBYTES];
    _operator(0x33, sk);
    _operator(0x34, other);
    identity_t *phone = _mk("alice-phone"), *laptop = _mk("alice-laptop");
    contact_t c;
    memset(&c, 0, sizeof(c));
    c.identity = *PUB(phone);
    c.identity.operator_key_binding = NULL;
    at_dir_signed_t cert;
    _cert(sk, laptop, &cert);
    ck_assert_int_eq(at_adopt_operator(&c, &cert, NULL), AT_DEVICE_MISMATCH);
    ck_assert_str_eq(c.operator_key, "");
    at_dir_free(&cert);
    _cert(sk, phone, &cert);
    ck_assert_int_eq(at_adopt_operator(&c, &cert, NULL), AT_DEVICE_OK);
    at_dir_free(&cert);
    _cert(other, phone, &cert);
    ck_assert_int_eq(at_adopt_operator(&c, &cert, NULL), AT_DEVICE_MISMATCH);
    at_dir_free(&cert);

    /* One operator key, one contact. */
    contacts_t store;
    contacts_init(&store);
    ck_assert_ret_ok(contacts_add(&store, &c));
    contact_t second;
    memset(&second, 0, sizeof(second));
    second.identity = *PUB(laptop);
    second.identity.operator_key_binding = NULL;
    _cert(sk, laptop, &cert);
    ck_assert_int_eq(at_adopt_operator(&second, &cert, &store), AT_DEVICE_KNOWN);
    at_dir_free(&cert);
    contacts_free(&store);
    identity_free(phone);
    identity_free(laptop);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_link_adds_a_verified_device_once)
{
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    _operator(0x33, sk);
    identity_t *phone = _mk("alice-phone"), *laptop = _mk("alice-laptop");
    contacts_t store;
    contacts_init(&store);
    _verified_alice(&store, sk, phone);
    at_dir_signed_t cert;
    _cert(sk, laptop, &cert);
    contact_t *got = NULL;
    ck_assert_int_eq(at_link_device(&store, PUB(laptop), &cert, &got), AT_DEVICE_OK);
    ck_assert_ptr_nonnull(got);
    ck_assert_int_eq(got->devices_count, 1);
    char uu[UUID_STRING_LEN + 1];
    uuid_unparse_lower(laptop->uuid, uu);
    ck_assert_str_eq(got->devices[0].uuid, uu);
    ck_assert_ptr_eq(contacts_get(&store, uu), got);
    ck_assert_int_eq(at_link_device(&store, PUB(laptop), &cert, NULL), AT_DEVICE_OK);
    ck_assert_int_eq(got->devices_count, 1);
    at_dir_free(&cert);
    contacts_free(&store);
    identity_free(phone);
    identity_free(laptop);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_link_refusals)
{
    unsigned char sk[crypto_sign_SECRETKEYBYTES], stranger[crypto_sign_SECRETKEYBYTES];
    _operator(0x33, sk);
    _operator(0x35, stranger);
    identity_t *phone = _mk("alice-phone"), *laptop = _mk("alice-laptop");
    identity_t *mallory = _mk("mallory");
    contacts_t store;
    contacts_init(&store);
    _verified_alice(&store, sk, phone);
    at_dir_signed_t cert;

    _cert(stranger, laptop, &cert);
    ck_assert_int_eq(at_link_device(&store, PUB(laptop), &cert, NULL),
                     AT_DEVICE_UNKNOWN_OPERATOR);
    at_dir_free(&cert);

    _cert(sk, laptop, &cert);     /* Alice's laptop cert, on Mallory's node */
    ck_assert_int_eq(at_link_device(&store, PUB(mallory), &cert, NULL), AT_DEVICE_MISMATCH);
    at_dir_free(&cert);

    contact_t other;            /* the laptop, already its own contact */
    memset(&other, 0, sizeof(other));
    other.identity = *PUB(laptop);
    other.identity.operator_key_binding = NULL;
    ck_assert_ret_ok(contacts_add(&store, &other));
    _cert(sk, laptop, &cert);
    ck_assert_int_eq(at_link_device(&store, PUB(laptop), &cert, NULL), AT_DEVICE_KNOWN);
    at_dir_free(&cert);

    contacts_free(&store);
    contacts_init(&store);
    contact_t c;                 /* an UNVERIFIED Alice */
    memset(&c, 0, sizeof(c));
    c.identity = *PUB(phone);
    c.identity.operator_key_binding = NULL;
    _cert(sk, phone, &cert);
    ck_assert_int_eq(at_adopt_operator(&c, &cert, NULL), AT_DEVICE_OK);
    at_dir_free(&cert);
    ck_assert_ret_ok(contacts_add(&store, &c));
    _cert(sk, laptop, &cert);
    ck_assert_int_eq(at_link_device(&store, PUB(laptop), &cert, NULL), AT_DEVICE_UNVERIFIED);
    at_dir_free(&cert);
    contacts_free(&store);

    contacts_init(&store);       /* the cap */
    _verified_alice(&store, sk, phone);
    for (int i = 0; i < AT_CONTACT_DEVICES_MAX; i++) {
        identity_t *d = _mk("dev");
        _cert(sk, d, &cert);
        ck_assert_int_eq(at_link_device(&store, PUB(d), &cert, NULL), AT_DEVICE_OK);
        at_dir_free(&cert);
        identity_free(d);
    }
    identity_t *extra = _mk("extra");
    _cert(sk, extra, &cert);
    ck_assert_int_eq(at_link_device(&store, PUB(extra), &cert, NULL), AT_DEVICE_FULL);
    ck_assert_str_eq(at_device_reason(AT_DEVICE_FULL), "full");
    at_dir_free(&cert);
    identity_free(extra);
    contacts_free(&store);
    identity_free(phone);
    identity_free(laptop);
    identity_free(mallory);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_devices_survive_the_store_and_hand_added_ones_do_not)
{
    unsigned char sk[crypto_sign_SECRETKEYBYTES], stranger[crypto_sign_SECRETKEYBYTES];
    _operator(0x33, sk);
    _operator(0x35, stranger);
    identity_t *phone = _mk("alice-phone"), *laptop = _mk("alice-laptop");
    identity_t *mallory = _mk("mallory");
    contacts_t store;
    contacts_init(&store);
    _verified_alice(&store, sk, phone);
    at_dir_signed_t cert;
    _cert(sk, laptop, &cert);
    ck_assert_int_eq(at_link_device(&store, PUB(laptop), &cert, NULL), AT_DEVICE_OK);
    at_dir_free(&cert);

    json_t *doc = NULL;
    ck_assert_ret_ok(contacts_to_json(&store, &doc));
    char pu[UUID_STRING_LEN + 1], lu[UUID_STRING_LEN + 1];
    uuid_unparse_lower(phone->uuid, pu);
    uuid_unparse_lower(laptop->uuid, lu);
    json_t *rec = json_object_get(json_object_get(doc, "contacts"), pu);
    ck_assert_ptr_nonnull(json_object_get(rec, "operator_key"));
    json_t *devs = json_object_get(rec, "devices");
    ck_assert_int_eq(json_array_size(devs), 1);
    /* Hand-add Mallory twice: under another operator, and with the laptop's
     * cert on her identity. */
    json_t *mid = NULL;
    ck_assert_ret_ok(public_identity_to_json(PUB(mallory), &mid));
    at_dir_signed_t mc;
    _cert(stranger, mallory, &mc);
    json_array_append_new(devs, json_pack("{s:O, s:o, s:f}", "identity", mid,
                                          "cert", at_dir_to_wire(&mc), "added_at", 1.0));
    at_dir_free(&mc);
    json_array_append_new(devs, json_pack("{s:O, s:O, s:f}", "identity", mid, "cert",
                                          json_object_get(json_array_get(devs, 0), "cert"),
                                          "added_at", 1.0));
    json_decref(mid);

    contacts_t back;
    ck_assert_ret_ok(contacts_from_json(doc, &back));
    contact_t *c = contacts_get(&back, lu);
    ck_assert_ptr_nonnull(c);
    ck_assert_int_eq(c->devices_count, 1);
    ck_assert_str_eq(c->devices[0].uuid, lu);
    ck_assert_str_eq(c->operator_key, store.items[0].operator_key);
    public_identity_t dev;
    ck_assert_ret_ok(at_contact_device_identity(&c->devices[0], &dev));
    ck_assert_int_eq(uuid_compare(dev.uuid, laptop->uuid), 0);
    free(dev.operator_key_binding);
    contacts_free(&back);
    json_decref(doc);

    /* A contact with no devices writes neither key. */
    contact_t plain;
    memset(&plain, 0, sizeof(plain));
    plain.identity = *PUB(mallory);
    plain.identity.operator_key_binding = NULL;
    json_t *pj = NULL;
    ck_assert_ret_ok(contact_to_json(&plain, &pj));
    ck_assert_ptr_null(json_object_get(pj, "operator_key"));
    ck_assert_ptr_null(json_object_get(pj, "devices"));
    json_decref(pj);

    contacts_free(&store);
    identity_free(phone);
    identity_free(laptop);
    identity_free(mallory);
}
END_TEST_DEFINITION()

RUN_TESTS(ContactsDevice,
          test_a_python_cert_verifies_and_c_mints_the_same_bytes,
          test_a_tampered_or_malformed_cert_is_refused,
          test_adopt_operator_needs_the_contacts_own_cert_and_never_changes,
          test_link_adds_a_verified_device_once,
          test_link_refusals,
          test_devices_survive_the_store_and_hand_added_ones_do_not)
