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

/* Directory entries and attestations (contacts/directory), FIRST_CONTACT_PLAN
 * Phase 3. Mirrors Python tests/a_unit/test_directory.py. */

#define _GNU_SOURCE
#define DEBUG_TESTS 1
#include "test_setup.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sodium.h>

#include "contacts/directory.h"
#include "identity/identity_priv.h"

/* Python: an entry for key(0x55*32) signed by it, attested by issuer
 * 0x44*32 for alice@example.org, seq 3, expiring 2100-01-01. */
#define PY_ENTRY "{\"body\":\"{\\\"v\\\":1,\\\"typename\\\":\\\"at-dir-entry\\\",\\\"handle\\\":\\\"alice@example.org\\\",\\\"uuid\\\":\\\"00000000-0000-4000-8000-0000000000a1\\\",\\\"key\\\":\\\"c6822637c7d310ec57627be00ba259d253749f4aaf644470cffbe53a35f73242\\\",\\\"visibility\\\":\\\"anyone\\\",\\\"seq\\\":3,\\\"expiry\\\":4102444800,\\\"identity\\\":{\\\"typename\\\":\\\"identity\\\",\\\"uuid\\\":\\\"00000000-0000-4000-8000-0000000000a1\\\",\\\"address\\\":\\\"\\\",\\\"nickname\\\":\\\"alice\\\",\\\"signature\\\":{\\\"hex_seed\\\":\\\"c6822637c7d310ec57627be00ba259d253749f4aaf644470cffbe53a35f73242\\\"},\\\"encryptor\\\":{\\\"hex_seed\\\":\\\"7777777777777777777777777777777777777777777777777777777777777777\\\"}},\\\"attestation\\\":{\\\"body\\\":\\\"{\\\\\\\"v\\\\\\\":1,\\\\\\\"typename\\\\\\\":\\\\\\\"at-dir-attest\\\\\\\",\\\\\\\"handle\\\\\\\":\\\\\\\"alice@example.org\\\\\\\",\\\\\\\"key\\\\\\\":\\\\\\\"c6822637c7d310ec57627be00ba259d253749f4aaf644470cffbe53a35f73242\\\\\\\",\\\\\\\"issuer\\\\\\\":\\\\\\\"d759793bbc13a2819a827c76adb6fba8a49aee007f49f2d0992d99b825ad2c48\\\\\\\",\\\\\\\"expiry\\\\\\\":4102444800}\\\",\\\"sig\\\":\\\"a41a0c2032f8e101cc170d50b656d7f4e02a13ca4e7a4a74fdbc30e0344bfe258fd342b4a32bc735d12e345cacae820940d1b58dc42bcd16e7a8ae205b81350a\\\"}}\",\"sig\":\"614e734f8e266214de83eb60732e59e307de1a663c7db9f83cdcd21e31eac4e3963d5c95d5c521e52652b6d82a37116a92c7318099e033b5cda028b7bbc8b300\"}"

/* Python: create_request by key(0x66*32) for alice@example.org (uuid ...a1),
 * nonce "ab"*16, one relay, expiring 2100-01-01. */
#define PY_REQUEST "{\"body\":\"{\\\"v\\\":1,\\\"typename\\\":\\\"at-contact-request\\\",\\\"from\\\":\\\"00000000-0000-4000-8000-0000000000b2\\\",\\\"key\\\":\\\"34b4d9043156cb6dcf0beb0a2949b7559c940d2bcb6dbe8c53a9b30278e3a746\\\",\\\"to\\\":\\\"00000000-0000-4000-8000-0000000000a1\\\",\\\"handle\\\":\\\"alice@example.org\\\",\\\"nonce\\\":\\\"abababababababababababababababab\\\",\\\"expiry\\\":4102444800,\\\"relays\\\":[\\\"relay://198.51.100.1:27790\\\"]}\",\"sig\":\"bc36d34b96552e98134f3b281e71b3b66dc653c9382fdae804d8e2b795dc4b85d0cbec096616a4f4682b3b7d569abeb19a07d7f913238d57301f6ecadd14c70d\"}"

static unsigned char g_issuer_sk[crypto_sign_SECRETKEYBYTES];
static char g_issuer_hex[65];

static void _issuer(void)
{
    unsigned char seed[32], pk[crypto_sign_PUBLICKEYBYTES];
    memset(seed, 0x44, sizeof(seed));
    crypto_sign_seed_keypair(pk, g_issuer_sk, seed);
    sodium_bin2hex(g_issuer_hex, sizeof(g_issuer_hex), pk, sizeof(pk));
}

static identity_t *_mk(const char *name)
{
    uuid_t u;
    uuid_generate(u);
    identity_t *id = NULL;
    ck_assert_ret_ok(identity_create(&u, "127.0.0.1", name, name, &id));
    return id;
}

static void _entry(const identity_t *who, const char *handle, long att_expiry,
                   at_dir_signed_t *out)
{
    at_dir_signed_t att;
    ck_assert_int_eq(at_dir_attest(g_issuer_sk, handle,
                                   (const char *)who->signature.public_hex,
                                   att_expiry, &att), AT_DIR_OK);
    ck_assert_int_eq(at_dir_create_entry(who, &att, 1, AT_DIR_VISIBILITY_ANYONE, 0,
                                         (double)time(NULL), out), AT_DIR_OK);
    at_dir_free(&att);
}

/* Re-sign @p entry's body with one field patched, as a forger could. */
static void _patched(const identity_t *who, const at_dir_signed_t *entry,
                     const char *field, json_t *value, at_dir_signed_t *out)
{
    json_t *body = json_deep_copy(entry->body);
    json_object_set_new(body, field, value);
    char *s = json_dumps(body, JSON_COMPACT);
    json_decref(body);
    size_t dl = strlen(AT_DIR_ENTRY_DOMAIN), bl = strlen(s);
    unsigned char *msg = malloc(dl + bl), sig[crypto_sign_BYTES];
    memcpy(msg, AT_DIR_ENTRY_DOMAIN, dl);
    memcpy(msg + dl, s, bl);
    crypto_sign_detached(sig, NULL, msg, dl + bl, who->signature.private);
    free(msg);
    char hex[129];
    sodium_bin2hex(hex, sizeof(hex), sig, sizeof(sig));
    json_t *w = json_pack("{s:s, s:s}", "body", s, "sig", hex);
    ck_assert_int_eq(at_dir_from_wire(w, out), AT_DIR_OK);
    json_decref(w);
    free(s);
}

DEFINE_TEST(test_handles_fold_to_lower_case)
{
    char out[AT_DIR_HANDLE_MAX + 1];
    ck_assert_int_eq(at_dir_normalize_handle("Alice@Example.ORG", out, sizeof(out)), 0);
    ck_assert_str_eq(out, "alice@example.org");
    ck_assert_int_eq(at_dir_normalize_handle("+15551234567", out, sizeof(out)), 0);
    ck_assert_int_eq(at_dir_normalize_handle("", out, sizeof(out)), -1);
    ck_assert_int_eq(at_dir_normalize_handle("b\xc3\xbc" "cher", out, sizeof(out)), -1);
    ck_assert_int_eq(at_dir_normalize_handle("a b", out, sizeof(out)), -1);
    ck_assert_int_eq(at_dir_normalize_handle("a/b", out, sizeof(out)), -1);
    char big[AT_DIR_HANDLE_MAX + 2];
    memset(big, 'x', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';
    ck_assert_int_eq(at_dir_normalize_handle(big, out, sizeof(out)), -1);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_an_entry_round_trips_and_verifies)
{
    _issuer();
    identity_t *alice = _mk("alice");
    at_dir_signed_t e, back;
    _entry(alice, "Alice@Example.org", (long)time(NULL) + 3600, &e);
    json_t *w = at_dir_to_wire(&e);
    char *text = json_dumps(w, JSON_COMPACT);
    ck_assert_int_eq(at_dir_from_text(text, &back), AT_DIR_OK);
    const char *trusted[] = {g_issuer_hex};
    ck_assert_int_eq(at_dir_entry_verify(&back, trusted, 1, (double)time(NULL)), AT_DIR_OK);
    ck_assert_str_eq(at_dir_handle(&back), "alice@example.org");
    ck_assert_str_eq(at_dir_key(&back), (const char *)alice->signature.public_hex);
    ck_assert_int_eq(at_dir_seq(&back), 1);
    free(text);
    json_decref(w);
    at_dir_free(&e);
    at_dir_free(&back);
    identity_free(alice);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_an_untrusted_issuer_is_refused)
{
    _issuer();
    identity_t *alice = _mk("alice");
    at_dir_signed_t e;
    _entry(alice, "alice@example.org", (long)time(NULL) + 3600, &e);
    const char *other[] = {"0000000000000000000000000000000000000000000000000000000000000000"};
    ck_assert_int_eq(at_dir_entry_verify(&e, other, 1, (double)time(NULL)), AT_DIR_UNTRUSTED);
    ck_assert_int_eq(at_dir_entry_verify(&e, NULL, 0, (double)time(NULL)), AT_DIR_OK);
    at_dir_free(&e);
    identity_free(alice);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_an_attestation_for_another_key_cannot_be_used)
{
    _issuer();
    identity_t *alice = _mk("alice"), *bob = _mk("bob");
    at_dir_signed_t att, e;
    ck_assert_int_eq(at_dir_attest(g_issuer_sk, "alice@example.org",
                                   (const char *)bob->signature.public_hex,
                                   (long)time(NULL) + 60, &att), AT_DIR_OK);
    ck_assert_int_eq(at_dir_create_entry(alice, &att, 1, AT_DIR_VISIBILITY_ANYONE, 0,
                                         (double)time(NULL), &e), AT_DIR_MISMATCH);
    at_dir_free(&att);
    identity_free(alice);
    identity_free(bob);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_lifted_attestation_is_refused_even_if_signed_in)
{
    _issuer();
    identity_t *alice = _mk("alice"), *mallory = _mk("mallory");
    at_dir_signed_t e, forged;
    _entry(alice, "alice@example.org", (long)time(NULL) + 3600, &e);
    _patched(mallory, &e, "key", json_string((const char *)mallory->signature.public_hex),
             &forged);
    ck_assert_int_eq(at_dir_entry_verify(&forged, NULL, 0, (double)time(NULL)),
                     AT_DIR_MISMATCH);
    at_dir_free(&e);
    at_dir_free(&forged);
    identity_free(alice);
    identity_free(mallory);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_the_entry_signature_covers_the_exact_body)
{
    _issuer();
    identity_t *alice = _mk("alice");
    at_dir_signed_t e;
    _entry(alice, "alice@example.org", (long)time(NULL) + 3600, &e);
    char *seq = strstr(e.body_str, "\"seq\":1");
    ck_assert(seq != NULL);
    seq[6] = '2';
    ck_assert_int_eq(at_dir_entry_verify(&e, NULL, 0, (double)time(NULL)), AT_DIR_BAD_SIG);
    at_dir_free(&e);
    identity_free(alice);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_expiry_is_capped_by_the_attestation_and_enforced)
{
    _issuer();
    identity_t *alice = _mk("alice");
    long att_exp = (long)time(NULL) + 10;
    at_dir_signed_t e;
    _entry(alice, "alice@example.org", att_exp, &e);
    ck_assert_int_eq(at_dir_expiry(&e), att_exp);
    ck_assert_int_eq(at_dir_entry_verify(&e, NULL, 0, (double)att_exp), AT_DIR_EXPIRED);
    at_dir_free(&e);
    identity_free(alice);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_bad_visibility_or_version_is_refused)
{
    _issuer();
    identity_t *alice = _mk("alice");
    at_dir_signed_t e, bad;
    _entry(alice, "alice@example.org", (long)time(NULL) + 3600, &e);
    json_t *patches[][2] = {
        {json_string("v"), json_real(1.0)}, {json_string("v"), json_true()},
        {json_string("seq"), json_integer(0)}, {json_string("seq"), json_true()},
        {json_string("visibility"), json_string("friends")},
        {json_string("handle"), json_string("Alice@example.org")},
    };
    for (size_t i = 0; i < sizeof(patches) / sizeof(patches[0]); i++) {
        _patched(alice, &e, json_string_value(patches[i][0]), patches[i][1], &bad);
        ck_assert_int_eq(at_dir_entry_verify(&bad, NULL, 0, (double)time(NULL)),
                         AT_DIR_MALFORMED);
        at_dir_free(&bad);
        json_decref(patches[i][0]);
    }
    at_dir_free(&e);
    identity_free(alice);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_python_signed_entry_verifies)
{
    _issuer();
    at_dir_signed_t e;
    ck_assert_int_eq(at_dir_from_text(PY_ENTRY, &e), AT_DIR_OK);
    const char *trusted[] = {g_issuer_hex};
    ck_assert_int_eq(at_dir_entry_verify(&e, trusted, 1, (double)time(NULL)), AT_DIR_OK);
    ck_assert_int_eq(at_dir_seq(&e), 3);
    at_dir_free(&e);
}
END_TEST_DEFINITION()

/* A request re-signed by @p who with one field patched. */
static void _req_patched(const identity_t *who, const at_dir_signed_t *req,
                         const char *field, json_t *value, at_dir_signed_t *out)
{
    json_t *body = json_deep_copy(req->body);
    json_object_set_new(body, field, value);
    char *s = json_dumps(body, JSON_COMPACT);
    json_decref(body);
    size_t dl = strlen(AT_DIR_REQUEST_DOMAIN), bl = strlen(s);
    unsigned char *msg = malloc(dl + bl), sig[crypto_sign_BYTES];
    memcpy(msg, AT_DIR_REQUEST_DOMAIN, dl);
    memcpy(msg + dl, s, bl);
    crypto_sign_detached(sig, NULL, msg, dl + bl, who->signature.private);
    free(msg);
    char hex[129];
    sodium_bin2hex(hex, sizeof(hex), sig, sizeof(sig));
    json_t *w = json_pack("{s:s, s:s}", "body", s, "sig", hex);
    ck_assert_int_eq(at_dir_from_wire(w, out), AT_DIR_OK);
    json_decref(w);
    free(s);
}

DEFINE_TEST(test_a_contact_request_round_trips_and_is_checked)
{
    _issuer();
    identity_t *alice = _mk("alice"), *bob = _mk("bob");
    at_dir_signed_t e, r, back, bad;
    _entry(alice, "alice@example.org", (long)time(NULL) + 3600, &e);
    const char *relays[] = {"relay://198.51.100.1:27790"};
    double now = (double)time(NULL);
    ck_assert_int_eq(at_dir_request_create(bob, &e, relays, 1, NULL, 0, now, &r), AT_DIR_OK);
    json_t *w = at_dir_to_wire(&r);
    char *text = json_dumps(w, JSON_COMPACT);
    ck_assert_int_eq(at_dir_from_text(text, &back), AT_DIR_OK);
    ck_assert_int_eq(at_dir_request_verify(&back, now), AT_DIR_OK);
    char au[UUID_STRING_LEN + 1], bu[UUID_STRING_LEN + 1];
    uuid_unparse_lower(alice->uuid, au);
    uuid_unparse_lower(bob->uuid, bu);
    ck_assert_str_eq(at_dir_request_to(&back), au);
    ck_assert_str_eq(at_dir_request_from(&back), bu);
    ck_assert_str_eq(at_dir_handle(&back), "alice@example.org");
    ck_assert_uint_eq(strlen(at_dir_request_nonce(&back)), AT_DIR_NONCE_HEX);
    ck_assert_int_eq(at_dir_request_verify(&back, (double)at_dir_expiry(&back)),
                     AT_DIR_EXPIRED);
    /* The signature covers the exact body. */
    char *h = strstr(back.body_str, "alice@");
    ck_assert(h != NULL);
    h[0] = 'b';
    ck_assert_int_eq(at_dir_request_verify(&back, now), AT_DIR_BAD_SIG);
    /* Malformed, however well signed. */
    json_t *patches[][2] = {
        {json_string("nonce"), json_string("ABABABABABABABABABABABABABABABAB")},
        {json_string("nonce"), json_string("abab")},
        {json_string("relays"), json_pack("[s]", "nonsense")},
        {json_string("relays"), json_pack("[s,s,s,s,s]", "a:1", "b:1", "c:1", "d:1", "e:1")},
        {json_string("v"), json_real(1.0)},
        {json_string("handle"), json_string("Alice@example.org")},
        {json_string("expiry"), json_integer(0)},
    };
    for (size_t i = 0; i < sizeof(patches) / sizeof(patches[0]); i++) {
        _req_patched(bob, &r, json_string_value(patches[i][0]), patches[i][1], &bad);
        ck_assert_int_eq(at_dir_request_verify(&bad, now), AT_DIR_MALFORMED);
        at_dir_free(&bad);
        json_decref(patches[i][0]);
    }
    /* An entry signature does not verify as a request. */
    ck_assert(at_dir_request_verify(&e, now) != AT_DIR_OK);
    free(text);
    json_decref(w);
    at_dir_free(&e);
    at_dir_free(&r);
    at_dir_free(&back);
    identity_free(alice);
    identity_free(bob);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_python_signed_request_verifies)
{
    at_dir_signed_t r;
    ck_assert_int_eq(at_dir_from_text(PY_REQUEST, &r), AT_DIR_OK);
    ck_assert_int_eq(at_dir_request_verify(&r, (double)time(NULL)), AT_DIR_OK);
    ck_assert_str_eq(at_dir_request_nonce(&r), "abababababababababababababababab");
    ck_assert_str_eq(at_dir_request_to(&r), "00000000-0000-4000-8000-0000000000a1");
    at_dir_free(&r);
}
END_TEST_DEFINITION()

RUN_TESTS(Directory,
          test_handles_fold_to_lower_case,
          test_an_entry_round_trips_and_verifies,
          test_an_untrusted_issuer_is_refused,
          test_an_attestation_for_another_key_cannot_be_used,
          test_a_lifted_attestation_is_refused_even_if_signed_in,
          test_the_entry_signature_covers_the_exact_body,
          test_expiry_is_capped_by_the_attestation_and_enforced,
          test_a_bad_visibility_or_version_is_refused,
          test_a_python_signed_entry_verifies,
          test_a_contact_request_round_trips_and_is_checked,
          test_a_python_signed_request_verifies)
