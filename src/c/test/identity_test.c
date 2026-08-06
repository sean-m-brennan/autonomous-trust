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

#include "identity/identity.h"
#include "identity/identity_priv.h"

/*
 * Corresponds to Python test_identity.py
 *
 * Tests: identity creation, publish, JSON roundtrip (especially address),
 * sign/verify, encrypt/decrypt.
 */

DEFINE_TEST(test_identity_create)
{
    ck_assert(sodium_init() >= 0);

    uuid_t uuid;
    uuid_generate(uuid);

    char addr[] = "192.168.1.100";
    char name[] = "Test User";
    char nick[] = "Tester";
    identity_t *ident = NULL;
    ck_assert_ret_ok(identity_create(&uuid, addr, name, nick, &ident));
    ck_assert_ptr_nonnull(ident);

    ck_assert_str_eq(ident->nickname, "Test User");
    ck_assert_str_eq(ident->petname, "Tester");
    ck_assert_str_eq(ident->address, "192.168.1.100");
    ck_assert_mem_eq(ident->uuid, uuid, sizeof(uuid_t));

    identity_free(ident);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_identity_publish_preserves_address)
{
    ck_assert(sodium_init() >= 0);

    uuid_t uuid;
    uuid_generate(uuid);

    char addr[] = "172.27.3.14";
    char name[] = "Node Alpha";
    char nick[] = "Alpha";
    identity_t *ident = NULL;
    ck_assert_ret_ok(identity_create(&uuid, addr, name, nick, &ident));

    public_identity_t *pub = NULL;
    ck_assert_ret_ok(identity_publish(ident, &pub));
    ck_assert_ptr_nonnull(pub);

    /* Address and names must survive publish */
    ck_assert_str_eq(pub->address, "172.27.3.14");
    ck_assert_str_eq(pub->nickname, "Node Alpha");
    ck_assert_str_eq(pub->petname, "Alpha");
    ck_assert_mem_eq(pub->uuid, uuid, sizeof(uuid_t));

    smrt_deref(pub);
    identity_free(ident);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_identity_json_roundtrip_address)
{
    ck_assert(sodium_init() >= 0);

    uuid_t uuid;
    uuid_generate(uuid);

    char addr[] = "10.0.0.42";
    char name[] = "Agent Smith";
    identity_t *ident = NULL;
    char nick3[] = "Smith";
    ck_assert_ret_ok(identity_create(&uuid, addr, name, nick3, &ident));

    /* Serialize to JSON */
    json_t *obj = NULL;
    ck_assert_ret_ok(identity_to_json(ident, &obj));
    ck_assert_ptr_nonnull(obj);

    /* Verify address is in JSON */
    const char *json_addr = json_string_value(json_object_get(obj, "address"));
    ck_assert_ptr_nonnull(json_addr);
    ck_assert_str_eq(json_addr, "10.0.0.42");

    /* Deserialize from JSON */
    identity_t ident2;
    memset(&ident2, 0, sizeof(identity_t));
    ck_assert_ret_ok(identity_from_json(obj, &ident2));

    /* Address must survive roundtrip */
    ck_assert_str_eq(ident2.address, "10.0.0.42");
    ck_assert_str_eq(ident2.nickname, "Agent Smith");

    /* UUID must match */
    char uuid_str1[UUID_STRING_LEN + 1];
    char uuid_str2[UUID_STRING_LEN + 1];
    uuid_unparse(ident->uuid, uuid_str1);
    uuid_unparse(ident2.uuid, uuid_str2);
    ck_assert_str_eq(uuid_str1, uuid_str2);

    json_decref(obj);
    identity_free(ident);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_identity_sign_verify)
{
    ck_assert(sodium_init() >= 0);

    uuid_t uuid;
    uuid_generate(uuid);

    char addr[] = "127.0.0.1";
    char name[] = "Signer";
    identity_t *ident = NULL;
    ck_assert_ret_ok(identity_create(&uuid, addr, name, NULL, &ident));

    /* Sign a message */
    const char *message = "Hello, world!";
    size_t msg_len = strlen(message);
    msg_str_t msg_in = {.msg = (unsigned char *)message, .len = msg_len};

    /* crypto_sign output: msg + signature */
    unsigned char *signed_buf = malloc(msg_len + crypto_sign_BYTES);
    ck_assert_ptr_nonnull(signed_buf);
    msg_str_t msg_signed = {.msg = signed_buf, .len = 0};
    ck_assert_ret_ok(identity_sign(ident, &msg_in, &msg_signed));
    ck_assert(msg_signed.len > msg_len);

    /* Verify with public identity */
    public_identity_t *pub = NULL;
    ck_assert_ret_ok(identity_publish(ident, &pub));

    unsigned char *verify_buf = malloc(msg_signed.len);
    ck_assert_ptr_nonnull(verify_buf);
    msg_str_t msg_out = {.msg = verify_buf, .len = 0};
    ck_assert_ret_ok(identity_verify(pub, &msg_signed, &msg_out));
    ck_assert_uint_eq(msg_out.len, msg_len);
    ck_assert_mem_eq(msg_out.msg, message, msg_len);

    free(signed_buf);
    free(verify_buf);
    smrt_deref(pub);
    identity_free(ident);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_identity_encrypt_decrypt)
{
    ck_assert(sodium_init() >= 0);

    uuid_t uuid1, uuid2;
    uuid_generate(uuid1);
    uuid_generate(uuid2);

    char addr1[] = "10.0.0.1";
    char name1[] = "Alice";
    char addr2[] = "10.0.0.2";
    char name2[] = "Bob";
    identity_t *alice = NULL;
    identity_t *bob = NULL;
    char nick_a[] = "Al";
    char nick_b[] = "Bo";
    ck_assert_ret_ok(identity_create(&uuid1, addr1, name1, nick_a, &alice));
    ck_assert_ret_ok(identity_create(&uuid2, addr2, name2, nick_b, &bob));

    public_identity_t *bob_pub = NULL;
    public_identity_t *alice_pub = NULL;
    ck_assert_ret_ok(identity_publish(bob, &bob_pub));
    ck_assert_ret_ok(identity_publish(alice, &alice_pub));

    /* Alice encrypts for Bob */
    const char *plaintext = "Secret message";
    msg_str_t msg = {.msg = (unsigned char *)plaintext, .len = strlen(plaintext)};
    unsigned char nonce[crypto_box_NONCEBYTES];
    randombytes_buf(nonce, sizeof(nonce));

    size_t cipher_len = msg.len + crypto_box_MACBYTES;
    unsigned char *cipher = malloc(cipher_len);
    ck_assert_ptr_nonnull(cipher);

    ck_assert_ret_ok(identity_encrypt(alice, &msg, bob_pub, nonce, cipher));

    /* Bob decrypts */
    msg_str_t cmsg = {.msg = cipher, .len = cipher_len};
    unsigned char *decrypted = malloc(msg.len);
    ck_assert_ptr_nonnull(decrypted);

    ck_assert_ret_ok(identity_decrypt(bob, &cmsg, alice_pub, nonce, decrypted));
    ck_assert_mem_eq(decrypted, plaintext, strlen(plaintext));

    free(cipher);
    free(decrypted);
    smrt_deref(bob_pub);
    smrt_deref(alice_pub);
    identity_free(alice);
    identity_free(bob);
}
END_TEST_DEFINITION()

RUN_TESTS(Identity, test_identity_create, test_identity_publish_preserves_address,
          test_identity_json_roundtrip_address, test_identity_sign_verify,
          test_identity_encrypt_decrypt)
