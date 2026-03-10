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
#include <sodium.h>
#include <uuid/uuid.h>

#include "identity/group.h"

DEFINE_TEST(test_group_create)
{
    ck_assert(sodium_init() >= 0);

    uuid_t uuid;
    uuid_generate(uuid);
    char addr[] = "192.168.1.1";

    group_t *grp = NULL;
    ck_assert_ret_ok(group_create(&uuid, addr, &grp));
    ck_assert_ptr_nonnull(grp);
    ck_assert_str_eq(grp->address, "192.168.1.1");
    ck_assert_mem_eq(grp->uuid, uuid, sizeof(uuid_t));

    group_free(grp);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_group_encrypt_decrypt)
{
    ck_assert(sodium_init() >= 0);

    uuid_t u1, u2;
    uuid_generate(u1);
    uuid_generate(u2);
    char addr1[] = "10.0.0.1";
    char addr2[] = "10.0.0.2";

    group_t *g1 = NULL;
    group_t *g2 = NULL;
    ck_assert_ret_ok(group_create(&u1, addr1, &g1));
    ck_assert_ret_ok(group_create(&u2, addr2, &g2));

    /* g1 encrypts for g2 */
    const char *plaintext = "Group secret";
    msg_str_t msg = {.msg = (unsigned char *)plaintext, .len = strlen(plaintext)};
    unsigned char nonce[crypto_box_NONCEBYTES];
    randombytes_buf(nonce, sizeof(nonce));

    size_t cipher_len = msg.len + crypto_box_MACBYTES;
    unsigned char *cipher = malloc(cipher_len);
    ck_assert_ptr_nonnull(cipher);

    ck_assert_ret_ok(group_encrypt(g1, &msg, g2, nonce, cipher));

    /* g2 decrypts */
    msg_str_t cmsg = {.msg = cipher, .len = cipher_len};
    unsigned char *decrypted = malloc(msg.len);
    ck_assert_ptr_nonnull(decrypted);

    ck_assert_ret_ok(group_decrypt(g2, &cmsg, g1, nonce, decrypted));
    ck_assert_mem_eq(decrypted, plaintext, strlen(plaintext));

    free(cipher);
    free(decrypted);
    group_free(g1);
    group_free(g2);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_group_proto_roundtrip)
{
    ck_assert(sodium_init() >= 0);

    uuid_t uuid;
    uuid_generate(uuid);
    char addr[] = "172.16.0.1";

    group_t *grp = NULL;
    ck_assert_ret_ok(group_create(&uuid, addr, &grp));

    /* Serialize to protobuf */
    void *data = NULL;
    size_t data_len = 0;
    ck_assert_ret_ok(group_to_proto(grp, &data, &data_len));
    ck_assert_ptr_nonnull(data);
    ck_assert(data_len > 0);

    /* Deserialize from protobuf */
    group_t grp2;
    memset(&grp2, 0, sizeof(group_t));
    ck_assert_ret_ok(proto_to_group((uint8_t *)data, data_len, &grp2));

    ck_assert_str_eq(grp2.address, "172.16.0.1");
    ck_assert_mem_eq(grp2.uuid, uuid, sizeof(uuid_t));

    free(data);
    group_free(grp);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_group_init_stack)
{
    ck_assert(sodium_init() >= 0);

    uuid_t uuid;
    uuid_generate(uuid);
    char addr[] = "10.0.0.5";

    group_t grp;
    memset(&grp, 0, sizeof(group_t));
    ck_assert_ret_ok(group_init(&uuid, addr, &grp));

    ck_assert_str_eq(grp.address, "10.0.0.5");
    ck_assert_mem_eq(grp.uuid, uuid, sizeof(uuid_t));
}
END_TEST_DEFINITION()

RUN_TESTS(Group, test_group_create, test_group_encrypt_decrypt,
          test_group_proto_roundtrip, test_group_init_stack)
