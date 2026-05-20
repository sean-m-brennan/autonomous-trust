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

RUN_TESTS(Group2, test_group_json_roundtrip, test_group_free_null,
          test_group_publish_null,
          test_group_init_nul_terminates_long_address)
