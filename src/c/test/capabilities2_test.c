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
#include <jansson.h>

#include "processes/capabilities_priv.h"
#include "structures/data_priv.h"
#include "structures/array_priv.h"

extern capability_t capability_table[];
extern size_t capability_table_size;

DEFINE_TEST(test_peer_capabilities_json_empty)
{
    ck_assert(sodium_init() >= 0);

    /* Empty matrix roundtrips */
    peer_capabilities_matrix_t matrix;
    map_init(&matrix);

    json_t *obj = NULL;
    ck_assert_ret_ok(peer_capabilities_to_json(&matrix, &obj));
    ck_assert_ptr_nonnull(obj);

    /* Check typename */
    const char *tn = json_string_value(json_object_get(obj, "typename"));
    ck_assert_ptr_nonnull(tn);
    ck_assert_str_eq(tn, "peer_capabilities");

    /* Deserialize back */
    peer_capabilities_matrix_t matrix2;
    ck_assert_ret_ok(peer_capabilities_from_json(obj, &matrix2));
    ck_assert_uint_eq(map_size(&matrix2), 0);

    json_decref(obj);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_peer_capabilities_json_roundtrip)
{
    ck_assert(sodium_init() >= 0);

    /* Build a matrix with one peer having two capabilities */
    peer_capabilities_matrix_t matrix;
    map_init(&matrix);

    array_t *caps;
    ck_assert_ret_ok(array_create(&caps));

    /* Capability 1 */
    capability_t *cap1 = smrt_create(sizeof(capability_t));
    memset(cap1, 0, sizeof(capability_t));
    strncpy(cap1->name, "sensing", CAP_NAMELEN);
    map_init(&cap1->arguments);
    data_t *cap1_dat = object_ptr_data(cap1, sizeof(capability_t));
    ck_assert_ret_ok(array_append(caps, cap1_dat));

    /* Capability 2 */
    capability_t *cap2 = smrt_create(sizeof(capability_t));
    memset(cap2, 0, sizeof(capability_t));
    strncpy(cap2->name, "compute", CAP_NAMELEN);
    map_init(&cap2->arguments);
    data_t *cap2_dat = object_ptr_data(cap2, sizeof(capability_t));
    ck_assert_ret_ok(array_append(caps, cap2_dat));

    char *peer_key = smrt_create(37);
    strcpy(peer_key, "550e8400-e29b-41d4-a716-446655440000");
    data_t *arr_dat = object_ptr_data(caps, sizeof(array_t));
    ck_assert_ret_ok(map_set(&matrix, peer_key, arr_dat));

    /* Serialize to JSON */
    json_t *obj = NULL;
    ck_assert_ret_ok(peer_capabilities_to_json(&matrix, &obj));
    ck_assert_ptr_nonnull(obj);

    /* Verify JSON structure */
    json_t *peers = json_object_get(obj, "peers");
    ck_assert_ptr_nonnull(peers);
    ck_assert(json_is_object(peers));
    json_t *peer_arr = json_object_get(peers, "550e8400-e29b-41d4-a716-446655440000");
    ck_assert_ptr_nonnull(peer_arr);
    ck_assert(json_is_array(peer_arr));
    ck_assert_uint_eq(json_array_size(peer_arr), 2);

    /* Deserialize back */
    peer_capabilities_matrix_t matrix2;
    ck_assert_ret_ok(peer_capabilities_from_json(obj, &matrix2));
    ck_assert_uint_eq(map_size(&matrix2), 1);

    /* Verify deserialized capability names */
    data_t *val = NULL;
    char uuid_key[] = "550e8400-e29b-41d4-a716-446655440000";
    ck_assert_ret_ok(map_get(&matrix2, uuid_key, &val));
    void *caps2_ptr;
    ck_assert_ret_ok(data_object_ptr(val, &caps2_ptr));
    array_t *caps2 = caps2_ptr;
    ck_assert_uint_eq(array_size(caps2), 2);

    data_t *c1_dat = NULL;
    ck_assert_ret_ok(array_get(caps2, 0, &c1_dat));
    capability_t *c1;
    ck_assert_ret_ok(data_object_ptr(c1_dat, (void **)&c1));
    ck_assert_str_eq(c1->name, "sensing");

    data_t *c2_dat = NULL;
    ck_assert_ret_ok(array_get(caps2, 1, &c2_dat));
    capability_t *c2;
    ck_assert_ret_ok(data_object_ptr(c2_dat, (void **)&c2));
    ck_assert_str_eq(c2->name, "compute");

    json_decref(obj);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_build_local_capabilities)
{
    ck_assert(sodium_init() >= 0);

    /* build_local_capabilities collects all local capabilities from the table */
    array_t *caps = NULL;
    ck_assert_ret_ok(build_local_capabilities("test-uuid", &caps));
    ck_assert_ptr_nonnull(caps);

    /* In test builds, capability_table_size may be 0 (no DEFINE_CAPABILITY used).
       The function should still succeed and return an empty array. */
    ck_assert(array_size(caps) <= capability_table_size);

    smrt_deref(caps);
}
END_TEST_DEFINITION()

RUN_TESTS(Capabilities2, test_peer_capabilities_json_empty,
          test_peer_capabilities_json_roundtrip, test_build_local_capabilities)
