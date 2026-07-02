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

DEFINE_TEST(test_capability_proto_roundtrip)
{
    ck_assert(sodium_init() >= 0);

    capability_t cap;
    memset(&cap, 0, sizeof(cap));
    strncpy(cap.name, "test_cap", CAP_NAMELEN);
    map_init(&cap.arguments);

    void *data = NULL;
    size_t data_len = 0;
    ck_assert_ret_ok(capability_to_proto(&cap, &data, &data_len));
    ck_assert_ptr_nonnull(data);
    ck_assert(data_len > 0);

    capability_t cap2;
    memset(&cap2, 0, sizeof(cap2));
    map_init(&cap2.arguments);
    ck_assert_ret_ok(proto_to_capability((uint8_t *)data, data_len, &cap2));

    ck_assert_str_eq(cap2.name, "test_cap");

    smrt_deref(data);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_capability_json_with_arguments)
{
    ck_assert(sodium_init() >= 0);

    peer_capabilities_matrix_t matrix;
    map_init(&matrix);

    array_t *caps;
    ck_assert_ret_ok(array_create(&caps));

    capability_t *cap = smrt_create(sizeof(capability_t));
    memset(cap, 0, sizeof(capability_t));
    strncpy(cap->name, "data_ingest", CAP_NAMELEN);
    map_init(&cap->arguments);

    char *k1 = smrt_create(16);
    strcpy(k1, "frequency");
    map_set(&cap->arguments, k1, integer_data(3));

    char *k2 = smrt_create(16);
    strcpy(k2, "format");
    map_set(&cap->arguments, k2, integer_data(5));

    data_t *cap_dat = object_ptr_data(cap, sizeof(capability_t));
    ck_assert_ret_ok(array_append(caps, cap_dat));

    char *peer_key = smrt_create(37);
    strcpy(peer_key, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
    data_t *arr_dat = object_ptr_data(caps, sizeof(array_t));
    ck_assert_ret_ok(map_set(&matrix, peer_key, arr_dat));

    json_t *obj = NULL;
    ck_assert_ret_ok(peer_capabilities_to_json(&matrix, &obj));

    json_t *peers = json_object_get(obj, "peers");
    json_t *parr = json_object_get(peers, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
    ck_assert_uint_eq(json_array_size(parr), 1);
    json_t *jcap = json_array_get(parr, 0);
    ck_assert_str_eq(json_string_value(json_object_get(jcap, "name")), "data_ingest");
    json_t *jargs = json_object_get(jcap, "arguments");
    ck_assert_int_eq(json_integer_value(json_object_get(jargs, "frequency")), 3);
    ck_assert_int_eq(json_integer_value(json_object_get(jargs, "format")), 5);

    peer_capabilities_matrix_t matrix2;
    ck_assert_ret_ok(peer_capabilities_from_json(obj, &matrix2));

    char get_key[] = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    data_t *val = NULL;
    ck_assert_ret_ok(map_get(&matrix2, get_key, &val));
    void *caps2_ptr;
    ck_assert_ret_ok(data_object_ptr(val, &caps2_ptr));
    array_t *caps2 = caps2_ptr;
    ck_assert_uint_eq(array_size(caps2), 1);

    data_t *c_dat = NULL;
    ck_assert_ret_ok(array_get(caps2, 0, &c_dat));
    capability_t *c;
    ck_assert_ret_ok(data_object_ptr(c_dat, (void **)&c));
    ck_assert_str_eq(c->name, "data_ingest");

    json_decref(obj);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_peer_capabilities_json_multiple_peers)
{
    ck_assert(sodium_init() >= 0);

    peer_capabilities_matrix_t matrix;
    map_init(&matrix);

    array_t *caps1;
    ck_assert_ret_ok(array_create(&caps1));
    capability_t *c1 = smrt_create(sizeof(capability_t));
    memset(c1, 0, sizeof(capability_t));
    strncpy(c1->name, "sensing", CAP_NAMELEN);
    map_init(&c1->arguments);
    ck_assert_ret_ok(array_append(caps1, object_ptr_data(c1, sizeof(capability_t))));
    char *k1 = smrt_create(37);
    strcpy(k1, "11111111-1111-1111-1111-111111111111");
    ck_assert_ret_ok(map_set(&matrix, k1, object_ptr_data(caps1, sizeof(array_t))));

    array_t *caps2;
    ck_assert_ret_ok(array_create(&caps2));
    capability_t *c2a = smrt_create(sizeof(capability_t));
    memset(c2a, 0, sizeof(capability_t));
    strncpy(c2a->name, "compute", CAP_NAMELEN);
    map_init(&c2a->arguments);
    ck_assert_ret_ok(array_append(caps2, object_ptr_data(c2a, sizeof(capability_t))));
    capability_t *c2b = smrt_create(sizeof(capability_t));
    memset(c2b, 0, sizeof(capability_t));
    strncpy(c2b->name, "storage", CAP_NAMELEN);
    map_init(&c2b->arguments);
    ck_assert_ret_ok(array_append(caps2, object_ptr_data(c2b, sizeof(capability_t))));
    char *k2 = smrt_create(37);
    strcpy(k2, "22222222-2222-2222-2222-222222222222");
    ck_assert_ret_ok(map_set(&matrix, k2, object_ptr_data(caps2, sizeof(array_t))));

    json_t *obj = NULL;
    ck_assert_ret_ok(peer_capabilities_to_json(&matrix, &obj));

    peer_capabilities_matrix_t matrix2;
    ck_assert_ret_ok(peer_capabilities_from_json(obj, &matrix2));
    ck_assert_uint_eq(map_size(&matrix2), 2);

    json_decref(obj);
}
END_TEST_DEFINITION()

RUN_TESTS(Capabilities3, test_capability_proto_roundtrip,
          test_capability_json_with_arguments,
          test_peer_capabilities_json_multiple_peers)
