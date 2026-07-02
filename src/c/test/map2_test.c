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
#include <stdlib.h>
#include <sodium.h>

#include "autonomous_trust/structures/map_priv.h"

DEFINE_TEST(test_map_overwrite_value)
{
    ck_assert(sodium_init() >= 0);

    map_t *map = NULL;
    ck_assert_ret_ok(map_create(&map));

    char k[] = "mykey";
    ck_assert_ret_ok(map_set(map, k, integer_data(10)));
    ck_assert_uint_eq(map_size(map), 1);

    /* Overwrite same key with new value */
    ck_assert_ret_ok(map_set(map, k, integer_data(99)));
    /* Size should NOT increase */
    ck_assert_uint_eq(map_size(map), 1);

    data_t *out = NULL;
    ck_assert_ret_ok(map_get(map, k, &out));
    int val = 0;
    ck_assert_ret_ok(data_integer(out, &val));
    ck_assert_int_eq(val, 99);

    map_free(map);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_map_for_each)
{
    ck_assert(sodium_init() >= 0);

    map_t *map = NULL;
    ck_assert_ret_ok(map_create(&map));

    char ka[] = "alpha";
    char kb[] = "beta";
    char kc[] = "gamma";
    ck_assert_ret_ok(map_set(map, ka, integer_data(1)));
    ck_assert_ret_ok(map_set(map, kb, integer_data(2)));
    ck_assert_ret_ok(map_set(map, kc, integer_data(3)));

    /* Iterate with for-each macro */
    int sum = 0;
    int count = 0;
    map_key_t key = NULL;
    data_t *value = NULL;
    map_entries_for_each(map, key, value)
    {
        int v = 0;
        data_integer(value, &v);
        sum += v;
        count++;
    }
    map_end_for_each

    ck_assert_int_eq(count, 3);
    ck_assert_int_eq(sum, 6);

    map_free(map);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_map_many_types)
{
    ck_assert(sodium_init() >= 0);

    map_t *map = NULL;
    ck_assert_ret_ok(map_create(&map));

    /* Store different data types */
    char k1[] = "int_key";
    char k2[] = "float_key";
    char k3[] = "bool_key";
    ck_assert_ret_ok(map_set(map, k1, integer_data(42)));
    ck_assert_ret_ok(map_set(map, k2, floating_pt_data(3.14f)));
    ck_assert_ret_ok(map_set(map, k3, boolean_data(true)));
    ck_assert_uint_eq(map_size(map), 3);

    /* Retrieve and verify types */
    data_t *out = NULL;
    ck_assert_ret_ok(map_get(map, k1, &out));
    int ival = 0;
    ck_assert_ret_ok(data_integer(out, &ival));
    ck_assert_int_eq(ival, 42);

    ck_assert_ret_ok(map_get(map, k2, &out));
    float fval = 0.0f;
    ck_assert_ret_ok(data_floating_pt(out, &fval));
    ck_assert(fval > 3.13f && fval < 3.15f);

    ck_assert_ret_ok(map_get(map, k3, &out));
    bool bval = false;
    ck_assert_ret_ok(data_boolean(out, &bval));
    ck_assert(bval == true);

    map_free(map);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_map_string_values)
{
    ck_assert(sodium_init() >= 0);

    map_t *map = NULL;
    ck_assert_ret_ok(map_create(&map));

    char k1[] = "name";
    char k2[] = "color";
    char v1[] = "Alice";
    char v2[] = "Blue";

    ck_assert_ret_ok(map_set(map, k1, string_data(v1, strlen(v1))));
    ck_assert_ret_ok(map_set(map, k2, string_data(v2, strlen(v2))));
    ck_assert_uint_eq(map_size(map), 2);

    data_t *out = NULL;
    ck_assert_ret_ok(map_get(map, k1, &out));
    char *sval = NULL;
    ck_assert_ret_ok(data_string_ptr(out, &sval));
    ck_assert_str_eq(sval, "Alice");

    map_free(map);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_map_remove_single)
{
    ck_assert(sodium_init() >= 0);

    map_t *map = NULL;
    ck_assert_ret_ok(map_create(&map));

    /* Insert two keys unlikely to collide (sparse capacity ~131) */
    char ka[] = "remove_me";
    char kb[] = "keep_me";
    ck_assert_ret_ok(map_set(map, ka, integer_data(1)));
    ck_assert_ret_ok(map_set(map, kb, integer_data(2)));
    ck_assert_uint_eq(map_size(map), 2);

    /* Remove one key */
    ck_assert_ret_ok(map_remove(map, ka));
    ck_assert_uint_eq(map_size(map), 1);

    /* Removed key should not be found */
    data_t *out = NULL;
    ck_assert_ret_nonzero(map_get(map, ka, &out));

    /* Other key still accessible */
    ck_assert_ret_ok(map_get(map, kb, &out));
    int val = 0;
    ck_assert_ret_ok(data_integer(out, &val));
    ck_assert_int_eq(val, 2);

    map_free(map);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_map_set_null_value)
{
    ck_assert(sodium_init() >= 0);

    map_t *map = NULL;
    ck_assert_ret_ok(map_create(&map));

    /* Setting NULL value should fail (EINVAL) */
    char k[] = "test";
    ck_assert_ret_nonzero(map_set(map, k, NULL));

    /* map_create with NULL should fail */
    ck_assert_ret_nonzero(map_create(NULL));

    map_free(map);
}
END_TEST_DEFINITION()

RUN_TESTS(Map2, test_map_overwrite_value, test_map_for_each,
          test_map_many_types, test_map_string_values,
          test_map_remove_single, test_map_set_null_value)
