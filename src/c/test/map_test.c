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
#include <stdlib.h>

#include "autonomous_trust/structures/map_priv.h"

DEFINE_TEST(test_map_create_empty)
{
    map_t *map = NULL;
    ck_assert_ret_ok(map_create(&map));
    ck_assert_ptr_nonnull(map);
    ck_assert_uint_eq(map_size(map), 0);

    /* Get from empty map should fail */
    data_t *val = NULL;
    char nokey[] = "nokey";
    ck_assert_ret_nonzero(map_get(map, nokey, &val));

    map_free(map);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_map_set_get)
{
    map_t *map = NULL;
    ck_assert_ret_ok(map_create(&map));

    data_t *v1 = integer_data(42);
    char hello[] = "hello";
    data_t *v2 = string_data(hello, 5);
    data_t *v3 = boolean_data(true);

    char k1[] = "key1";
    char k2[] = "key2";
    char k3[] = "key3";

    ck_assert_ret_ok(map_set(map, k1, v1));
    ck_assert_ret_ok(map_set(map, k2, v2));
    ck_assert_ret_ok(map_set(map, k3, v3));
    ck_assert_uint_eq(map_size(map), 3);

    /* Retrieve values */
    data_t *out = NULL;
    ck_assert_ret_ok(map_get(map, k1, &out));
    int ival = 0;
    ck_assert_ret_ok(data_integer(out, &ival));
    ck_assert_int_eq(ival, 42);

    ck_assert_ret_ok(map_get(map, k2, &out));
    string_t sptr = NULL;
    ck_assert_ret_ok(data_string_ptr(out, &sptr));
    ck_assert_str_eq(sptr, "hello");

    map_free(map);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_map_overwrite)
{
    map_t *map = NULL;
    ck_assert_ret_ok(map_create(&map));

    data_t *v1 = integer_data(10);
    data_t *v2 = integer_data(20);
    char key[] = "key";

    ck_assert_ret_ok(map_set(map, key, v1));
    ck_assert_uint_eq(map_size(map), 1);

    /* Overwrite existing key */
    ck_assert_ret_ok(map_set(map, key, v2));
    ck_assert_uint_eq(map_size(map), 1);

    data_t *out = NULL;
    ck_assert_ret_ok(map_get(map, key, &out));
    int val = 0;
    ck_assert_ret_ok(data_integer(out, &val));
    ck_assert_int_eq(val, 20);

    map_free(map);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_map_remove)
{
    map_t *map = NULL;
    ck_assert_ret_ok(map_create(&map));

    data_t *v1 = integer_data(1);
    data_t *v2 = integer_data(2);
    data_t *v3 = integer_data(3);
    char ka[] = "a";
    char kb[] = "b";
    char kc[] = "c";

    ck_assert_ret_ok(map_set(map, ka, v1));
    ck_assert_ret_ok(map_set(map, kb, v2));
    ck_assert_ret_ok(map_set(map, kc, v3));
    ck_assert_uint_eq(map_size(map), 3);

    /* Remove middle */
    ck_assert_ret_ok(map_remove(map, kb));
    ck_assert_uint_eq(map_size(map), 2);

    /* Removed key is gone */
    data_t *out = NULL;
    ck_assert_ret_nonzero(map_get(map, kb, &out));

    /* Others remain */
    ck_assert_ret_ok(map_get(map, ka, &out));
    ck_assert_ret_ok(map_get(map, kc, &out));

    map_free(map);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_map_keys)
{
    map_t *map = NULL;
    ck_assert_ret_ok(map_create(&map));

    char kalpha[] = "alpha";
    char kbeta[] = "beta";
    char kgamma[] = "gamma";

    ck_assert_ret_ok(map_set(map, kalpha, integer_data(1)));
    ck_assert_ret_ok(map_set(map, kbeta, integer_data(2)));
    ck_assert_ret_ok(map_set(map, kgamma, integer_data(3)));

    array_t *keys = map_keys(map);
    ck_assert_ptr_nonnull(keys);
    ck_assert_uint_eq(array_size(keys), 3);

    /* Verify all keys are present (order may vary) */
    bool found_alpha = false, found_beta = false, found_gamma = false;
    for (size_t i = 0; i < array_size(keys); i++) {
        data_t *kd = NULL;
        ck_assert_ret_ok(array_get(keys, i, &kd));
        string_t s = NULL;
        ck_assert_ret_ok(data_string_ptr(kd, &s));
        if (strcmp(s, "alpha") == 0) found_alpha = true;
        else if (strcmp(s, "beta") == 0) found_beta = true;
        else if (strcmp(s, "gamma") == 0) found_gamma = true;
    }
    ck_assert(found_alpha);
    ck_assert(found_beta);
    ck_assert(found_gamma);

    map_free(map);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_map_for_each)
{
    map_t *map = NULL;
    ck_assert_ret_ok(map_create(&map));

    char kx[] = "x";
    char ky[] = "y";

    ck_assert_ret_ok(map_set(map, kx, integer_data(10)));
    ck_assert_ret_ok(map_set(map, ky, integer_data(20)));

    int sum = 0;
    int count = 0;
    map_key_t key = NULL;
    data_t *value = NULL;
    map_entries_for_each(map, key, value)
        int v = 0;
        data_integer(value, &v);
        sum += v;
        count++;
    map_end_for_each

    ck_assert_int_eq(count, 2);
    ck_assert_int_eq(sum, 30);

    map_free(map);
}
END_TEST_DEFINITION()

RUN_TESTS(Map, test_map_create_empty, test_map_set_get,
          test_map_overwrite, test_map_remove,
          test_map_keys, test_map_for_each)
