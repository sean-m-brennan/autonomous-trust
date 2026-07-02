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
#include <stdio.h>

#include "structures/map_priv.h"
#include "structures/data_priv.h"

DEFINE_TEST(test_map_init_stack)
{
    /* Test map_init on a stack-allocated map */
    map_t map;
    ck_assert_ret_ok(map_init(&map));
    ck_assert_uint_eq(map_size(&map), 0);

    /* Insert and retrieve */
    char *k = smrt_create(8);
    strcpy(k, "key1");
    data_t *v = integer_data(42);
    ck_assert_ret_ok(map_set(&map, k, v));
    ck_assert_uint_eq(map_size(&map), 1);

    data_t *out = NULL;
    char get_k[] = "key1";
    ck_assert_ret_ok(map_get(&map, get_k, &out));
    int val;
    ck_assert_ret_ok(data_integer(out, &val));
    ck_assert_int_eq(val, 42);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_map_capacity_growth)
{
    /* Insert enough items to trigger hash table growth */
    map_t *map = NULL;
    ck_assert_ret_ok(map_create(&map));

    for (int i = 0; i < 50; i++) {
        char *k = smrt_create(16);
        snprintf(k, 16, "key_%03d", i);
        data_t *v = integer_data(i * 10);
        ck_assert_ret_ok(map_set(map, k, v));
    }
    ck_assert_uint_eq(map_size(map), 50);

    /* Verify all values survive growth */
    for (int i = 0; i < 50; i++) {
        char gk[16];
        snprintf(gk, 16, "key_%03d", i);
        data_t *out = NULL;
        ck_assert_ret_ok(map_get(map, gk, &out));
        int val;
        ck_assert_ret_ok(data_integer(out, &val));
        ck_assert_int_eq(val, i * 10);
    }

    smrt_deref(map);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_map_entries_for_each_macro)
{
    map_t *map = NULL;
    ck_assert_ret_ok(map_create(&map));

    char *k1 = smrt_create(8);
    strcpy(k1, "alpha");
    ck_assert_ret_ok(map_set(map, k1, integer_data(1)));

    char *k2 = smrt_create(8);
    strcpy(k2, "beta");
    ck_assert_ret_ok(map_set(map, k2, integer_data(2)));

    char *k3 = smrt_create(8);
    strcpy(k3, "gamma");
    ck_assert_ret_ok(map_set(map, k3, integer_data(3)));

    /* Iterate and sum values */
    int sum = 0;
    int count = 0;
    char *key;
    data_t *val;
    map_entries_for_each(map, key, val)
        int v;
        if (data_integer(val, &v) == 0)
            sum += v;
        count++;
    map_end_for_each

    ck_assert_int_eq(count, 3);
    ck_assert_int_eq(sum, 6);

    smrt_deref(map);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_map_get_missing_key)
{
    map_t *map = NULL;
    ck_assert_ret_ok(map_create(&map));

    data_t *out = NULL;
    char miss_k[] = "nonexistent";
    int ret = map_get(map, miss_k, &out);
    ck_assert(ret != 0);  /* Should fail for missing key */

    smrt_deref(map);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_map_remove_and_reinsert)
{
    map_t *map = NULL;
    ck_assert_ret_ok(map_create(&map));

    char *k = smrt_create(8);
    strcpy(k, "rmkey");
    ck_assert_ret_ok(map_set(map, k, integer_data(99)));
    ck_assert_uint_eq(map_size(map), 1);

    char rm_k[] = "rmkey";
    ck_assert_ret_ok(map_remove(map, rm_k));
    ck_assert_uint_eq(map_size(map), 0);

    /* Re-insert with different value */
    char *k2 = smrt_create(8);
    strcpy(k2, "rmkey");
    ck_assert_ret_ok(map_set(map, k2, integer_data(77)));
    ck_assert_uint_eq(map_size(map), 1);

    data_t *out = NULL;
    char get_rm[] = "rmkey";
    ck_assert_ret_ok(map_get(map, get_rm, &out));
    int val;
    ck_assert_ret_ok(data_integer(out, &val));
    ck_assert_int_eq(val, 77);

    smrt_deref(map);
}
END_TEST_DEFINITION()

RUN_TESTS(Map3, test_map_init_stack, test_map_capacity_growth,
          test_map_entries_for_each_macro, test_map_get_missing_key,
          test_map_remove_and_reinsert)
