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
#include <jansson.h>

#include "structures/map_priv.h"
#include "structures/data_priv.h"

DEFINE_TEST(test_map_init_stack)
{
    /* Test map_init on a stack-allocated map */
    map_t map;
    ck_assert_ret_ok(map_init(&map));
    ck_assert_uint_eq(map_size(&map), 0);

    /* Insert and retrieve */
    char k[8];   /* map_set copies the key */
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
        char k[16];   /* map_set copies the key */
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

    char k1[8];   /* map_set copies the key */
    strcpy(k1, "alpha");
    ck_assert_ret_ok(map_set(map, k1, integer_data(1)));

    char k2[8];   /* map_set copies the key */
    strcpy(k2, "beta");
    ck_assert_ret_ok(map_set(map, k2, integer_data(2)));

    char k3[8];   /* map_set copies the key */
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

    char k[8];   /* map_set copies the key */
    strcpy(k, "rmkey");
    ck_assert_ret_ok(map_set(map, k, integer_data(99)));
    ck_assert_uint_eq(map_size(map), 1);

    char rm_k[] = "rmkey";
    ck_assert_ret_ok(map_remove(map, rm_k));
    ck_assert_uint_eq(map_size(map), 0);

    /* Re-insert with different value */
    char k2[8];   /* map_set copies the key */
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

/* How many times map_entries_for_each visits @p key. */
static int _visits(map_t *map, const char *want)
{
    int n = 0;
    map_key_t key = NULL;
    data_t *val = NULL;
    map_entries_for_each(map, key, val)
        if (strcmp(key, want) == 0)
            n++;
    map_end_for_each
    return n;
}

/* Churn: the key index stays under twice the live count, however many keys
 * come and go (it used to keep every key ever set). */
DEFINE_TEST(test_map_key_index_is_bounded_under_churn)
{
    map_t map;
    ck_assert_ret_ok(map_init(&map));
    char key[32];
    for (int i = 0; i < 1000; i++)
    {
        snprintf(key, sizeof(key), "k%d", i);
        ck_assert_ret_ok(map_set(&map, key, integer_data(i)));
        if (i >= 4)
        {
            snprintf(key, sizeof(key), "k%d", i - 4);
            ck_assert_ret_ok(map_remove(&map, key));
        }
        ck_assert(array_size(map_keys(&map)) <= 2 * map_size(&map) + 1);
    }
    ck_assert_uint_eq(map_size(&map), 4);
    map_free(&map);
}
END_TEST_DEFINITION()

/* A key removed and set again is visited once, not twice. */
DEFINE_TEST(test_map_reinserted_key_is_visited_once)
{
    map_t map;
    ck_assert_ret_ok(map_init(&map));
    ck_assert_ret_ok(map_set(&map, (char *)"a", integer_data(1)));
    ck_assert_ret_ok(map_set(&map, (char *)"b", integer_data(2)));
    ck_assert_ret_ok(map_remove(&map, (char *)"a"));
    ck_assert_ret_ok(map_set(&map, (char *)"a", integer_data(3)));
    ck_assert_int_eq(_visits(&map, "a"), 1);
    ck_assert_int_eq(_visits(&map, "b"), 1);
    map_free(&map);
}
END_TEST_DEFINITION()

/* Removing entries while walking the index still visits every live one: the
 * removal does not move the index (only a NEW key may compact it). */
DEFINE_TEST(test_map_remove_while_walking_visits_all)
{
    map_t map;
    ck_assert_ret_ok(map_init(&map));
    char key[16];
    for (int i = 0; i < 20; i++)
    {
        snprintf(key, sizeof(key), "k%d", i);
        ck_assert_ret_ok(map_set(&map, key, integer_data(i)));
    }
    int seen = 0;
    array_t *keys = map_keys(&map);
    for (size_t i = 0; i < array_size(keys); i++)
    {
        data_t *kd = NULL;
        char *k = NULL;
        ck_assert_ret_ok(array_get(keys, (int)i, &kd));
        ck_assert_ret_ok(data_string_ptr(kd, &k));
        data_t *v = NULL;
        if (map_get(&map, k, &v) != 0)
            continue;
        seen++;
        ck_assert_ret_ok(map_remove(&map, k));
    }
    ck_assert_int_eq(seen, 20);
    ck_assert_uint_eq(map_size(&map), 0);
    map_free(&map);
}
END_TEST_DEFINITION()

/* JSON carries the live keys only, and a reload drops dead and repeated keys
 * that older output may hold. */
DEFINE_TEST(test_map_json_keys_are_live_only)
{
    map_t map;
    ck_assert_ret_ok(map_init(&map));
    ck_assert_ret_ok(map_set(&map, (char *)"a", integer_data(1)));
    ck_assert_ret_ok(map_set(&map, (char *)"b", integer_data(2)));
    ck_assert_ret_ok(map_set(&map, (char *)"c", integer_data(3)));
    ck_assert_ret_ok(map_remove(&map, (char *)"b"));
    json_t *obj = NULL;
    ck_assert_ret_ok(map_to_json(&map, &obj));
    ck_assert_uint_eq(json_array_size(json_object_get(json_object_get(obj, "keys"), "array")), 2);

    /* An old-style index: a dead "zz" and "a" twice. */
    json_t *karr = json_object_get(json_object_get(obj, "keys"), "array");
    json_t *dup = json_deep_copy(json_array_get(karr, 0));
    json_array_append_new(karr, dup);
    data_t *zz = string_data((char *)"zz", 2);
    json_t *zj = NULL;
    ck_assert_ret_ok(data_to_json(zz, &zj));
    json_array_append_new(karr, zj);
    smrt_deref(zz);
    json_object_set_new(json_object_get(obj, "keys"), "size",
                        json_integer((json_int_t)json_array_size(karr)));

    map_t back;
    memset(&back, 0, sizeof(back));
    ck_assert_ret_ok(map_from_json(obj, &back));
    ck_assert_uint_eq(array_size(map_keys(&back)), 2);
    ck_assert_int_eq(_visits(&back, "a"), 1);
    ck_assert_int_eq(_visits(&back, "c"), 1);
    json_decref(obj);
    map_free(&back);
    map_free(&map);
}
END_TEST_DEFINITION()

RUN_TESTS(Map3, test_map_init_stack, test_map_capacity_growth,
          test_map_entries_for_each_macro, test_map_get_missing_key,
          test_map_remove_and_reinsert,
          test_map_key_index_is_bounded_under_churn,
          test_map_reinserted_key_is_visited_once,
          test_map_remove_while_walking_visits_all,
          test_map_json_keys_are_live_only)
