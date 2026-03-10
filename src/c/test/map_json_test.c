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
#include <sodium.h>
#include <jansson.h>

#include "autonomous_trust/structures/map_priv.h"

DEFINE_TEST(test_map_init_stack)
{
    ck_assert(sodium_init() >= 0);

    map_t map;
    ck_assert_ret_ok(map_init(&map));
    ck_assert_uint_eq(map_size(&map), 0);

    char k[] = "test";
    ck_assert_ret_ok(map_set(&map, k, integer_data(42)));
    ck_assert_uint_eq(map_size(&map), 1);

    data_t *out = NULL;
    ck_assert_ret_ok(map_get(&map, k, &out));
    int val = 0;
    ck_assert_ret_ok(data_integer(out, &val));
    ck_assert_int_eq(val, 42);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_map_get_missing)
{
    ck_assert(sodium_init() >= 0);

    map_t *map = NULL;
    ck_assert_ret_ok(map_create(&map));

    char ka[] = "exists";
    char kb[] = "missing";
    ck_assert_ret_ok(map_set(map, ka, integer_data(42)));

    /* Get existing key succeeds */
    data_t *out = NULL;
    ck_assert_ret_ok(map_get(map, ka, &out));

    /* Get missing key fails */
    ck_assert_ret_nonzero(map_get(map, kb, &out));

    /* Remove nonexistent key should fail */
    ck_assert_ret_nonzero(map_remove(map, kb));

    map_free(map);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_map_many_entries)
{
    ck_assert(sodium_init() >= 0);

    map_t *map = NULL;
    ck_assert_ret_ok(map_create(&map));

    /* Insert many entries to test rehashing */
    char keys[20][16];
    for (int i = 0; i < 20; i++) {
        snprintf(keys[i], sizeof(keys[i]), "key_%03d", i);
        ck_assert_ret_ok(map_set(map, keys[i], integer_data(i * 10)));
    }
    ck_assert_uint_eq(map_size(map), 20);

    /* Verify all entries retrievable */
    for (int i = 0; i < 20; i++) {
        data_t *out = NULL;
        ck_assert_ret_ok(map_get(map, keys[i], &out));
        int val = 0;
        ck_assert_ret_ok(data_integer(out, &val));
        ck_assert_int_eq(val, i * 10);
    }

    map_free(map);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_map_remove_reinsert)
{
    ck_assert(sodium_init() >= 0);

    map_t *map = NULL;
    ck_assert_ret_ok(map_create(&map));

    char ka[] = "key_a";
    char kb[] = "key_b";
    ck_assert_ret_ok(map_set(map, ka, integer_data(1)));
    ck_assert_ret_ok(map_set(map, kb, integer_data(2)));
    ck_assert_uint_eq(map_size(map), 2);

    /* Remove and re-insert */
    ck_assert_ret_ok(map_remove(map, ka));
    ck_assert_uint_eq(map_size(map), 1);

    ck_assert_ret_ok(map_set(map, ka, integer_data(99)));
    ck_assert_uint_eq(map_size(map), 2);

    data_t *out = NULL;
    ck_assert_ret_ok(map_get(map, ka, &out));
    int val = 0;
    ck_assert_ret_ok(data_integer(out, &val));
    ck_assert_int_eq(val, 99);

    map_free(map);
}
END_TEST_DEFINITION()

RUN_TESTS(MapJson, test_map_init_stack, test_map_get_missing,
          test_map_many_entries, test_map_remove_reinsert)
