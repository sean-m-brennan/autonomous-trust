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
#include <jansson.h>

#include "autonomous_trust/structures/array_priv.h"

static bool is_positive(data_t *d)
{
    int val = 0;
    if (data_integer(d, &val) != 0)
        return false;
    return val > 0;
}

DEFINE_TEST(test_array_copy)
{
    array_t arr;
    ck_assert_ret_ok(array_init(&arr));

    ck_assert_ret_ok(array_append(&arr, integer_data(10)));
    ck_assert_ret_ok(array_append(&arr, integer_data(20)));
    ck_assert_ret_ok(array_append(&arr, integer_data(30)));

    array_t cpy;
    memset(&cpy, 0, sizeof(cpy));
    ck_assert_ret_ok(array_copy(&arr, &cpy));

    /* Copy should have same size and values */
    ck_assert_uint_eq(array_size(&arr), array_size(&cpy));

    data_t *out = NULL;
    ck_assert_ret_ok(array_get(&cpy, 1, &out));
    int val = 0;
    ck_assert_ret_ok(data_integer(out, &val));
    ck_assert_int_eq(val, 20);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_array_filter)
{
    array_t arr;
    ck_assert_ret_ok(array_init(&arr));

    ck_assert_ret_ok(array_append(&arr, integer_data(-5)));
    ck_assert_ret_ok(array_append(&arr, integer_data(-3)));
    ck_assert_ret_ok(array_append(&arr, integer_data(7)));
    ck_assert_ret_ok(array_append(&arr, integer_data(2)));

    /* Find first positive */
    int idx = array_filter(&arr, is_positive);
    ck_assert_int_eq(idx, 2);  /* index of 7 */
}
END_TEST_DEFINITION()

DEFINE_TEST(test_array_filter_no_match)
{
    array_t arr;
    ck_assert_ret_ok(array_init(&arr));

    ck_assert_ret_ok(array_append(&arr, integer_data(-1)));
    ck_assert_ret_ok(array_append(&arr, integer_data(-2)));

    int idx = array_filter(&arr, is_positive);
    ck_assert_int_eq(idx, -1);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_array_for_each_macro)
{
    array_t arr;
    ck_assert_ret_ok(array_init(&arr));

    ck_assert_ret_ok(array_append(&arr, integer_data(10)));
    ck_assert_ret_ok(array_append(&arr, integer_data(20)));
    ck_assert_ret_ok(array_append(&arr, integer_data(30)));

    int sum = 0;
    int idx = 0;
    data_t *val = NULL;
    array_for_each(&arr, idx, val)
        int v = 0;
        data_integer(val, &v);
        sum += v;
    array_end_for_each

    ck_assert_int_eq(sum, 60);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_array_json_roundtrip)
{
    array_t arr;
    ck_assert_ret_ok(array_init(&arr));

    ck_assert_ret_ok(array_append(&arr, integer_data(1)));
    ck_assert_ret_ok(array_append(&arr, integer_data(2)));
    ck_assert_ret_ok(array_append(&arr, integer_data(3)));

    json_t *obj = NULL;
    ck_assert_ret_ok(array_to_json(&arr, &obj));
    ck_assert_ptr_nonnull(obj);

    /* Verify structure */
    ck_assert(json_is_object(obj));
    json_t *size_j = json_object_get(obj, "size");
    ck_assert_ptr_nonnull(size_j);
    ck_assert_int_eq(json_integer_value(size_j), 3);

    json_decref(obj);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_array_large_append)
{
    array_t *arr = NULL;
    ck_assert_ret_ok(array_create(&arr));

    /* Append many elements to test resizing */
    for (int i = 0; i < 100; i++) {
        ck_assert_ret_ok(array_append(arr, integer_data(i)));
    }
    ck_assert_uint_eq(array_size(arr), 100);

    /* Verify first and last */
    data_t *out = NULL;
    ck_assert_ret_ok(array_get(arr, 0, &out));
    int val = 0;
    ck_assert_ret_ok(data_integer(out, &val));
    ck_assert_int_eq(val, 0);

    ck_assert_ret_ok(array_get(arr, 99, &out));
    ck_assert_ret_ok(data_integer(out, &val));
    ck_assert_int_eq(val, 99);

    array_free(arr);
}
END_TEST_DEFINITION()

RUN_TESTS(Array2, test_array_copy, test_array_filter,
          test_array_filter_no_match, test_array_for_each_macro,
          test_array_json_roundtrip, test_array_large_append)
