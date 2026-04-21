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

#include <stdlib.h>
#include "autonomous_trust/structures/array_priv.h"
#include "autonomous_trust/utilities/protobuf_shutdown.h"
#include "autonomous_trust/utilities/util.h"
#include "autonomous_trust/utilities/logger.h"

#define DEBUG_TESTS 1

#include "test_setup.h"


DEFINE_TEST(test_array_data)
{
    array_t arr;
    ck_assert_ret_ok(array_init(&arr));

    data_t *data1 = integer_data(1);
    ck_assert_ptr_nonnull(data1);
    ck_assert_ret_ok(array_append(&arr, data1));
    data_t *data2 = string_data((char*)"two", 3);
    ck_assert_ptr_nonnull(data2);
    ck_assert_ret_ok(array_append(&arr, data2));
    data_t *data3 = boolean_data(true);
    ck_assert_ptr_nonnull(data3);
    ck_assert_ret_ok(array_append(&arr, data3));
    data_t *data4 = floating_pt_data(4.0);
    ck_assert_ptr_nonnull(data4);
    ck_assert_ret_ok(array_append(&arr, data4));
    data_t *data5 = ul_integer_data(5UL);
    ck_assert_ptr_nonnull(data5);
    ck_assert_ret_ok(array_append(&arr, data5));
    data_t *data6 = bytes_data((unsigned char*)"six", 3);
    ck_assert_ptr_nonnull(data6);
    ck_assert_ret_ok(array_append(&arr, data6));
    int size = array_size(&arr);
    ck_assert_int_eq(6, size);

    data_t *data;
    ck_assert_ret_ok(array_get(&arr, 5, &data));
    unsigned char *bytes;
    ck_assert_ret_ok(data_bytes_ptr(data, &bytes));
    ck_assert_mem_eq(bytes, (unsigned char*)"six", 3);

    ck_assert_ret_ok(array_get(&arr, 4, &data));
    unsigned long l;
    ck_assert_ret_ok(data_ul_integer(data, &l));
    ck_assert_uint_eq(l, 5UL);

    ck_assert_ret_ok(array_get(&arr, 3, &data));
    float d;
    ck_assert_ret_ok(data_floating_pt(data, &d));
    ck_assert_double_eq_tol(d, 4.0, 0.0001);

    ck_assert_ret_ok(array_get(&arr, 2, &data));
    bool b;
    ck_assert_ret_ok(data_boolean(data, &b));
    ck_assert(b);

    ck_assert_ret_ok(array_get(&arr, 1, &data));
    char *str;
    ck_assert_ret_ok(data_string_ptr(data, &str));
    ck_assert_str_eq(str, "two");

    ck_assert_ret_ok(array_get(&arr, 0, &data));
    int one;
    ck_assert_ret_ok(data_integer(data, &one));
    ck_assert_int_eq(one, 1);

    smrt_deref(data1);
    smrt_deref(data2);
    smrt_deref(data3);
    smrt_deref(data4);
    smrt_deref(data5);
    smrt_deref(data6);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_array_create_heap)
{
    array_t *arr = NULL;
    ck_assert_ret_ok(array_create(&arr));
    ck_assert_ptr_nonnull(arr);
    ck_assert_uint_eq(array_size(arr), 0);

    ck_assert_ret_ok(array_append(arr, integer_data(10)));
    ck_assert_ret_ok(array_append(arr, integer_data(20)));
    ck_assert_uint_eq(array_size(arr), 2);

    data_t *out = NULL;
    ck_assert_ret_ok(array_get(arr, 0, &out));
    int val = 0;
    ck_assert_ret_ok(data_integer(out, &val));
    ck_assert_int_eq(val, 10);

    array_free(arr);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_array_find_contains)
{
    array_t arr;
    ck_assert_ret_ok(array_init(&arr));

    data_t *d1 = integer_data(100);
    data_t *d2 = integer_data(200);
    data_t *d3 = integer_data(300);
    data_t *d_missing = integer_data(999);

    ck_assert_ret_ok(array_append(&arr, d1));
    ck_assert_ret_ok(array_append(&arr, d2));
    ck_assert_ret_ok(array_append(&arr, d3));

    /* find returns index */
    ck_assert_int_eq(array_find(&arr, d1), 0);
    ck_assert_int_eq(array_find(&arr, d2), 1);
    ck_assert_int_eq(array_find(&arr, d3), 2);
    ck_assert_int_eq(array_find(&arr, d_missing), -1);

    /* contains returns bool */
    ck_assert(array_contains(&arr, d2) == true);
    ck_assert(array_contains(&arr, d_missing) == false);

    smrt_deref(d1);
    smrt_deref(d2);
    smrt_deref(d3);
    smrt_deref(d_missing);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_array_set_overwrite)
{
    array_t arr;
    ck_assert_ret_ok(array_init(&arr));

    ck_assert_ret_ok(array_append(&arr, integer_data(10)));
    ck_assert_ret_ok(array_append(&arr, integer_data(20)));
    ck_assert_ret_ok(array_append(&arr, integer_data(30)));

    /* Overwrite middle element */
    ck_assert_ret_ok(array_set(&arr, 1, integer_data(99)));
    ck_assert_uint_eq(array_size(&arr), 3);

    data_t *out = NULL;
    ck_assert_ret_ok(array_get(&arr, 1, &out));
    int val = 0;
    ck_assert_ret_ok(data_integer(out, &val));
    ck_assert_int_eq(val, 99);

    /* Out-of-bounds set should fail */
    ck_assert_ret_nonzero(array_set(&arr, 10, integer_data(0)));
}
END_TEST_DEFINITION()

DEFINE_TEST(test_array_remove)
{
    array_t arr;
    ck_assert_ret_ok(array_init(&arr));

    data_t *d1 = integer_data(10);
    data_t *d2 = integer_data(20);
    data_t *d3 = integer_data(30);

    ck_assert_ret_ok(array_append(&arr, d1));
    ck_assert_ret_ok(array_append(&arr, d2));
    ck_assert_ret_ok(array_append(&arr, d3));
    ck_assert_uint_eq(array_size(&arr), 3);

    /* Remove middle element */
    ck_assert_ret_ok(array_remove(&arr, d2));
    ck_assert_uint_eq(array_size(&arr), 2);

    /* Verify d2 is gone, d1 and d3 remain */
    ck_assert(array_contains(&arr, d2) == false);
    ck_assert(array_contains(&arr, d1) == true);
    ck_assert(array_contains(&arr, d3) == true);

    /* Removing non-existent element should fail */
    data_t *d_missing = integer_data(999);
    ck_assert_ret_nonzero(array_remove(&arr, d_missing));

    smrt_deref(d1);
    smrt_deref(d2);
    smrt_deref(d3);
    smrt_deref(d_missing);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_array_oob_errors)
{
    array_t arr;
    ck_assert_ret_ok(array_init(&arr));

    /* Add some elements */
    ck_assert_ret_ok(array_append(&arr, integer_data(10)));
    ck_assert_ret_ok(array_append(&arr, integer_data(20)));
    ck_assert_ret_ok(array_append(&arr, integer_data(30)));
    ck_assert_uint_eq(array_size(&arr), 3);

    /* Way out-of-bounds get should fail */
    data_t *out = NULL;
    ck_assert_ret_nonzero(array_get(&arr, 10, &out));

    /* Valid gets succeed */
    ck_assert_ret_ok(array_get(&arr, 0, &out));
    int val = 0;
    ck_assert_ret_ok(data_integer(out, &val));
    ck_assert_int_eq(val, 10);

    ck_assert_ret_ok(array_get(&arr, 2, &out));
    ck_assert_ret_ok(data_integer(out, &val));
    ck_assert_int_eq(val, 30);

    /* Way out-of-bounds set should fail */
    ck_assert_ret_nonzero(array_set(&arr, 10, integer_data(0)));
}
END_TEST_DEFINITION()

/* Regression for array.c:111 — the boundary index == size must be rejected.
 * The backing buffer holds exactly `size` slots; reading at index == size
 * is one past the end.  Original code used `index > a->size`, which allowed
 * a silent OOB read.  Fix is `index >= a->size`. */
DEFINE_TEST(test_array_get_rejects_index_equal_size)
{
    array_t arr;
    ck_assert_ret_ok(array_init(&arr));
    ck_assert_ret_ok(array_append(&arr, integer_data(10)));
    ck_assert_ret_ok(array_append(&arr, integer_data(20)));
    ck_assert_uint_eq(array_size(&arr), 2);

    data_t *out = (data_t *)0xDEADBEEF;
    ck_assert_ret_nonzero(array_get(&arr, (int)array_size(&arr), &out));
}
END_TEST_DEFINITION()

RUN_TESTS(Array, test_array_data, test_array_create_heap,
          test_array_find_contains, test_array_set_overwrite,
          test_array_remove, test_array_oob_errors,
          test_array_get_rejects_index_equal_size)
