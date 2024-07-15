/********************
 *  Copyright 2024 TekFive, Inc. and contributors
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

#define DEBUG_TESTS 0

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

RUN_TESTS(Array, test_array_data)
