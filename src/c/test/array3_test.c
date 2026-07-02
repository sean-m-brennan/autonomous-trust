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

#include "structures/array_priv.h"

DEFINE_TEST(test_array_proto_roundtrip_ints)
{
    array_t *arr;
    ck_assert_ret_ok(array_create(&arr));

    ck_assert_ret_ok(array_append(arr, integer_data(10)));
    ck_assert_ret_ok(array_append(arr, integer_data(20)));
    ck_assert_ret_ok(array_append(arr, integer_data(30)));

    /* Sync out to proto */
    AutonomousTrust__Core__Protobuf__Structures__Data **parr = NULL;
    size_t n = 0;
    ck_assert_ret_ok(array_sync_out(arr, &parr, &n));
    ck_assert_uint_eq(n, 3);
    ck_assert_ptr_nonnull(parr);

    /* Sync in from proto */
    array_t arr2;
    ck_assert_ret_ok(array_init(&arr2));
    ck_assert_ret_ok(array_sync_in(parr, n, &arr2));
    ck_assert_uint_eq(array_size(&arr2), 3);

    for (int i = 0; i < 3; i++) {
        data_t *d = NULL;
        ck_assert_ret_ok(array_get(&arr2, i, &d));
        int val = 0;
        ck_assert_ret_ok(data_integer(d, &val));
        ck_assert_int_eq(val, (i + 1) * 10);
    }

    array_proto_free(parr, n);
    smrt_deref(arr);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_array_proto_roundtrip_empty)
{
    array_t *arr;
    ck_assert_ret_ok(array_create(&arr));

    AutonomousTrust__Core__Protobuf__Structures__Data **parr = NULL;
    size_t n = 0;
    ck_assert_ret_ok(array_sync_out(arr, &parr, &n));
    ck_assert_uint_eq(n, 0);
    ck_assert_ptr_null(parr);

    array_t arr2;
    ck_assert_ret_ok(array_init(&arr2));
    ck_assert_ret_ok(array_sync_in(parr, n, &arr2));
    ck_assert_uint_eq(array_size(&arr2), 0);

    array_proto_free(parr, n);
    smrt_deref(arr);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_array_proto_roundtrip_strings)
{
    array_t *arr;
    ck_assert_ret_ok(array_create(&arr));

    char a[] = "alpha";
    char b[] = "beta";
    ck_assert_ret_ok(array_append(arr, string_data(a, strlen(a))));
    ck_assert_ret_ok(array_append(arr, string_data(b, strlen(b))));

    AutonomousTrust__Core__Protobuf__Structures__Data **parr = NULL;
    size_t n = 0;
    ck_assert_ret_ok(array_sync_out(arr, &parr, &n));
    ck_assert_uint_eq(n, 2);

    array_t arr2;
    ck_assert_ret_ok(array_init(&arr2));
    ck_assert_ret_ok(array_sync_in(parr, n, &arr2));
    ck_assert_uint_eq(array_size(&arr2), 2);

    data_t *d0 = NULL;
    ck_assert_ret_ok(array_get(&arr2, 0, &d0));
    ck_assert(d0->type == STRING);
    ck_assert_uint_eq(d0->size, 5);
    ck_assert_mem_eq(d0->str, "alpha", 5);

    array_proto_free(parr, n);
    smrt_deref(arr);
}
END_TEST_DEFINITION()

RUN_TESTS(Array3, test_array_proto_roundtrip_ints,
          test_array_proto_roundtrip_empty, test_array_proto_roundtrip_strings)
