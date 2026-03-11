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

#include "utilities/util.h"

DEFINE_TEST(test_min_max)
{
    ck_assert(min(3, 5) == 3);
    ck_assert(min(5, 3) == 3);
    ck_assert(min(-1, 1) == -1);
    ck_assert(min(0, 0) == 0);

    ck_assert(max(3, 5) == 5);
    ck_assert(max(5, 3) == 5);
    ck_assert(max(-1, 1) == 1);
    ck_assert(max(0, 0) == 0);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_strremove)
{
    char str1[] = "hello world hello";
    strremove(str1, "hello");
    ck_assert_str_eq(str1, " world ");

    char str2[] = "abcabc";
    strremove(str2, "abc");
    ck_assert_str_eq(str2, "");

    char str3[] = "no match here";
    strremove(str3, "xyz");
    ck_assert_str_eq(str3, "no match here");

    /* Empty sub - no change */
    char str4[] = "test";
    strremove(str4, "");
    ck_assert_str_eq(str4, "test");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_compare_float)
{
    ck_assert_int_eq(compare_float(1.0f, 1.0f), 0);
    ck_assert_int_eq(compare_float(1.0f, 1.000001f), 0);
    ck_assert(compare_float(1.0f, 2.0f) < 0);
    ck_assert(compare_float(2.0f, 1.0f) > 0);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_compare_double)
{
    ck_assert_int_eq(compare_double(1.0, 1.0), 0);
    ck_assert_int_eq(compare_double(1.0, 1.000001), 0);
    ck_assert(compare_double(1.0, 2.0) < 0);
    ck_assert(compare_double(2.0, 1.0) > 0);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_compare_float_precision_custom)
{
    /* With larger epsilon, values further apart should be equal */
    ck_assert_int_eq(compare_float_precision(1.0f, 1.05f, 0.1f), 0);
    /* But not if epsilon is small */
    ck_assert(compare_float_precision(1.0f, 1.05f, 0.01f) != 0);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_compare_double_precision_custom)
{
    ck_assert_int_eq(compare_double_precision(1.0, 1.05, 0.1), 0);
    ck_assert(compare_double_precision(1.0, 1.05, 0.01) != 0);
}
END_TEST_DEFINITION()

RUN_TESTS(Util, test_min_max, test_strremove,
          test_compare_float, test_compare_double,
          test_compare_float_precision_custom, test_compare_double_precision_custom)
