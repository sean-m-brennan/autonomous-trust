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
#include <unistd.h>
#include <sys/stat.h>

#include "autonomous_trust/utilities/util.h"

extern int makedirs(char *path, mode_t mode);

DEFINE_TEST(test_strremove_multiple)
{
    /* Remove all occurrences of a substring */
    char str[] = "hello world hello world";
    char *result = strremove(str, "hello ");
    ck_assert_str_eq(result, "world world");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_strremove_not_found)
{
    char str[] = "abcdef";
    char *result = strremove(str, "xyz");
    ck_assert_str_eq(result, "abcdef");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_strremove_empty_sub)
{
    char str[] = "hello";
    char *result = strremove(str, "");
    ck_assert_str_eq(result, "hello");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_strremove_entire_string)
{
    /* Remove the entire string content */
    char str[] = "abcabc";
    char *result = strremove(str, "abc");
    ck_assert_str_eq(result, "");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_compare_float_edge_cases)
{
    /* Equal values */
    ck_assert_int_eq(compare_float_precision(1.0f, 1.0f, 0.001f), 0);

    /* Very close values within epsilon */
    ck_assert_int_eq(compare_float_precision(1.0f, 1.0001f, 0.001f), 0);

    /* Clearly different */
    ck_assert_int_eq(compare_float_precision(1.0f, 2.0f, 0.001f), -1);
    ck_assert_int_eq(compare_float_precision(2.0f, 1.0f, 0.001f), 1);

    /* Negative values */
    ck_assert_int_eq(compare_float_precision(-1.0f, -1.0f, 0.001f), 0);
    ck_assert_int_eq(compare_float_precision(-2.0f, -1.0f, 0.001f), -1);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_compare_double_edge_cases)
{
    ck_assert_int_eq(compare_double_precision(3.14, 3.14, 0.001), 0);
    ck_assert_int_eq(compare_double_precision(3.14, 3.15, 0.001), -1);
    ck_assert_int_eq(compare_double_precision(3.15, 3.14, 0.001), 1);

    /* Large epsilon makes everything equal */
    ck_assert_int_eq(compare_double_precision(1.0, 100.0, 200.0), 0);
}
END_TEST_DEFINITION()

RUN_TESTS(Util2, test_strremove_multiple, test_strremove_not_found,
          test_strremove_empty_sub, test_strremove_entire_string,
          test_compare_float_edge_cases, test_compare_double_edge_cases)
