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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "autonomous_trust/utilities/at_jansson.h"

#define DEBUG_TESTS 1
#include "test_setup.h"

DEFINE_TEST(test_object_or_log_succeeds)
{
    /* Sunny path: jansson is allocator-healthy, so we always get a
     * fresh json_t back. The NULL-logger leg is also exercised. */
    json_t *j = at_json_object_or_log(NULL, "test:create");
    ck_assert_ptr_nonnull(j);
    ck_assert(json_is_object(j));
    ck_assert_int_eq(json_object_size(j), 0);
    json_decref(j);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_string_copy_present)
{
    json_t *root = json_pack("{s:s, s:s}",
                             "name", "alice",
                             "addr", "127.0.0.1");
    ck_assert_ptr_nonnull(root);

    char name[16] = {0};
    ck_assert_int_eq(at_json_string_copy(root, "name", name, sizeof(name)), 0);
    ck_assert_str_eq(name, "alice");

    char addr[32] = {0};
    ck_assert_int_eq(AT_JSON_STRING(root, "addr", addr), 0);
    ck_assert_str_eq(addr, "127.0.0.1");

    json_decref(root);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_string_copy_truncates_safely)
{
    json_t *root = json_pack("{s:s}", "k", "abcdefghij");
    ck_assert_ptr_nonnull(root);
    char dst[5] = {0};  /* room for 4 chars + NUL */
    ck_assert_int_eq(AT_JSON_STRING(root, "k", dst), 0);
    ck_assert_str_eq(dst, "abcd");
    /* Explicit NUL must be present at the boundary. */
    ck_assert_int_eq((int)dst[4], 0);
    json_decref(root);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_string_copy_missing_key)
{
    json_t *root = json_pack("{s:s}", "k", "abc");
    ck_assert_ptr_nonnull(root);
    char dst[8];
    memset(dst, 'X', sizeof(dst));
    dst[sizeof(dst) - 1] = '\0';
    /* Original default must be preserved. */
    ck_assert_int_eq(AT_JSON_STRING(root, "missing", dst), -1);
    ck_assert_int_eq((int)dst[0], (int)'X');
    json_decref(root);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_string_copy_wrong_type)
{
    json_t *root = json_pack("{s:i}", "k", 42);
    ck_assert_ptr_nonnull(root);
    char dst[8] = "ORIG";
    ck_assert_int_eq(AT_JSON_STRING(root, "k", dst), -1);
    ck_assert_str_eq(dst, "ORIG");
    json_decref(root);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_string_copy_null_obj)
{
    char dst[4] = "ORG";
    ck_assert_int_eq(at_json_string_copy(NULL, "k", dst, sizeof(dst)), -1);
    ck_assert_str_eq(dst, "ORG");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_string_dup_and_peek)
{
    json_t *root = json_pack("{s:s}", "k", "hello-world");
    ck_assert_ptr_nonnull(root);

    char *heap = NULL;
    ck_assert_int_eq(at_json_string_dup(root, "k", &heap), 0);
    ck_assert_ptr_nonnull(heap);
    ck_assert_str_eq(heap, "hello-world");
    free(heap);

    const char *peek = at_json_string_peek(root, "k");
    ck_assert_ptr_nonnull(peek);
    ck_assert_str_eq(peek, "hello-world");

    /* Missing key */
    heap = (char *)0xdead;
    ck_assert_int_eq(at_json_string_dup(root, "missing", &heap), -1);
    ck_assert_ptr_null(heap);
    ck_assert_ptr_null(at_json_string_peek(root, "missing"));

    /* Wrong type */
    json_t *root2 = json_pack("{s:i}", "k", 1);
    ck_assert_ptr_nonnull(root2);
    ck_assert_ptr_null(at_json_string_peek(root2, "k"));

    json_decref(root);
    json_decref(root2);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_integer_and_boolean)
{
    json_t *root = json_pack("{s:i, s:b, s:b, s:s}",
                             "n", 42,
                             "t", 1,
                             "f", 0,
                             "s", "not-int");
    ck_assert_ptr_nonnull(root);

    int64_t i = 0;
    ck_assert_int_eq(at_json_integer(root, "n", &i), 0);
    ck_assert_int_eq(i, 42);

    bool b = false;
    ck_assert_int_eq(at_json_boolean(root, "t", &b), 0);
    ck_assert(b);
    ck_assert_int_eq(at_json_boolean(root, "f", &b), 0);
    ck_assert(!b);

    /* Wrong type, missing — both preserve the default. */
    i = 99;
    ck_assert_int_eq(at_json_integer(root, "s", &i), -1);
    ck_assert_int_eq(i, 99);
    ck_assert_int_eq(at_json_integer(root, "missing", &i), -1);
    ck_assert_int_eq(i, 99);

    b = true;
    ck_assert_int_eq(at_json_boolean(root, "n", &b), -1);
    ck_assert(b);

    json_decref(root);
}
END_TEST_DEFINITION()

RUN_TESTS(AtJansson,
          test_object_or_log_succeeds,
          test_string_copy_present,
          test_string_copy_truncates_safely,
          test_string_copy_missing_key,
          test_string_copy_wrong_type,
          test_string_copy_null_obj,
          test_string_dup_and_peek,
          test_integer_and_boolean)
