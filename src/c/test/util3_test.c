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
#include <unistd.h>
#include <sys/stat.h>

#include "utilities/util.h"

DEFINE_TEST(test_makedirs_basic)
{
    char path[] = "/tmp/at_test_makedirs/a/b/c";
    ck_assert_ret_ok(makedirs(path, 0755));

    struct stat st;
    ck_assert(stat("/tmp/at_test_makedirs/a/b/c", &st) == 0);
    ck_assert(S_ISDIR(st.st_mode));

    /* Calling again should succeed (EEXIST handled) */
    ck_assert_ret_ok(makedirs(path, 0755));

    /* Cleanup */
    rmdir("/tmp/at_test_makedirs/a/b/c");
    rmdir("/tmp/at_test_makedirs/a/b");
    rmdir("/tmp/at_test_makedirs/a");
    rmdir("/tmp/at_test_makedirs");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_makedirs_trailing_slash)
{
    char path[] = "/tmp/at_test_makedirs2/x/y/";
    ck_assert_ret_ok(makedirs(path, 0755));

    struct stat st;
    ck_assert(stat("/tmp/at_test_makedirs2/x/y", &st) == 0);
    ck_assert(S_ISDIR(st.st_mode));

    rmdir("/tmp/at_test_makedirs2/x/y");
    rmdir("/tmp/at_test_makedirs2/x");
    rmdir("/tmp/at_test_makedirs2");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_at_strlcpy_short_fits)
{
    char dst[16];
    memset(dst, 'X', sizeof(dst));
    size_t r = at_strlcpy(dst, "hello", sizeof(dst));
    ck_assert_int_eq(r, 5);
    ck_assert_str_eq(dst, "hello");
    /* Bytes beyond the copy+NUL must remain whatever the caller left
     * (we only NUL-terminate at the copy boundary). */
    ck_assert_int_eq((int)dst[6], (int)'X');
}
END_TEST_DEFINITION()

DEFINE_TEST(test_at_strlcpy_truncates_with_nul)
{
    char dst[5];
    memset(dst, 'X', sizeof(dst));
    size_t r = at_strlcpy(dst, "abcdefghij", sizeof(dst));
    /* Returns full source length so caller can detect truncation. */
    ck_assert_int_eq(r, 10);
    ck_assert(r >= sizeof(dst));
    /* First 4 bytes are the prefix, 5th byte is the NUL terminator. */
    ck_assert_str_eq(dst, "abcd");
    ck_assert_int_eq((int)dst[4], 0);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_at_strlcpy_exact_fit)
{
    /* src strlen == dst_len - 1: no truncation, NUL fits at boundary. */
    char dst[6];
    memset(dst, 'X', sizeof(dst));
    size_t r = at_strlcpy(dst, "abcde", sizeof(dst));
    ck_assert_int_eq(r, 5);
    ck_assert_str_eq(dst, "abcde");
    ck_assert_int_eq((int)dst[5], 0);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_at_strlcpy_empty_src)
{
    char dst[8];
    memset(dst, 'X', sizeof(dst));
    size_t r = at_strlcpy(dst, "", sizeof(dst));
    ck_assert_int_eq(r, 0);
    ck_assert_int_eq((int)dst[0], 0);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_at_strlcpy_null_src_clears_dst)
{
    char dst[8];
    memset(dst, 'X', sizeof(dst));
    size_t r = at_strlcpy(dst, NULL, sizeof(dst));
    ck_assert_int_eq(r, 0);
    ck_assert_int_eq((int)dst[0], 0);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_at_strlcpy_zero_dstlen_no_write)
{
    /* dst_len == 0 must NOT touch dst; the BSD contract returns the
     * source length for sizing queries. */
    char dst[4] = {'A', 'B', 'C', 'D'};
    size_t r = at_strlcpy(dst, "hello", 0);
    ck_assert_int_eq(r, 5);
    ck_assert_int_eq((int)dst[0], (int)'A');
    ck_assert_int_eq((int)dst[3], (int)'D');
}
END_TEST_DEFINITION()

DEFINE_TEST(test_at_strlcpy_dstlen_one_writes_only_nul)
{
    char dst[4] = {'A', 'B', 'C', 'D'};
    size_t r = at_strlcpy(dst, "hello", 1);
    ck_assert_int_eq(r, 5);
    ck_assert_int_eq((int)dst[0], 0);
    /* Subsequent bytes untouched. */
    ck_assert_int_eq((int)dst[1], (int)'B');
}
END_TEST_DEFINITION()

RUN_TESTS(Util2,
          test_makedirs_basic, test_makedirs_trailing_slash,
          test_at_strlcpy_short_fits,
          test_at_strlcpy_truncates_with_nul,
          test_at_strlcpy_exact_fit,
          test_at_strlcpy_empty_src,
          test_at_strlcpy_null_src_clears_dst,
          test_at_strlcpy_zero_dstlen_no_write,
          test_at_strlcpy_dstlen_one_writes_only_nul)
