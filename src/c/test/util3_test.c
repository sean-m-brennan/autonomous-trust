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

RUN_TESTS(Util2, test_makedirs_basic, test_makedirs_trailing_slash)
