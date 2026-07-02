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

#include "utilities/message.h"

DEFINE_TEST(test_messaging_max_size_default)
{
    ck_assert_uint_eq(messaging_max_size(), DEFAULT_MAX_MSG_SIZE);
    ck_assert_uint_eq(MAX_MSG_SIZE, DEFAULT_MAX_MSG_SIZE);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_messaging_set_max_size)
{
    /* Set to a custom value */
    messaging_set_max_size(4096);
    ck_assert_uint_eq(messaging_max_size(), 4096);
    ck_assert_uint_eq(MAX_MSG_SIZE, 4096);

    /* 0 should not change the value */
    messaging_set_max_size(0);
    ck_assert_uint_eq(messaging_max_size(), 4096);

    /* Restore default */
    messaging_set_max_size(DEFAULT_MAX_MSG_SIZE);
    ck_assert_uint_eq(messaging_max_size(), DEFAULT_MAX_MSG_SIZE);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_messaging_set_max_size_large)
{
    /* Large value should work */
    messaging_set_max_size(65536);
    ck_assert_uint_eq(messaging_max_size(), 65536);

    /* Restore default */
    messaging_set_max_size(DEFAULT_MAX_MSG_SIZE);
}
END_TEST_DEFINITION()

RUN_TESTS(Message2, test_messaging_max_size_default, test_messaging_set_max_size,
          test_messaging_set_max_size_large)
