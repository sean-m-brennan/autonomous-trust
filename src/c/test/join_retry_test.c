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

/**
 * @file join_retry_test.c
 * @brief A joiner keeps asking until it is admitted.
 *
 * A joiner used to broadcast request_access once and found a group of its own
 * five seconds later. On a loaded host a large share of UDP sends is dropped
 * at the sender while the kernel reports success, and a cohort's admitter can
 * come up minutes after its members. Mirrors the Python tests in
 * test_choose_group.py.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <stdlib.h>

#include "identity/id_proc_priv.h"

#define S 1000000L

DEFINE_TEST(test_the_retry_schedule_is_two_seconds_then_doubling_to_a_cap)
{
    long last = 0, interval = 2 * S;
    long asked[8];
    int n = 0;
    for (long t = 0; t <= 70 * S && n < 8; t += S / 10)
        if (identity_rejoin_due(t, &last, &interval, 5 * S, 30 * S))
            asked[n++] = t / S;
    ck_assert_int_eq(n, 7);
    long want[] = {2, 4, 6, 10, 18, 34, 64};
    for (int i = 0; i < 7; i++)
        ck_assert_int_eq((int)asked[i], (int)want[i]);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_patience_extends_the_wait_and_never_shortens_it)
{
    unsetenv("AT_JOIN_PATIENCE_SEC");
    ck_assert_int_eq((int)(identity_join_wait_us(5 * S) / S), 5);
    setenv("AT_JOIN_PATIENCE_SEC", "300", 1);
    ck_assert_int_eq((int)(identity_join_wait_us(5 * S) / S), 300);
    setenv("AT_JOIN_PATIENCE_SEC", "1", 1);
    ck_assert_int_eq((int)(identity_join_wait_us(5 * S) / S), 5);
    unsetenv("AT_JOIN_PATIENCE_SEC");
}
END_TEST_DEFINITION()

RUN_TESTS(JoinRetry,
          test_the_retry_schedule_is_two_seconds_then_doubling_to_a_cap,
          test_patience_extends_the_wait_and_never_shortens_it)
