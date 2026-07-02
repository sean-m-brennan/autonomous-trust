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
#include <sys/time.h>
#include <sodium.h>

#include "processes/processes.h"

/* timeval_subtract is not declared in the header but has external linkage */
extern long timeval_subtract(struct timeval *a, struct timeval *b);

DEFINE_TEST(test_process_name_to_signal)
{
    ck_assert(sodium_init() >= 0);

    char sig[SIG_NAME_LEN + 1] = {0};
    process_name_to_signal("network", sig);
    ck_assert_str_eq(sig, "network_s");

    char sig2[SIG_NAME_LEN + 1] = {0};
    process_name_to_signal("identity", sig2);
    ck_assert_str_eq(sig2, "identity_s");

    char sig3[SIG_NAME_LEN + 1] = {0};
    process_name_to_signal("rep_proc", sig3);
    ck_assert_str_eq(sig3, "rep_proc_s");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_timeval_subtract_basic)
{
    ck_assert(sodium_init() >= 0);

    struct timeval a = {.tv_sec = 10, .tv_usec = 500};
    struct timeval b = {.tv_sec = 5, .tv_usec = 200};

    long result = timeval_subtract(&a, &b);
    /* (10-5)*1000 + (500-200) = 5300 */
    ck_assert(result == 5300);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_timeval_subtract_borrow)
{
    ck_assert(sodium_init() >= 0);

    struct timeval a = {.tv_sec = 10, .tv_usec = 100};
    struct timeval b = {.tv_sec = 5, .tv_usec = 500};

    long result = timeval_subtract(&a, &b);
    /* usec < 0: extra=1, usec=1000+(-400)=600, sec=10-5-1=4 */
    /* result = 4*1000 + 600 = 4600 */
    ck_assert(result == 4600);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_timeval_subtract_zero)
{
    ck_assert(sodium_init() >= 0);

    struct timeval a = {.tv_sec = 5, .tv_usec = 300};
    struct timeval b = {.tv_sec = 5, .tv_usec = 300};

    long result = timeval_subtract(&a, &b);
    ck_assert(result == 0);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_sig_quit_constant)
{
    ck_assert(sodium_init() >= 0);

    ck_assert_ptr_nonnull(sig_quit);
    ck_assert_str_eq(sig_quit, "quit");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_cadence_constant)
{
    ck_assert(sodium_init() >= 0);

    ck_assert(cadence == 500000L);
}
END_TEST_DEFINITION()

RUN_TESTS(Processes, test_process_name_to_signal, test_timeval_subtract_basic,
          test_timeval_subtract_borrow, test_timeval_subtract_zero,
          test_sig_quit_constant, test_cadence_constant)
