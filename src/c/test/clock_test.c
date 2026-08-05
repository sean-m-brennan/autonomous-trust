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

/* The startup clock gate: AT reads stock NTP's state and refuses an
 * undisciplined clock. The Python mirror is
 * tests/a_unit/test_network_clock.py; both must agree on "synced". */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <stdlib.h>
#include <string.h>
#include <sys/timex.h>

#include "autonomous_trust/utilities/clock.h"

DEFINE_TEST(test_clock_state_queries_the_real_kernel)
{
    /* Unmocked on purpose: the syscall must actually answer here, which is
     * the whole reason it was chosen over a chrony socket. */
    at_clock_state_t state = at_clock_state();
    ck_assert(state.available);
    /* An undisciplined kernel reports 16 s; a disciplined one reports far
     * less. Either is legitimate — what must hold is the invariant between
     * the two fields. */
    if (state.synced)
        ck_assert((state.status & STA_UNSYNC) == 0);
    else
        ck_assert(state.max_error_us > 0);
}

DEFINE_TEST(test_required_parses_env)
{
    const char *truthy[] = {"1", "true", "TRUE", "yes", "on"};
    const char *falsy[] = {"0", "", "no", "off", "maybe"};

    for (size_t i = 0; i < sizeof(truthy) / sizeof(truthy[0]); i++)
    {
        setenv(AT_CLOCK_REQUIRE_ENV, truthy[i], 1);
        ck_assert(at_clock_required());   /* truthy[i] */
    }
    for (size_t i = 0; i < sizeof(falsy) / sizeof(falsy[0]); i++)
    {
        setenv(AT_CLOCK_REQUIRE_ENV, falsy[i], 1);
        ck_assert(!at_clock_required());  /* falsy[i] */
    }
    unsetenv(AT_CLOCK_REQUIRE_ENV);
    ck_assert(!at_clock_required()); /* absent means advisory */
}

DEFINE_TEST(test_describe_names_the_verdict)
{
    at_clock_state_t state;
    memset(&state, 0, sizeof(state));
    char buf[192];

    state.available = true;
    state.synced = false;
    state.status = STA_UNSYNC;
    state.max_error_us = 16000000L;
    at_clock_describe(&state, buf, sizeof(buf));
    ck_assert(strstr(buf, "UNSYNCED") != NULL);
    ck_assert(strstr(buf, "16.000s") != NULL);
    ck_assert(strstr(buf, "ntp_adjtime") != NULL);

    state.synced = true;
    state.status = 0;
    state.max_error_us = 12000L;
    at_clock_describe(&state, buf, sizeof(buf));
    ck_assert(strstr(buf, "synced") != NULL);
    ck_assert(strstr(buf, "UNSYNCED") == NULL);

    state.hardware_fault = true;
    state.status = STA_CLOCKERR;
    at_clock_describe(&state, buf, sizeof(buf));
    ck_assert(strstr(buf, "CLOCK HARDWARE FAULT") != NULL);

    /* An unavailable query must not read as a clean clock. */
    state.available = false;
    at_clock_describe(&state, buf, sizeof(buf));
    ck_assert(strstr(buf, "UNAVAILABLE") != NULL);
}

DEFINE_TEST(test_advisory_mode_never_refuses)
{
    /* This host is genuinely STA_UNSYNC in the sandbox, and may be synced on
     * a developer machine. Advisory must return 0 either way — a gate that
     * refused by default would break every local run and both test suites. */
    unsetenv(AT_CLOCK_REQUIRE_ENV);
    ck_assert_int_eq(at_clock_require_synced(NULL, 0), 0);
    setenv(AT_CLOCK_REQUIRE_ENV, "0", 1);
    ck_assert_int_eq(at_clock_require_synced(NULL, 0), 0);
    unsetenv(AT_CLOCK_REQUIRE_ENV);
}

DEFINE_TEST(test_enforcing_refuses_an_unacceptable_clock)
{
    at_clock_state_t actual = at_clock_state();
    setenv(AT_CLOCK_REQUIRE_ENV, "1", 1);

    /* A 1-nanosecond bound is unreachable for any real clock, so this asserts
     * the refusal path regardless of whether the build host runs a daemon. */
    ck_assert_int_eq(at_clock_require_synced(NULL, 1L), -1);

    if (!actual.synced)
        /* And with the ordinary bound, an unsynced host must also refuse. */
        ck_assert_int_eq(at_clock_require_synced(NULL, 0), -1);

    unsetenv(AT_CLOCK_REQUIRE_ENV);
}

DEFINE_TEST(test_enforcing_accepts_a_good_clock)
{
    at_clock_state_t state = at_clock_state();
    setenv(AT_CLOCK_REQUIRE_ENV, "1", 1);
    if (state.synced)
        /* Generous bound: a synced clock must pass the gate it is meant to. */
        ck_assert_int_eq(at_clock_require_synced(NULL, 60000000L), 0);
    else
        /* Unsynced hosts cannot exercise the accept path; the refusal above
         * already covers this host, and the bound is checked there. */
        ck_assert(state.max_error_us > 0);
    unsetenv(AT_CLOCK_REQUIRE_ENV);
}

RUN_TESTS(Clock, test_clock_state_queries_the_real_kernel,
          test_required_parses_env, test_describe_names_the_verdict,
          test_advisory_mode_never_refuses,
          test_enforcing_refuses_an_unacceptable_clock,
          test_enforcing_accepts_a_good_clock)
