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

#include <math.h>
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

/* --- Cohort skew (doc/architecture/cohort-clock-skew.md) -------------------- *
 * Measurement only: nothing here steers a clock. The Python mirror is
 * TestClockSampleMath / TestCohortAggregation in test_network_clock.py, and the
 * two must agree — the estimator especially, since a corpus case compares them. */

DEFINE_TEST(test_sample_offset_and_delay_from_a_round_trip)
{
    /* Peer 4 s ahead; 100 ms each way; peer took 500 ms to answer. */
    double t1 = 1000.0;
    double t2 = t1 + 4.0 + 0.1;
    double t3 = t2 + 0.5;
    double t4 = t1 + 0.1 + 0.5 + 0.1;
    at_clock_sample_t s = at_clock_sample_from_round_trip(t1, t2, t3, t4);
    ck_assert(s.valid);
    ck_assert(s.usable);
    ck_assert_double_eq_tol(s.offset_s, 4.0, 1e-9);
    /* The peer's own 500 ms is subtracted: delay is network time only. */
    ck_assert_double_eq_tol(s.delay_s, 0.2, 1e-9);
}

DEFINE_TEST(test_a_slow_responder_is_not_reported_as_skewed)
{
    /* Why t2 and t3 must be separate readings: same clocks both sides, but the
     * peer sits on the request for a full minute. */
    double t1 = 1000.0, t2 = 1000.05, t3 = 1060.05, t4 = 1060.1;
    at_clock_sample_t s = at_clock_sample_from_round_trip(t1, t2, t3, t4);
    ck_assert_double_eq_tol(s.offset_s, 0.0, 1e-9);
    ck_assert_double_eq_tol(s.delay_s, 0.1, 1e-9);
}

DEFINE_TEST(test_impossible_timings_are_unusable)
{
    /* Round trip of 1 s, but the peer claims 2 s of processing inside it. */
    at_clock_sample_t s = at_clock_sample_from_round_trip(0.0, 0.0, 2.0, 1.0);
    ck_assert(s.valid);
    ck_assert(!s.usable);
    char buf[160];
    at_clock_sample_describe(&s, "liar", buf, sizeof(buf));
    ck_assert(strstr(buf, "UNUSABLE") != NULL);
    /* ...and it must not reach the estimate. */
    at_cohort_view_t view = at_clock_cohort_offset(&s, 1);
    ck_assert(!view.valid);
    ck_assert_uint_eq((unsigned)view.count, 0u);
}

DEFINE_TEST(test_non_finite_input_yields_no_sample)
{
    at_clock_sample_t inf = at_clock_sample_from_round_trip(INFINITY, 1.0, 2.0, 3.0);
    at_clock_sample_t nan = at_clock_sample_from_round_trip(1.0, NAN, 2.0, 3.0);
    ck_assert(!inf.valid);
    ck_assert(!nan.valid);
    /* An invalid sample never claims to exceed a bound. */
    ck_assert(!at_clock_sample_exceeds(&inf, 1L));
    ck_assert(!at_clock_sample_exceeds(NULL, 1L));
}

DEFINE_TEST(test_exceeds_is_symmetric_about_zero)
{
    at_clock_sample_t ahead = at_clock_sample_from_round_trip(0.0, 5.0, 5.0, 0.0);
    at_clock_sample_t behind = at_clock_sample_from_round_trip(0.0, -5.0, -5.0, 0.0);
    ck_assert_double_eq_tol(ahead.offset_s, 5.0, 1e-9);
    ck_assert_double_eq_tol(behind.offset_s, -5.0, 1e-9);
    ck_assert(at_clock_sample_exceeds(&ahead, 2000L));
    ck_assert(at_clock_sample_exceeds(&behind, 2000L));
    ck_assert(!at_clock_sample_exceeds(&ahead, 10000L));
}

DEFINE_TEST(test_median_resists_a_lying_minority)
{
    /* Why the estimator is a median: one peer reporting a wild offset must not
     * move the cohort estimate, and a mean lets it. */
    at_clock_sample_t good[4];
    double offsets[4] = {0.01, 0.02, 0.03, 9999.0};
    for (int i = 0; i < 4; i++)
    {
        good[i] = at_clock_sample_from_round_trip(0.0, offsets[i], offsets[i], 0.0);
        ck_assert(good[i].usable);
    }
    at_cohort_view_t clean = at_clock_cohort_offset(good, 3);
    ck_assert(clean.valid);
    ck_assert_double_eq_tol(clean.offset_s, 0.02, 1e-9);

    at_cohort_view_t poisoned = at_clock_cohort_offset(good, 4);
    /* Even count averages the two middles, matching Python's statistics.median
     * exactly -- (0.02 + 0.03) / 2. */
    ck_assert_double_eq_tol(poisoned.offset_s, 0.025, 1e-9);
    ck_assert_uint_eq((unsigned)poisoned.count, 4u);
    /* The estimator resists; dispersion still reports something is very wrong. */
    ck_assert(poisoned.dispersion_s > 9000.0);
}

DEFINE_TEST(test_cohort_view_of_nothing_is_invalid)
{
    at_cohort_view_t none = at_clock_cohort_offset(NULL, 0);
    ck_assert(!none.valid);
    ck_assert_uint_eq((unsigned)none.count, 0u);
}

DEFINE_TEST(test_skew_bound_resolves_env_then_default)
{
    bool from_env = true;
    unsetenv(AT_CLOCK_COHORT_SKEW_ENV);
    ck_assert_int_eq((int)at_clock_max_cohort_skew_ms(NULL, &from_env),
                     AT_CLOCK_COHORT_SKEW_MS);
    ck_assert(!from_env);

    setenv(AT_CLOCK_COHORT_SKEW_ENV, "250", 1);
    ck_assert_int_eq((int)at_clock_max_cohort_skew_ms(NULL, &from_env), 250);
    ck_assert(from_env);

    /* Out of range and unparseable are both REFUSED, keeping the default --
     * never clamped, which would hide the mistake. Same rule as Python's
     * resolve_max_cohort_skew. */
    const char *bad[] = {"0", "-1", "abc", "999999999", "12x"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
    {
        setenv(AT_CLOCK_COHORT_SKEW_ENV, bad[i], 1);
        from_env = true;
        ck_assert_int_eq((int)at_clock_max_cohort_skew_ms(NULL, &from_env),
                         AT_CLOCK_COHORT_SKEW_MS);
        ck_assert(!from_env);
    }
    unsetenv(AT_CLOCK_COHORT_SKEW_ENV);
}

RUN_TESTS(Clock, test_clock_state_queries_the_real_kernel,
          test_required_parses_env, test_describe_names_the_verdict,
          test_advisory_mode_never_refuses,
          test_enforcing_refuses_an_unacceptable_clock,
          test_enforcing_accepts_a_good_clock,
          test_sample_offset_and_delay_from_a_round_trip,
          test_a_slow_responder_is_not_reported_as_skewed,
          test_impossible_timings_are_unusable,
          test_non_finite_input_yields_no_sample,
          test_exceeds_is_symmetric_about_zero,
          test_median_resists_a_lying_minority,
          test_cohort_view_of_nothing_is_invalid,
          test_skew_bound_resolves_env_then_default)
