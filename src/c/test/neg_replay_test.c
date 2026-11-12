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

/* The executor's half of live replication (RD_12.6_LIVE_REPLICATION_PLAN.md
 * section 3.2): a replayable capability runs step by step and commits to the
 * hash chain of its states. The chain is pinned against Python's
 * (test_replay_executor.py, negotiation-task-result.yaml). */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "negotiation/neg_replay.h"

/* h_2 of the chain over s0, s1, s2. */
static const char H2[] = "7a795ece0f922bf5090999cded4068f473e8bebe46265e829edf9b7024479d85";

static int g_limit;

static int _init(const char *kwargs_json, char *out, size_t len)
{
    (void)kwargs_json;
    snprintf(out, len, "s0");
    return 0;
}

static int _step(const char *state, int i, char *next, size_t len)
{
    (void)state;
    if (i > g_limit)
        return 0;
    snprintf(next, len, "s%d", i);
    return 1;
}

static int _times_ten(const char *final_state, char *out, size_t len)
{
    snprintf(out, len, "%d", atoi(final_state + 1) * 10);
    return 0;
}

static int _fail(const char *state, int i, char *next, size_t len)
{
    (void)state; (void)i; (void)next; (void)len;
    return -1;
}

DEFINE_TEST(test_a_trace_runs_and_its_chain_is_pinned)
{
    capability_replay_t r = { .init = _init, .step = _step, .result = NULL };
    neg_trace_t t = {0};
    char result[64] = {0};
    g_limit = 2;
    ck_assert_int_eq(neg_replay_run(&r, "{}", &t, result, sizeof(result)), 0);
    ck_assert_int_eq(t.n, 3);
    ck_assert_str_eq(result, "s2");
    char root[NEG_REPLAY_HASH_HEX_LEN + 1];
    ck_assert(neg_trace_digest(&t, 2, root));
    ck_assert_str_eq(root, H2);
    ck_assert(!neg_trace_digest(&t, 3, root));
    neg_trace_free(&t);
    ck_assert_int_eq(t.n, 0);

    r.result = _times_ten;
    ck_assert_int_eq(neg_replay_run(&r, "{}", &t, result, sizeof(result)), 0);
    ck_assert_str_eq(result, "20");
    neg_trace_free(&t);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_trace_past_the_bound_or_failing_is_refused)
{
    capability_replay_t r = { .init = _init, .step = _step, .result = NULL };
    neg_trace_t t = {0};
    char result[64] = {0};
    g_limit = NEG_REPLAY_MAX_STEPS;              /* one state too many */
    ck_assert(neg_replay_run(&r, "{}", &t, result, sizeof(result)) != 0);
    ck_assert_int_eq(t.n, 0);
    g_limit = NEG_REPLAY_MAX_STEPS - 1;          /* exactly the bound */
    ck_assert_int_eq(neg_replay_run(&r, "{}", &t, result, sizeof(result)), 0);
    ck_assert_int_eq(t.n, NEG_REPLAY_MAX_STEPS);
    neg_trace_free(&t);
    r.step = _fail;
    ck_assert(neg_replay_run(&r, "{}", &t, result, sizeof(result)) != 0);
    ck_assert_int_eq(t.n, 0);
}
END_TEST_DEFINITION()

RUN_TESTS(NegReplay,
          test_a_trace_runs_and_its_chain_is_pinned,
          test_a_trace_past_the_bound_or_failing_is_refused)
