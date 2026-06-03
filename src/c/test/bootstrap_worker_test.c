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

#include <math.h>
#include <string.h>

#include "bootstrap/bootstrap_worker.h"

/* Capturing emit sink: records the last cap name + a running tally and can
 * simulate a full queue. Mirrors the Python tests reading from the
 * negotiation queue / _counts_by_cap. */
typedef struct {
    int  emit_calls;
    char last_cap[32];
    bool fail;          /* simulate queue-full: emit returns false */
} emit_ctx_t;

static bool _capture_emit(void *ctx, const char *cap_name,
                          long nonce, const char *echo_payload)
{
    (void)nonce; (void)echo_payload;
    emit_ctx_t *e = (emit_ctx_t *)ctx;
    if (e->fail)
        return false;
    e->emit_calls++;
    strncpy(e->last_cap, cap_name, sizeof(e->last_cap) - 1);
    e->last_cap[sizeof(e->last_cap) - 1] = '\0';
    return true;
}

DEFINE_TEST(test_config_defaults)
{
    bootstrap_worker_t w;
    bootstrap_worker_init_config(&w, AT_BOOTSTRAP_DEFAULT_DURATION_SEC,
                                 AT_BOOTSTRAP_DEFAULT_PAIRS_TARGET, 1, false);
    ck_assert(fabs(w.duration_sec - AT_BOOTSTRAP_DEFAULT_DURATION_SEC) < 1e-9);
    ck_assert_int_eq(w.pairs_target, AT_BOOTSTRAP_DEFAULT_PAIRS_TARGET);
    ck_assert_int_eq(w.pairs_issued, 0);
    ck_assert(w.window_open == false);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_no_peers_returns_false)
{
    bootstrap_worker_t w;
    bootstrap_worker_init_config(&w, 999, 20, 1, false);
    emit_ctx_t e = {0};
    ck_assert(bootstrap_worker_try_issue_pair(&w, 0, _capture_emit, &e) == false);
    ck_assert_int_eq(w.pairs_issued, 0);
    ck_assert_int_eq(e.emit_calls, 0);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_no_registered_caps_returns_false)
{
    bootstrap_worker_t w;
    bootstrap_worker_init_config(&w, 999, 20, 7, false);
    for (int i = 0; i < BOOTSTRAP_CAPABILITY_COUNT; i++)
        bootstrap_worker_set_registered(&w, BOOTSTRAP_CAPABILITY_NAMES[i], false);
    emit_ctx_t e = {0};
    for (int i = 0; i < 20; i++)
        bootstrap_worker_try_issue_pair(&w, 3, _capture_emit, &e);
    ck_assert_int_eq(w.pairs_issued, 0);
    ck_assert_int_eq(e.emit_calls, 0);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_issues_pair_and_counts)
{
    bootstrap_worker_t w;
    bootstrap_worker_init_config(&w, 999, 20, 1, false);
    emit_ctx_t e = {0};
    bool ok = bootstrap_worker_try_issue_pair(&w, 3, _capture_emit, &e);
    ck_assert(ok == true);
    ck_assert_int_eq(w.pairs_issued, 1);
    ck_assert_int_eq(e.emit_calls, 1);
    /* the emitted cap must be one of the three bootstrap caps */
    int idx = -1;
    for (int i = 0; i < BOOTSTRAP_CAPABILITY_COUNT; i++)
        if (strcmp(e.last_cap, BOOTSTRAP_CAPABILITY_NAMES[i]) == 0)
            idx = i;
    ck_assert((idx) >= (0));
    ck_assert_int_eq(bootstrap_worker_count_for(&w, e.last_cap), 1);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_queue_full_no_count)
{
    bootstrap_worker_t w;
    bootstrap_worker_init_config(&w, 999, 20, 1, false);
    emit_ctx_t e = {0};
    e.fail = true;     /* queue full */
    ck_assert(bootstrap_worker_try_issue_pair(&w, 3, _capture_emit, &e) == false);
    ck_assert_int_eq(w.pairs_issued, 0);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_seeded_deterministic)
{
    /* Same seed → identical issuance sequence (cap name per tick). */
    bootstrap_worker_t a, b;
    bootstrap_worker_init_config(&a, 999, 30, 12345, false);
    bootstrap_worker_init_config(&b, 999, 30, 12345, false);
    emit_ctx_t ea = {0}, eb = {0};
    for (int i = 0; i < 30; i++) {
        bootstrap_worker_tick(&a, 3, 0.0, _capture_emit, &ea);
        bootstrap_worker_tick(&b, 3, 0.0, _capture_emit, &eb);
        ck_assert_str_eq(ea.last_cap, eb.last_cap);
    }
    for (int i = 0; i < BOOTSTRAP_CAPABILITY_COUNT; i++)
        ck_assert_int_eq(a.counts_by_cap[i], b.counts_by_cap[i]);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_all_three_caps_fired_over_run)
{
    /* The §6.5 conformance contract: a seeded run with a generous pair budget
     * exercises all three at.* caps at least once. */
    bootstrap_worker_t w;
    bootstrap_worker_init_config(&w, 999, 30, 12345, false);
    emit_ctx_t e = {0};
    for (int i = 0; i < 30; i++)
        bootstrap_worker_tick(&w, 3, 0.0, _capture_emit, &e);
    ck_assert_int_eq(w.pairs_issued, 30);
    for (int i = 0; i < BOOTSTRAP_CAPABILITY_COUNT; i++)
        ck_assert(bootstrap_worker_count_for(&w, BOOTSTRAP_CAPABILITY_NAMES[i]) >= 1);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_window_respects_pairs_target)
{
    bootstrap_worker_t w;
    bootstrap_worker_init_config(&w, 999, 5, 99, false);
    emit_ctx_t e = {0};
    for (int i = 0; i < 50; i++)
        bootstrap_worker_tick(&w, 3, 0.0, _capture_emit, &e);
    ck_assert_int_eq(w.pairs_issued, 5);  /* capped at target */
}
END_TEST_DEFINITION()

DEFINE_TEST(test_window_closes_after_duration)
{
    bootstrap_worker_t w;
    bootstrap_worker_init_config(&w, 10.0, 100, 5, false);
    emit_ctx_t e = {0};
    /* first tick opens window at t=0, issues 1 */
    bootstrap_worker_tick(&w, 3, 0.0, _capture_emit, &e);
    ck_assert_int_eq(w.pairs_issued, 1);
    /* tick past the duration → no further issuance */
    bootstrap_worker_tick(&w, 3, 11.0, _capture_emit, &e);
    ck_assert_int_eq(w.pairs_issued, 1);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_disabled_no_issue)
{
    bootstrap_worker_t w;
    bootstrap_worker_init_config(&w, 999, 20, 1, true /* disabled */);
    emit_ctx_t e = {0};
    for (int i = 0; i < 10; i++)
        bootstrap_worker_tick(&w, 3, 0.0, _capture_emit, &e);
    ck_assert_int_eq(w.pairs_issued, 0);
}
END_TEST_DEFINITION()

RUN_TESTS(BootstrapWorker,
          test_config_defaults,
          test_no_peers_returns_false,
          test_no_registered_caps_returns_false,
          test_issues_pair_and_counts,
          test_queue_full_no_count,
          test_seeded_deterministic,
          test_all_three_caps_fired_over_run,
          test_window_respects_pairs_target,
          test_window_closes_after_duration,
          test_disabled_no_issue)
