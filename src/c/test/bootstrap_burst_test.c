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

/** @file The join burst (RD_14.4_HOSTILE_JOIN_PLAN.md Phase 5, D5 (b)): under
 *  the join policy, k probes per peer reputation reads under the told
 *  ceiling, at the burst's own rate and budget. Split from
 *  bootstrap_worker_test.c, whose suite is at RUN_TESTS' 28. Mirrors
 *  TestJoinBurst in tests/a_unit/test_bootstrap_worker.py.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

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

/* Probe sink: records which peer index and capability each addressed probe
 * went to. The per-peer tally is what the allocation assertions read. */
typedef struct {
    int  calls;
    char last_cap[32];
    size_t last_peer;
    int  per_peer[8];
    bool fail;
} probe_ctx_t;

static bool _capture_probe(void *ctx, const char *cap_name, size_t peer_index,
                           long nonce, const char *echo_payload)
{
    (void)nonce; (void)echo_payload;
    probe_ctx_t *p = (probe_ctx_t *)ctx;
    if (p->fail)
        return false;
    p->calls++;
    p->last_peer = peer_index;
    if (peer_index < 8)
        p->per_peer[peer_index]++;
    strncpy(p->last_cap, cap_name, sizeof(p->last_cap) - 1);
    p->last_cap[sizeof(p->last_cap) - 1] = '\0';
    return true;
}

/* Both sinks in one run need one ctx pointer, and the two callbacks cast it to
 * different types -- so route them through a struct that holds both rather than
 * aliasing an emit_ctx_t as a (larger) probe_ctx_t. */
typedef struct {
    emit_ctx_t  e;
    probe_ctx_t p;
} both_ctx_t;

static bool _both_emit(void *ctx, const char *cap_name, long nonce,
                       const char *echo_payload)
{
    return _capture_emit(&((both_ctx_t *)ctx)->e, cap_name, nonce, echo_payload);
}

static bool _both_probe(void *ctx, const char *cap_name, size_t peer_index,
                        long nonce, const char *echo_payload)
{
    return _capture_probe(&((both_ctx_t *)ctx)->p, cap_name, peer_index, nonce,
                          echo_payload);
}

/* --- The join burst (RD_14.4 Phase 5, D5 (b)) ----------------------------
 * Mirrors TestJoinBurst in test_bootstrap_worker.py. The window closes at once
 * (no pairs) and continuous probing is off, so every probe is a burst probe. */

static const char *const UUIDS[3] = {
    "00000000-0000-4000-8000-00000000000a",
    "00000000-0000-4000-8000-00000000000b",
    "00000000-0000-4000-8000-00000000000c",
};

static void _burst_worker(bootstrap_worker_t *w, bool on, int k,
                          double interval, int factor)
{
    bootstrap_worker_init_config(w, 999, 0, 1, false);
    w->continuous_enabled = false;
    bootstrap_worker_set_burst(w, on, k, interval, factor);
}

/* @p ticks ticks, @p step seconds apart from @p *t, peers a, b, c held. */
static void _burst_run(bootstrap_worker_t *w, int ticks, double *t,
                       double step, both_ctx_t *both)
{
    for (int i = 0; i < ticks; i++) {
        w->peer_uuids = UUIDS;
        bootstrap_worker_tick_all(w, 3, *t, _both_emit, _both_probe, both);
        w->peer_uuids = NULL;
        *t += step;
    }
}

DEFINE_TEST(test_burst_the_policy_off_runs_no_burst)
{
    bootstrap_worker_t w;
    _burst_worker(&w, false, 3, 0.0, 4);
    for (int i = 0; i < 3; i++)
        bootstrap_worker_note_probe_count(&w, UUIDS[i], true, 0);
    both_ctx_t both = {0};
    double t = 0.0;
    _burst_run(&w, 6, &t, 10.0, &both);
    ck_assert_int_eq(both.p.calls, 0);
    ck_assert_int_eq(w.burst_state, BOOTSTRAP_BURST_IDLE);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_burst_k_probes_each_spread_over_the_targets)
{
    bootstrap_worker_t w;
    _burst_worker(&w, true, 2, 0.0, 4);
    bootstrap_worker_note_probe_count(&w, UUIDS[0], true, 0);
    bootstrap_worker_note_probe_count(&w, UUIDS[1], true, 0);
    both_ctx_t both = {0};
    double t = 0.0;
    _burst_run(&w, 4, &t, 10.0, &both);
    ck_assert_int_eq(both.p.per_peer[0], 2);
    ck_assert_int_eq(both.p.per_peer[1], 2);
    ck_assert_int_eq(both.p.per_peer[2], 0);      /* never listed */
    ck_assert_int_eq(w.burst_budget, 4 * 2 * 2);
    ck_assert_int_eq(w.probes_by_peer[0], 2);     /* UCB tallies */
    ck_assert_int_eq(bootstrap_worker_burst_peers_probed(&w), 2);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_burst_ends_when_every_target_has_k)
{
    bootstrap_worker_t w;
    _burst_worker(&w, true, 2, 0.0, 4);
    bootstrap_worker_note_probe_count(&w, UUIDS[0], true, 0);
    bootstrap_worker_note_probe_count(&w, UUIDS[1], true, 0);
    both_ctx_t both = {0};
    double t = 0.0;
    _burst_run(&w, 2, &t, 10.0, &both);
    bootstrap_worker_note_probe_count(&w, UUIDS[0], true, 2);   /* k reached */
    bootstrap_worker_note_probe_count(&w, UUIDS[1], false, 0);  /* graduated */
    _burst_run(&w, 4, &t, 10.0, &both);
    ck_assert_int_eq(both.p.calls, 2);
    ck_assert_int_eq(w.burst_spent, 2);
    ck_assert_int_eq(w.burst_state, BOOTSTRAP_BURST_DONE);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_burst_budget_bounds_a_burst_whose_verdicts_never_come)
{
    bootstrap_worker_t w;
    _burst_worker(&w, true, 1, 0.0, 2);
    for (int i = 0; i < 3; i++)
        bootstrap_worker_note_probe_count(&w, UUIDS[i], true, 0);
    both_ctx_t both = {0};
    double t = 0.0;
    _burst_run(&w, 20, &t, 10.0, &both);
    ck_assert_int_eq(both.p.calls, 2 * 1 * 3);
    ck_assert_int_eq(w.burst_state, BOOTSTRAP_BURST_DONE);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_burst_interval_spaces_burst_probes)
{
    bootstrap_worker_t w;
    _burst_worker(&w, true, 3, 5.0, 4);
    for (int i = 0; i < 3; i++)
        bootstrap_worker_note_probe_count(&w, UUIDS[i], true, 0);
    both_ctx_t both = {0};
    double t = 0.0;
    _burst_run(&w, 10, &t, 1.0, &both);
    ck_assert_int_eq(both.p.calls, 2);            /* t = 0 and t = 5 */
}
END_TEST_DEFINITION()

DEFINE_TEST(test_burst_a_peer_listed_later_joins_and_grows_the_budget)
{
    bootstrap_worker_t w;
    _burst_worker(&w, true, 1, 0.0, 1);
    bootstrap_worker_note_probe_count(&w, UUIDS[0], true, 0);
    both_ctx_t both = {0};
    double t = 0.0;
    _burst_run(&w, 1, &t, 10.0, &both);
    ck_assert_int_eq(w.burst_budget, 1);
    bootstrap_worker_note_probe_count(&w, UUIDS[0], true, 1);
    bootstrap_worker_note_probe_count(&w, UUIDS[1], true, 0);
    ck_assert_int_eq(w.burst_budget, 2);
    _burst_run(&w, 3, &t, 10.0, &both);
    ck_assert_int_eq(both.p.per_peer[1], 1);
    ck_assert_int_eq(both.p.calls, 2);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_burst_is_not_reentered)
{
    bootstrap_worker_t w;
    _burst_worker(&w, true, 1, 0.0, 4);
    bootstrap_worker_note_probe_count(&w, UUIDS[0], true, 0);
    both_ctx_t both = {0};
    double t = 0.0;
    _burst_run(&w, 2, &t, 10.0, &both);
    bootstrap_worker_note_probe_count(&w, UUIDS[0], true, 1);
    _burst_run(&w, 2, &t, 10.0, &both);
    ck_assert_int_eq(w.burst_state, BOOTSTRAP_BURST_DONE);
    int before = both.p.calls;
    bootstrap_worker_note_probe_count(&w, UUIDS[1], true, 0);
    _burst_run(&w, 3, &t, 10.0, &both);
    ck_assert_int_eq(both.p.calls, before);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_burst_a_target_not_held_or_absent_waits)
{
    bootstrap_worker_t w;
    _burst_worker(&w, true, 3, 0.0, 4);
    bootstrap_worker_note_probe_count(&w, "00000000-0000-4000-8000-0000000000ff",
                                      true, 0);
    bootstrap_worker_note_probe_count(&w, UUIDS[0], true, 0);
    bool absent[3] = {true, false, false};
    w.skip_peer = absent;
    both_ctx_t both = {0};
    double t = 0.0;
    _burst_run(&w, 3, &t, 10.0, &both);
    w.skip_peer = NULL;
    ck_assert_int_eq(both.p.calls, 0);
    ck_assert_int_eq(w.burst_state, BOOTSTRAP_BURST_ACTIVE);
    ck_assert_int_eq(w.burst_spent, 0);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_burst_a_refused_probe_is_not_counted)
{
    bootstrap_worker_t w;
    _burst_worker(&w, true, 1, 0.0, 4);
    bootstrap_worker_note_probe_count(&w, UUIDS[0], true, 0);
    both_ctx_t both = {0};
    both.p.fail = true;
    double t = 0.0;
    _burst_run(&w, 3, &t, 10.0, &both);
    ck_assert_int_eq(w.burst_spent, 0);
    ck_assert_int_eq(w.burst_peers[0].issued, 0);
}
END_TEST_DEFINITION()

RUN_TESTS(BootstrapBurst,
          test_burst_the_policy_off_runs_no_burst,
          test_burst_k_probes_each_spread_over_the_targets,
          test_burst_ends_when_every_target_has_k,
          test_burst_budget_bounds_a_burst_whose_verdicts_never_come,
          test_burst_interval_spaces_burst_probes,
          test_burst_a_peer_listed_later_joins_and_grows_the_budget,
          test_burst_is_not_reentered,
          test_burst_a_target_not_held_or_absent_waits,
          test_burst_a_refused_probe_is_not_counted)
