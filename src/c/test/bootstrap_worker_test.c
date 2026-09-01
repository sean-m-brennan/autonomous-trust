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

DEFINE_TEST(test_probes_continue_after_the_window)
{
    /* The window seeds and stops; probing past it is what makes the honeypot
     * an anchor rather than a one-off initiation rite (R+D.md §12.7). */
    bootstrap_worker_t w;
    bootstrap_worker_init_config(&w, 999, 1 /* one pair, then done */, 1, false);
    w.probe_interval_sec = 0.0;
    both_ctx_t both = {0};
    for (int i = 0; i < 6; i++)
        bootstrap_worker_tick_all(&w, 3, 0.0, _both_emit, _both_probe, &both);
    ck_assert_int_eq(w.pairs_issued, 1);
    ck_assert_int_eq(both.e.emit_calls, 1);
    ck_assert(w.probes_issued >= 4);
    ck_assert_int_eq(both.p.calls, w.probes_issued);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_tick_without_probe_sink_is_window_only)
{
    /* bootstrap_worker_tick must stay exactly what it was: the seeded unit
     * tests and the conformance coverage pin depend on it. */
    bootstrap_worker_t w;
    bootstrap_worker_init_config(&w, 999, 1, 1, false);
    w.probe_interval_sec = 0.0;
    emit_ctx_t e = {0};
    for (int i = 0; i < 6; i++)
        bootstrap_worker_tick(&w, 3, 0.0, _capture_emit, &e);
    ck_assert_int_eq(w.pairs_issued, 1);
    ck_assert_int_eq(w.probes_issued, 0);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_continuous_can_be_disabled)
{
    bootstrap_worker_t w;
    bootstrap_worker_init_config(&w, 999, 1, 1, false);
    w.probe_interval_sec = 0.0;
    w.continuous_enabled = false;
    both_ctx_t both = {0};
    for (int i = 0; i < 6; i++)
        bootstrap_worker_tick_all(&w, 3, 0.0, _both_emit, _both_probe, &both);
    ck_assert_int_eq(w.probes_issued, 0);
    ck_assert_int_eq(both.p.calls, 0);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_probe_rate_limit_spaces_probes)
{
    bootstrap_worker_t w;
    bootstrap_worker_init_config(&w, 999, 1, 1, false);
    w.probe_interval_sec = 3600.0;
    both_ctx_t both = {0};
    for (int i = 0; i < 10; i++)
        bootstrap_worker_tick_all(&w, 3, 0.0, _both_emit, _both_probe, &both);
    /* First post-window tick probes immediately (waiting an hour to START
     * probing serves nobody); the interval blocks the rest. */
    ck_assert_int_eq(w.probes_issued, 1);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_ucb_bonus_widest_for_unprobed)
{
    ck_assert_double_lt(bootstrap_ucb_bonus(5, 100), bootstrap_ucb_bonus(0, 100));
    ck_assert_double_lt(bootstrap_ucb_bonus(50, 100), bootstrap_ucb_bonus(5, 100));
    /* Positive on the very first draw: ln(total + 1) would be 0 here and would
     * zero every arm's bonus, degenerating selection to its tie-break. */
    ck_assert_double_lt(0.0, bootstrap_ucb_bonus(0, 0));
}
END_TEST_DEFINITION()

DEFINE_TEST(test_target_selection_prefers_least_probed)
{
    bootstrap_worker_t w;
    bootstrap_worker_init_config(&w, 999, 20, 1, false);
    w.probes_issued = 20;
    w.probes_by_peer[0] = 10;
    w.probes_by_peer[1] = 10;
    w.probes_by_peer[2] = 0;
    ck_assert_uint_eq(bootstrap_worker_select_target(&w, 3), 2);
    /* All equal → lowest index, so equal counts round-robin rather than
     * depending on iteration direction. */
    bootstrap_worker_init_config(&w, 999, 20, 1, false);
    ck_assert_uint_eq(bootstrap_worker_select_target(&w, 3), 0);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_probes_spread_across_peers)
{
    /* Three peers, three probes → each peer probed once. */
    bootstrap_worker_t w;
    bootstrap_worker_init_config(&w, 999, 0 /* window done immediately */, 1, false);
    w.probe_interval_sec = 0.0;
    probe_ctx_t p = {0};
    for (int i = 0; i < 3; i++)
        bootstrap_worker_tick_all(&w, 3, 0.0, NULL, _capture_probe, &p);
    ck_assert_int_eq(p.calls, 3);
    ck_assert_int_eq(p.per_peer[0], 1);
    ck_assert_int_eq(p.per_peer[1], 1);
    ck_assert_int_eq(p.per_peer[2], 1);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_capability_allocation_covers_all_and_is_proportional)
{
    /* weight / (n + 1): with equal weights this round-robins, so every
     * capability keeps getting exercised. Ranking by weight alone would leave
     * an adversary a single capability to answer correctly. */
    bootstrap_worker_t w;
    bootstrap_worker_init_config(&w, 999, 0, 1, false);
    w.probe_interval_sec = 0.0;
    probe_ctx_t p = {0};
    for (int i = 0; i < 30; i++)
        bootstrap_worker_tick_all(&w, 3, 0.0, NULL, _capture_probe, &p);
    ck_assert_int_eq(p.calls, 30);
    for (int i = 0; i < BOOTSTRAP_CAPABILITY_COUNT; i++)
        ck_assert(w.probes_by_cap[i] > 0);
    /* Equal weights → within one of each other. */
    int lo = w.probes_by_cap[0], hi = w.probes_by_cap[0];
    for (int i = 1; i < BOOTSTRAP_CAPABILITY_COUNT; i++) {
        if (w.probes_by_cap[i] < lo) lo = w.probes_by_cap[i];
        if (w.probes_by_cap[i] > hi) hi = w.probes_by_cap[i];
    }
    ck_assert(hi - lo <= 1);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_unregistered_caps_are_not_probed)
{
    bootstrap_worker_t w;
    bootstrap_worker_init_config(&w, 999, 0, 1, false);
    w.probe_interval_sec = 0.0;
    bootstrap_worker_set_registered(&w, "at.handshake", false);
    bootstrap_worker_set_registered(&w, "at.time-attest", false);
    probe_ctx_t p = {0};
    for (int i = 0; i < 5; i++)
        bootstrap_worker_tick_all(&w, 3, 0.0, NULL, _capture_probe, &p);
    ck_assert_int_eq(p.calls, 5);
    ck_assert_str_eq(p.last_cap, "at.echo-challenge");
    ck_assert_int_eq(w.probes_by_cap[0], 0);
    ck_assert_int_eq(w.probes_by_cap[1], 0);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_probe_queue_full_no_count)
{
    bootstrap_worker_t w;
    bootstrap_worker_init_config(&w, 999, 0, 1, false);
    w.probe_interval_sec = 0.0;
    probe_ctx_t p = {0};
    p.fail = true;
    bootstrap_worker_tick_all(&w, 3, 0.0, NULL, _capture_probe, &p);
    ck_assert_int_eq(w.probes_issued, 0);
}
END_TEST_DEFINITION()

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
          test_disabled_no_issue,
          test_probes_continue_after_the_window,
          test_tick_without_probe_sink_is_window_only,
          test_continuous_can_be_disabled,
          test_probe_rate_limit_spaces_probes,
          test_ucb_bonus_widest_for_unprobed,
          test_target_selection_prefers_least_probed,
          test_probes_spread_across_peers,
          test_capability_allocation_covers_all_and_is_proportional,
          test_unregistered_caps_are_not_probed,
          test_probe_queue_full_no_count)
