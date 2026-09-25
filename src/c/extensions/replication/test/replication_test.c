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
 ********************/

/* Sampled replication with bisection dispute resolution (R+D.md §12.6). The
 * pure functions are pinned here against the Python twin's values -- the draw,
 * the majority rule, and the committed hash-chain root -- because a layer whose
 * two runtimes disagree lets a peer's exposure, or the fault a game convicts,
 * depend on which implementation was watching. The cross-runtime pin lives in
 * the conformance corpus; these are the per-side API and edge-case guards. */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <string.h>

#include "replication/adjudication.h"
#include "replication/bisection.h"
#include "replication/replication.h"
#include "replication/sampling.h"

DEFINE_TEST(test_sampling_draw_is_the_shared_stream)
{
    /* The same seeds and draws the Python twin produces (certificates/rng
     * SplitMix64, top 53 bits). */
    double draw = 0.0;
    bool r = at_replication_should_replicate(0.5, 3, &draw);
    ck_assert_double_eq_tol(draw, 0.11345034205715454, 1e-15);
    ck_assert(r);                                  /* 0.113 < 0.5 */
    r = at_replication_should_replicate(0.05, 3, &draw);
    ck_assert(!r);                                 /* 0.113 >= 0.05 */
    r = at_replication_should_replicate(0.5, 0, &draw);
    ck_assert_double_eq_tol(draw, 0.8833108082136426, 1e-15);
    ck_assert(!r);
}

DEFINE_TEST(test_sampling_endpoints_are_strict)
{
    double draw = 0.0;
    /* p = 1 replicates even the highest draw; p = 0 replicates none; and a
     * draw exactly equal to p does NOT replicate (draw < p is strict). */
    ck_assert(at_replication_should_replicate(1.0, 0, &draw));
    ck_assert(!at_replication_should_replicate(0.0, 3, &draw));
    ck_assert(!at_replication_should_replicate(0.11345034205715454, 3, &draw));
    /* an override is clamped, not refused */
    ck_assert(at_replication_should_replicate(2.0, 0, &draw));
    ck_assert(!at_replication_should_replicate(-1.0, 3, &draw));
}

DEFINE_TEST(test_model_resolves_and_rejects)
{
    at_replication_model_t m;
    char err[256] = {0};
    ck_assert(at_replication_model_parse(
        "{\"version\":1,\"default_prob\":0.05,"
        "\"capabilities\":{\"cmd\":{\"replicate_prob\":0.5,"
        "\"tolerance\":0.1}}}",
        &m, err, sizeof(err)));
    ck_assert_double_eq_tol(at_replication_prob_for(&m, "cmd"), 0.5, 1e-15);
    ck_assert_double_eq_tol(at_replication_prob_for(&m, "other"), 0.05, 1e-15);
    ck_assert_double_eq_tol(at_replication_tolerance_for(&m, "cmd"), 0.1, 1e-15);
    ck_assert_double_eq_tol(at_replication_tolerance_for(&m, "other"), 0.0,
                            1e-15);
    /* an out-of-range probability is refused on load */
    ck_assert(!at_replication_model_parse(
        "{\"version\":1,\"capabilities\":{\"x\":{\"replicate_prob\":1.5}}}",
        &m, err, sizeof(err)));
    /* the empty model: opt-in, not configured */
    ck_assert(at_replication_model_parse("", &m, err, sizeof(err)));
    ck_assert_double_eq_tol(at_replication_prob_for(&m, "cmd"), 0.05, 1e-15);
}

static void _num(at_repl_result_t *r, const char *peer, double v)
{
    memset(r, 0, sizeof(*r));
    snprintf(r->peer, sizeof(r->peer), "%s", peer);
    r->is_number = true;
    r->num = v;
}

DEFINE_TEST(test_adjudicate_needs_a_strict_majority)
{
    at_repl_result_t r[4];
    at_repl_verdict_t v[4];

    /* clear majority: two agree, one dissents */
    _num(&r[0], "E", 42);
    _num(&r[1], "R1", 42);
    _num(&r[2], "R2", 7);
    at_replication_adjudicate(r, 3, 0.0, v);
    ck_assert_int_eq(v[0], AT_REPL_CORROBORATED);
    ck_assert_int_eq(v[1], AT_REPL_CORROBORATED);
    ck_assert_int_eq(v[2], AT_REPL_OUTVOTED);

    /* a two-way disagreement scores nobody */
    _num(&r[0], "E", 42);
    _num(&r[1], "R1", 7);
    at_replication_adjudicate(r, 2, 0.0, v);
    ck_assert_int_eq(v[0], AT_REPL_DISPUTE);
    ck_assert_int_eq(v[1], AT_REPL_DISPUTE);

    /* a 2-2 split is a dispute: 2 is not strictly more than half of 4 */
    _num(&r[0], "E", 1);
    _num(&r[1], "R1", 1);
    _num(&r[2], "R2", 2);
    _num(&r[3], "R3", 2);
    at_replication_adjudicate(r, 4, 0.0, v);
    ck_assert_int_eq(v[0], AT_REPL_DISPUTE);
    ck_assert_int_eq(v[3], AT_REPL_DISPUTE);

    /* fewer than two: nothing was replicated */
    _num(&r[0], "E", 42);
    at_replication_adjudicate(r, 1, 0.0, v);
    ck_assert_int_eq(v[0], AT_REPL_SINGLE);
}

DEFINE_TEST(test_verify_maps_only_the_scored_verdicts)
{
    double sc = 0.0;
    const char *ch = NULL;
    ck_assert(at_replication_verify(AT_REPL_CORROBORATED, &sc, &ch));
    ck_assert_double_eq_tol(sc, 0.9, 1e-15);
    ck_assert_str_eq(ch, "replication");
    ck_assert(at_replication_verify(AT_REPL_OUTVOTED, &sc, &ch));
    ck_assert_double_eq_tol(sc, 0.1, 1e-15);
    ck_assert(!at_replication_verify(AT_REPL_DISPUTE, &sc, &ch));
    ck_assert(!at_replication_verify(AT_REPL_SINGLE, &sc, &ch));
}

DEFINE_TEST(test_bisection_localizes_and_adjudicates)
{
    const char *A[] = {"s0", "s1", "s2", "s3", "s4"};
    const char *B[] = {"s0", "s1", "X2", "X3", "X4"};
    /* committed root identical to the Python twin's commit_root */
    char root[AT_REPL_HASH_HEX_LEN + 1];
    ck_assert(at_replication_commit_root(A, 5, root));
    ck_assert_str_eq(
        root,
        "4339f13f00492a5b54735f094c5ce6e70d7956e1a56fce6eed6c496fe4d955a6");

    int k = -1;
    bool diverged = false;
    at_repl_verdict_t va, vb;
    ck_assert(at_replication_bisect_adjudicate(A, 5, B, 5, A, 5, &k, &diverged,
                                               &va, &vb));
    ck_assert(diverged);
    ck_assert_int_eq(k, 2);
    ck_assert_int_eq(va, AT_REPL_CORROBORATED);
    ck_assert_int_eq(vb, AT_REPL_OUTVOTED);

    /* both wrong at the divergence -> both outvoted */
    const char *A2[] = {"a", "q", "c"};
    const char *B2[] = {"a", "w", "c"};
    const char *R2[] = {"a", "b", "c"};
    at_replication_bisect_adjudicate(A2, 3, B2, 3, R2, 3, &k, &diverged, &va,
                                     &vb);
    ck_assert_int_eq(k, 1);
    ck_assert_int_eq(va, AT_REPL_OUTVOTED);
    ck_assert_int_eq(vb, AT_REPL_OUTVOTED);

    /* identical traces never diverge and are not a dispute */
    at_replication_bisect_adjudicate(A, 5, A, 5, A, 5, &k, &diverged, &va, &vb);
    ck_assert(!diverged);
    ck_assert_int_eq(va, AT_REPL_CORROBORATED);
    ck_assert_int_eq(vb, AT_REPL_CORROBORATED);
}

RUN_TESTS(Replication,
          test_sampling_draw_is_the_shared_stream,
          test_sampling_endpoints_are_strict,
          test_model_resolves_and_rejects,
          test_adjudicate_needs_a_strict_majority,
          test_verify_maps_only_the_scored_verdicts,
          test_bisection_localizes_and_adjudicates)
