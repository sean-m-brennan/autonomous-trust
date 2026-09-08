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

/* Prequential competence (R+D.md §12.5). The arithmetic is pinned here
 * against values produced by the Python twin, because the conformance corpus
 * sees the multiplier a whole sequence produced and not the interval score
 * inside it -- and a layer whose two runtimes disagree by one weight step
 * makes an EMA depend on which implementation happened to be scoring. */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <math.h>
#include <string.h>

#include "prequential/prequential.h"
#include "prequential/scoring.h"

/* Two capabilities forecasting ONE quantity, deliberately: the aggregate is a
 * single interval, so the parse has to accept them only when their alpha and
 * scale agree, and the mixture adds their losses together. min_samples 2 keeps
 * the sequences in these tests short enough to read. */
#define DECL                                                                  \
    "{\"version\": 1, \"min_samples\": 2, \"max_outcomes\": 8,"               \
    " \"max_outstanding\": 8, \"horizon_sec\": 10.0, \"eta\": 1.0,"           \
    " \"weight_band\": {\"min\": 0.5, \"max\": 2.0},"                         \
    " \"capabilities\": {"                                                    \
    "   \"F\": {\"quantity\": \"q\", \"scale\": 10.0, \"alpha\": 0.1,"        \
    "           \"horizon_sec\": 10.0},"                                      \
    "   \"R\": {\"quantity\": \"q\", \"scale\": 10.0, \"alpha\": 0.1}}}"

/* Attach a forecast box to one peer. */
static bool _forecast(at_prequential_estimator_t *est, const char *cap,
                      const char *peer, double lo, double hi, double now)
{
    json_t *pred = json_object();
    json_t *jlo = json_array();
    json_t *jhi = json_array();
    json_array_append_new(jlo, json_real(lo));
    json_array_append_new(jhi, json_real(hi));
    json_object_set_new(pred, "lo", jlo);
    json_object_set_new(pred, "hi", jhi);
    bool ok = at_prequential_observe(est, cap, pred, peer, now);
    json_decref(pred);
    return ok;
}

/* The shared four-round sequence: a sharp forecaster and a vague one, both
 * awake every round. The numbers every assertion below quotes came from the
 * Python twin on this same sequence. */
static void _sharp_and_vague(at_prequential_estimator_t *est)
{
    const double truth[] = {5.0, 6.0, 4.0, 5.0};
    for (int t = 0; t < 4; t++)
    {
        double now = (double)t;
        double y = truth[t];
        _forecast(est, "F", "A", y - 0.5, y + 0.5, now);
        _forecast(est, "F", "B", y - 8.0, y + 8.0, now);
        at_prequential_settle(est, "q", &y, 1, now + 0.5, NULL);
    }
}

/**********************
 * The loss
 **********************/

DEFINE_TEST(test_interval_score_splits_sharpness_from_the_miss)
{
    double lo = 4.0, hi = 6.0, y = 5.0;
    /* Covered: the width alone, so a peer is charged for vagueness even when
     * it is right. */
    ck_assert_double_eq_tol(at_preq_interval_score(&lo, &hi, 1, &y, 1, 0.1, 0.0),
                            2.0, 1e-12);
    /* Missed high by 2 at alpha 0.1: 2 + (2/0.1)*2 = 42. The miss dominates,
     * which is the point of a proper rule. */
    y = 8.0;
    ck_assert_double_eq_tol(at_preq_interval_score(&lo, &hi, 1, &y, 1, 0.1, 0.0),
                            42.0, 1e-12);
    /* The tolerance forgives a miss inside measurement error -- and leaves
     * the sharpness term alone, so the peer is charged for the width it
     * DECLARED and not for our instrument. Were the widened width charged,
     * 2*tolerance/scale would be a floor under every peer's loss on this
     * capability and a flawless record could not reach band_max. */
    ck_assert_double_eq_tol(at_preq_interval_score(&lo, &hi, 1, &y, 1, 0.1, 2.0),
                            2.0, 1e-12);
}

DEFINE_TEST(test_interval_score_is_the_mean_over_components)
{
    /* A 3-vector forecast must not be three times worse than a scalar one, so
     * the score is the MEAN: two components each scoring 2 give 2, not 4. */
    double lo[2] = {0.0, 10.0}, hi[2] = {2.0, 12.0}, y[2] = {1.0, 11.0};
    ck_assert_double_eq_tol(at_preq_interval_score(lo, hi, 2, y, 2, 0.1, 0.0),
                            2.0, 1e-12);
    /* An arity mismatch is a shape the world contradicted, not an absence:
     * the sentinel, which callers map to the maximum loss. */
    ck_assert_double_eq_tol(at_preq_interval_score(lo, hi, 2, y, 1, 0.1, 0.0),
                            AT_PREQ_SHAPE_MISMATCH, 1e-12);
}

DEFINE_TEST(test_normalized_loss_saturates_at_one)
{
    ck_assert_double_eq_tol(at_preq_normalized_loss(2.0, 10.0), 0.2, 1e-12);
    /* Missing by 2.5 scales is not usefully worse than missing by 1: Hedge
     * needs a bounded loss, and "impossible" is the physics layer's verdict. */
    ck_assert_double_eq_tol(at_preq_normalized_loss(25.0, 10.0),
                            AT_PREQ_MAX_LOSS, 1e-12);
    /* An unusable scale is the ceiling rather than a division. */
    ck_assert_double_eq_tol(at_preq_normalized_loss(2.0, 0.0),
                            AT_PREQ_MAX_LOSS, 1e-12);
    /* The mismatch sentinel is NOT mapped here -- this function clamps a
     * negative ratio to 0, and every caller maps AT_PREQ_SHAPE_MISMATCH to
     * the ceiling before calling it. Pinned so the division of labour is
     * deliberate: were a call site to forget, a forecast whose shape the
     * world contradicted would score as the BEST possible loss.
     * test_shape_mismatch_scores_the_worst_case checks the mapping where it
     * actually lives. */
    ck_assert_double_eq_tol(
        at_preq_normalized_loss(AT_PREQ_SHAPE_MISMATCH, 10.0), 0.0, 1e-12);
}

DEFINE_TEST(test_band_multiplier_spans_exactly_the_declared_band)
{
    /* A perfect record earns the top of the band and a saturated one the
     * bottom -- and nothing reaches outside it, which is what keeps the
     * operator's authored weight the anchor. */
    ck_assert_double_eq_tol(at_preq_band_multiplier(0.0, 0.5, 2.0), 2.0, 1e-12);
    ck_assert_double_eq_tol(at_preq_band_multiplier(1.0, 0.5, 2.0), 0.5, 1e-12);
    ck_assert_double_eq_tol(at_preq_band_multiplier(0.5, 0.5, 2.0), 1.25, 1e-12);
}

DEFINE_TEST(test_weight_round_is_floor_of_x_plus_half)
{
    /* THE cross-runtime trap: Python's round() is banker's (2.5 -> 2) and C's
     * lround is half-away-from-zero. floor(x + 0.5) is neither, it is what
     * both runtimes implement, and a band-mapped weight lands on .5 often. */
    ck_assert_int_eq(at_preq_weight_round(1.5), 2);
    ck_assert_int_eq(at_preq_weight_round(2.5), 3);
    ck_assert_int_eq(at_preq_weight_round(3.49), 3);
    /* Floored at 1: the EMA folds a score in `weight` times. */
    ck_assert_int_eq(at_preq_weight_round(0.4), 1);
    ck_assert_int_eq(at_preq_weight_round(-5.0), 1);
}

DEFINE_TEST(test_hedge_weights_survive_underflow)
{
    double w[2];
    double equal[2] = {3.0, 3.0};
    at_preq_hedge_weights(equal, 2, 1.0, w);
    ck_assert_double_eq_tol(w[0], 0.5, 1e-12);
    ck_assert_double_eq_tol(w[1], 0.5, 1e-12);
    /* exp(-800) is zero in a double, so a naive implementation normalizes a
     * table of zeros -- no aggregate at all, at exactly the run lengths where
     * the bound is worth having. The max-shift keeps the RATIO, which is all
     * the weights depend on. */
    double big[2] = {800.0, 802.0};
    at_preq_hedge_weights(big, 2, 1.0, w);
    ck_assert_double_eq_tol(w[0], 0.8807970779778823, 1e-12);
    ck_assert_double_eq_tol(w[1], 0.11920292202211755, 1e-12);
    ck_assert_double_eq_tol(w[0] + w[1], 1.0, 1e-12);
}

DEFINE_TEST(test_hedge_bound_is_log_n_over_eta_plus_eta_t_over_eight)
{
    ck_assert_double_eq_tol(at_preq_hedge_bound(2, 4, 1.0),
                            1.1931471805599454, 1e-12);
    /* One expert has nothing to regret against. */
    ck_assert_double_eq_tol(at_preq_hedge_bound(1, 0, 1.0), 0.0, 1e-12);
}

/**********************
 * The declaration
 **********************/

DEFINE_TEST(test_model_is_empty_until_configured)
{
    at_prequential_model_t m;
    ck_assert(at_prequential_model_parse(NULL, &m, NULL, 0));
    ck_assert_int_eq(m.n_capabilities, 0);
    at_prequential_estimator_t est;
    at_prequential_estimator_init(&est, &m);
    ck_assert(!at_prequential_enabled(&est));
    /* Opt-in means EXACTLY the authored weight, not approximately it. */
    ck_assert_double_eq_tol(at_prequential_competence(&est, "A", "F"),
                            AT_PREQ_NEUTRAL_COMPETENCE, 0.0);
}

DEFINE_TEST(test_model_rejects_incoherent_declarations)
{
    at_prequential_model_t m;
    char err[AT_PREQ_ERR_LEN];

    /* A ring that can never reach the threshold would make the layer
     * silently inert -- the failure mode hardest to notice. */
    ck_assert(!at_prequential_model_parse(
        "{\"min_samples\": 8, \"max_outcomes\": 4,"
        " \"capabilities\": {\"F\": {\"quantity\": \"q\", \"scale\": 1.0}}}",
        &m, err, sizeof(err)));
    ck_assert_int_eq(m.n_capabilities, 0);

    /* A band that excludes 1.0 makes the authored weight unreachable, so the
     * operator's number would not be the anchor it is documented to be. */
    ck_assert(!at_prequential_model_parse(
        "{\"weight_band\": {\"min\": 1.5, \"max\": 2.0},"
        " \"capabilities\": {\"F\": {\"quantity\": \"q\", \"scale\": 1.0}}}",
        &m, err, sizeof(err)));

    /* One quantity, two levels: the mixture adds losses divided by different
     * scales, and two peers scored at different alphas are not being
     * compared at all. */
    ck_assert(!at_prequential_model_parse(
        "{\"capabilities\": {"
        "  \"F\": {\"quantity\": \"q\", \"scale\": 10.0, \"alpha\": 0.1},"
        "  \"G\": {\"quantity\": \"q\", \"scale\": 10.0, \"alpha\": 0.2}}}",
        &m, err, sizeof(err)));
    ck_assert(!at_prequential_model_parse(
        "{\"capabilities\": {"
        "  \"F\": {\"quantity\": \"q\", \"scale\": 10.0, \"alpha\": 0.1},"
        "  \"G\": {\"quantity\": \"q\", \"scale\": 20.0, \"alpha\": 0.1}}}",
        &m, err, sizeof(err)));

    /* ...and the coherent version of the same declaration parses. */
    ck_assert(at_prequential_model_parse(DECL, &m, err, sizeof(err)));
    ck_assert_int_eq(m.n_capabilities, 2);
    ck_assert_int_eq(m.n_quantities, 1);
}

/**********************
 * The multiplier
 **********************/

DEFINE_TEST(test_competence_is_silent_below_min_samples)
{
    at_prequential_model_t m;
    ck_assert(at_prequential_model_parse(DECL, &m, NULL, 0));
    at_prequential_estimator_t est;
    at_prequential_estimator_init(&est, &m);

    double y = 5.0;
    _forecast(&est, "F", "A", 4.5, 5.5, 0.0);
    at_prequential_settle(&est, "q", &y, 1, 0.5, NULL);
    /* One resolution, min_samples 2: a layer whose failure mode is a guess is
     * worse than one that says nothing. */
    ck_assert_double_eq_tol(at_prequential_competence(&est, "A", "F"),
                            AT_PREQ_NEUTRAL_COMPETENCE, 0.0);

    _forecast(&est, "F", "A", 4.5, 5.5, 1.0);
    at_prequential_settle(&est, "q", &y, 1, 1.5, NULL);
    /* Two now, and a sharp record moves the weight up. */
    ck_assert(at_prequential_competence(&est, "A", "F") > 1.0);
}

DEFINE_TEST(test_competence_rewards_sharpness_and_bounds_both_ends)
{
    at_prequential_model_t m;
    ck_assert(at_prequential_model_parse(DECL, &m, NULL, 0));
    at_prequential_estimator_t est;
    at_prequential_estimator_init(&est, &m);
    _sharp_and_vague(&est);

    /* Pinned against the Python twin on this sequence. A's mean loss is 0.1
     * (width 1 over scale 10, covered every round) -> 2.0 - 1.5*0.1; B's
     * forecasts are so wide they saturate -> the floor of the band. The
     * coverage audit (R+D.md §12.4) is REQUIRED to forgive B, since it never
     * over-claimed; this is the layer that does not. */
    ck_assert_double_eq_tol(at_prequential_competence(&est, "A", "F"),
                            1.85, 1e-12);
    ck_assert_double_eq_tol(at_prequential_competence(&est, "B", "F"),
                            0.5, 1e-12);
    /* Nothing this layer has an opinion about gets exactly 1.0. */
    ck_assert_double_eq_tol(at_prequential_competence(&est, "Z", "F"),
                            AT_PREQ_NEUTRAL_COMPETENCE, 0.0);
    ck_assert_double_eq_tol(at_prequential_competence(&est, "A", "X"),
                            AT_PREQ_NEUTRAL_COMPETENCE, 0.0);
    ck_assert_double_eq_tol(at_prequential_competence(&est, NULL, "F"),
                            AT_PREQ_NEUTRAL_COMPETENCE, 0.0);

    /* The competence is REGIONAL by capability as well as by quantity: A's
     * record on F says nothing about A on R, which has resolved nothing. */
    ck_assert_double_eq_tol(at_prequential_competence(&est, "A", "R"),
                            AT_PREQ_NEUTRAL_COMPETENCE, 0.0);
}

DEFINE_TEST(test_a_peer_never_settles_its_own_forecast)
{
    at_prequential_model_t m;
    ck_assert(at_prequential_model_parse(DECL, &m, NULL, 0));
    at_prequential_estimator_t est;
    at_prequential_estimator_init(&est, &m);

    double y = 5.0;
    _forecast(&est, "F", "A", 4.5, 5.5, 0.0);
    /* A supplying the truth A is scored against is A grading itself. */
    ck_assert_int_eq(at_prequential_settle(&est, "q", &y, 1, 0.5, "A"), 0);
    /* Anyone else closes it. */
    ck_assert_int_eq(at_prequential_settle(&est, "q", &y, 1, 0.5, "B"), 1);
}

DEFINE_TEST(test_expired_forecasts_are_dropped_not_scored)
{
    at_prequential_model_t m;
    ck_assert(at_prequential_model_parse(DECL, &m, NULL, 0));
    at_prequential_estimator_t est;
    at_prequential_estimator_init(&est, &m);

    double y = 5.0;
    _forecast(&est, "F", "A", 4.5, 5.5, 0.0);
    /* Past the 10-second horizon: a truth that arrived too late to be about
     * this forecast records no loss, rather than the maximum one. */
    ck_assert_int_eq(at_prequential_settle(&est, "q", &y, 1, 100.0, NULL), 0);
    ck_assert_double_eq_tol(at_prequential_competence(&est, "A", "F"),
                            AT_PREQ_NEUTRAL_COMPETENCE, 0.0);
}

DEFINE_TEST(test_an_unusable_forecast_is_recorded_as_nothing)
{
    at_prequential_model_t m;
    ck_assert(at_prequential_model_parse(DECL, &m, NULL, 0));
    at_prequential_estimator_t est;
    at_prequential_estimator_init(&est, &m);

    /* "Declared predictive and attached nothing" is a fact about the CLAIM,
     * and the coverage audit already scores it. Scoring it here too would
     * double-count one omission -- and this layer has no channel to score on. */
    ck_assert(!at_prequential_observe(&est, "F", NULL, "A", 0.0));
    /* An inverted box, and mismatched arities, are shapes rather than claims. */
    ck_assert(!_forecast(&est, "F", "A", 6.0, 4.0, 0.0));
    json_t *pred = json_object();
    json_t *jlo = json_array();
    json_array_append_new(jlo, json_real(1.0));
    json_object_set_new(pred, "lo", jlo);
    ck_assert(!at_prequential_observe(&est, "F", pred, "A", 0.0));
    json_decref(pred);
    /* An undeclared capability is not this layer's business. */
    ck_assert(!_forecast(&est, "X", "A", 4.0, 6.0, 0.0));
}

DEFINE_TEST(test_shape_mismatch_scores_the_worst_case)
{
    at_prequential_model_t m;
    ck_assert(at_prequential_model_parse(DECL, &m, NULL, 0));
    at_prequential_estimator_t est;
    at_prequential_estimator_init(&est, &m);

    /* A 2-component forecast against a scalar observation: the forecast
     * committed to a shape the world contradicted, which is the WORST case
     * and not an absent one. Where the sentinel is mapped -- if a call site
     * ever forgot, this peer would come out at the top of the band instead of
     * the bottom. */
    for (int t = 0; t < 3; t++)
    {
        double now = (double)t;
        double y = 5.0;
        json_t *pred = json_object();
        json_t *jlo = json_array();
        json_t *jhi = json_array();
        json_array_append_new(jlo, json_real(4.5));
        json_array_append_new(jlo, json_real(4.5));
        json_array_append_new(jhi, json_real(5.5));
        json_array_append_new(jhi, json_real(5.5));
        json_object_set_new(pred, "lo", jlo);
        json_object_set_new(pred, "hi", jhi);
        ck_assert(at_prequential_observe(&est, "F", pred, "A", now));
        json_decref(pred);
        at_prequential_settle(&est, "q", &y, 1, now + 0.5, NULL);
    }
    ck_assert_double_eq_tol(at_prequential_competence(&est, "A", "F"),
                            0.5, 1e-12);
}

DEFINE_TEST(test_settle_result_reads_the_carried_forms)
{
    at_prequential_model_t m;
    ck_assert(at_prequential_model_parse(DECL, &m, NULL, 0));
    at_prequential_estimator_t est;

    /* The three shapes a `report results` payload carries, which is what lets
     * an ordinary later result close the loop with no application
     * involvement. */
    const char *forms[] = {"5.0", "[5.0]", "{\"value\": 5.0}"};
    for (size_t i = 0; i < sizeof(forms) / sizeof(forms[0]); i++)
    {
        at_prequential_estimator_init(&est, &m);
        _forecast(&est, "F", "A", 4.5, 5.5, 0.0);
        ck_assert_int_eq(
            at_prequential_settle_result(&est, "q", forms[i], "B", 0.5), 1);
    }
    /* Prose settles nothing. */
    at_prequential_estimator_init(&est, &m);
    _forecast(&est, "F", "A", 4.5, 5.5, 0.0);
    ck_assert_int_eq(
        at_prequential_settle_result(&est, "q", "warm", "B", 0.5), 0);
}

/**********************
 * The aggregate, and the bound it claims
 **********************/

DEFINE_TEST(test_combine_is_the_weighted_endpoint_average)
{
    at_prequential_model_t m;
    ck_assert(at_prequential_model_parse(DECL, &m, NULL, 0));
    at_prequential_estimator_t est;
    at_prequential_estimator_init(&est, &m);

    /* Two peers with no record yet weigh equally, so the aggregate of [0,2]
     * and [10,12] is [5,7] -- endpoint-wise, which is what makes the raw
     * interval score convex in the endpoints and the Jensen step below hold. */
    _forecast(&est, "F", "A", 0.0, 2.0, 0.0);
    _forecast(&est, "F", "B", 10.0, 12.0, 0.0);
    at_preq_aggregate_t agg;
    ck_assert(at_prequential_combine(&est, "q", 0.1, &agg));
    ck_assert_int_eq(agg.n_components, 1);
    ck_assert_double_eq_tol(agg.lo[0], 5.0, 1e-12);
    ck_assert_double_eq_tol(agg.hi[0], 7.0, 1e-12);
    ck_assert_int_eq(agg.n_contributors, 2);
    ck_assert_double_eq_tol(agg.contributors[0].weight, 0.5, 1e-12);
    ck_assert_str_eq(agg.contributors[0].capability, "F");

    /* Nothing outstanding is not an aggregate of nothing. */
    at_prequential_estimator_reset(&est);
    ck_assert(!at_prequential_combine(&est, "q", 0.1, &agg));
}

DEFINE_TEST(test_regret_reports_the_realized_gap_and_the_bound)
{
    at_prequential_model_t m;
    ck_assert(at_prequential_model_parse(DECL, &m, NULL, 0));
    at_prequential_estimator_t est;
    at_prequential_estimator_init(&est, &m);
    _sharp_and_vague(&est);

    at_preq_regret_t r;
    ck_assert(at_prequential_regret(&est, "q", &r));
    ck_assert_int_eq(r.rounds, 4);
    ck_assert_int_eq(r.experts, 2);
    ck_assert_int_eq(r.n_peers, 2);
    /* Pinned against the Python twin on the same sequence. */
    ck_assert_double_eq_tol(r.mixture_loss, 1.2944874264992323, 1e-12);
    ck_assert_double_eq_tol(r.aggregate_loss, 1.8908123774987204, 1e-12);
    /* Hedge's guarantee, MEASURED: the mixture's realized excess over each
     * peer's own loss on the rounds that peer was awake stays under the
     * bound. This is the one claim in AT that holds against arbitrary
     * adversarial peers at any sample size. */
    for (int i = 0; i < r.n_peers; i++)
    {
        ck_assert_double_lt(r.peers[i].realized, r.peers[i].bound);
        ck_assert_int_eq(r.peers[i].rounds, 4);
        ck_assert_double_eq_tol(r.peers[i].bound, 1.1931471805599454, 1e-12);
    }

    /* The aggregate lost to the mixture here, and that is a property of the
     * BOUNDED loss rather than a defect: min(1, IS/scale) is not convex, so
     * once several awake forecasts saturate, averaging endpoints can land
     * outside the capped average of their scores. Reported rather than
     * papered over -- a reader who found the totals crossed with no
     * explanation would reasonably conclude the code was wrong. */
    ck_assert(r.saturated_rounds > 0);
    ck_assert(r.aggregate_loss > r.mixture_loss);

    /* A quantity nothing has forecast has no regret to report. */
    ck_assert(!at_prequential_regret(&est, "other", &r));
}

DEFINE_TEST(test_jensen_holds_where_nothing_saturates)
{
    /* The inversion above is entirely the ceiling's doing. On a sequence where
     * no awake forecast saturates, the aggregate's loss is at most the
     * mixture's, which is the Jensen step the combine() guarantee rests on. */
    at_prequential_model_t m;
    ck_assert(at_prequential_model_parse(DECL, &m, NULL, 0));
    at_prequential_estimator_t est;
    at_prequential_estimator_init(&est, &m);

    const double truth[] = {5.0, 5.2, 4.9, 5.1};
    for (int t = 0; t < 4; t++)
    {
        double now = (double)t;
        double y = truth[t];
        /* A covers tightly; B's box is offset just enough to MISS low every
         * round, which is what makes the score strictly convex here and the
         * inequality strict. Two narrow boxes both covering would satisfy
         * Jensen with EQUALITY -- and then floating-point noise decides the
         * comparison, which is no test at all. Nothing saturates: the widths
         * and the misses stay well inside the scale of 10. */
        _forecast(&est, "F", "A", y - 0.5, y + 0.5, now);
        _forecast(&est, "F", "B", y + 0.2, y + 1.2, now);
        at_prequential_settle(&est, "q", &y, 1, now + 0.5, NULL);
    }
    at_preq_regret_t r;
    ck_assert(at_prequential_regret(&est, "q", &r));
    ck_assert_int_eq(r.saturated_rounds, 0);
    /* Pinned against the Python twin: the aggregate interval covers where B's
     * did not, so it beats the mixture by a wide margin rather than by an
     * ULP. */
    ck_assert_double_eq_tol(r.mixture_loss, 0.97712523010436758, 1e-12);
    ck_assert_double_eq_tol(r.aggregate_loss, 0.40000000000000002, 1e-12);
    ck_assert_double_lt(r.aggregate_loss, r.mixture_loss);
}

RUN_TESTS(Prequential,
          test_interval_score_splits_sharpness_from_the_miss,
          test_interval_score_is_the_mean_over_components,
          test_normalized_loss_saturates_at_one,
          test_band_multiplier_spans_exactly_the_declared_band,
          test_weight_round_is_floor_of_x_plus_half,
          test_hedge_weights_survive_underflow,
          test_hedge_bound_is_log_n_over_eta_plus_eta_t_over_eight,
          test_model_is_empty_until_configured,
          test_model_rejects_incoherent_declarations,
          test_competence_is_silent_below_min_samples,
          test_competence_rewards_sharpness_and_bounds_both_ends,
          test_a_peer_never_settles_its_own_forecast,
          test_expired_forecasts_are_dropped_not_scored,
          test_an_unusable_forecast_is_recorded_as_nothing,
          test_shape_mismatch_scores_the_worst_case,
          test_settle_result_reads_the_carried_forms,
          test_combine_is_the_weighted_endpoint_average,
          test_regret_reports_the_realized_gap_and_the_bound,
          test_jensen_holds_where_nothing_saturates)
