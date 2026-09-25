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

/* Conformal coverage audit (R+D.md §12.4). The tail arithmetic is pinned here
 * against values computed independently, because the whole layer rests on it
 * and the conformance corpus can only see the verdict it produces. */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <math.h>
#include <string.h>

#include "calibration/calibration.h"
#include "calibration/conformal.h"

/**********************
 * The exact test
 **********************/

DEFINE_TEST(test_binomial_tail_matches_closed_forms)
{
    /* P(X <= 5 | n = 10, p = 1/2) = 638/1024, by symmetry of the binomial. */
    ck_assert_double_eq_tol(exp(at_binomial_tail_log(5, 10, 0.5)),
                            638.0 / 1024.0, 1e-12);
    /* P(X <= 0 | n = 1, p = 0.9) = 0.1 */
    ck_assert_double_eq_tol(exp(at_binomial_tail_log(0, 1, 0.9)), 0.1, 1e-12);
    /* P(X <= 0 | n = 3, p = 0.5) = 1/8 */
    ck_assert_double_eq_tol(exp(at_binomial_tail_log(0, 3, 0.5)), 0.125, 1e-12);
    /* The whole mass, and the empty tail. */
    ck_assert_double_eq_tol(at_binomial_tail_log(10, 10, 0.9), 0.0, 1e-15);
    ck_assert(isinf(at_binomial_tail_log(-1, 10, 0.9)));
}

DEFINE_TEST(test_binomial_tail_survives_underflow)
{
    /* (1 - p)^n underflows to zero here, which is why the sum is in log space:
     * a naive recurrence would return a tail of exactly 0 and reject every
     * peer. The value is finite and the peer is NOT rejected. */
    double lp = at_binomial_tail_log(400, 512, 0.9);
    ck_assert(isfinite(lp));
    ck_assert(lp < 0.0);
    ck_assert(!at_conformal_overconfident(500, 512, 0.9, 0.05));
}

DEFINE_TEST(test_binomial_tail_boundary_probabilities)
{
    /* p at 0 or 1 would evaluate 0 * -inf = NaN in the general path. */
    ck_assert_double_eq_tol(at_binomial_tail_log(0, 5, 0.0), 0.0, 1e-15);
    ck_assert(isinf(at_binomial_tail_log(4, 5, 1.0)));
    ck_assert(!isnan(at_binomial_tail_log(0, 5, 0.0)));
    ck_assert(!isnan(at_binomial_tail_log(4, 5, 1.0)));
}

DEFINE_TEST(test_overconfident_is_one_sided)
{
    /* Claiming 0.9 and delivering half is rejected; delivering ALL of them is
     * not. An over-cautious peer is useless, not dishonest, and separating
     * those two is the entire point of the layer. */
    ck_assert(at_conformal_overconfident(4, 8, 0.9, 0.05));
    ck_assert(!at_conformal_overconfident(8, 8, 0.9, 0.05));
    ck_assert(!at_conformal_overconfident(100, 100, 0.9, 0.05));
    /* n = 8, k = 6 has a tail of 0.187 and must NOT reject at 0.05. */
    ck_assert(!at_conformal_overconfident(6, 8, 0.9, 0.05));
}

DEFINE_TEST(test_covers_is_componentwise)
{
    double lo[3] = {0.0, 0.0, 0.0}, hi[3] = {10.0, 10.0, 10.0};
    double inside[3] = {5.0, 5.0, 5.0};
    double outside[3] = {5.0, 5.0, 50.0};
    ck_assert(at_conformal_covers(lo, hi, 3, inside, 3, 0.0));
    ck_assert(!at_conformal_covers(lo, hi, 3, outside, 3, 0.0));
    /* Wrong arity is a miss, not an error: a set of the wrong shape does not
     * contain anything. */
    ck_assert(!at_conformal_covers(lo, hi, 3, inside, 2, 0.0));
    /* Tolerance widens both sides. */
    double edge[1] = {10.5};
    ck_assert(!at_conformal_covers(lo, hi, 1, edge, 1, 0.0));
    ck_assert(at_conformal_covers(lo, hi, 1, edge, 1, 1.0));
}

/**********************
 * Declaration
 **********************/

DEFINE_TEST(test_model_is_empty_until_configured)
{
    at_calibration_model_t m;
    ck_assert(at_calibration_model_parse(NULL, &m, NULL, 0));
    ck_assert_int_eq(m.n_capabilities, 0);
    at_calibration_auditor_t a;
    at_calibration_auditor_init(&a, &m);
    ck_assert(!at_calibration_enabled(&a));
}

DEFINE_TEST(test_model_rejects_incoherent_declarations)
{
    at_calibration_model_t m;
    char err[AT_CAL_ERR_LEN];
    /* max_outcomes below min_samples means the audit could never speak, which
     * is the silent-inertness the loader refuses to degrade into. */
    ck_assert(!at_calibration_model_parse(
        "{\"version\":1,\"min_samples\":30,\"max_outcomes\":8}", &m, err,
        sizeof(err)));
    /* alpha outside (0,1) */
    ck_assert(!at_calibration_model_parse(
        "{\"version\":1,\"audit_alpha\":0}", &m, err, sizeof(err)));
    /* a predictive capability with no quantity has nothing to be about */
    ck_assert(!at_calibration_model_parse(
        "{\"version\":1,\"capabilities\":{\"f\":{}}}", &m, err, sizeof(err)));
    /* an inverted coverage band */
    ck_assert(!at_calibration_model_parse(
        "{\"version\":1,\"capabilities\":{\"f\":{\"quantity\":\"q\","
        "\"min_coverage\":0.9,\"max_coverage\":0.5}}}", &m, err, sizeof(err)));
}

/**********************
 * The auditor
 **********************/

static const char DECL[] =
    "{\"version\":1,\"min_samples\":8,\"audit_alpha\":0.05,"
    "\"max_outcomes\":64,\"horizon_sec\":100.0,"
    "\"capabilities\":{\"fc\":{\"quantity\":\"q\",\"min_coverage\":0.5}}}";

static void _predict(at_calibration_auditor_t *a, const char *who, double t)
{
    json_t *p = json_pack("{s:f, s:[f], s:[f]}", "coverage", 0.9,
                          "lo", 0.0, "hi", 10.0);
    at_calibration_assess(a, "fc", p, who, t, NULL, NULL, 0);
    json_decref(p);
}

DEFINE_TEST(test_audit_is_silent_below_min_samples)
{
    at_calibration_model_t m;
    ck_assert(at_calibration_model_parse(DECL, &m, NULL, 0));
    at_calibration_auditor_t a;
    at_calibration_auditor_init(&a, &m);

    /* Seven resolutions, every one a miss. Still silent: "no verdict" is the
     * honest report when there is not enough evidence, and finite-sample
     * validity is the whole reason to use this test. */
    for (int i = 0; i < 7; i++)
    {
        _predict(&a, "B", (double)i);
        double miss = 99.0;
        at_calibration_settle(&a, "q", &miss, 1, (double)i + 0.5, NULL);
    }
    json_t *p = json_pack("{s:f, s:[f], s:[f]}", "coverage", 0.9,
                          "lo", 0.0, "hi", 10.0);
    double score = 0.0;
    at_cal_verdict_t v = at_calibration_assess(&a, "fc", p, "B", 100.0,
                                               &score, NULL, 0);
    json_decref(p);
    ck_assert_int_eq((int)v, (int)AT_CAL_NONE);
}

DEFINE_TEST(test_audit_rejects_the_overconfident)
{
    at_calibration_model_t m;
    ck_assert(at_calibration_model_parse(DECL, &m, NULL, 0));
    at_calibration_auditor_t a;
    at_calibration_auditor_init(&a, &m);

    for (int i = 0; i < 8; i++)
    {
        _predict(&a, "B", (double)i);
        double v = (i % 2 == 0) ? 5.0 : 99.0;   /* four hits in eight */
        at_calibration_settle(&a, "q", &v, 1, (double)i + 0.5, NULL);
    }
    json_t *p = json_pack("{s:f, s:[f], s:[f]}", "coverage", 0.9,
                          "lo", 0.0, "hi", 10.0);
    double score = 0.0;
    char why[AT_CAL_ERR_LEN] = {0};
    at_cal_verdict_t v = at_calibration_assess(&a, "fc", p, "B", 50.0, &score,
                                               why, sizeof(why));
    json_decref(p);
    ck_assert_int_eq((int)v, (int)AT_CAL_OVERCONFIDENT);
    ck_assert_double_eq_tol(score, AT_CAL_OVERCONFIDENT_SCORE, 1e-12);
    ck_assert(strlen(why) > 0);
}

DEFINE_TEST(test_absent_and_malformed_sets_score_the_same)
{
    at_calibration_model_t m;
    ck_assert(at_calibration_model_parse(DECL, &m, NULL, 0));
    at_calibration_auditor_t a;
    at_calibration_auditor_init(&a, &m);
    double score = 0.0;

    ck_assert_int_eq((int)at_calibration_assess(&a, "fc", NULL, "B", 0.0,
                                                &score, NULL, 0),
                     (int)AT_CAL_ABSENT);
    ck_assert_double_eq_tol(score, AT_CAL_ABSENT_SCORE, 1e-12);

    /* Coverage under the declared floor: without a floor a peer passes
     * forever by advertising a coverage its sets trivially meet. */
    json_t *low = json_pack("{s:f, s:[f], s:[f]}", "coverage", 0.01,
                            "lo", 0.0, "hi", 10.0);
    ck_assert_int_eq((int)at_calibration_assess(&a, "fc", low, "B", 0.0, NULL,
                                                NULL, 0),
                     (int)AT_CAL_ABSENT);
    json_decref(low);

    /* An inverted interval is not a set. */
    json_t *inv = json_pack("{s:f, s:[f], s:[f]}", "coverage", 0.9,
                            "lo", 9.0, "hi", 1.0);
    ck_assert_int_eq((int)at_calibration_assess(&a, "fc", inv, "B", 0.0, NULL,
                                                NULL, 0),
                     (int)AT_CAL_ABSENT);
    json_decref(inv);

    /* An undeclared capability is not this layer's business at all. */
    json_t *ok = json_pack("{s:f, s:[f], s:[f]}", "coverage", 0.9,
                           "lo", 0.0, "hi", 10.0);
    ck_assert_int_eq((int)at_calibration_assess(&a, "other", ok, "B", 0.0,
                                                NULL, NULL, 0),
                     (int)AT_CAL_NONE);
    json_decref(ok);
}

DEFINE_TEST(test_a_peer_cannot_resolve_its_own_prediction)
{
    at_calibration_model_t m;
    ck_assert(at_calibration_model_parse(DECL, &m, NULL, 0));
    at_calibration_auditor_t a;
    at_calibration_auditor_init(&a, &m);

    _predict(&a, "S", 1.0);
    double v = 5.0;
    /* S reporting the truth about its own prediction settles nothing: that is
     * the peer supplying the evidence it is audited against. */
    ck_assert_int_eq(at_calibration_settle(&a, "q", &v, 1, 2.0, "S"), 0);
    /* Anyone else settles it. */
    ck_assert_int_eq(at_calibration_settle(&a, "q", &v, 1, 3.0, "R"), 1);
    ck_assert_int_eq(at_calibration_settle(&a, "q", &v, 1, 4.0, "R"), 0);
}

DEFINE_TEST(test_expired_predictions_are_dropped_not_missed)
{
    at_calibration_model_t m;
    char decl[512];
    snprintf(decl, sizeof(decl),
             "{\"version\":1,\"min_samples\":1,\"max_outcomes\":8,"
             "\"capabilities\":{\"fc\":{\"quantity\":\"q\","
             "\"horizon_sec\":2.0,\"min_coverage\":0.5}}}");
    ck_assert(at_calibration_model_parse(decl, &m, NULL, 0));
    at_calibration_auditor_t a;
    at_calibration_auditor_init(&a, &m);

    _predict(&a, "E", 1.0);
    double miss = 99.0;
    /* Well past the horizon: nothing was observed in time, so there is no
     * evidence either way and the peer is not charged a miss. */
    ck_assert_int_eq(at_calibration_settle(&a, "q", &miss, 1, 100.0, NULL), 0);
    json_t *p = json_pack("{s:f, s:[f], s:[f]}", "coverage", 0.9,
                          "lo", 0.0, "hi", 10.0);
    ck_assert_int_eq((int)at_calibration_assess(&a, "fc", p, "E", 101.0, NULL,
                                                NULL, 0),
                     (int)AT_CAL_NONE);
    json_decref(p);
}

DEFINE_TEST(test_settle_result_reads_the_carried_forms)
{
    at_calibration_model_t m;
    ck_assert(at_calibration_model_parse(DECL, &m, NULL, 0));
    at_calibration_auditor_t a;

    /* A bare number, a JSON array, and an object with a `value` member are the
     * three shapes a `report results` payload carries. */
    const char *forms[] = {"5.0", "[5.0]", "{\"value\": 5.0}"};
    for (size_t i = 0; i < sizeof(forms) / sizeof(forms[0]); i++)
    {
        at_calibration_auditor_init(&a, &m);
        _predict(&a, "P", 1.0);
        ck_assert_int_eq(
            at_calibration_settle_result(&a, "q", forms[i], "R", 2.0), 1);
    }
    /* Prose settles nothing. */
    at_calibration_auditor_init(&a, &m);
    _predict(&a, "P", 1.0);
    ck_assert_int_eq(at_calibration_settle_result(&a, "q", "warm", "R", 2.0), 0);
}

RUN_TESTS(Calibration,
          test_binomial_tail_matches_closed_forms,
          test_binomial_tail_survives_underflow,
          test_binomial_tail_boundary_probabilities,
          test_overconfident_is_one_sided,
          test_covers_is_componentwise,
          test_model_is_empty_until_configured,
          test_model_rejects_incoherent_declarations,
          test_audit_is_silent_below_min_samples,
          test_audit_rejects_the_overconfident,
          test_absent_and_malformed_sets_score_the_same,
          test_a_peer_cannot_resolve_its_own_prediction,
          test_expired_predictions_are_dropped_not_missed,
          test_settle_result_reads_the_carried_forms)
