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

/* C adapter for the `prequential` conformance protocol (R+D.md §12.5).
 *
 * Non-message-driven, like the physics, calibration and bootstrap adapters:
 * the scenario carries a declaration and a list of events; this loads the
 * declaration into this runtime's estimator and replays the events in order,
 * carrying the outstanding-forecast and resolved-loss stores forward.
 *
 * Unlike every other oracle adapter, nothing here asserts a score: this layer
 * produces no evidence and no channel, only the EMA weight multiplier. So a
 * `competence` event asserts the multiplier and a `weight` event the composed
 * integer weight the reputation process folds a score in at -- which is where
 * the two runtimes could differ without either looking wrong, since
 * floor(x + 0.5) is neither language's native rounding.
 *
 * Both resolution paths are exercised, because the design has two: a `report`
 * event goes through the physics-declared path (a later result for the
 * quantity's reporting capability settles the forecast) and a `resolve` event
 * through the explicit one.
 *
 * `outstanding` and `outcomes` events assert STORE state rather than a
 * number, and they earn their place the way the calibration adapter's do: a
 * peer's own report not settling its own forecast, and an expired forecast
 * being dropped, have no observable effect on any single multiplier. Silence
 * is also what a correctly-weighted neutral peer produces.
 */

#include "prequential.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <jansson.h>

#include "prequential/prequential.h"
#include "prequential/scoring.h"

/* Loss and weight comparisons. Tight enough that a different formula fails,
 * loose enough that the last ulp of an `exp` does not decide a run: both
 * runtimes go to libm, but not necessarily to the same libm. Mirrors the
 * Python adapter's TOL. */
#define PREQ_TOL 1e-9

/* The reporting capability -> quantity link, out of the scenario's physics
 * fixture. Read here rather than by building a physics model, because that is
 * all this adapter needs from it and the prequential module is deliberately
 * independent of the physics one -- the same arrangement the calibration
 * adapter uses. */
static const char *_quantity_for_capability(json_t *physics,
                                            const char *capability)
{
    if (physics == NULL || capability == NULL)
        return NULL;
    json_t *quantities = json_object_get(physics, "quantities");
    if (!json_is_object(quantities))
        return NULL;
    const char *name;
    json_t *decl;
    json_object_foreach(quantities, name, decl)
    {
        json_t *cap = json_object_get(decl, "capability");
        if (json_is_string(cap)
            && strcmp(json_string_value(cap), capability) == 0)
            return name;
    }
    return NULL;
}

/* A scalar or an array of scalars into a double vector. */
static size_t _values(json_t *v, double *out, size_t cap)
{
    if (json_is_number(v))
    {
        if (cap == 0)
            return 0;
        out[0] = json_number_value(v);
        return 1;
    }
    if (!json_is_array(v))
        return 0;
    size_t n = 0, i;
    json_t *item;
    json_array_foreach(v, i, item)
    {
        if (n >= cap || !json_is_number(item))
            return 0;
        out[n++] = json_number_value(item);
    }
    return n;
}

/* Render a scenario result value as the text a `report results` payload
 * holds, which is what this runtime receives. The Python adapter hands its
 * estimator the decoded value instead, for the same reason: each side is fed
 * the shape its own scoring path is fed. */
static void _result_text(json_t *v, char *out, size_t cap)
{
    out[0] = '\0';
    if (json_is_string(v))
    {
        snprintf(out, cap, "%s", json_string_value(v));
        return;
    }
    char *dumped = json_dumps(v, JSON_COMPACT | JSON_ENCODE_ANY);
    if (dumped != NULL)
    {
        snprintf(out, cap, "%s", dumped);
        free(dumped);
    }
}

static int _outstanding_count(const at_prequential_estimator_t *est,
                              const char *quantity)
{
    if (quantity == NULL)
        return 0;
    for (int i = 0; i < est->model.n_quantities; i++)
        if (strcmp(est->model.quantities[i], quantity) == 0)
            return est->pending[i].count;
    return 0;
}

static int _outcome_count(const at_prequential_estimator_t *est,
                          const char *subject, const char *capability)
{
    if (subject == NULL || capability == NULL)
        return 0;
    int ci = -1;
    for (int i = 0; i < est->model.n_capabilities; i++)
        if (strcmp(est->model.capabilities[i].capability, capability) == 0)
            ci = i;
    if (ci < 0)
        return 0;
    for (int p = 0; p < est->n_peers; p++)
        if (strcmp(est->peers[p], subject) == 0)
            return est->losses[p][ci].count;
    return 0;
}

/* Compare a settle count against the row's expectation. Asserted here, unlike
 * the calibration adapter: how many forecasts one observation closes IS the
 * sleeping-experts awake set, and it decides every weight that follows. */
static int _check_settled(json_t *event, int index, int got, char *err,
                          size_t err_len)
{
    json_t *want = json_object_get(event, "settled");
    if (want == NULL)
        return 0;
    int expected = (int)json_integer_value(want);
    if (got != expected)
    {
        snprintf(err, err_len,
                 "event %d: settled %d forecast(s), expected %d",
                 index, got, expected);
        return -1;
    }
    return 0;
}

static int _run_forecast(at_prequential_estimator_t *est, json_t *event,
                         int index, char *err, size_t err_len)
{
    json_t *spec = json_object_get(event, "forecast");
    const char *capability =
        json_string_value(json_object_get(spec, "capability"));
    const char *subject = json_string_value(json_object_get(event, "subject"));
    double t = json_number_value(json_object_get(event, "t"));

    /* A spec carrying nothing but `capability` means "declared predictive and
     * attached nothing", which is a distinct row from "attached a malformed
     * box" -- and the estimator tells them apart, so the fixture has to be
     * able to say which one it means. */
    json_t *prediction = json_deep_copy(spec);
    json_object_del(prediction, "capability");
    if (json_object_size(prediction) == 0)
    {
        json_decref(prediction);
        prediction = NULL;
    }
    bool got = at_prequential_observe(est, capability, prediction, subject, t);
    if (prediction != NULL)
        json_decref(prediction);

    bool want = json_is_true(json_object_get(event, "recorded"));
    if (got != want)
    {
        snprintf(err, err_len, "event %d: forecast %s, expected %s",
                 index, got ? "recorded" : "rejected",
                 want ? "recorded" : "rejected");
        return -1;
    }
    return 0;
}

static int _run_competence(at_prequential_estimator_t *est, json_t *event,
                           int index, char *err, size_t err_len)
{
    json_t *spec = json_object_get(event, "competence");
    const char *subject = json_string_value(json_object_get(spec, "subject"));
    const char *capability =
        json_string_value(json_object_get(spec, "capability"));
    double got = at_prequential_competence(est, subject, capability);
    double want = json_number_value(json_object_get(event, "value"));
    /* The neutral case is EXACT, not approximate: "the authored
     * transaction_weight, verbatim" is the documented behaviour, and a
     * multiplier of 1.0 + 1e-12 would silently perturb a weight the operator
     * authored. Compared against the constant rather than against a literal,
     * so this stays a float-equality check the project's -Wfloat-equal build
     * does not object to. */
    if (fabs(want - AT_PREQ_NEUTRAL_COMPETENCE) < PREQ_TOL
        && fabs(got - AT_PREQ_NEUTRAL_COMPETENCE) > 0.0)
    {
        snprintf(err, err_len,
                 "event %d: expected exactly the neutral multiplier, got %.17g",
                 index, got);
        return -1;
    }
    if (fabs(got - want) > PREQ_TOL)
    {
        snprintf(err, err_len, "event %d: competence %.17g, expected %.17g",
                 index, got, want);
        return -1;
    }
    return 0;
}

static int _run_weight(at_prequential_estimator_t *est, json_t *event,
                       int index, char *err, size_t err_len)
{
    json_t *spec = json_object_get(event, "weight");
    const char *subject = json_string_value(json_object_get(spec, "subject"));
    const char *capability =
        json_string_value(json_object_get(spec, "capability"));
    int authored =
        (int)json_integer_value(json_object_get(spec, "transaction_weight"));
    double competence = at_prequential_competence(est, subject, capability);
    /* The composition rep_proc.c performs on the LOCAL path, minus the
     * channel multiplier the scenario does not vary: authored x competence,
     * rounded by the rule both runtimes share, floored at one fold. */
    int got = at_preq_weight_round((double)authored * competence);
    int want = (int)json_integer_value(json_object_get(event, "value"));
    if (got != want)
    {
        snprintf(err, err_len,
                 "event %d: authored %d x %.17g composed to weight %d, "
                 "expected %d", index, authored, competence, got, want);
        return -1;
    }
    return 0;
}

static int _run_aggregate(at_prequential_estimator_t *est, json_t *event,
                          int index, char *err, size_t err_len)
{
    json_t *spec = json_object_get(event, "aggregate");
    const char *quantity = json_string_value(json_object_get(spec, "quantity"));
    double now = json_number_value(json_object_get(spec, "now"));
    at_preq_aggregate_t agg;
    bool have = at_prequential_combine(est, quantity, now, &agg);

    if (json_is_true(json_object_get(event, "absent")))
    {
        if (have)
        {
            snprintf(err, err_len, "event %d: expected no aggregate, got one",
                     index);
            return -1;
        }
        return 0;
    }
    if (!have)
    {
        snprintf(err, err_len, "event %d: expected an aggregate, got none",
                 index);
        return -1;
    }
    const char *keys[2] = {"lo", "hi"};
    for (int k = 0; k < 2; k++)
    {
        json_t *want = json_object_get(event, keys[k]);
        if (want == NULL)
            continue;
        const double *got = (k == 0) ? agg.lo : agg.hi;
        if ((int)json_array_size(want) != agg.n_components)
        {
            snprintf(err, err_len,
                     "event %d: aggregate %s has %d component(s), expected %d",
                     index, keys[k], agg.n_components,
                     (int)json_array_size(want));
            return -1;
        }
        for (int i = 0; i < agg.n_components; i++)
        {
            double w = json_number_value(json_array_get(want, (size_t)i));
            if (fabs(got[i] - w) > PREQ_TOL)
            {
                snprintf(err, err_len,
                         "event %d: aggregate %s[%d] is %.17g, expected %.17g",
                         index, keys[k], i, got[i], w);
                return -1;
            }
        }
    }
    json_t *want_n = json_object_get(event, "contributors");
    if (want_n != NULL
        && agg.n_contributors != (int)json_integer_value(want_n))
    {
        snprintf(err, err_len,
                 "event %d: aggregate has %d contributor(s), expected %d",
                 index, agg.n_contributors,
                 (int)json_integer_value(want_n));
        return -1;
    }
    json_t *want_w = json_object_get(event, "weights");
    if (want_w != NULL)
    {
        if ((int)json_array_size(want_w) != agg.n_contributors)
        {
            snprintf(err, err_len,
                     "event %d: %d aggregate weight(s), expected %d", index,
                     agg.n_contributors, (int)json_array_size(want_w));
            return -1;
        }
        for (int i = 0; i < agg.n_contributors; i++)
        {
            double w = json_number_value(json_array_get(want_w, (size_t)i));
            if (fabs(agg.contributors[i].weight - w) > PREQ_TOL)
            {
                snprintf(err, err_len,
                         "event %d: aggregate weight[%d] is %.17g, expected "
                         "%.17g", index, i, agg.contributors[i].weight, w);
                return -1;
            }
        }
    }
    return 0;
}

static int _run_regret(at_prequential_estimator_t *est, json_t *event,
                       int index, char *err, size_t err_len)
{
    json_t *spec = json_object_get(event, "regret");
    const char *quantity = json_string_value(json_object_get(spec, "quantity"));
    at_preq_regret_t r;
    bool have = at_prequential_regret(est, quantity, &r);

    if (json_is_true(json_object_get(event, "absent")))
    {
        if (have)
        {
            snprintf(err, err_len,
                     "event %d: expected no regret report, got one", index);
            return -1;
        }
        return 0;
    }
    if (!have)
    {
        snprintf(err, err_len, "event %d: expected a regret report, got none",
                 index);
        return -1;
    }
    const char *int_keys[3] = {"rounds", "experts", "saturated_rounds"};
    const int int_got[3] = {r.rounds, r.experts, r.saturated_rounds};
    for (int k = 0; k < 3; k++)
    {
        json_t *want = json_object_get(event, int_keys[k]);
        if (want != NULL && int_got[k] != (int)json_integer_value(want))
        {
            snprintf(err, err_len, "event %d: %s %d, expected %d", index,
                     int_keys[k], int_got[k], (int)json_integer_value(want));
            return -1;
        }
    }
    const char *dbl_keys[2] = {"mixture_loss", "aggregate_loss"};
    const double dbl_got[2] = {r.mixture_loss, r.aggregate_loss};
    for (int k = 0; k < 2; k++)
    {
        json_t *want = json_object_get(event, dbl_keys[k]);
        if (want != NULL
            && fabs(dbl_got[k] - json_number_value(want)) > PREQ_TOL)
        {
            snprintf(err, err_len, "event %d: %s %.17g, expected %.17g", index,
                     dbl_keys[k], dbl_got[k], json_number_value(want));
            return -1;
        }
    }
    if (json_is_true(json_object_get(event, "bound_holds")))
    {
        /* The guarantee, checked rather than quoted: for every peer, the
         * mixture's realized excess over that peer's own loss on the rounds
         * that peer was awake stays under Hedge's bound. Per peer, because
         * the sleeping-experts claim IS per specialist. */
        for (int p = 0; p < r.n_peers; p++)
        {
            if (!(r.peers[p].realized < r.peers[p].bound))
            {
                snprintf(err, err_len,
                         "event %d: realized regret %.17g against %s is not "
                         "below the bound %.17g", index, r.peers[p].realized,
                         r.peers[p].peer, r.peers[p].bound);
                return -1;
            }
        }
    }
    return 0;
}

static int _run_peer_regret(at_prequential_estimator_t *est, json_t *event,
                            int index, char *err, size_t err_len)
{
    json_t *spec = json_object_get(event, "peer_regret");
    const char *quantity = json_string_value(json_object_get(spec, "quantity"));
    const char *peer = json_string_value(json_object_get(spec, "peer"));
    at_preq_regret_t r;
    if (!at_prequential_regret(est, quantity, &r))
    {
        snprintf(err, err_len, "event %d: no regret report to read", index);
        return -1;
    }
    const at_preq_peer_regret_t *row = NULL;
    for (int p = 0; p < r.n_peers; p++)
        if (peer != NULL && strcmp(r.peers[p].peer, peer) == 0)
            row = &r.peers[p];
    if (row == NULL)
    {
        snprintf(err, err_len, "event %d: %s is not in the regret report",
                 index, peer ? peer : "(null)");
        return -1;
    }
    json_t *want_rounds = json_object_get(event, "rounds");
    if (want_rounds != NULL
        && row->rounds != (int)json_integer_value(want_rounds))
    {
        snprintf(err, err_len,
                 "event %d: %s was awake %d round(s), expected %d", index,
                 peer, row->rounds, (int)json_integer_value(want_rounds));
        return -1;
    }
    const char *keys[2] = {"cumulative_loss", "bound"};
    const double got[2] = {row->cumulative_loss, row->bound};
    for (int k = 0; k < 2; k++)
    {
        json_t *want = json_object_get(event, keys[k]);
        if (want != NULL && fabs(got[k] - json_number_value(want)) > PREQ_TOL)
        {
            snprintf(err, err_len, "event %d: %s %s %.17g, expected %.17g",
                     index, peer, keys[k], got[k], json_number_value(want));
            return -1;
        }
    }
    return 0;
}

void at_prequential_conformance_run(const at_case_t *c, at_case_result_t *out)
{
    if (strcmp(c->kind, "scenario") != 0)
    {
        char detail[160];
        snprintf(detail, sizeof(detail),
                 "C prequential adapter only handles kind:scenario (got %s)",
                 c->kind);
        at_case_result_set_skip(out, detail);
        return;
    }

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    char err[512] = {0};
    int rc = -1;

    /* One estimator for the whole scenario: the multiplier IS the accumulated
     * record, so the stores have to carry from event to event. Static for the
     * same reason the calibration adapter's auditor is -- the struct holds
     * fixed arrays and is far too large for this frame. */
    static at_prequential_estimator_t est;

    json_t *fixtures = json_object_get(c->data, "fixtures");
    json_t *decl = fixtures ? json_object_get(fixtures, "prequential") : NULL;
    json_t *physics = fixtures ? json_object_get(fixtures, "physics") : NULL;
    if (!json_is_object(decl))
    {
        snprintf(err, sizeof(err),
                 "prequential scenario needs fixtures.prequential");
        goto done;
    }

    char *decl_text = json_dumps(decl, JSON_COMPACT);
    if (decl_text == NULL)
    {
        snprintf(err, sizeof(err), "cannot re-encode fixtures.prequential");
        goto done;
    }
    at_prequential_model_t model;
    char model_err[AT_PREQ_ERR_LEN] = {0};
    bool parsed = at_prequential_model_parse(decl_text, &model, model_err,
                                             sizeof(model_err));
    free(decl_text);
    if (!parsed)
    {
        snprintf(err, sizeof(err), "fixtures.prequential rejected: %s",
                 model_err);
        goto done;
    }
    at_prequential_estimator_init(&est, &model);

    json_t *events = fixtures ? json_object_get(fixtures, "events") : NULL;
    size_t i;
    json_t *event;
    json_array_foreach(events, i, event)
    {
        int index = (int)i + 1;
        double t = json_number_value(json_object_get(event, "t"));

        if (json_object_get(event, "forecast") != NULL)
        {
            if (_run_forecast(&est, event, index, err, sizeof(err)) != 0)
                goto done;
        }
        else if (json_object_get(event, "report") != NULL)
        {
            json_t *spec = json_object_get(event, "report");
            const char *cap =
                json_string_value(json_object_get(spec, "capability"));
            const char *subject =
                json_string_value(json_object_get(event, "subject"));
            const char *quantity = _quantity_for_capability(physics, cap);
            int settled = 0;
            if (quantity != NULL)
            {
                char text[512];
                _result_text(json_object_get(spec, "result"), text,
                             sizeof(text));
                settled = at_prequential_settle_result(&est, quantity, text,
                                                       subject, t);
            }
            if (_check_settled(event, index, settled, err, sizeof(err)) != 0)
                goto done;
        }
        else if (json_object_get(event, "resolve") != NULL)
        {
            json_t *spec = json_object_get(event, "resolve");
            const char *quantity =
                json_string_value(json_object_get(spec, "quantity"));
            const char *reporter =
                json_string_value(json_object_get(spec, "reporter"));
            double values[AT_PREQ_MAX_COMPONENTS];
            size_t n = _values(json_object_get(spec, "value"), values,
                               AT_PREQ_MAX_COMPONENTS);
            int settled = 0;
            if (quantity != NULL && n > 0)
                settled = at_prequential_settle(&est, quantity, values, n, t,
                                                reporter);
            if (_check_settled(event, index, settled, err, sizeof(err)) != 0)
                goto done;
        }
        else if (json_object_get(event, "outstanding") != NULL)
        {
            json_t *spec = json_object_get(event, "outstanding");
            const char *quantity =
                json_string_value(json_object_get(spec, "quantity"));
            int want = (int)json_integer_value(json_object_get(spec, "count"));
            int got = _outstanding_count(&est, quantity);
            if (got != want)
            {
                snprintf(err, sizeof(err),
                         "event %d: %s has %d outstanding forecast(s), "
                         "expected %d", index,
                         quantity ? quantity : "(null)", got, want);
                goto done;
            }
        }
        else if (json_object_get(event, "outcomes") != NULL)
        {
            json_t *spec = json_object_get(event, "outcomes");
            const char *subject =
                json_string_value(json_object_get(spec, "subject"));
            const char *cap =
                json_string_value(json_object_get(spec, "capability"));
            int want = (int)json_integer_value(json_object_get(spec, "count"));
            int got = _outcome_count(&est, subject, cap);
            if (got != want)
            {
                snprintf(err, sizeof(err),
                         "event %d: %s/%s has %d resolved loss(es), expected "
                         "%d", index, subject ? subject : "(null)",
                         cap ? cap : "(null)", got, want);
                goto done;
            }
        }
        else if (json_object_get(event, "competence") != NULL)
        {
            if (_run_competence(&est, event, index, err, sizeof(err)) != 0)
                goto done;
        }
        else if (json_object_get(event, "weight") != NULL)
        {
            if (_run_weight(&est, event, index, err, sizeof(err)) != 0)
                goto done;
        }
        else if (json_object_get(event, "aggregate") != NULL)
        {
            if (_run_aggregate(&est, event, index, err, sizeof(err)) != 0)
                goto done;
        }
        else if (json_object_get(event, "regret") != NULL)
        {
            if (_run_regret(&est, event, index, err, sizeof(err)) != 0)
                goto done;
        }
        else if (json_object_get(event, "peer_regret") != NULL)
        {
            if (_run_peer_regret(&est, event, index, err, sizeof(err)) != 0)
                goto done;
        }
        else
        {
            snprintf(err, sizeof(err), "event %d: unrecognised event", index);
            goto done;
        }
    }
    rc = 0;

done:
    clock_gettime(CLOCK_MONOTONIC, &t1);
    int ms = (int)((t1.tv_sec - t0.tv_sec) * 1000
                   + (t1.tv_nsec - t0.tv_nsec) / 1000000);
    if (rc == 0)
        at_case_result_set_pass(out, ms);
    else
        at_case_result_set_fail(out, ms, "AssertionError", err);
}
