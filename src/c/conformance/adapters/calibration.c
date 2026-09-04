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

/* C adapter for the `calibration` conformance protocol (R+D.md §12.4).
 *
 * Non-message-driven, like the physics and bootstrap adapters: the scenario
 * carries a declaration and a list of events; this loads the declaration into
 * this runtime's auditor and replays the events in order, carrying the
 * outstanding-prediction and outcome stores forward.
 *
 * Both resolution paths are exercised, because the design has two: a `report`
 * event goes through the physics-declared path (a later result for the
 * quantity's reporting capability settles the prediction) and a `resolve`
 * event through the explicit one.
 *
 * `outstanding` and `outcomes` events assert STORE state rather than a
 * verdict, and they earn their place because two of the rules have no
 * observable effect on any single score: a peer's own report not settling its
 * own prediction, and an expired prediction being dropped rather than counted
 * as a miss. Silence is also what a correctly-audited honest peer produces, so
 * a verdict-only scenario would pass with either rule broken.
 */

#include "calibration.h"

#include <math.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <jansson.h>

#include "calibration/calibration.h"
#include "reputation/tx_channel.h"

/* The reporting capability -> quantity link, out of the scenario's physics
 * fixture. Read here rather than by building a physics model, because that is
 * all this adapter needs from it and the calibration module is deliberately
 * independent of the physics one. */
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

/* Render a scenario result value the way this runtime carries it: as the text
 * a `report results` payload holds. Mirrors the Python adapter handing the
 * decoded value straight to its auditor. */
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

static int _outstanding_count(const at_calibration_auditor_t *auditor,
                              const char *quantity)
{
    for (int i = 0; i < auditor->model.n_quantities; i++)
        if (strcmp(auditor->model.quantities[i], quantity) == 0)
            return auditor->pending[i].count;
    return 0;
}

static void _outcome_counts(const at_calibration_auditor_t *auditor,
                            const char *subject, const char *capability,
                            int *n_out, int *hits_out)
{
    *n_out = 0;
    *hits_out = 0;
    int ci = -1;
    for (int i = 0; i < auditor->model.n_capabilities; i++)
        if (strcmp(auditor->model.capabilities[i].capability, capability) == 0)
            ci = i;
    if (ci < 0)
        return;
    for (int p = 0; p < auditor->n_peers; p++)
    {
        if (strcmp(auditor->peers[p], subject) != 0)
            continue;
        const at_cal_ring_t *ring = &auditor->outcomes[p][ci];
        *n_out = ring->count;
        for (int i = 0; i < ring->count; i++)
            if (ring->hits[i / 8] & (uint8_t)(1u << (i % 8)))
                (*hits_out)++;
        return;
    }
}

static int _run_predict(at_calibration_auditor_t *auditor, json_t *event,
                        int index, char *err, size_t err_len)
{
    json_t *spec = json_object_get(event, "predict");
    const char *capability =
        json_string_value(json_object_get(spec, "capability"));
    const char *subject = json_string_value(json_object_get(event, "subject"));
    double t = json_number_value(json_object_get(event, "t"));

    /* A spec carrying nothing but `capability` means "declared predictive and
     * attached nothing", which is a distinct row from "attached a malformed
     * set" — and the auditor tells them apart, so the fixture has to be able
     * to say which one it means. */
    json_t *prediction = json_deep_copy(spec);
    json_object_del(prediction, "capability");
    if (json_object_size(prediction) == 0)
    {
        json_decref(prediction);
        prediction = NULL;
    }

    double score = 0.0;
    char why[AT_CAL_ERR_LEN] = {0};
    at_cal_verdict_t verdict = at_calibration_assess(
        auditor, capability, prediction, subject, t, &score, why, sizeof(why));
    if (prediction != NULL)
        json_decref(prediction);

    json_t *want_score = json_object_get(event, "score");
    json_t *want_channel = json_object_get(event, "channel");
    bool want_none = (want_score == NULL || json_is_null(want_score));

    if (want_none)
    {
        if (verdict != AT_CAL_NONE)
        {
            snprintf(err, err_len,
                     "event %d: expected no verdict, got %.2f (%s)",
                     index, score, why);
            return -1;
        }
        return 0;
    }
    if (verdict == AT_CAL_NONE)
    {
        snprintf(err, err_len, "event %d: expected %.2f, got no verdict",
                 index, json_number_value(want_score));
        return -1;
    }
    if (fabs(score - json_number_value(want_score)) > 1e-9)
    {
        snprintf(err, err_len, "event %d: scored %.2f, expected %.2f",
                 index, score, json_number_value(want_score));
        return -1;
    }
    const char *channel = json_string_value(want_channel);
    if (channel == NULL || strcmp(channel, TX_CHANNEL_CALIBRATION) != 0)
    {
        snprintf(err, err_len,
                 "event %d: expected the calibration channel, scenario says %s",
                 index, channel ? channel : "(null)");
        return -1;
    }
    return 0;
}

void at_calibration_run(const at_case_t *c, at_case_result_t *out)
{
    if (strcmp(c->kind, "scenario") != 0)
    {
        char detail[160];
        snprintf(detail, sizeof(detail),
                 "C calibration adapter only handles kind:scenario (got %s)",
                 c->kind);
        at_case_result_set_skip(out, detail);
        return;
    }

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    char err[512] = {0};
    int rc = -1;

    /* One auditor for the whole scenario: the verdict IS the accumulated
     * record, so the stores have to carry from event to event. */
    static at_calibration_auditor_t auditor;

    json_t *fixtures = json_object_get(c->data, "fixtures");
    json_t *decl = fixtures ? json_object_get(fixtures, "calibration") : NULL;
    json_t *physics = fixtures ? json_object_get(fixtures, "physics") : NULL;
    if (!json_is_object(decl))
    {
        snprintf(err, sizeof(err),
                 "calibration scenario needs fixtures.calibration");
        goto done;
    }

    char *decl_text = json_dumps(decl, JSON_COMPACT);
    if (decl_text == NULL)
    {
        snprintf(err, sizeof(err), "cannot re-encode fixtures.calibration");
        goto done;
    }
    at_calibration_model_t model;
    char model_err[AT_CAL_ERR_LEN] = {0};
    bool parsed = at_calibration_model_parse(decl_text, &model, model_err,
                                             sizeof(model_err));
    free(decl_text);
    if (!parsed)
    {
        snprintf(err, sizeof(err), "fixtures.calibration rejected: %s",
                 model_err);
        goto done;
    }
    at_calibration_auditor_init(&auditor, &model);

    json_t *events = fixtures ? json_object_get(fixtures, "events") : NULL;
    size_t i;
    json_t *event;
    json_array_foreach(events, i, event)
    {
        int index = (int)i + 1;
        double t = json_number_value(json_object_get(event, "t"));

        if (json_object_get(event, "predict") != NULL)
        {
            if (_run_predict(&auditor, event, index, err, sizeof(err)) != 0)
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
            if (quantity != NULL)
            {
                char text[512];
                _result_text(json_object_get(spec, "result"), text,
                             sizeof(text));
                at_calibration_settle_result(&auditor, quantity, text, subject,
                                             t);
            }
        }
        else if (json_object_get(event, "resolve") != NULL)
        {
            json_t *spec = json_object_get(event, "resolve");
            const char *quantity =
                json_string_value(json_object_get(spec, "quantity"));
            double values[AT_CAL_MAX_COMPONENTS];
            size_t n = _values(json_object_get(spec, "value"), values,
                               AT_CAL_MAX_COMPONENTS);
            if (quantity != NULL && n > 0)
                at_calibration_settle(&auditor, quantity, values, n, t, NULL);
        }
        else if (json_object_get(event, "outstanding") != NULL)
        {
            json_t *spec = json_object_get(event, "outstanding");
            const char *quantity =
                json_string_value(json_object_get(spec, "quantity"));
            int want = (int)json_integer_value(json_object_get(spec, "count"));
            int got = _outstanding_count(&auditor, quantity);
            if (got != want)
            {
                snprintf(err, sizeof(err),
                         "event %d: %s has %d outstanding prediction(s), "
                         "expected %d", index, quantity, got, want);
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
            int want_n = (int)json_integer_value(json_object_get(spec, "count"));
            int want_h = (int)json_integer_value(json_object_get(spec, "hits"));
            int got_n = 0, got_h = 0;
            _outcome_counts(&auditor, subject, cap, &got_n, &got_h);
            if (got_n != want_n || got_h != want_h)
            {
                snprintf(err, sizeof(err),
                         "event %d: %s/%s has %d/%d resolutions, expected "
                         "%d/%d", index, subject, cap, got_h, got_n, want_h,
                         want_n);
                goto done;
            }
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
