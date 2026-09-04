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

#include "calibration/calibration.h"
#include "calibration/conformal.h"
#include "utilities/util.h"   /* at_strlcpy */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------------ */
/* Helpers                                                                    */
/* ------------------------------------------------------------------------ */

static void _fail(char *err, size_t err_len, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

static void _fail(char *err, size_t err_len, const char *fmt, ...)
{
    if (err == NULL || err_len == 0)
        return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err, err_len, fmt, ap);
    va_end(ap);
}

/* A JSON number, or @p dflt when the key is absent or null. Returns false and
 * fills @p err when it is present but not a number. */
static bool _number(const json_t *obj, const char *key, double dflt,
                    const char *where, double *out, char *err, size_t err_len)
{
    *out = dflt;
    if (obj == NULL)
        return true;
    json_t *v = json_object_get((json_t *)obj, key);
    if (v == NULL || json_is_null(v))
        return true;
    if (!json_is_number(v))
    {
        _fail(err, err_len, "%s: %s must be a number", where, key);
        return false;
    }
    *out = json_number_value(v);
    return true;
}

/* Index of @p name in the quantity table, appending it if new. -1 if full. */
static int _intern_quantity(at_calibration_model_t *model, const char *name)
{
    for (int i = 0; i < model->n_quantities; i++)
        if (strcmp(model->quantities[i], name) == 0)
            return i;
    if (model->n_quantities >= AT_CAL_MAX_QUANTITIES)
        return -1;
    int idx = model->n_quantities++;
    at_strlcpy(model->quantities[idx], name, sizeof(model->quantities[idx]));
    return idx;
}

static int _capability_index(const at_calibration_model_t *model,
                             const char *capability)
{
    if (capability == NULL)
        return -1;
    for (int i = 0; i < model->n_capabilities; i++)
        if (strcmp(model->capabilities[i].capability, capability) == 0)
            return i;
    return -1;
}

static int _quantity_index(const at_calibration_model_t *model,
                           const char *quantity)
{
    if (quantity == NULL)
        return -1;
    for (int i = 0; i < model->n_quantities; i++)
        if (strcmp(model->quantities[i], quantity) == 0)
            return i;
    return -1;
}

/* Index of @p peer, appending it if new. -1 when the table is full, in which
 * case the peer is simply not audited: dropping the OLDEST peer instead would
 * let an attacker flush an incriminating record by introducing identities. */
static int _peer_index(at_calibration_auditor_t *auditor, const char *peer)
{
    for (int i = 0; i < auditor->n_peers; i++)
        if (strcmp(auditor->peers[i], peer) == 0)
            return i;
    if (auditor->n_peers >= AT_CAL_MAX_PEERS)
        return -1;
    int idx = auditor->n_peers++;
    at_strlcpy(auditor->peers[idx], peer, sizeof(auditor->peers[idx]));
    memset(auditor->outcomes[idx], 0, sizeof(auditor->outcomes[idx]));
    return idx;
}

/* ------------------------------------------------------------------------ */
/* Declaration                                                                */
/* ------------------------------------------------------------------------ */

bool at_calibration_model_parse(const char *json_text,
                                at_calibration_model_t *out,
                                char *err, size_t err_len)
{
    if (out == NULL)
        return false;
    memset(out, 0, sizeof(*out));
    out->min_samples = AT_CAL_DEFAULT_MIN_SAMPLES;
    out->audit_alpha = AT_CAL_DEFAULT_AUDIT_ALPHA;
    out->max_outcomes = AT_CAL_MAX_OUTCOMES;
    out->max_outstanding = AT_CAL_MAX_OUTSTANDING;
    if (json_text == NULL || json_text[0] == '\0')
        return true;   /* the empty model: opt-in, and not configured */

    json_error_t jerr;
    json_t *root = json_loads(json_text, 0, &jerr);
    if (root == NULL)
    {
        _fail(err, err_len, "calibration: cannot parse: %s", jerr.text);
        return false;
    }
    bool ok = false;

    if (!json_is_object(root))
    {
        _fail(err, err_len, "calibration declaration must be an object");
        goto done;
    }
    json_t *v = json_object_get(root, "version");
    if (v != NULL && (!json_is_integer(v) || json_integer_value(v) != 1))
    {
        _fail(err, err_len, "unsupported calibration declaration version");
        goto done;
    }

    double d;
    if (!_number(root, "min_samples", AT_CAL_DEFAULT_MIN_SAMPLES,
                 "calibration", &d, err, err_len))
        goto done;
    out->min_samples = (int)d;
    if (out->min_samples < 1)
    {
        _fail(err, err_len, "min_samples must be at least 1, got %d",
              out->min_samples);
        goto done;
    }
    if (!_number(root, "audit_alpha", AT_CAL_DEFAULT_AUDIT_ALPHA,
                 "calibration", &out->audit_alpha, err, err_len))
        goto done;
    if (!(out->audit_alpha > 0.0 && out->audit_alpha < 1.0))
    {
        _fail(err, err_len, "audit_alpha must be in (0, 1), got %g",
              out->audit_alpha);
        goto done;
    }
    if (!_number(root, "max_outcomes", AT_CAL_MAX_OUTCOMES, "calibration",
                 &d, err, err_len))
        goto done;
    out->max_outcomes = (int)d;
    if (out->max_outcomes > AT_CAL_MAX_OUTCOMES)
        out->max_outcomes = AT_CAL_MAX_OUTCOMES;
    if (out->max_outcomes < out->min_samples)
    {
        /* Otherwise the ring can never hold enough to reach min_samples and
         * the layer is silently inert — exactly the failure the loader below
         * refuses to degrade into. */
        _fail(err, err_len,
              "max_outcomes (%d) is below min_samples (%d), so the audit "
              "could never speak", out->max_outcomes, out->min_samples);
        goto done;
    }
    if (!_number(root, "max_outstanding", AT_CAL_MAX_OUTSTANDING,
                 "calibration", &d, err, err_len))
        goto done;
    out->max_outstanding = (int)d;
    if (out->max_outstanding > AT_CAL_MAX_OUTSTANDING)
        out->max_outstanding = AT_CAL_MAX_OUTSTANDING;
    if (out->max_outstanding < 1)
    {
        _fail(err, err_len, "max_outstanding must be at least 1, got %d",
              out->max_outstanding);
        goto done;
    }
    double default_horizon;
    if (!_number(root, "horizon_sec", AT_CAL_DEFAULT_HORIZON_SEC,
                 "calibration", &default_horizon, err, err_len))
        goto done;

    json_t *caps = json_object_get(root, "capabilities");
    if (caps != NULL && !json_is_null(caps))
    {
        if (!json_is_object(caps))
        {
            _fail(err, err_len, "capabilities must be an object");
            goto done;
        }
        const char *name;
        json_t *decl;
        json_object_foreach(caps, name, decl)
        {
            char where[AT_CAL_NAME_LEN + 32];
            snprintf(where, sizeof(where), "capability '%.*s'",
                     AT_CAL_NAME_LEN, name);
            if (out->n_capabilities >= AT_CAL_MAX_CAPS)
            {
                _fail(err, err_len, "%s: more than %d predictive capabilities",
                      where, AT_CAL_MAX_CAPS);
                goto done;
            }
            if (!json_is_object(decl))
            {
                _fail(err, err_len, "%s: must be an object", where);
                goto done;
            }
            json_t *q = json_object_get(decl, "quantity");
            if (!json_is_string(q) || json_string_value(q)[0] == '\0')
            {
                _fail(err, err_len,
                      "%s: quantity is required and must be a string", where);
                goto done;
            }
            at_cal_predictive_t *p = &out->capabilities[out->n_capabilities];
            memset(p, 0, sizeof(*p));
            at_strlcpy(p->capability, name, sizeof(p->capability));
            at_strlcpy(p->quantity, json_string_value(q), sizeof(p->quantity));
            p->quantity_index = _intern_quantity(out, p->quantity);
            if (p->quantity_index < 0)
            {
                _fail(err, err_len, "%s: more than %d distinct quantities",
                      where, AT_CAL_MAX_QUANTITIES);
                goto done;
            }
            if (!_number(decl, "horizon_sec", default_horizon, where,
                         &p->horizon_sec, err, err_len))
                goto done;
            if (!(p->horizon_sec > 0.0))
            {
                _fail(err, err_len, "%s: horizon_sec must be positive, got %g",
                      where, p->horizon_sec);
                goto done;
            }
            if (!_number(decl, "min_coverage", AT_CAL_DEFAULT_MIN_COVERAGE,
                         where, &p->min_coverage, err, err_len))
                goto done;
            if (!_number(decl, "max_coverage", AT_CAL_DEFAULT_MAX_COVERAGE,
                         where, &p->max_coverage, err, err_len))
                goto done;
            if (!(p->min_coverage > 0.0 && p->min_coverage <= p->max_coverage
                  && p->max_coverage < 1.0))
            {
                _fail(err, err_len,
                      "%s: need 0 < min_coverage <= max_coverage < 1, "
                      "got %g and %g", where, p->min_coverage,
                      p->max_coverage);
                goto done;
            }
            if (!_number(decl, "tolerance", 0.0, where, &p->tolerance,
                         err, err_len))
                goto done;
            if (p->tolerance < 0.0)
            {
                _fail(err, err_len, "%s: tolerance must not be negative, got %g",
                      where, p->tolerance);
                goto done;
            }
            out->n_capabilities++;
        }
    }
    ok = true;

done:
    json_decref(root);
    if (!ok)
        memset(out, 0, sizeof(*out));
    return ok;
}

bool at_calibration_model_load(const char *path, at_calibration_model_t *out,
                               char *err, size_t err_len)
{
    if (out == NULL)
        return false;
    if (path == NULL)
        path = getenv("AT_CALIBRATION");
    if (path == NULL || path[0] == '\0')
        return at_calibration_model_parse(NULL, out, err, err_len);

    FILE *f = fopen(path, "rb");
    if (f == NULL)
    {
        memset(out, 0, sizeof(*out));
        _fail(err, err_len, "AT_CALIBRATION names %s, which cannot be read",
              path);
        return false;
    }
    if (fseek(f, 0, SEEK_END) != 0)
    {
        fclose(f);
        memset(out, 0, sizeof(*out));
        _fail(err, err_len, "%s: cannot size", path);
        return false;
    }
    long len = ftell(f);
    rewind(f);
    if (len < 0 || len > (long)(4 * 1024 * 1024))
    {
        fclose(f);
        memset(out, 0, sizeof(*out));
        _fail(err, err_len, "%s: implausible declaration size", path);
        return false;
    }
    char *text = (char *)calloc((size_t)len + 1, 1);
    if (text == NULL)
    {
        fclose(f);
        memset(out, 0, sizeof(*out));
        _fail(err, err_len, "%s: out of memory", path);
        return false;
    }
    size_t got = fread(text, 1, (size_t)len, f);
    fclose(f);
    text[got] = '\0';
    bool ok = at_calibration_model_parse(text, out, err, err_len);
    free(text);
    return ok;
}

/* ------------------------------------------------------------------------ */
/* Auditor                                                                    */
/* ------------------------------------------------------------------------ */

void at_calibration_auditor_init(at_calibration_auditor_t *auditor,
                                 const at_calibration_model_t *model)
{
    if (auditor == NULL)
        return;
    memset(auditor, 0, sizeof(*auditor));
    if (model != NULL)
        auditor->model = *model;
}

void at_calibration_auditor_reset(at_calibration_auditor_t *auditor)
{
    if (auditor == NULL)
        return;
    for (int q = 0; q < AT_CAL_MAX_QUANTITIES; q++)
        auditor->pending[q].count = 0;
    /* Zero only the rows a peer was actually filed under; n_peers is the sole
     * thing that makes a row live, so nothing may read past it. */
    for (int p = 0; p < auditor->n_peers; p++)
        memset(auditor->outcomes[p], 0, sizeof(auditor->outcomes[p]));
    auditor->n_peers = 0;
}

bool at_calibration_enabled(const at_calibration_auditor_t *auditor)
{
    return auditor != NULL && auditor->model.n_capabilities > 0;
}

static void _record_outcome(at_calibration_auditor_t *auditor,
                            const char *subject, int cap_index, bool hit)
{
    int p = _peer_index(auditor, subject);
    if (p < 0 || cap_index < 0 || cap_index >= AT_CAL_MAX_CAPS)
        return;
    at_cal_ring_t *ring = &auditor->outcomes[p][cap_index];
    int cap = auditor->model.max_outcomes;
    if (cap <= 0 || cap > AT_CAL_MAX_OUTCOMES)
        cap = AT_CAL_MAX_OUTCOMES;
    int slot = ring->head % cap;
    if (hit)
        ring->hits[slot / 8] |= (uint8_t)(1u << (slot % 8));
    else
        ring->hits[slot / 8] &= (uint8_t)~(1u << (slot % 8));
    ring->head = (slot + 1) % cap;
    if (ring->count < cap)
        ring->count++;
}

static int _ring_hits(const at_cal_ring_t *ring)
{
    int hits = 0;
    for (int i = 0; i < ring->count; i++)
        if (ring->hits[i / 8] & (uint8_t)(1u << (i % 8)))
            hits++;
    return hits;
}

int at_calibration_settle(at_calibration_auditor_t *auditor,
                          const char *quantity,
                          const double *actual, size_t n_actual,
                          double now, const char *reporter)
{
    if (!at_calibration_enabled(auditor) || quantity == NULL
        || actual == NULL || n_actual == 0)
        return 0;
    int qi = _quantity_index(&auditor->model, quantity);
    if (qi < 0)
        return 0;
    at_cal_pending_t *pending = &auditor->pending[qi];
    if (pending->count == 0)
        return 0;

    int settled = 0;
    int kept = 0;
    for (int i = 0; i < pending->count; i++)
    {
        at_cal_pred_t *pred = &pending->items[i];
        if (now > pred->deadline)
        {
            /* Expired unresolved. Dropped rather than counted as a miss:
             * nothing was observed, so there is no evidence either way, and
             * counting silence against a peer would let a quiet sensor
             * convict it. */
            continue;
        }
        if (reporter != NULL && strcmp(reporter, pred->subject) == 0)
        {
            /* A peer's own report cannot resolve its own prediction — that is
             * the peer supplying the truth it is audited against, and it would
             * make the whole layer self-graded. Left outstanding for some
             * other observer to settle. */
            if (kept != i)
                pending->items[kept] = *pred;
            kept++;
            continue;
        }
        bool hit = at_conformal_covers(pred->lo, pred->hi,
                                       (size_t)pred->n_components,
                                       actual, n_actual, pred->tolerance);
        _record_outcome(auditor, pred->subject, pred->capability, hit);
        settled++;
    }
    pending->count = kept;
    return settled;
}

/* Pull a value vector out of a result payload: a bare number, a JSON array, or
 * an object with a `value`/`values` member. Mirrors the Python auditor's
 * `_as_floats` applied to the same three shapes. */
static size_t _result_values(const char *result_str, double *out, size_t cap)
{
    if (result_str == NULL || result_str[0] == '\0' || out == NULL || cap == 0)
        return 0;

    char *end = NULL;
    double bare = strtod(result_str, &end);
    if (end != NULL && end != result_str)
    {
        while (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r')
            end++;
        if (*end == '\0')
        {
            out[0] = bare;
            return 1;
        }
    }

    json_error_t jerr;
    json_t *root = json_loads(result_str, 0, &jerr);
    if (root == NULL)
        return 0;
    json_t *payload = root;
    if (json_is_object(root))
    {
        json_t *v = json_object_get(root, "value");
        if (v == NULL)
            v = json_object_get(root, "values");
        payload = v;
    }
    size_t n = 0;
    if (json_is_number(payload))
    {
        out[0] = json_number_value(payload);
        n = 1;
    }
    else if (json_is_array(payload))
    {
        size_t idx;
        json_t *item;
        json_array_foreach(payload, idx, item)
        {
            if (n >= cap || !json_is_number(item))
            {
                n = 0;
                break;
            }
            out[n++] = json_number_value(item);
        }
    }
    json_decref(root);
    return n;
}

int at_calibration_settle_result(at_calibration_auditor_t *auditor,
                                 const char *quantity,
                                 const char *result_str,
                                 const char *subject, double now)
{
    if (!at_calibration_enabled(auditor) || quantity == NULL
        || subject == NULL)
        return 0;
    double values[AT_CAL_MAX_COMPONENTS];
    size_t n = _result_values(result_str, values, AT_CAL_MAX_COMPONENTS);
    if (n == 0)
        return 0;
    return at_calibration_settle(auditor, quantity, values, n, now, subject);
}

/* Read the numeric vector at @p key. Returns the count, 0 when absent or not
 * all-numeric. */
static size_t _bounds(const json_t *obj, const char *key, double *out,
                      size_t cap)
{
    json_t *v = json_object_get((json_t *)obj, key);
    if (v == NULL)
        return 0;
    if (json_is_number(v))
    {
        out[0] = json_number_value(v);
        return 1;
    }
    if (!json_is_array(v))
        return 0;
    size_t n = 0, idx;
    json_t *item;
    json_array_foreach(v, idx, item)
    {
        if (n >= cap || !json_is_number(item))
            return 0;
        out[n++] = json_number_value(item);
    }
    return n;
}

at_cal_verdict_t at_calibration_assess(at_calibration_auditor_t *auditor,
                                       const char *capability,
                                       const json_t *prediction,
                                       const char *subject, double now,
                                       double *score_out,
                                       char *reason_out, size_t reason_len)
{
    if (!at_calibration_enabled(auditor) || subject == NULL)
        return AT_CAL_NONE;
    int ci = _capability_index(&auditor->model, capability);
    if (ci < 0)
        return AT_CAL_NONE;
    const at_cal_predictive_t *decl = &auditor->model.capabilities[ci];

    /* -- validate the attached set ------------------------------------- */
    double coverage = 0.0;
    double lo[AT_CAL_MAX_COMPONENTS], hi[AT_CAL_MAX_COMPONENTS];
    size_t n_lo = 0, n_hi = 0;
    const char *absent_reason = NULL;

    if (prediction == NULL || json_is_null(prediction))
        absent_reason = "attached no prediction";
    else if (!json_is_object(prediction))
        absent_reason = "attached a prediction that is not an object";
    else
    {
        json_t *q = json_object_get((json_t *)prediction, "quantity");
        json_t *c = json_object_get((json_t *)prediction, "coverage");
        if (json_is_string(q)
            && strcmp(json_string_value(q), decl->quantity) != 0)
            absent_reason = "predicted a quantity the capability does not declare";
        else if (!json_is_number(c))
            absent_reason = "claimed a non-numeric coverage";
        else
        {
            coverage = json_number_value(c);
            if (coverage < decl->min_coverage || coverage > decl->max_coverage)
                absent_reason = "claimed a coverage outside the declared range";
            else
            {
                n_lo = _bounds(prediction, "lo", lo, AT_CAL_MAX_COMPONENTS);
                n_hi = _bounds(prediction, "hi", hi, AT_CAL_MAX_COMPONENTS);
                if (n_lo == 0 || n_hi == 0)
                    absent_reason = "attached a set without numeric lo/hi bounds";
                else if (n_lo != n_hi)
                    absent_reason = "attached mismatched lo/hi arities";
                else
                {
                    for (size_t i = 0; i < n_lo; i++)
                        if (lo[i] > hi[i])
                        {
                            absent_reason = "attached an inverted interval";
                            break;
                        }
                }
            }
        }
    }

    if (absent_reason != NULL)
    {
        if (score_out != NULL)
            *score_out = AT_CAL_ABSENT_SCORE;
        if (reason_out != NULL && reason_len > 0)
            snprintf(reason_out, reason_len, "%s declares %s predictive and %s",
                     subject, decl->capability, absent_reason);
        return AT_CAL_ABSENT;
    }

    /* -- record it ------------------------------------------------------ */
    int qi = decl->quantity_index;
    if (qi >= 0 && qi < AT_CAL_MAX_QUANTITIES)
    {
        at_cal_pending_t *pending = &auditor->pending[qi];
        int cap = auditor->model.max_outstanding;
        if (cap <= 0 || cap > AT_CAL_MAX_OUTSTANDING)
            cap = AT_CAL_MAX_OUTSTANDING;
        if (pending->count >= cap)
        {
            /* Full: drop the OLDEST, which is the one closest to expiring
             * unscored anyway. */
            memmove(&pending->items[0], &pending->items[1],
                    sizeof(pending->items[0]) * (size_t)(cap - 1));
            pending->count = cap - 1;
        }
        at_cal_pred_t *slot = &pending->items[pending->count++];
        memset(slot, 0, sizeof(*slot));
        at_strlcpy(slot->subject, subject, sizeof(slot->subject));
        slot->capability = ci;
        slot->coverage = coverage;
        slot->n_components = (int)n_lo;
        for (size_t i = 0; i < n_lo; i++)
        {
            slot->lo[i] = lo[i];
            slot->hi[i] = hi[i];
        }
        slot->tolerance = decl->tolerance;
        slot->made_at = now;
        slot->deadline = now + decl->horizon_sec;
    }

    /* -- and report this peer's standing -------------------------------- */
    int p = _peer_index(auditor, subject);
    if (p < 0)
        return AT_CAL_NONE;
    const at_cal_ring_t *ring = &auditor->outcomes[p][ci];
    if (ring->count < auditor->model.min_samples)
    {
        /* Not enough resolved predictions for the test to mean anything.
         * Silence, not leniency: "no verdict" is the honest report, and
         * finite-sample validity is the whole reason to use this test. */
        return AT_CAL_NONE;
    }
    int hits = _ring_hits(ring);
    if (!at_conformal_overconfident(hits, ring->count, coverage,
                                    auditor->model.audit_alpha))
        return AT_CAL_NONE;

    if (score_out != NULL)
        *score_out = AT_CAL_OVERCONFIDENT_SCORE;
    if (reason_out != NULL && reason_len > 0)
        snprintf(reason_out, reason_len,
                 "%s claims %.3f coverage on %s and realized %d/%d; rejected "
                 "at alpha=%.3f", subject, coverage, decl->capability, hits,
                 ring->count, auditor->model.audit_alpha);
    return AT_CAL_OVERCONFIDENT;
}
