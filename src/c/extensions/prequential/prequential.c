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

#include "prequential/prequential.h"
#include "prequential/scoring.h"
#include "utilities/util.h"   /* at_strlcpy */

#include <math.h>
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
static int _intern_quantity(at_prequential_model_t *model, const char *name)
{
    for (int i = 0; i < model->n_quantities; i++)
        if (strcmp(model->quantities[i], name) == 0)
            return i;
    if (model->n_quantities >= AT_PREQ_MAX_QUANTITIES)
        return -1;
    int idx = model->n_quantities++;
    at_strlcpy(model->quantities[idx], name, sizeof(model->quantities[idx]));
    return idx;
}

static int _capability_index(const at_prequential_model_t *model,
                             const char *capability)
{
    if (capability == NULL)
        return -1;
    for (int i = 0; i < model->n_capabilities; i++)
        if (strcmp(model->capabilities[i].capability, capability) == 0)
            return i;
    return -1;
}

static int _quantity_index(const at_prequential_model_t *model,
                           const char *quantity)
{
    if (quantity == NULL)
        return -1;
    for (int i = 0; i < model->n_quantities; i++)
        if (strcmp(model->quantities[i], quantity) == 0)
            return i;
    return -1;
}

static int _find_peer(const at_prequential_estimator_t *est, const char *peer)
{
    if (peer == NULL)
        return -1;
    for (int i = 0; i < est->n_peers; i++)
        if (strcmp(est->peers[i], peer) == 0)
            return i;
    return -1;
}

/* Index of @p peer, appending it if new. -1 when the table is full, in which
 * case the peer is simply not weighted: dropping the OLDEST instead would let
 * an attacker flush an unflattering record by introducing identities. */
static int _peer_index(at_prequential_estimator_t *est, const char *peer)
{
    int found = _find_peer(est, peer);
    if (found >= 0)
        return found;
    if (peer == NULL || est->n_peers >= AT_PREQ_MAX_PEERS)
        return -1;
    int idx = est->n_peers++;
    at_strlcpy(est->peers[idx], peer, sizeof(est->peers[idx]));
    memset(est->losses[idx], 0, sizeof(est->losses[idx]));
    return idx;
}

/* ------------------------------------------------------------------------ */
/* Declaration                                                                */
/* ------------------------------------------------------------------------ */

bool at_prequential_model_parse(const char *json_text,
                                at_prequential_model_t *out,
                                char *err, size_t err_len)
{
    if (out == NULL)
        return false;
    memset(out, 0, sizeof(*out));
    out->min_samples = AT_PREQ_DEFAULT_MIN_SAMPLES;
    out->max_outcomes = AT_PREQ_MAX_OUTCOMES;
    out->max_outstanding = AT_PREQ_MAX_OUTSTANDING;
    out->eta = AT_PREQ_DEFAULT_ETA;
    out->band_min = AT_PREQ_DEFAULT_BAND_MIN;
    out->band_max = AT_PREQ_DEFAULT_BAND_MAX;
    if (json_text == NULL || json_text[0] == '\0')
        return true;   /* the empty model: opt-in, and not configured */

    json_error_t jerr;
    json_t *root = json_loads(json_text, 0, &jerr);
    if (root == NULL)
    {
        _fail(err, err_len, "prequential: cannot parse: %s", jerr.text);
        return false;
    }
    bool ok = false;

    if (!json_is_object(root))
    {
        _fail(err, err_len, "prequential declaration must be an object");
        goto done;
    }
    json_t *v = json_object_get(root, "version");
    if (v != NULL && (!json_is_integer(v) || json_integer_value(v) != 1))
    {
        _fail(err, err_len, "unsupported prequential declaration version");
        goto done;
    }

    double d;
    if (!_number(root, "min_samples", AT_PREQ_DEFAULT_MIN_SAMPLES,
                 "prequential", &d, err, err_len))
        goto done;
    out->min_samples = (int)d;
    if (out->min_samples < 1)
    {
        _fail(err, err_len, "min_samples must be at least 1, got %d",
              out->min_samples);
        goto done;
    }
    if (!_number(root, "max_outcomes", AT_PREQ_MAX_OUTCOMES, "prequential",
                 &d, err, err_len))
        goto done;
    out->max_outcomes = (int)d;
    if (out->max_outcomes > AT_PREQ_MAX_OUTCOMES)
        out->max_outcomes = AT_PREQ_MAX_OUTCOMES;
    if (out->max_outcomes < out->min_samples)
    {
        /* Otherwise the ring can never hold enough to reach min_samples and
         * the layer is silently inert. */
        _fail(err, err_len,
              "max_outcomes (%d) is below min_samples (%d), so the weight "
              "could never move", out->max_outcomes, out->min_samples);
        goto done;
    }
    if (!_number(root, "max_outstanding", AT_PREQ_MAX_OUTSTANDING,
                 "prequential", &d, err, err_len))
        goto done;
    out->max_outstanding = (int)d;
    if (out->max_outstanding > AT_PREQ_MAX_OUTSTANDING)
        out->max_outstanding = AT_PREQ_MAX_OUTSTANDING;
    if (out->max_outstanding < 1)
    {
        _fail(err, err_len, "max_outstanding must be at least 1, got %d",
              out->max_outstanding);
        goto done;
    }
    if (!_number(root, "eta", AT_PREQ_DEFAULT_ETA, "prequential", &out->eta,
                 err, err_len))
        goto done;
    if (!(out->eta > 0.0))
    {
        _fail(err, err_len, "eta must be positive, got %g", out->eta);
        goto done;
    }
    double default_horizon;
    if (!_number(root, "horizon_sec", AT_PREQ_DEFAULT_HORIZON_SEC,
                 "prequential", &default_horizon, err, err_len))
        goto done;
    if (!(default_horizon > 0.0))
    {
        _fail(err, err_len, "horizon_sec must be positive, got %g",
              default_horizon);
        goto done;
    }

    json_t *band = json_object_get(root, "weight_band");
    if (band != NULL && !json_is_null(band))
    {
        if (!json_is_object(band))
        {
            _fail(err, err_len, "weight_band must be an object");
            goto done;
        }
        if (!_number(band, "min", AT_PREQ_DEFAULT_BAND_MIN, "weight_band",
                     &out->band_min, err, err_len))
            goto done;
        if (!_number(band, "max", AT_PREQ_DEFAULT_BAND_MAX, "weight_band",
                     &out->band_max, err, err_len))
            goto done;
    }
    if (!(out->band_min > 0.0 && out->band_min <= 1.0
          && out->band_max >= 1.0))
    {
        /* The authored transaction_weight is the anchor, so it has to be
         * inside the band. A band that excludes 1.0 makes the operator's own
         * number unreachable. */
        _fail(err, err_len,
              "weight_band must satisfy 0 < min <= 1 <= max, got %g and %g",
              out->band_min, out->band_max);
        goto done;
    }

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
            char where[AT_PREQ_NAME_LEN + 32];
            snprintf(where, sizeof(where), "capability '%.*s'",
                     AT_PREQ_NAME_LEN, name);
            if (out->n_capabilities >= AT_PREQ_MAX_CAPS)
            {
                _fail(err, err_len, "%s: more than %d forecasting capabilities",
                      where, AT_PREQ_MAX_CAPS);
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
            json_t *sc = json_object_get(decl, "scale");
            if (sc == NULL || json_is_null(sc))
            {
                /* No default is defensible: the scale is what makes a loss in
                 * one quantity's units comparable to a loss in another's, and
                 * a guessed one would silently decide how much a metre
                 * matters. */
                _fail(err, err_len,
                      "%s: scale is required (one unit of loss, in the "
                      "quantity's units)", where);
                goto done;
            }
            at_preq_forecasting_t *p = &out->capabilities[out->n_capabilities];
            memset(p, 0, sizeof(*p));
            at_strlcpy(p->capability, name, sizeof(p->capability));
            at_strlcpy(p->quantity, json_string_value(q), sizeof(p->quantity));
            p->quantity_index = _intern_quantity(out, p->quantity);
            if (p->quantity_index < 0)
            {
                _fail(err, err_len, "%s: more than %d distinct quantities",
                      where, AT_PREQ_MAX_QUANTITIES);
                goto done;
            }
            if (!_number(decl, "scale", 0.0, where, &p->scale, err, err_len))
                goto done;
            if (!(p->scale > 0.0))
            {
                _fail(err, err_len, "%s: scale must be positive, got %g",
                      where, p->scale);
                goto done;
            }
            if (!_number(decl, "alpha", AT_PREQ_DEFAULT_ALPHA, where,
                         &p->alpha, err, err_len))
                goto done;
            if (!(p->alpha > 0.0 && p->alpha < 1.0))
            {
                _fail(err, err_len, "%s: alpha must be in (0, 1), got %g",
                      where, p->alpha);
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
            if (!_number(decl, "tolerance", 0.0, where, &p->tolerance, err,
                         err_len))
                goto done;
            if (p->tolerance < 0.0)
            {
                _fail(err, err_len,
                      "%s: tolerance must not be negative, got %g", where,
                      p->tolerance);
                goto done;
            }
            /* Every capability forecasting ONE quantity must be scored at one
             * level and on one scale. Refused here rather than tie-broken at
             * runtime: the aggregate forecast is a single interval, so it has
             * a single alpha; and the mixture loss adds peers' losses
             * together, which means nothing if they are divided by different
             * scales. */
            for (int i = 0; i < out->n_capabilities; i++)
            {
                const at_preq_forecasting_t *other = &out->capabilities[i];
                if (other->quantity_index != p->quantity_index)
                    continue;
                if (fabs(other->alpha - p->alpha) > 0.0
                    || fabs(other->scale - p->scale) > 0.0)
                {
                    _fail(err, err_len,
                          "%s: forecasts %s at alpha=%g scale=%g, but %s "
                          "forecasts it at alpha=%g scale=%g; capabilities "
                          "sharing a quantity must share both", where,
                          p->quantity, p->alpha, p->scale, other->capability,
                          other->alpha, other->scale);
                    goto done;
                }
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

bool at_prequential_model_load(const char *path, at_prequential_model_t *out,
                               char *err, size_t err_len)
{
    if (out == NULL)
        return false;
    if (path == NULL)
        path = getenv("AT_PREQUENTIAL");
    if (path == NULL || path[0] == '\0')
        return at_prequential_model_parse(NULL, out, err, err_len);

    FILE *f = fopen(path, "rb");
    if (f == NULL)
    {
        memset(out, 0, sizeof(*out));
        _fail(err, err_len, "AT_PREQUENTIAL names %s, which cannot be read",
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
    bool ok = at_prequential_model_parse(text, out, err, err_len);
    free(text);
    return ok;
}

/* ------------------------------------------------------------------------ */
/* Estimator                                                                  */
/* ------------------------------------------------------------------------ */

void at_prequential_estimator_init(at_prequential_estimator_t *est,
                                   const at_prequential_model_t *model)
{
    if (est == NULL)
        return;
    memset(est, 0, sizeof(*est));
    if (model != NULL)
        est->model = *model;
}

void at_prequential_estimator_reset(at_prequential_estimator_t *est)
{
    if (est == NULL)
        return;
    for (int q = 0; q < AT_PREQ_MAX_QUANTITIES; q++)
    {
        est->pending[q].count = 0;
        memset(&est->hedge[q], 0, sizeof(est->hedge[q]));
    }
    /* Zero only the rows a peer was actually filed under; n_peers is the sole
     * thing that makes a row live, so nothing may read past it. */
    for (int p = 0; p < est->n_peers; p++)
        memset(est->losses[p], 0, sizeof(est->losses[p]));
    est->n_peers = 0;
}

bool at_prequential_enabled(const at_prequential_estimator_t *est)
{
    return est != NULL && est->model.n_capabilities > 0;
}

static int _ring_cap(const at_prequential_estimator_t *est)
{
    int cap = est->model.max_outcomes;
    if (cap <= 0 || cap > AT_PREQ_MAX_OUTCOMES)
        cap = AT_PREQ_MAX_OUTCOMES;
    return cap;
}

static void _record_loss(at_prequential_estimator_t *est, const char *subject,
                         int cap_index, double loss)
{
    int p = _peer_index(est, subject);
    if (p < 0 || cap_index < 0 || cap_index >= AT_PREQ_MAX_CAPS)
        return;
    at_preq_ring_t *ring = &est->losses[p][cap_index];
    int cap = _ring_cap(est);
    int slot = ring->head % cap;
    ring->losses[slot] = loss;
    ring->head = (slot + 1) % cap;
    if (ring->count < cap)
        ring->count++;
}

/* The mean of a ring, summed in SLOT order — the order the Python twin's
 * LossRing.mean() uses, because a floating-point sum depends on its order and
 * the two runtimes have to agree to the last bit. */
static double _ring_mean(const at_preq_ring_t *ring)
{
    if (ring->count <= 0)
        return 0.0;
    double total = 0.0;
    for (int i = 0; i < ring->count; i++)
        total += ring->losses[i];
    return total / (double)ring->count;
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

bool at_prequential_observe(at_prequential_estimator_t *est,
                            const char *capability, const json_t *prediction,
                            const char *subject, double now)
{
    if (!at_prequential_enabled(est) || subject == NULL)
        return false;
    int ci = _capability_index(&est->model, capability);
    if (ci < 0)
        return false;
    const at_preq_forecasting_t *decl = &est->model.capabilities[ci];

    if (prediction == NULL || !json_is_object(prediction))
        return false;
    double lo[AT_PREQ_MAX_COMPONENTS], hi[AT_PREQ_MAX_COMPONENTS];
    size_t n_lo = _bounds(prediction, "lo", lo, AT_PREQ_MAX_COMPONENTS);
    size_t n_hi = _bounds(prediction, "hi", hi, AT_PREQ_MAX_COMPONENTS);
    /* `coverage` is deliberately NOT read: the level this layer scores at is
     * the operator's declared alpha (see scoring.h), so a prediction carrying
     * no coverage at all is perfectly usable here. */
    if (n_lo == 0 || n_hi == 0 || n_lo != n_hi)
        return false;
    for (size_t i = 0; i < n_lo; i++)
        if (lo[i] > hi[i])
            return false;

    int qi = decl->quantity_index;
    if (qi < 0 || qi >= AT_PREQ_MAX_QUANTITIES)
        return false;
    at_preq_pending_t *pending = &est->pending[qi];
    int cap = est->model.max_outstanding;
    if (cap <= 0 || cap > AT_PREQ_MAX_OUTSTANDING)
        cap = AT_PREQ_MAX_OUTSTANDING;
    if (pending->count >= cap)
    {
        /* Full: drop the OLDEST, which is the one closest to expiring
         * unscored anyway. */
        memmove(&pending->items[0], &pending->items[1],
                sizeof(pending->items[0]) * (size_t)(cap - 1));
        pending->count = cap - 1;
    }
    at_preq_forecast_entry_t *slot = &pending->items[pending->count++];
    memset(slot, 0, sizeof(*slot));
    at_strlcpy(slot->subject, subject, sizeof(slot->subject));
    slot->capability = ci;
    slot->n_components = (int)n_lo;
    for (size_t i = 0; i < n_lo; i++)
    {
        slot->lo[i] = lo[i];
        slot->hi[i] = hi[i];
    }
    slot->alpha = decl->alpha;
    slot->scale = decl->scale;
    slot->tolerance = decl->tolerance;
    slot->made_at = now;
    slot->deadline = now + decl->horizon_sec;
    return true;
}

/* The vincentized forecast the aggregate query would have returned, scored the
 * same way — tracked so the Jensen step behind the bound is measured rather
 * than assumed. Mirrors the Python twin's _aggregate_loss. */
static double _aggregate_loss(const at_preq_forecast_entry_t **awake,
                              const double *weights, int n_awake,
                              const double *actual, size_t n_actual)
{
    double lo[AT_PREQ_MAX_COMPONENTS] = {0};
    double hi[AT_PREQ_MAX_COMPONENTS] = {0};
    double total = 0.0;
    for (int i = 0; i < n_awake; i++)
    {
        if ((size_t)awake[i]->n_components != n_actual)
            continue;
        total += weights[i];
        for (size_t c = 0; c < n_actual; c++)
        {
            lo[c] += weights[i] * awake[i]->lo[c];
            hi[c] += weights[i] * awake[i]->hi[c];
        }
    }
    if (!(total > 0.0))
        return AT_PREQ_MAX_LOSS;
    /* Renormalize over what was included, in case a forecast of another arity
     * was left out — unconditionally, both because dividing by exactly 1.0 is
     * exact in IEEE and because a `total != 1.0` guard would be a float
     * equality comparison. */
    for (size_t c = 0; c < n_actual; c++)
    {
        lo[c] /= total;
        hi[c] /= total;
    }
    double raw = at_preq_interval_score(lo, hi, n_actual, actual, n_actual,
                                        awake[0]->alpha, awake[0]->tolerance);
    if (raw < 0.0)
        return AT_PREQ_MAX_LOSS;
    return at_preq_normalized_loss(raw, awake[0]->scale);
}

int at_prequential_settle(at_prequential_estimator_t *est,
                          const char *quantity,
                          const double *actual, size_t n_actual,
                          double now, const char *reporter)
{
    if (!at_prequential_enabled(est) || quantity == NULL || actual == NULL
        || n_actual == 0)
        return 0;
    int qi = _quantity_index(&est->model, quantity);
    if (qi < 0)
        return 0;
    at_preq_pending_t *pending = &est->pending[qi];
    if (pending->count == 0)
        return 0;

    /* Partition into the AWAKE set and what stays outstanding. Both walks are
     * in slot order, so the loss vector below is in the same order the Python
     * twin builds it. */
    const at_preq_forecast_entry_t *awake[AT_PREQ_MAX_OUTSTANDING];
    int n_awake = 0;
    int kept = 0;
    static at_preq_forecast_entry_t keep[AT_PREQ_MAX_OUTSTANDING];
    for (int i = 0; i < pending->count; i++)
    {
        const at_preq_forecast_entry_t *f = &pending->items[i];
        if (now > f->deadline)
        {
            /* Expired unresolved. Dropped rather than scored at the ceiling:
             * nothing was observed, so there is no evidence either way, and
             * charging silence to a peer would let a quiet sensor convict an
             * honest forecaster. */
            continue;
        }
        if (reporter != NULL && strcmp(reporter, f->subject) == 0)
        {
            /* A peer's own report cannot resolve its own forecast; left
             * outstanding for some other observer to settle. */
            keep[kept++] = *f;
            continue;
        }
        awake[n_awake++] = f;
    }
    if (n_awake == 0)
    {
        for (int i = 0; i < kept; i++)
            pending->items[i] = keep[i];
        pending->count = kept;
        return 0;
    }

    double losses[AT_PREQ_MAX_OUTSTANDING];
    double cum[AT_PREQ_MAX_OUTSTANDING];
    double weights[AT_PREQ_MAX_OUTSTANDING];
    at_preq_quantity_record_t *record = &est->hedge[qi];
    for (int i = 0; i < n_awake; i++)
    {
        double raw = at_preq_interval_score(
            awake[i]->lo, awake[i]->hi, (size_t)awake[i]->n_components,
            actual, n_actual, awake[i]->alpha, awake[i]->tolerance);
        /* A forecast that committed to a shape the observation contradicts is
         * the worst case, not an absent one. */
        losses[i] = (raw < 0.0) ? AT_PREQ_MAX_LOSS
                                : at_preq_normalized_loss(raw, awake[i]->scale);
        int pi = _find_peer(est, awake[i]->subject);
        cum[i] = (pi >= 0) ? record->peers[pi].cumulative_loss : 0.0;
    }
    at_preq_hedge_weights(cum, (size_t)n_awake, est->model.eta, weights);

    double mixture = 0.0;
    for (int i = 0; i < n_awake; i++)
        mixture += weights[i] * losses[i];
    double aggregate = _aggregate_loss(awake, weights, n_awake, actual,
                                       n_actual);

    record->rounds++;
    record->mixture_loss += mixture;
    record->aggregate_loss += aggregate;
    for (int i = 0; i < n_awake; i++)
        if (losses[i] >= AT_PREQ_MAX_LOSS)
        {
            /* A saturated round is the one where the aggregate may score worse
             * than the mixture; counted so that comparison is read with the
             * caveat rather than as a violated guarantee. */
            record->saturated_rounds++;
            break;
        }

    for (int i = 0; i < n_awake; i++)
    {
        _record_loss(est, awake[i]->subject, awake[i]->capability, losses[i]);
        int pi = _find_peer(est, awake[i]->subject);
        if (pi < 0)
            continue;
        at_preq_peer_record_t *entry = &record->peers[pi];
        entry->seen = true;
        entry->cumulative_loss += losses[i];
        entry->rounds++;
        entry->mixture_on_awake += mixture;
    }

    for (int i = 0; i < kept; i++)
        pending->items[i] = keep[i];
    pending->count = kept;
    return n_awake;
}

/* Pull a value vector out of a result payload: a bare number, a JSON array, or
 * an object with a `value`/`values` member. Mirrors the Python twin's
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

int at_prequential_settle_result(at_prequential_estimator_t *est,
                                 const char *quantity, const char *result_str,
                                 const char *subject, double now)
{
    if (!at_prequential_enabled(est) || quantity == NULL || subject == NULL)
        return 0;
    double values[AT_PREQ_MAX_COMPONENTS];
    size_t n = _result_values(result_str, values, AT_PREQ_MAX_COMPONENTS);
    if (n == 0)
        return 0;
    return at_prequential_settle(est, quantity, values, n, now, subject);
}

double at_prequential_competence(const at_prequential_estimator_t *est,
                                 const char *subject, const char *capability)
{
    if (!at_prequential_enabled(est) || subject == NULL)
        return AT_PREQ_NEUTRAL_COMPETENCE;
    int ci = _capability_index(&est->model, capability);
    if (ci < 0)
        return AT_PREQ_NEUTRAL_COMPETENCE;
    int pi = _find_peer(est, subject);
    if (pi < 0)
        return AT_PREQ_NEUTRAL_COMPETENCE;
    const at_preq_ring_t *ring = &est->losses[pi][ci];
    if (ring->count < est->model.min_samples)
    {
        /* Silence rather than a guess: the weight does not move until there is
         * something to move it with. */
        return AT_PREQ_NEUTRAL_COMPETENCE;
    }
    return at_preq_band_multiplier(_ring_mean(ring), est->model.band_min,
                                   est->model.band_max);
}

bool at_prequential_combine(const at_prequential_estimator_t *est,
                            const char *quantity, double now,
                            at_preq_aggregate_t *out)
{
    if (out == NULL)
        return false;
    memset(out, 0, sizeof(*out));
    if (!at_prequential_enabled(est) || quantity == NULL)
        return false;
    int qi = _quantity_index(&est->model, quantity);
    if (qi < 0)
        return false;
    const at_preq_pending_t *pending = &est->pending[qi];

    const at_preq_forecast_entry_t *awake[AT_PREQ_MAX_OUTSTANDING];
    int n_awake = 0;
    for (int i = 0; i < pending->count; i++)
        if (now <= pending->items[i].deadline)
            awake[n_awake++] = &pending->items[i];
    if (n_awake == 0)
        return false;

    /* One arity, because a box has one shape: take the arity the largest
     * number of forecasts agree on, ties to the earliest, and leave the rest
     * out rather than combining shapes that are not the same claim. */
    int counts[AT_PREQ_MAX_COMPONENTS + 1] = {0};
    for (int i = 0; i < n_awake; i++)
        if (awake[i]->n_components >= 0
            && awake[i]->n_components <= AT_PREQ_MAX_COMPONENTS)
            counts[awake[i]->n_components]++;
    int arity = 0, best = 0;
    for (int i = 0; i < n_awake; i++)   /* slot order, so ties go earliest */
    {
        int n = awake[i]->n_components;
        if (n >= 0 && n <= AT_PREQ_MAX_COMPONENTS && counts[n] > best)
        {
            arity = n;
            best = counts[n];
        }
    }
    int n_use = 0;
    for (int i = 0; i < n_awake; i++)
        if (awake[i]->n_components == arity)
            awake[n_use++] = awake[i];
    n_awake = n_use;
    if (n_awake == 0 || arity == 0)
        return false;

    double cum[AT_PREQ_MAX_OUTSTANDING];
    double weights[AT_PREQ_MAX_OUTSTANDING];
    const at_preq_quantity_record_t *record = &est->hedge[qi];
    for (int i = 0; i < n_awake; i++)
    {
        int pi = _find_peer(est, awake[i]->subject);
        cum[i] = (pi >= 0) ? record->peers[pi].cumulative_loss : 0.0;
    }
    at_preq_hedge_weights(cum, (size_t)n_awake, est->model.eta, weights);

    at_strlcpy(out->quantity, quantity, sizeof(out->quantity));
    out->n_components = arity;
    /* Every capability forecasting one quantity declares the same alpha and
     * scale (enforced at load), so the aggregate has one unambiguous level. */
    out->alpha = awake[0]->alpha;
    for (int i = 0; i < n_awake; i++)
    {
        for (int c = 0; c < arity; c++)
        {
            out->lo[c] += weights[i] * awake[i]->lo[c];
            out->hi[c] += weights[i] * awake[i]->hi[c];
        }
        at_preq_contributor_t *contributor =
            &out->contributors[out->n_contributors++];
        at_strlcpy(contributor->peer, awake[i]->subject,
                   sizeof(contributor->peer));
        at_strlcpy(contributor->capability,
                   est->model.capabilities[awake[i]->capability].capability,
                   sizeof(contributor->capability));
        contributor->weight = weights[i];
    }
    return true;
}

bool at_prequential_regret(const at_prequential_estimator_t *est,
                           const char *quantity, at_preq_regret_t *out)
{
    if (out == NULL)
        return false;
    memset(out, 0, sizeof(*out));
    if (!at_prequential_enabled(est) || quantity == NULL)
        return false;
    int qi = _quantity_index(&est->model, quantity);
    if (qi < 0)
        return false;
    const at_preq_quantity_record_t *record = &est->hedge[qi];
    if (record->rounds <= 0)
        return false;

    at_strlcpy(out->quantity, quantity, sizeof(out->quantity));
    out->rounds = record->rounds;
    out->mixture_loss = record->mixture_loss;
    out->aggregate_loss = record->aggregate_loss;
    out->saturated_rounds = record->saturated_rounds;
    for (int p = 0; p < est->n_peers; p++)
        if (record->peers[p].seen)
            out->experts++;
    for (int p = 0; p < est->n_peers; p++)
    {
        const at_preq_peer_record_t *entry = &record->peers[p];
        if (!entry->seen)
            continue;
        at_preq_peer_regret_t *slot = &out->peers[out->n_peers++];
        at_strlcpy(slot->peer, est->peers[p], sizeof(slot->peer));
        slot->cumulative_loss = entry->cumulative_loss;
        slot->rounds = entry->rounds;
        slot->realized = entry->mixture_on_awake - entry->cumulative_loss;
        slot->bound = at_preq_hedge_bound(out->experts, entry->rounds,
                                          est->model.eta);
    }
    return true;
}
