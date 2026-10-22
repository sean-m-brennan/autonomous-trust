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

#include "replication/replication.h"
#include "replication/bisection.h"   /* AT_REPL_MAX_STEPS */
#include "utilities/compiler.h"   /* AT_PRINTF_FORMAT */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <jansson.h>

static void _fail(char *err, size_t err_len, const char *fmt, ...)
    __attribute__((format(AT_PRINTF_FORMAT, 3, 4)));

static void _fail(char *err, size_t err_len, const char *fmt, ...)
{
    if (err == NULL || err_len == 0)
        return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err, err_len, fmt, ap);
    va_end(ap);
}

/* A number in [0, 1], refused (not clamped) on a declaration: a bad authored
 * number is a mistake to surface. Mirrors Python _check_prob. */
static bool _check_prob(json_t *v, const char *where, double *out,
                        char *err, size_t err_len)
{
    if (!json_is_number(v))
    {
        _fail(err, err_len, "%s: not a number", where);
        return false;
    }
    double p = json_number_value(v);
    if (!(p >= 0.0 && p <= 1.0))
    {
        _fail(err, err_len, "%s: probability %g out of [0, 1]", where, p);
        return false;
    }
    *out = p;
    return true;
}

/* A bounded integer of a `replay` object: absent is @p dflt. */
static bool _check_bound(const json_t *spec, const char *key, int dflt, int low,
                         int high, const char *cap, int *out,
                         char *err, size_t err_len)
{
    json_t *v = json_object_get(spec, key);
    if (v == NULL)
    {
        *out = dflt;
        return true;
    }
    if (!json_is_integer(v) || json_integer_value(v) < low
        || json_integer_value(v) > high)
    {
        _fail(err, err_len, "capability '%.*s' replay %s: not an integer in "
              "[%d, %d]", AT_REPL_NAME_LEN, cap, key, low, high);
        return false;
    }
    *out = (int)json_integer_value(v);
    return true;
}

bool at_replication_model_parse(const char *json_text,
                                at_replication_model_t *out,
                                char *err, size_t err_len)
{
    if (out == NULL)
        return false;
    memset(out, 0, sizeof(*out));
    out->default_prob = AT_REPLICATION_DEFAULT_PROB;
    if (json_text == NULL || json_text[0] == '\0')
        return true;   /* the empty model: opt-in, not configured */

    json_error_t jerr;
    json_t *root = json_loads(json_text, 0, &jerr);
    if (root == NULL)
    {
        _fail(err, err_len, "replication: cannot parse: %s", jerr.text);
        return false;
    }
    bool ok = false;

    if (!json_is_object(root))
    {
        _fail(err, err_len, "replication declaration must be an object");
        goto done;
    }
    json_t *v = json_object_get(root, "version");
    if (v == NULL || !json_is_integer(v) || json_integer_value(v) != 1)
    {
        _fail(err, err_len, "unsupported replication declaration version");
        goto done;
    }

    json_t *dp = json_object_get(root, "default_prob");
    if (dp != NULL && !_check_prob(dp, "default_prob", &out->default_prob,
                                   err, err_len))
        goto done;

    json_t *caps = json_object_get(root, "capabilities");
    if (caps != NULL)
    {
        if (!json_is_object(caps))
        {
            _fail(err, err_len, "capabilities is not an object");
            goto done;
        }
        const char *name;
        json_t *decl;
        json_object_foreach(caps, name, decl)
        {
            if (out->num_caps >= AT_REPL_MAX_CAPS)
            {
                _fail(err, err_len, "too many capabilities (max %d)",
                      AT_REPL_MAX_CAPS);
                goto done;
            }
            char where[AT_REPL_NAME_LEN + 40];
            snprintf(where, sizeof(where),
                     "capability '%.*s' replicate_prob",
                     AT_REPL_NAME_LEN, name);
            if (!json_is_object(decl))
            {
                _fail(err, err_len, "capability '%.*s': not an object",
                      AT_REPL_NAME_LEN, name);
                goto done;
            }
            /* A replayable capability may leave its probability to
             * default_prob; any other entry exists only to set one. */
            json_t *replay = json_object_get(decl, "replay");
            int max_steps = 0, max_state_bytes = 0;
            if (replay != NULL)
            {
                if (!json_is_object(replay))
                {
                    _fail(err, err_len, "capability '%.*s' replay: not an object",
                          AT_REPL_NAME_LEN, name);
                    goto done;
                }
                if (!_check_bound(replay, "max_steps", AT_REPL_MAX_STEPS, 1,
                                  AT_REPL_MAX_STEPS, name, &max_steps, err, err_len)
                    || !_check_bound(replay, "max_state_bytes",
                                     AT_REPL_DEFAULT_MAX_STATE_BYTES, 1,
                                     AT_REPL_MAX_STATE_BYTES_LIMIT, name,
                                     &max_state_bytes, err, err_len))
                    goto done;
            }
            json_t *rp = json_object_get(decl, "replicate_prob");
            if (rp == NULL && replay == NULL)
            {
                _fail(err, err_len,
                      "capability '%.*s': missing replicate_prob",
                      AT_REPL_NAME_LEN, name);
                goto done;
            }
            double p = out->default_prob;
            if (rp != NULL && !_check_prob(rp, where, &p, err, err_len))
                goto done;
            double tol = 0.0;
            json_t *tj = json_object_get(decl, "tolerance");
            if (tj != NULL)
            {
                if (!json_is_number(tj) || json_number_value(tj) < 0.0)
                {
                    _fail(err, err_len,
                          "capability '%.*s' tolerance: not a "
                          "non-negative number", AT_REPL_NAME_LEN, name);
                    goto done;
                }
                tol = json_number_value(tj);
            }
            at_replication_cap_t *slot = &out->caps[out->num_caps++];
            snprintf(slot->capability, sizeof(slot->capability), "%s", name);
            slot->prob = p;
            slot->tolerance = tol;
            slot->has_prob = rp != NULL;
            slot->replay = replay != NULL;
            slot->max_steps = max_steps;
            slot->max_state_bytes = max_state_bytes;
        }
    }
    ok = true;

done:
    json_decref(root);
    if (!ok)
        memset(out, 0, sizeof(*out));
    return ok;
}

bool at_replication_model_load(const char *path,
                               at_replication_model_t *out,
                               char *err, size_t err_len)
{
    if (path == NULL || out == NULL)
        return false;
    FILE *fp = fopen(path, "rb");
    if (fp == NULL)
    {
        _fail(err, err_len, "replication: cannot open %s", path);
        return false;
    }
    fseek(fp, 0, SEEK_END);
    long len = ftell(fp);
    if (len < 0)
    {
        fclose(fp);
        _fail(err, err_len, "replication: cannot size %s", path);
        return false;
    }
    fseek(fp, 0, SEEK_SET);
    char *buf = malloc((size_t)len + 1);
    if (buf == NULL)
    {
        fclose(fp);
        _fail(err, err_len, "replication: out of memory");
        return false;
    }
    size_t got = fread(buf, 1, (size_t)len, fp);
    buf[got] = '\0';
    fclose(fp);
    bool ok = at_replication_model_parse(buf, out, err, err_len);
    free(buf);
    return ok;
}

bool at_replication_model_load_env(at_replication_model_t *out,
                                   char *err, size_t err_len)
{
    const char *path = getenv(AT_REPLICATION_ENV);
    if (path == NULL || path[0] == '\0')
        return at_replication_model_parse(NULL, out, err, err_len);
    return at_replication_model_load(path, out, err, err_len);
}

double at_replication_prob_for(const at_replication_model_t *model,
                               const char *capability)
{
    if (model == NULL)
        return AT_REPLICATION_DEFAULT_PROB;
    if (capability != NULL)
        for (size_t i = 0; i < model->num_caps; i++)
            if (strcmp(model->caps[i].capability, capability) == 0)
                return model->caps[i].prob;
    return model->default_prob;
}

static const at_replication_cap_t *_cap(const at_replication_model_t *model,
                                        const char *capability)
{
    if (model == NULL || capability == NULL)
        return NULL;
    for (size_t i = 0; i < model->num_caps; i++)
        if (strcmp(model->caps[i].capability, capability) == 0)
            return &model->caps[i];
    return NULL;
}

bool at_replication_replay_for(const at_replication_model_t *model,
                               const char *capability, int *max_steps,
                               int *max_state_bytes)
{
    const at_replication_cap_t *c = _cap(model, capability);
    if (c == NULL || !c->replay)
        return false;
    if (max_steps != NULL)
        *max_steps = c->max_steps;
    if (max_state_bytes != NULL)
        *max_state_bytes = c->max_state_bytes;
    return true;
}

double at_replication_live_prob_for(const at_replication_model_t *model,
                                    const char *capability)
{
    return at_replication_replay_for(model, capability, NULL, NULL)
        ? at_replication_prob_for(model, capability) : 0.0;
}

double at_replication_tolerance_for(const at_replication_model_t *model,
                                    const char *capability)
{
    if (model == NULL || capability == NULL)
        return 0.0;
    for (size_t i = 0; i < model->num_caps; i++)
        if (strcmp(model->caps[i].capability, capability) == 0)
            return model->caps[i].tolerance;
    return 0.0;
}
