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

/* Conformance adapter for the physical-consistency layer (R+D.md §12.2).
 *
 * A `physics` scenario declares a model in `fixtures.physics` — the same shape
 * a physics.json file carries — and a list of `fixtures.claims`, each
 * {capability, result, subject, t}. Every row is fed through this runtime's
 * checker in order, carrying the observation store forward, and the verdict,
 * score and evidence channel are asserted per row.
 *
 * What is pinned is the RULES, not a shared call site: the two runtimes check
 * in different processes for the same reason they score probes in different
 * ones (R+D.md §12.7). The Python adapter reaches its checker through
 * automate.score_task_result; production C reaches this one through
 * negotiation_score_task_result.
 *
 * A result is spelled naturally in the fixture and reaches each runtime the
 * way that runtime carries it. A fixture STRING is delivered as its CONTENTS,
 * not as a quoted JSON string — the same rule the bootstrap adapter follows —
 * so "lots" is prose to both runtimes and a numeric string is a number to
 * both. Objects and arrays are delivered as compact JSON, which is what a
 * `report results` payload would carry.
 */

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <jansson.h>

#include "adapters/physics.h"
#include "physics/physics.h"
#include "reputation/tx_channel.h"

/* Verdict -> the name the scenario spells, and the (score, channel) it must
 * carry. Asserting all three catches a runtime that returned the right number
 * on the wrong channel — `none` is not "scored zero", it is "this layer has
 * nothing to say", and the caller then falls through to its completion arm. */
static const char *_verdict_name(at_physics_verdict_t v)
{
    switch (v)
    {
    case AT_PHYSICS_REFUTED:
        return "refuted";
    case AT_PHYSICS_IMPLICATED:
        return "implicated";
    case AT_PHYSICS_NONE:
        break;
    }
    return "none";
}

static const char *_verdict_channel(at_physics_verdict_t v)
{
    switch (v)
    {
    case AT_PHYSICS_REFUTED:
        return TX_CHANNEL_PHYSICAL;
    case AT_PHYSICS_IMPLICATED:
        return TX_CHANNEL_SWARM_DISAGREEMENT;
    case AT_PHYSICS_NONE:
        break;
    }
    return NULL;
}

static double _num_field(json_t *obj, const char *key, double dflt)
{
    json_t *v = json_object_get(obj, key);
    if (json_is_real(v))
        return json_real_value(v);
    if (json_is_integer(v))
        return (double)json_integer_value(v);
    return dflt;
}

/* Render a fixture `result` the way this runtime carries a reply. */
static bool _result_text(json_t *result, char *buf, size_t len)
{
    buf[0] = '\0';
    if (result == NULL || json_is_null(result))
        return false;
    if (json_is_string(result))
    {
        /* Contents, not the quoted form: see the file comment. */
        snprintf(buf, len, "%s", json_string_value(result));
        return true;
    }
    if (json_is_integer(result))
    {
        snprintf(buf, len, "%lld", (long long)json_integer_value(result));
        return true;
    }
    if (json_is_real(result))
    {
        /* 17 significant digits round-trips a double exactly, so the value
         * this runtime checks is the value the fixture wrote. */
        snprintf(buf, len, "%.17g", json_real_value(result));
        return true;
    }
    char *dumped = json_dumps(result, JSON_COMPACT | JSON_ENCODE_ANY);
    if (dumped == NULL)
        return false;
    snprintf(buf, len, "%s", dumped);
    free(dumped);
    return true;
}

static bool _fail(at_case_result_t *out, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

static bool _fail(at_case_result_t *out, const char *fmt, ...)
{
    char detail[320];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(detail, sizeof(detail), fmt, ap);
    va_end(ap);
    at_case_result_set_fail(out, 0, "AssertionError", detail);
    return false;
}

void at_physics_run(const at_case_t *c, at_case_result_t *out)
{
    json_t *data = c->data;
    json_t *fixtures = json_object_get(data, "fixtures");
    json_t *declaration = json_is_object(fixtures)
        ? json_object_get(fixtures, "physics") : NULL;
    if (!json_is_object(declaration))
    {
        _fail(out, "physics scenario needs fixtures.physics");
        return;
    }
    json_t *rows = json_is_object(fixtures)
        ? json_object_get(fixtures, "claims") : NULL;
    size_t nrows = json_is_array(rows) ? json_array_size(rows) : 0;

    /* Host = the participant with role new_node, else the first. */
    const char *host_id = NULL;
    json_t *parts = json_object_get(data, "participants");
    for (size_t i = 0; i < json_array_size(parts); i++)
    {
        json_t *p = json_array_get(parts, i);
        const char *role = json_string_value(json_object_get(p, "role"));
        const char *id = json_string_value(json_object_get(p, "id"));
        if (host_id == NULL && id != NULL)
            host_id = id;
        if (role != NULL && strcmp(role, "new_node") == 0 && id != NULL)
        {
            host_id = id;
            break;
        }
    }

    /* The declaration crosses as its JSON text, which is exactly what the
     * production loader reads off disk -- so this exercises the same parser
     * production does, not a hand-built model. */
    char *decl_text = json_dumps(declaration, JSON_COMPACT);
    if (decl_text == NULL)
    {
        _fail(out, "cannot serialise fixtures.physics");
        return;
    }
    at_physics_model_t model;
    char err[AT_PHYS_ERR_LEN] = {0};
    bool loaded = at_physics_model_parse(decl_text, &model, err, sizeof(err));
    free(decl_text);
    if (!loaded)
    {
        _fail(out, "fixtures.physics rejected: %s", err);
        return;
    }

    at_physics_checker_t *checker = calloc(1, sizeof(*checker));
    if (checker == NULL)
    {
        _fail(out, "cannot allocate the checker");
        return;
    }
    at_physics_checker_init(checker, &model);

    json_t *expected_state = json_object_get(data, "expected_state");
    json_t *host_exp = (host_id != NULL && json_is_object(expected_state))
        ? json_object_get(expected_state, host_id) : NULL;
    json_t *want_verdicts = json_is_object(host_exp)
        ? json_object_get(host_exp, "claim_verdicts") : NULL;
    json_t *want_scores = json_is_object(host_exp)
        ? json_object_get(host_exp, "claim_scores") : NULL;
    json_t *want_channels = json_is_object(host_exp)
        ? json_object_get(host_exp, "claim_channels") : NULL;

    if (json_is_array(want_verdicts) &&
        json_array_size(want_verdicts) != nrows)
    {
        _fail(out, "%s: %zu claims checked, %zu claim_verdicts pinned",
              host_id ? host_id : "?", nrows, json_array_size(want_verdicts));
        free(checker);
        return;
    }

    bool ok = true;
    for (size_t i = 0; i < nrows && ok; i++)
    {
        json_t *row = json_array_get(rows, i);
        const char *cap = json_string_value(json_object_get(row, "capability"));
        json_t *subj = json_object_get(row, "subject");
        const char *subject = json_is_string(subj) ? json_string_value(subj)
                                                   : NULL;
        double t = _num_field(row, "t", 0.0);

        char result_buf[512];
        bool have = _result_text(json_object_get(row, "result"), result_buf,
                                 sizeof(result_buf));

        double score = 0.0;
        at_physics_verdict_t verdict = at_physics_check(
            checker, cap, have ? result_buf : NULL, subject, t, &score,
            NULL, 0);
        const char *got_name = _verdict_name(verdict);
        const char *got_channel = _verdict_channel(verdict);

        if (json_is_array(want_verdicts))
        {
            const char *want = json_string_value(json_array_get(want_verdicts, i));
            if (want == NULL || strcmp(want, got_name) != 0)
                ok = _fail(out, "%s: row %zu (%s -> %s from %s) reported "
                                "verdict %s, expected %s",
                           host_id ? host_id : "?", i, cap ? cap : "?",
                           have ? result_buf : "null",
                           subject ? subject : "null", got_name,
                           want ? want : "?");
        }
        if (ok && json_is_array(want_scores))
        {
            json_t *w = json_array_get(want_scores, i);
            if (json_is_null(w) || w == NULL)
            {
                if (verdict != AT_PHYSICS_NONE)
                    ok = _fail(out, "%s: row %zu scored %.3f, expected no "
                                    "verdict", host_id ? host_id : "?", i, score);
            }
            else
            {
                double want = json_is_real(w) ? json_real_value(w)
                    : (json_is_integer(w) ? (double)json_integer_value(w) : -1.0);
                if (verdict == AT_PHYSICS_NONE || fabs(score - want) > 1e-9)
                    ok = _fail(out, "%s: row %zu scored %.3f, expected %.3f",
                               host_id ? host_id : "?", i,
                               verdict == AT_PHYSICS_NONE ? 0.0 : score, want);
            }
        }
        if (ok && json_is_array(want_channels))
        {
            json_t *w = json_array_get(want_channels, i);
            const char *want = json_is_string(w) ? json_string_value(w) : NULL;
            if (want == NULL)
            {
                if (got_channel != NULL)
                    ok = _fail(out, "%s: row %zu reported channel %s, "
                                    "expected none",
                               host_id ? host_id : "?", i, got_channel);
            }
            else if (got_channel == NULL || strcmp(got_channel, want) != 0)
                ok = _fail(out, "%s: row %zu reported channel %s, expected %s",
                           host_id ? host_id : "?", i,
                           got_channel ? got_channel : "none", want);
        }
    }

    free(checker);
    if (ok)
        at_case_result_set_pass(out, 0);
}
