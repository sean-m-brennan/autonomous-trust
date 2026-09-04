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

/* Conformance adapter for certificate-carrying interfaces (R+D.md §12.3).
 *
 * A `certificate` scenario declares a model in `fixtures.certificates` — the
 * same shape a certificates.json file carries — and a list of
 * `fixtures.claims`, each {capability, kwargs, result, certificate}. Every row
 * is fed through this runtime's verifier and the verdict, plus the score it
 * maps to, is asserted per row.
 *
 * The verdict is asserted alongside the score because three of the five
 * produce no score at all and would be indistinguishable on the numbers alone:
 * `absent` is a fact about the peer, `indeterminate` is our own record failing
 * and must never reach a score, and `none` is a capability nobody declared or
 * one declared uncertifiable.
 *
 * Inputs reach this runtime the way it carries them — compact JSON text — while
 * the Python adapter passes the decoded values. `fixtures.seed` is the
 * verifier's challenge for the one probabilistic checker; in production it
 * comes from the requestor's own entropy at check time, and is fixed here so
 * the replay reproduces the verdicts.
 */

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <jansson.h>

#include "adapters/certificate.h"
#include "certificates/certificates.h"

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

/* Serialise a fixture value to the compact JSON text this runtime carries.
 * Returns a malloc'd string, or NULL when the field is absent. */
static char *_dump(json_t *value)
{
    if (value == NULL || json_is_null(value))
        return NULL;
    return json_dumps(value, JSON_COMPACT | JSON_ENCODE_ANY);
}

void at_certificate_run(const at_case_t *c, at_case_result_t *out)
{
    json_t *data = c->data;
    json_t *fixtures = json_object_get(data, "fixtures");
    json_t *declaration = json_is_object(fixtures)
        ? json_object_get(fixtures, "certificates") : NULL;
    if (!json_is_object(declaration))
    {
        _fail(out, "certificate scenario needs fixtures.certificates");
        return;
    }
    json_t *rows = json_is_object(fixtures)
        ? json_object_get(fixtures, "claims") : NULL;
    size_t nrows = json_is_array(rows) ? json_array_size(rows) : 0;
    json_t *j_seed = json_is_object(fixtures)
        ? json_object_get(fixtures, "seed") : NULL;
    uint64_t seed = json_is_integer(j_seed)
        ? (uint64_t)json_integer_value(j_seed) : 0;

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

    /* The declaration crosses as its JSON text, which is what the production
     * loader reads off disk — so this exercises the same parser production
     * does, not a hand-built model. */
    char *decl_text = json_dumps(declaration, JSON_COMPACT);
    if (decl_text == NULL)
    {
        _fail(out, "cannot serialise fixtures.certificates");
        return;
    }
    at_cert_model_t *model = calloc(1, sizeof(*model));
    if (model == NULL)
    {
        free(decl_text);
        _fail(out, "cannot allocate the model");
        return;
    }
    char err[AT_CERT_ERR_LEN] = {0};
    bool loaded = at_cert_model_parse(decl_text, model, err, sizeof(err));
    free(decl_text);
    if (!loaded)
    {
        free(model);
        _fail(out, "fixtures.certificates rejected: %s", err);
        return;
    }

    json_t *expected_state = json_object_get(data, "expected_state");
    json_t *host_exp = (host_id != NULL && json_is_object(expected_state))
        ? json_object_get(expected_state, host_id) : NULL;
    json_t *want_verdicts = json_is_object(host_exp)
        ? json_object_get(host_exp, "claim_verdicts") : NULL;
    json_t *want_scores = json_is_object(host_exp)
        ? json_object_get(host_exp, "claim_scores") : NULL;

    if (json_is_array(want_verdicts) && json_array_size(want_verdicts) != nrows)
    {
        free(model);
        _fail(out, "%s: %zu claims checked, %zu claim_verdicts pinned",
              host_id ? host_id : "?", nrows, json_array_size(want_verdicts));
        return;
    }

    bool ok = true;
    for (size_t i = 0; i < nrows && ok; i++)
    {
        json_t *row = json_array_get(rows, i);
        const char *cap = json_string_value(json_object_get(row, "capability"));
        char *kwargs = _dump(json_object_get(row, "kwargs"));
        char *result = _dump(json_object_get(row, "result"));
        char *cert = _dump(json_object_get(row, "certificate"));

        char why[AT_CERT_ERR_LEN] = {0};
        at_cert_verdict_t verdict = at_cert_evaluate(
            model, cap, result, cert, kwargs, seed, why, sizeof(why));
        const char *got = at_cert_verdict_name(verdict);
        double score = at_cert_score(verdict);

        if (json_is_array(want_verdicts))
        {
            const char *want =
                json_string_value(json_array_get(want_verdicts, i));
            if (want == NULL || strcmp(want, got) != 0)
                ok = _fail(out, "%s: row %zu (%s) reported verdict %s, "
                                "expected %s (%s)",
                           host_id ? host_id : "?", i, cap ? cap : "?", got,
                           want ? want : "?", why);
        }
        if (ok && json_is_array(want_scores))
        {
            json_t *w = json_array_get(want_scores, i);
            if (w == NULL || json_is_null(w))
            {
                if (verdict == AT_CERT_VALID || verdict == AT_CERT_INVALID ||
                    verdict == AT_CERT_ABSENT)
                    ok = _fail(out, "%s: row %zu scored %.3f, expected no score",
                               host_id ? host_id : "?", i, score);
            }
            else
            {
                double want = json_is_real(w) ? json_real_value(w)
                    : (json_is_integer(w) ? (double)json_integer_value(w)
                                          : -1.0);
                if (fabs(score - want) > 1e-9)
                    ok = _fail(out, "%s: row %zu scored %.3f, expected %.3f",
                               host_id ? host_id : "?", i, score, want);
            }
        }
        free(kwargs);
        free(result);
        free(cert);
    }

    free(model);
    if (ok)
        at_case_result_set_pass(out, 0);
}
